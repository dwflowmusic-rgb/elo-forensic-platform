"""Infraestrutura fisica da Fase 03 — Copiador 4MiB + fsync + Releitura Fria e Trava Read-Only."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Callable

from edrm.phase03_collection.domain import PlannedAcquisitionItem
from edrm.shared_kernel.contracts import (
    FileStatEntry,
    MediaSnapshot,
    Phase02ToPhase03Contract,
    StateCollectionFinding,
    VaultAcquiredEntry,
)
from edrm.shared_kernel.enums import AcquisitionMode
from edrm.shared_kernel.exceptions import CollectionHashMismatchError
from edrm.shared_kernel.value_objects import SafeOsPath, canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly

COPY_CHUNK_BYTES: int = 4 * 1024 * 1024


class FsyncColdVerifyCopierAdapter:
    """Copiador forense com descarga fisica os.fsync, releitura fria e bloqueio Read-Only."""

    def __init__(
        self,
        fault_injector: Callable[[bytes], bytes] | None = None,
    ) -> None:
        self._fault_injector = fault_injector

    def acquire_into_vault(
        self,
        vault_dir: str,
        item: PlannedAcquisitionItem,
    ) -> VaultAcquiredEntry:
        """Copia em blocos de 4 MiB, aplica fsync, reabre a frio e trava permissoes."""
        is_win = os.name == "nt"
        src_ext = SafeOsPath(item.origin_abs_path).to_os_extended(is_windows=is_win)

        if item.mode == AcquisitionMode.IMMUTABLE_REFERENCED_INDEX:
            src_hash, src_bytes = self._hash_cold_file(src_ext)
            if src_hash != item.expected_sha256 or src_bytes != item.expected_bytes:
                raise CollectionHashMismatchError(
                    f"Divergencia de hash em imagem referenciada {item.origin_rel_path}"
                )
            return VaultAcquiredEntry(
                control_number=item.control_number.code,
                source_id=item.source_id,
                origin_rel_path=item.origin_rel_path,
                vault_rel_path=f"REFERENCED::{item.origin_rel_path}",
                vault_abs_path=item.origin_abs_path,
                acquisition_mode=item.mode,
                size_bytes=src_bytes,
                mtime_utc_ns=item.mtime_utc_ns,
                source_sha256=src_hash,
                vault_cold_sha256=src_hash,
                vault_locked_readonly=True,
            )

        dest_path = Path(vault_dir) / item.vault_rel_path
        dest_ext = SafeOsPath(str(dest_path)).to_os_extended(is_windows=is_win)
        os.makedirs(str(dest_path.parent), exist_ok=True)
        if dest_path.exists():
            os.chmod(dest_ext, 0o600)

        source_hasher = hashlib.sha256()
        bytes_read = 0

        with open(src_ext, "rb") as src_fh, open(dest_ext, "wb") as dst_fh:
            while True:
                buf = src_fh.read(COPY_CHUNK_BYTES)
                if not buf:
                    break
                source_hasher.update(buf)
                bytes_read += len(buf)
                out_buf = self._fault_injector(buf) if self._fault_injector is not None else buf
                dst_fh.write(out_buf)
            dst_fh.flush()
            os.fsync(dst_fh.fileno())

        source_sha = source_hasher.hexdigest()
        cold_vault_sha, cold_vault_bytes = self._hash_cold_file(dest_ext)

        if (
            source_sha != cold_vault_sha
            or bytes_read != cold_vault_bytes
            or cold_vault_sha != item.expected_sha256
        ):
            if dest_path.exists():
                os.remove(dest_ext)
            raise CollectionHashMismatchError(
                f"Falha de mesmidade na coleta de {item.origin_rel_path}: "
                f"source_sha={source_sha} vs vault_cold_sha={cold_vault_sha}"
            )

        self._lock_readonly(dest_ext)
        st_after = os.stat(dest_ext, follow_symlinks=False)
        locked = not bool(st_after.st_mode & stat.S_IWUSR)

        return VaultAcquiredEntry(
            control_number=item.control_number.code,
            source_id=item.source_id,
            origin_rel_path=item.origin_rel_path,
            vault_rel_path=item.vault_rel_path,
            vault_abs_path=str(dest_path),
            acquisition_mode=item.mode,
            size_bytes=cold_vault_bytes,
            mtime_utc_ns=item.mtime_utc_ns,
            source_sha256=source_sha,
            vault_cold_sha256=cold_vault_sha,
            vault_locked_readonly=locked,
        )

    def _hash_cold_file(self, ext_path: str) -> tuple[str, int]:
        """Reabre o arquivo do zero e calcula SHA-256 em blocos de 4 MiB."""
        hasher = hashlib.sha256()
        total = 0
        with open(ext_path, "rb") as fh:
            while True:
                chunk = fh.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                hasher.update(chunk)
                total += len(chunk)
        return hasher.hexdigest(), total

    def _lock_readonly(self, ext_path: str) -> None:
        """Aplica trava somente leitura no cofre (chmod 0o444 / FILE_ATTRIBUTE_READONLY)."""
        if os.name == "nt":
            os.chmod(ext_path, stat.S_IREAD)
        else:
            os.chmod(ext_path, 0o444)

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Recaptura snapshot passivo de --source."""
        entries: list[FileStatEntry] = []
        is_win = os.name == "nt"
        for src_idx, root_str in enumerate(source_roots, start=1):
            source_id = f"SRC-{src_idx:02d}"
            root_path = Path(root_str).resolve()
            all_files = sorted(p for p in root_path.rglob("*") if p.is_file() and not p.is_symlink())
            for abs_f in all_files:
                ext_f = SafeOsPath(str(abs_f)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_f, follow_symlinks=False)
                entries.append(
                    FileStatEntry(
                        source_id=source_id,
                        rel_path=abs_f.relative_to(root_path).as_posix(),
                        size_bytes=int(st.st_size),
                        mtime_utc_ns=int(st.st_mtime_ns),
                        mode_octal=oct(st.st_mode & 0o777),
                        inode_or_file_index=int(st.st_ino),
                        is_os_readonly=not bool(st.st_mode & stat.S_IWUSR),
                    )
                )
        _, snap_sha = canonical_json_sha256([asdict(e) for e in entries])
        return MediaSnapshot(
            captured_at_utc=ts_utc,
            entries=tuple(entries),
            snapshot_sha256=snap_sha,
        )


class Phase03ManifestAndReportAdapter:
    """Atualiza o catalogo com ControlNumbers do cofre, gera manifesto ICP-Brasil e Relatorio."""

    def finalize_phase03_artifacts(
        self,
        phase02_bundle: Phase02ToPhase03Contract,
        vault_entries: tuple[VaultAcquiredEntry, ...],
        state_findings: tuple[StateCollectionFinding, ...],
        issued_at_utc: str,
    ) -> tuple[str, str, str, str]:
        """Grava manifesto lateral ICP-Brasil e phase03_collection_report.md verificado."""
        gov = phase02_bundle.phase01_bundle.governance
        is_win = os.name == "nt"
        db_ext = SafeOsPath(gov.catalog_db_path).to_os_extended(is_windows=is_win)

        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                for ve in vault_entries:
                    conn.execute(
                        """
                        UPDATE evidence_inventory_tree
                        SET vault_rel_path = ?, is_os_readonly = ?
                        WHERE control_number = ?
                        """,
                        (ve.vault_rel_path, 1 if ve.vault_locked_readonly else 0, ve.control_number),
                    )
        finally:
            conn.close()

        icp_payload = {
            "standard": "ICP-Brasil_DOC-ICP-15_Detached_Manifest_Ready",
            "case_id": gov.case_id,
            "issued_at_utc": issued_at_utc,
            "hash_algorithm": "SHA-256",
            "vault_items": [asdict(v) for v in vault_entries],
        }
        icp_json, icp_sha = canonical_json_sha256(icp_payload)
        icp_payload["master_hashlist_sha256"] = icp_sha

        icp_path = Path(gov.audit_dir) / "phase03_icp_brasil_manifest.json"
        icp_ext = SafeOsPath(str(icp_path)).to_os_extended(is_windows=is_win)
        with open(icp_ext, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(icp_payload, ensure_ascii=False, indent=2, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())

        known_hashes = {ve.vault_cold_sha256 for ve in vault_entries} | {icp_sha}
        known_cns = {ve.control_number for ve in vault_entries}
        corpus_parts = [pf.text_preview for pf in phase02_bundle.phase01_bundle.discovery_blueprint.probed_files]
        for sf in state_findings:
            known_cns.add(sf.anchor.origin_control_number)
            known_hashes.add(sf.anchor.origin_sha256)
            corpus_parts.append(sf.anchor.verbatim_excerpt)

        lines: list[str] = [
            "# Relatorio Oficial Fase 03 — Coleta Verificada e Aquisicao Defensavel",
            "",
            f"- Manifesto ICP-Brasil Master Hash: `{icp_sha}`",
            "",
            "## 1. Inventario de Coleta no Cofre (os.fsync + Releitura Fria)",
        ]
        for ve in vault_entries:
            lines.append(
                f"- `{ve.control_number}` | `{ve.origin_rel_path}` -> `{ve.vault_rel_path}` | "
                f"`{ve.size_bytes}` bytes | SHA-256 Frio: `{ve.vault_cold_sha256}` | "
                f"Read-Only: `{ve.vault_locked_readonly}`"
            )

        lines.append("")
        lines.append("## 2. Auditoria Tecnica do Metodo Estatal de Coleta (CPP Arts. 158-C/158-D)")
        for sf in state_findings:
            lines.append(
                f"- Vestigio `{sf.declared_id}` | Metodo: `{sf.method_used}` | "
                f"Perito Oficial: `{sf.official_expert_verified}` | "
                f"Alto Risco: `{sf.high_risk_flag}` | {sf.notes}"
            )

        md = "\n".join(lines) + "\n"
        verify_markdown_report_strictly(
            markdown_text=md,
            known_sha256_set=known_hashes,
            known_cn_set=known_cns,
            all_verbatim_corpus_text="\n".join(corpus_parts),
        )

        rep_path = Path(gov.deliverables_dir) / "phase03_collection_report.md"
        rep_ext = SafeOsPath(str(rep_path)).to_os_extended(is_windows=is_win)
        with open(rep_ext, "w", encoding="utf-8") as fh:
            fh.write(md)
            fh.flush()
            os.fsync(fh.fileno())
        return str(icp_path), icp_sha, str(rep_path), sha256_text(md)
