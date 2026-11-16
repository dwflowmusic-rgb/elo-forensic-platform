"""Infraestrutura fisica da Fase 02 — SQLite quick_check Imutavel, Inspecao WAL e Relatorio."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import stat
import struct
import zipfile

from edrm.phase02_preservation.domain import LegalHoldRecord
from edrm.shared_kernel.contracts import (
    FileStatEntry,
    MediaSnapshot,
    Phase01ToPhase02Contract,
    PreservationAxisFinding,
    ProbedFileRecord,
    SpofRiskEntry,
    StructuralHealthFinding,
)
from edrm.shared_kernel.enums import EpistemicStatus, MagicSignature
from edrm.shared_kernel.value_objects import ControlNumber, SafeOsPath, canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly


class ImmutableStructuralHealthAdapter:
    """Executa PRAGMA quick_check imutavel, mede frames -wal passivamente e testa CRCs."""

    def audit_structural_health(
        self,
        probed_files: tuple[ProbedFileRecord, ...],
    ) -> tuple[StructuralHealthFinding, ...]:
        """Audita saude estrutural sem jamais abrir descritores de escrita."""
        results: list[StructuralHealthFinding] = []
        is_win = os.name == "nt"

        for pf in probed_files:
            ext_path = SafeOsPath(pf.abs_path).to_os_extended(is_windows=is_win)
            qc_ok = True
            has_wal_frames = False
            wal_frames = 0
            crc_ok = True
            details: list[str] = []

            if pf.magic_signature == MagicSignature.SQLITE3:
                uri = SafeOsPath(pf.abs_path).to_sqlite_immutable_uri(is_windows=is_win)
                try:
                    conn = sqlite3.connect(uri, uri=True)
                    try:
                        conn.execute("PRAGMA query_only = 1;")
                        row = conn.execute("PRAGMA quick_check;").fetchone()
                        qc_ok = bool(row and str(row[0]).lower() == "ok")
                        if not qc_ok:
                            details.append(f"SQLite quick_check falhou: {row}")
                    finally:
                        conn.close()
                except sqlite3.DatabaseError as exc:
                    qc_ok = False
                    details.append(f"Erro SQLite imutavel: {exc}")

                wal_candidate = Path(f"{pf.abs_path}-wal")
                if wal_candidate.exists():
                    wal_frames = self._count_wal_frames_passively(str(wal_candidate))
                    if wal_frames > 0:
                        has_wal_frames = True
                        details.append(
                            f"Arquivo irmao -wal contem {wal_frames} frames pendentes nao consolidados."
                        )

            elif pf.magic_signature in (
                MagicSignature.ZIP_CONTAINER,
                MagicSignature.CELLEBRITE_UFDR_UFDX,
            ):
                try:
                    with open(ext_path, "rb") as raw_fh:
                        with zipfile.ZipFile(raw_fh, mode="r") as zf:
                            bad_member = zf.testzip()
                            if bad_member is not None:
                                crc_ok = False
                                details.append(f"CRC invalido no membro {bad_member}")
                except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                    crc_ok = False
                    details.append(f"Pacote ZIP/UFDR corrompido ou cifrado: {exc}")

            if pf.pdf_eof_count > 1:
                details.append(
                    f"PDF possui {pf.pdf_eof_count} marcadores %%EOF (atualizacoes incrementais)."
                )

            healthy = qc_ok and crc_ok and (not pf.is_encrypted_or_corrupted)
            if not details:
                details.append("Integridade estrutural verificada em modo imutavel.")

            results.append(
                StructuralHealthFinding(
                    rel_path=pf.rel_path,
                    sha256_hex=pf.sha256_hex,
                    sqlite_quick_check_ok=qc_ok,
                    has_unconsolidated_wal_frames=has_wal_frames,
                    wal_frame_count=wal_frames,
                    archive_crc_ok=crc_ok,
                    pdf_incremental_revisions=pf.pdf_eof_count,
                    is_healthy=healthy,
                    detail="; ".join(details),
                )
            )
        return tuple(results)

    def _count_wal_frames_passively(self, wal_abs_path: str) -> int:
        """Conta quadros pendentes no arquivo -wal lendo apenas os 32 bytes de cabecalho."""
        ext_wal = SafeOsPath(wal_abs_path).to_os_extended(is_windows=(os.name == "nt"))
        st = os.stat(ext_wal, follow_symlinks=False)
        if st.st_size <= 32:
            return 0
        with open(ext_wal, "rb") as fh:
            hdr = fh.read(32)
        if len(hdr) < 32:
            return 0
        magic, _, page_size = struct.unpack(">III", hdr[:12])
        if magic not in (0x377F0682, 0x377F0683) or page_size == 0:
            return 1
        frame_bytes = page_size + 24
        return max(1, (int(st.st_size) - 32) // frame_bytes)

    def list_existing_vault_files(self, vault_dir: str) -> set[str]:
        """Retorna conjunto de caminhos relativos ja armazenados em workspace/vault/."""
        vp = Path(vault_dir)
        if not vp.exists():
            return set()
        return {f.relative_to(vp).as_posix() for f in vp.rglob("*") if f.is_file()}

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Captura fotografia os.stat passiva identica a linha de base."""
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


class Phase02CatalogAndMarkdownAdapter:
    """Persiste os achados dos 6 Eixos no catalogo e compila o Relatorio Oficial Fase 02."""

    def persist_and_compile(
        self,
        phase01_bundle: Phase01ToPhase02Contract,
        structural_findings: tuple[StructuralHealthFinding, ...],
        spof_map: tuple[SpofRiskEntry, ...],
        six_axes_findings: tuple[PreservationAxisFinding, ...],
        legal_hold: LegalHoldRecord,
    ) -> tuple[str, str]:
        """Persiste no SQLite do caso e grava phase02_preservation_report.md verificado."""
        db_ext = SafeOsPath(phase01_bundle.governance.catalog_db_path).to_os_extended(
            is_windows=(os.name == "nt")
        )
        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                for ax in six_axes_findings:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO custody_and_parity_findings (
                            finding_id, declared_id, matched_cn, parity_state,
                            preservation_axis, defect_category, legal_tags_json,
                            is_judicial_critical, epistemic_status, anchor_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ax.finding_id,
                            ax.declared_id,
                            ax.anchor.origin_control_number,
                            "COMPLIANT" if ax.compliant else "NON_COMPLIANT",
                            str(ax.axis),
                            "PENDING_PHASE_05",
                            json.dumps(list(ax.legal_tags)),
                            0 if ax.compliant else 1,
                            str(EpistemicStatus.VERIFIED_FACT),
                            json.dumps(ax.anchor.to_dict(), ensure_ascii=False, sort_keys=True),
                        ),
                    )
        finally:
            conn.close()

        known_hashes = {pf.sha256_hex for pf in phase01_bundle.discovery_blueprint.probed_files}
        known_cns = {
            ControlNumber.root(i).code
            for i in range(1, len(phase01_bundle.discovery_blueprint.probed_files) + 1)
        }
        corpus_parts = [pf.text_preview for pf in phase01_bundle.discovery_blueprint.probed_files]
        for ax in six_axes_findings:
            known_cns.add(ax.anchor.origin_control_number)
            known_hashes.add(ax.anchor.origin_sha256)
            corpus_parts.append(ax.anchor.verbatim_excerpt)

        lines: list[str] = [
            "# Relatorio Oficial Fase 02 — Preservacao e Auditoria dos 6 Eixos na Origem",
            "",
            f"- Legal Hold ID: `{legal_hold.hold_id}` ({legal_hold.issued_at_utc})",
            f"- Total de arquivos protegidos: `{legal_hold.total_protected_files}` | SPOF Criticos: `{legal_hold.spof_critical_count}`",
            "",
            "## 1. Diagnostico de Integridade Estrutural (SQLite Immutable, WAL e CRCs)",
        ]
        for sf in structural_findings:
            lines.append(
                f"- `{sf.rel_path}` | SHA-256: `{sf.sha256_hex}` | Saudavel: `{sf.is_healthy}` | "
                f"WAL Pendente: `{sf.has_unconsolidated_wal_frames}` ({sf.wal_frame_count} frames) | "
                f"%%EOF: `{sf.pdf_incremental_revisions}` | {sf.detail}"
            )

        lines.append("")
        lines.append("## 2. Mapa de Risco SPOF")
        for sp in spof_map:
            lines.append(
                f"- `{sp.rel_path}` | SPOF Critico: `{sp.is_spof_critical}` | "
                f"Modo Recomendado: `{sp.recommended_mode}`"
            )

        lines.append("")
        lines.append("## 3. Avaliacao Atomica dos 6 Eixos Obrigatorios da Preservacao Estatal")
        for ax in six_axes_findings:
            status_str = "CONFORME" if ax.compliant else "NAO_CONFORME"
            lines.append(
                f"- `{ax.finding_id}` | Vestigio `{ax.declared_id}` | Eixo `{ax.axis}`: **{status_str}** | "
                f"Tags: `{', '.join(ax.legal_tags) or 'OK'}` | {ax.summary}"
            )

        md = "\n".join(lines) + "\n"
        verify_markdown_report_strictly(
            markdown_text=md,
            known_sha256_set=known_hashes,
            known_cn_set=known_cns,
            all_verbatim_corpus_text="\n".join(corpus_parts),
        )

        out_path = Path(phase01_bundle.governance.deliverables_dir) / "phase02_preservation_report.md"
        ext_out = SafeOsPath(str(out_path)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_out, "w", encoding="utf-8") as fh:
            fh.write(md)
            fh.flush()
            os.fsync(fh.fileno())
        return str(out_path), sha256_text(md)
