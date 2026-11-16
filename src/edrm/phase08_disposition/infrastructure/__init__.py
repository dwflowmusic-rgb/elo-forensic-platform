"""Infraestrutura fisica da Fase 08 — Limpeza Exclusiva de Staging, Git Bundle e NIST 800-88."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import tempfile

from edrm.phase08_disposition.domain import Nist80088Certificate
from edrm.shared_kernel.contracts import (
    FileStatEntry,
    MediaSnapshot,
    Phase07ToPhase08Contract,
)
from edrm.shared_kernel.enums import AcquisitionMode
from edrm.shared_kernel.exceptions import BlockingVerificationError
from edrm.shared_kernel.value_objects import SafeOsPath, canonical_json_sha256


class StagingCleanerAndBundleAdapter:
    """Verifica entregaveis/cofre, expurga exclusivamente staging/ e gera Recovery Bundle."""

    def verify_deliverables_and_purge_staging(
        self,
        bundle: Phase07ToPhase08Contract,
    ) -> tuple[int, int, bool]:
        """Confere SHA-256 de deliverables/ e vault/ antes de remover arquivos de staging/."""
        p04 = bundle.phase06_bundle.phase05_bundle.phase04_bundle
        p03 = p04.phase03_bundle
        gov = p04.updated_phase01_bundle.governance

        deliv_dir = Path(gov.deliverables_dir)
        for fname, expected_sha in bundle.all_deliverables:
            fpath = deliv_dir / fname
            if not fpath.exists():
                raise BlockingVerificationError(f"Entregavel ausente antes do expurgo: {fname}")
            real_sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if real_sha != expected_sha:
                raise BlockingVerificationError(f"Divergencia SHA-256 no entregavel {fname}")

        vault_ok = True
        for ve in p03.vault_entries:
            if ve.acquisition_mode == AcquisitionMode.IMMUTABLE_REFERENCED_INDEX:
                continue
            vp = Path(ve.vault_abs_path)
            if not vp.exists():
                vault_ok = False
                break
            v_sha = hashlib.sha256(vp.read_bytes()).hexdigest()
            if v_sha != ve.vault_cold_sha256:
                vault_ok = False
                break
        if not vault_ok:
            raise BlockingVerificationError("Integridade do vault/ violada antes da Fase 08!")

        purged_count = 0
        purged_bytes = 0
        staging_path = Path(gov.staging_dir)
        if bundle.authorize_staging_purge and staging_path.exists():
            for item in sorted(staging_path.rglob("*"), reverse=True):
                if item.is_file() or item.is_symlink():
                    purged_bytes += int(item.stat().st_size)
                    purged_count += 1
                    os.chmod(str(item), 0o600)
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(str(item), ignore_errors=False)

        return purged_count, purged_bytes, vault_ok

    def build_manifest_and_recovery_bundle(
        self,
        workspace_root: str,
        audit_dir: str,
        deliverables_dir: str,
    ) -> tuple[str, str]:
        """Gera MANIFESTO_SHA256.txt e pacote versionado recovery_case.bundle."""
        ws = Path(workspace_root)
        manifest_lines: list[str] = []
        for zone_name in ("vault", "catalog", "deliverables", "audit"):
            z_dir = ws / zone_name
            if not z_dir.exists():
                continue
            for f in sorted(z_dir.rglob("*")):
                if f.is_file() and f.name not in ("MANIFESTO_SHA256.txt", "recovery_case.bundle"):
                    digest = hashlib.sha256(f.read_bytes()).hexdigest()
                    rel = f.relative_to(ws).as_posix()
                    manifest_lines.append(f"{digest}  {rel}")

        manifest_path = Path(audit_dir) / "MANIFESTO_SHA256.txt"
        manifest_content = "\n".join(manifest_lines) + "\n"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            fh.write(manifest_content)
            fh.flush()
            os.fsync(fh.fileno())

        bundle_path = Path(audit_dir) / "recovery_case.bundle"
        git_bin = shutil.which("git")
        if git_bin is not None:
            with tempfile.TemporaryDirectory() as tmp_git:
                tmp_repo = Path(tmp_git) / "repo"
                shutil.copytree(deliverables_dir, tmp_repo / "deliverables")
                os.makedirs(tmp_repo / "audit", exist_ok=True)
                shutil.copy2(manifest_path, tmp_repo / "audit" / "MANIFESTO_SHA256.txt")
                subprocess.run([git_bin, "init", "-q"], cwd=str(tmp_repo), check=True)
                subprocess.run(
                    [git_bin, "config", "user.email", "audit@elo.local"],
                    cwd=str(tmp_repo),
                    check=True,
                )
                subprocess.run(
                    [git_bin, "config", "user.name", "ELO Forensic"],
                    cwd=str(tmp_repo),
                    check=True,
                )
                subprocess.run([git_bin, "add", "."], cwd=str(tmp_repo), check=True)
                subprocess.run(
                    [git_bin, "commit", "-q", "-m", "ELO Recovery Snapshot"],
                    cwd=str(tmp_repo),
                    check=True,
                )
                subprocess.run(
                    [git_bin, "bundle", "create", str(bundle_path), "--all"],
                    cwd=str(tmp_repo),
                    check=True,
                    capture_output=True,
                )
        else:
            shutil.make_archive(str(bundle_path), "zip", deliverables_dir)

        return str(manifest_path), str(bundle_path)

    def capture_final_source_snapshot(
        self,
        source_roots: tuple[str, ...],
        ts_utc: str,
    ) -> MediaSnapshot:
        """Captura PostScanSnapshot final de --source e grava registro em governance_runs."""
        entries: list[FileStatEntry] = []
        is_win = os.name == "nt"
        for src_idx, root_str in enumerate(source_roots, start=1):
            source_id = f"SRC-{src_idx:02d}"
            root_path = Path(SafeOsPath(root_str).logical_path).resolve()
            clean_root = Path(SafeOsPath(str(root_path)).logical_path)
            all_files = sorted(p for p in root_path.rglob("*") if p.is_file() and not p.is_symlink())
            for abs_f in all_files:
                ext_f = SafeOsPath(str(abs_f)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_f, follow_symlinks=False)
                clean_abs = Path(SafeOsPath(str(abs_f)).logical_path)
                entries.append(
                    FileStatEntry(
                        source_id=source_id,
                        rel_path=clean_abs.relative_to(clean_root).as_posix(),
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


class Nist80088SanitizerAdapter:
    """Executa sanitizacao certificada sobre copias descartaveis e emite CertificateOfDisposition.json."""

    def execute_and_write_certificate(
        self,
        audit_dir: str,
        target_dir_to_purge: str | None,
        certificate: Nist80088Certificate,
    ) -> str:
        """Sobrescreve blocos de copias de trabalho autorizadas e grava certificado assinado."""
        if target_dir_to_purge is not None:
            t_path = Path(target_dir_to_purge)
            if t_path.exists() and t_path.is_dir():
                for f in sorted(t_path.rglob("*"), reverse=True):
                    if f.is_file():
                        size = int(f.stat().st_size)
                        os.chmod(str(f), 0o600)
                        with open(f, "wb") as fh:
                            fh.write(b"\x00" * size)
                            fh.flush()
                            os.fsync(fh.fileno())
                        f.unlink()
                shutil.rmtree(str(t_path), ignore_errors=True)

        cert_dict = asdict(certificate)
        _, cert_sha = canonical_json_sha256(cert_dict)
        cert_dict["certificate_sha256"] = cert_sha
        cert_dict["standard"] = certificate.standard
        cert_dict["sanitization_method"] = str(certificate.sanitization_method)

        out_path = Path(audit_dir) / "CertificateOfDisposition.json"
        ext_out = SafeOsPath(str(out_path)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_out, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(cert_dict, ensure_ascii=False, indent=2, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        return str(out_path)
