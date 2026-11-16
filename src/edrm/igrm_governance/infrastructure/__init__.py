"""Infraestrutura fisica da Camada 00 — Write-Blocker, Socket Guard, Manifesto e Ledger."""

from __future__ import annotations

import builtins
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
try:
    import resource
except ImportError:  # Windows / ambientes nao-POSIX
    resource = None  # type: ignore[assignment]
import socket
import sqlite3
import sys
from types import TracebackType
from typing import Any

from edrm.igrm_governance.domain import (
    CaseWorkspaceLayout,
    SecrecyNetworkPolicy,
    SourceWriteBlockerPolicy,
)
from edrm.shared_kernel.contracts import CaseGovernanceContract
from edrm.shared_kernel.enums import PhaseCode, SecrecyLevel
from edrm.shared_kernel.exceptions import ReadOnlyViolationError
from edrm.shared_kernel.schema_sql import CANONICAL_CATALOG_DDL_STATEMENTS
from edrm.shared_kernel.value_objects import SafeOsPath, canonical_json_sha256


class SystemUtcClockAdapter:
    """Adaptador de relogio UTC real do sistema operacional."""

    def now_iso_utc(self) -> str:
        """Retorna o horario atual em UTC ISO-8601 terminado em Z."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FsWriteBlockerGuard:
    """Guarda de contexto que intercepta aberturas e mutacoes em --source e sockets externos."""

    def __init__(
        self,
        source_roots: tuple[str, ...],
        secrecy_level: SecrecyLevel = SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY,
    ) -> None:
        resolved = tuple(str(Path(p).resolve()) for p in source_roots)
        self._policy = SourceWriteBlockerPolicy(protected_roots=resolved)
        self._net_policy = SecrecyNetworkPolicy(secrecy_level=secrecy_level)
        self._orig_open = builtins.open
        self._orig_os_open = os.open
        self._orig_remove = os.remove
        self._orig_unlink = os.unlink
        self._orig_rename = os.rename
        self._orig_replace = os.replace
        self._orig_chmod = os.chmod
        self._orig_truncate = os.truncate
        self._orig_mkdir = os.mkdir
        self._orig_rmdir = os.rmdir
        self._orig_connect = socket.socket.connect

    @property
    def policy(self) -> SourceWriteBlockerPolicy:
        """Retorna a politica subjacente de bloqueio de escrita."""
        return self._policy

    def safe_open_readonly(self, path_str: str) -> Any:
        """Abre um arquivo exclusivamente em leitura binaria verificando a politica."""
        resolved = str(Path(path_str).resolve())
        self._policy.assert_open_allowed(resolved, "rb")
        ext = SafeOsPath(resolved).to_os_extended(is_windows=(os.name == "nt"))
        return self._orig_open(ext, "rb")

    def __enter__(self) -> FsWriteBlockerGuard:
        policy = self._policy
        net_policy = self._net_policy
        orig_open = self._orig_open
        orig_os_open = self._orig_os_open
        orig_remove = self._orig_remove
        orig_unlink = self._orig_unlink
        orig_rename = self._orig_rename
        orig_replace = self._orig_replace
        orig_chmod = self._orig_chmod
        orig_truncate = self._orig_truncate
        orig_mkdir = self._orig_mkdir
        orig_rmdir = self._orig_rmdir
        orig_connect = self._orig_connect

        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

        def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if isinstance(file, (str, Path, os.PathLike)):
                resolved = str(Path(file).resolve())
                policy.assert_open_allowed(resolved, mode)
            return orig_open(file, mode, *args, **kwargs)

        def guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
            if isinstance(path, (str, Path, os.PathLike)):
                raw_str = str(path)
                if raw_str.startswith("file:"):
                    cleaned_uri = raw_str[5:].split("?", 1)[0]
                    resolved = str(Path(cleaned_uri).resolve())
                else:
                    resolved = str(Path(raw_str).resolve())
                if policy.is_protected_path(resolved) and (flags & write_flags):
                    raise ReadOnlyViolationError(
                        f"os.open com flags de escrita ({flags}) bloqueado em --source: {resolved}"
                    )
            return orig_os_open(path, flags, *args, **kwargs)

        def guarded_remove(path: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.remove")
            orig_remove(path, *args, **kwargs)

        def guarded_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.unlink")
            orig_unlink(path, *args, **kwargs)

        def guarded_rename(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(src).resolve()), "os.rename(src)")
            policy.assert_mutation_forbidden(str(Path(dst).resolve()), "os.rename(dst)")
            orig_rename(src, dst, *args, **kwargs)

        def guarded_replace(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(src).resolve()), "os.replace(src)")
            policy.assert_mutation_forbidden(str(Path(dst).resolve()), "os.replace(dst)")
            orig_replace(src, dst, *args, **kwargs)

        def guarded_chmod(path: Any, mode: int, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.chmod")
            orig_chmod(path, mode, *args, **kwargs)

        def guarded_truncate(path: Any, length: int) -> None:
            if isinstance(path, (str, Path, os.PathLike)):
                policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.truncate")
            orig_truncate(path, length)

        def guarded_mkdir(path: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.mkdir")
            orig_mkdir(path, *args, **kwargs)

        def guarded_rmdir(path: Any, *args: Any, **kwargs: Any) -> None:
            policy.assert_mutation_forbidden(str(Path(path).resolve()), "os.rmdir")
            orig_rmdir(path, *args, **kwargs)

        def guarded_connect(sock_self: socket.socket, address: Any) -> Any:
            if isinstance(address, tuple) and len(address) >= 1 and isinstance(address[0], str):
                net_policy.assert_endpoint_allowed(address[0])
            return orig_connect(sock_self, address)

        builtins.open = guarded_open  # type: ignore[assignment]
        os.open = guarded_os_open  # type: ignore[assignment]
        os.remove = guarded_remove  # type: ignore[assignment]
        os.unlink = guarded_unlink  # type: ignore[assignment]
        os.rename = guarded_rename  # type: ignore[assignment]
        os.replace = guarded_replace  # type: ignore[assignment]
        os.chmod = guarded_chmod  # type: ignore[assignment]
        os.truncate = guarded_truncate  # type: ignore[assignment]
        os.mkdir = guarded_mkdir  # type: ignore[assignment]
        os.rmdir = guarded_rmdir  # type: ignore[assignment]
        socket.socket.connect = guarded_connect  # type: ignore[assignment]
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        builtins.open = self._orig_open  # type: ignore[assignment]
        os.open = self._orig_os_open
        os.remove = self._orig_remove
        os.unlink = self._orig_unlink
        os.rename = self._orig_rename
        os.replace = self._orig_replace
        os.chmod = self._orig_chmod
        os.truncate = self._orig_truncate
        os.mkdir = self._orig_mkdir
        os.rmdir = self._orig_rmdir
        socket.socket.connect = self._orig_connect  # type: ignore[assignment]


class FsWorkspaceProvisionerAdapter:
    """Adaptador fisico de provisionamento das 5 zonas do workspace e schema SQLite."""

    def __init__(self, codebase_root: str | None = None) -> None:
        default_root = Path(__file__).resolve().parents[2]
        self._codebase_root = Path(codebase_root).resolve() if codebase_root else default_root

    def resolve_real_path(self, raw_path: str) -> str:
        """Resolve o caminho real absoluto no sistema operacional."""
        clean = SafeOsPath(raw_path).logical_path
        return str(Path(clean).resolve())

    def create_workspace_zones(self, layout: CaseWorkspaceLayout) -> None:
        """Cria vault/, staging/, catalog/, deliverables/ e audit/ + tabelas canonicas."""
        for zone_dir in (
            layout.workspace_root,
            layout.vault_dir,
            layout.staging_dir,
            layout.catalog_dir,
            layout.deliverables_dir,
            layout.audit_dir,
        ):
            ext = SafeOsPath(zone_dir).to_os_extended(is_windows=(os.name == "nt"))
            os.makedirs(ext, exist_ok=True)

        db_ext = SafeOsPath(layout.catalog_db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                for ddl in CANONICAL_CATALOG_DDL_STATEMENTS:
                    conn.execute(ddl)
        finally:
            conn.close()

    def compute_codebase_sha256(self) -> str:
        """Calcula o SHA-256 deterministico sobre todos os arquivos .py do pacote edrm."""
        hasher = hashlib.sha256()
        py_files = sorted(self._codebase_root.rglob("*.py"))
        for py_file in py_files:
            rel = py_file.relative_to(self._codebase_root).as_posix()
            hasher.update(rel.encode("utf-8"))
            hasher.update(b"\x00")
            hasher.update(py_file.read_bytes())
            hasher.update(b"\x00")
        return hasher.hexdigest()


def _build_mini_sbom_payload(extra_files: Sequence[Path] | None = None) -> dict[str, object]:
    """Gera Mini-SBOM deterministico (NIST SSDF PS.3) com (modulo, versao, sha256)."""
    sbom_entries: list[dict[str, str]] = []
    seen_names: set[str] = set()
    for mod_name in sorted(sys.modules):
        if not mod_name.startswith("edrm"):
            continue
        mod_obj = sys.modules.get(mod_name)
        mod_file = getattr(mod_obj, "__file__", None)
        if not mod_file or mod_name in seen_names:
            continue
        p = Path(mod_file)
        if p.is_file():
            seen_names.add(mod_name)
            sbom_entries.append(
                {
                    "component": mod_name,
                    "version": "2.1.0",
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                }
            )
    if extra_files:
        for src_p in extra_files:
            if src_p.is_file():
                comp_id = src_p.name
                if comp_id not in seen_names:
                    seen_names.add(comp_id)
                    sbom_entries.append(
                        {
                            "component": comp_id,
                            "version": "2.1.0",
                            "sha256": hashlib.sha256(src_p.read_bytes()).hexdigest(),
                        }
                    )
    return {
        "nist_ssdf_version": "1.1",
        "controls": ["PO.4", "PS.1", "PS.3", "PW.1", "PW.4", "PW.7", "PW.8"],
        "components": sbom_entries,
    }


def _get_max_rss_kb() -> int:
    """Retorna o pico de memoria RSS em KiB inteiros (POSIX via resource; Windows via Psapi)."""
    if resource is not None:
        return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            class _ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = _ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            h_proc = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(h_proc, ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize // 1024)
        except Exception:
            return 0
    return 0


def write_execution_manifest(
    audit_dir: str,
    *,
    run_id: str,
    case_id: str,
    started_at_utc: str,
    source_files: Sequence[Path] | None = None,
    codebase_sha256: str = "",
    governance_contract: CaseGovernanceContract | None = None,
) -> str:
    """Grava execution_manifest.json com Mini-SBOM (NIST SSDF v1.1 PS.3), hashes e telemetria."""
    import platform

    max_rss_kb = _get_max_rss_kb()
    manifest_obj: dict[str, object] = {
        "case_id": case_id,
        "run_id": run_id,
        "started_at_utc": started_at_utc,
        "igrm_normative_reference": "IGRM v4.1 (versao vigente oficial do EDRM)",
        "nist_ssdf_profile": "NIST SP 800-218 SSDF v1.1 (PO.4, PS.1, PS.3, PW.1, PW.4, PW.7, PW.8)",
        "python_version": sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
        "platform_os": os.name,
        "platform_detail": platform.platform(),
        "codebase_sha256": codebase_sha256,
        "mini_sbom": _build_mini_sbom_payload(source_files),
        "max_rss_kb": max_rss_kb,
    }
    if governance_contract is not None:
        manifest_obj["governance_contract"] = asdict(governance_contract)

    _, manifest_sha = canonical_json_sha256(manifest_obj)
    manifest_obj["manifest_sha256"] = manifest_sha

    out_path = Path(audit_dir) / "execution_manifest.json"
    ext = SafeOsPath(str(out_path)).to_os_extended(is_windows=(os.name == "nt"))
    with open(ext, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest_obj, ensure_ascii=False, indent=2, sort_keys=True))
        handle.flush()
        os.fsync(handle.fileno())
    return str(out_path)


@dataclass(frozen=True, slots=True)
class SupervisedProcessResult:
    """Resultado imutavel de execucao supervisionada em sandbox isolado."""

    returncode: int
    stdout: str
    stderr: str


class AppendOnlyLedgerAdapter:
    """Livro de auditoria append-only (audit_ledger.jsonl) e gravador de execution_manifest.json."""

    def append_event(
        self,
        audit_dir: str,
        phase: PhaseCode,
        event_name: str,
        payload: dict[str, object],
        ts_utc: str,
    ) -> str:
        """Anexa uma entrada JSON assinada com encadeamento SHA-256."""
        ledger_path = Path(audit_dir) / "audit_ledger.jsonl"
        prev_hash = "0" * 64
        if ledger_path.exists():
            lines = [ln for ln in ledger_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                last_obj = json.loads(lines[-1])
                prev_hash = str(last_obj.get("entry_sha256", prev_hash))

        record_core = {
            "ts_utc": ts_utc,
            "phase": str(phase),
            "event_name": event_name,
            "prev_entry_sha256": prev_hash,
            "payload": payload,
        }
        _, entry_sha256 = canonical_json_sha256(record_core)
        full_record = dict(record_core)
        full_record["entry_sha256"] = entry_sha256
        serialized_line = json.dumps(full_record, ensure_ascii=False, sort_keys=True)

        ext = SafeOsPath(str(ledger_path)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext, "a", encoding="utf-8") as handle:
            handle.write(serialized_line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry_sha256

    def write_execution_manifest(
        self,
        contract: CaseGovernanceContract,
        started_at_utc: str,
    ) -> str:
        """Grava execution_manifest.json com Mini-SBOM (NIST SSDF PS.3), parametros, hashes e RAM."""
        return write_execution_manifest(
            contract.audit_dir,
            run_id=contract.run_id,
            case_id=contract.case_id,
            started_at_utc=started_at_utc,
            codebase_sha256=contract.codebase_sha256,
            governance_contract=contract,
        )


class SubprocessSandboxSupervisor:
    """Guardiao pai-filho de subprocessos com timeout, encerramento de arvore e limpeza garantida de staging/."""

    def __init__(self, staging_root: str, default_timeout_sec: int = 120) -> None:
        self._staging_root = Path(staging_root).resolve()
        self._default_timeout_sec = default_timeout_sec

    def run_isolated(
        self,
        command: list[str],
        timeout_seconds: int | None = None,
        task_id: str = "isolated",
    ) -> SupervisedProcessResult:
        """Executa comando isolado em staging/subproc_<task_id> garantindo remocao integral de temporarios."""
        import shutil
        import signal
        import subprocess

        safe_task = "".join(c if c.isalnum() or c in "-_" else "_" for c in task_id)
        worker_tmp_dir = self._staging_root / f"subproc_{safe_task}"
        os.makedirs(worker_tmp_dir, exist_ok=True)
        effective_timeout = timeout_seconds if timeout_seconds is not None else self._default_timeout_sec

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(worker_tmp_dir),
            start_new_session=(os.name != "nt"),
        )
        try:
            stdout_str, stderr_str = proc.communicate(timeout=effective_timeout)
            return SupervisedProcessResult(
                returncode=int(proc.returncode),
                stdout=stdout_str,
                stderr=stderr_str,
            )
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    proc.kill()
            else:
                proc.kill()
            proc.communicate()
            return SupervisedProcessResult(
                returncode=-9,
                stdout="",
                stderr=f"TimeoutExpired({effective_timeout}s)",
            )
        finally:
            shutil.rmtree(worker_tmp_dir, ignore_errors=True)

    def run_supervised(
        self,
        command: list[str],
        task_id: str,
        control_number: str,
        rel_path: str,
        sha256_hex: str,
        timeout_sec: int | None = None,
    ) -> tuple[bool, str, dict[str, str] | None]:
        """Executa worker externo isolado em workspace/staging/subproc_<task_id> limpando orfaos em falha."""
        from edrm.shared_kernel.contracts import DeadLetterExceptionRecord

        res = self.run_isolated(command, timeout_seconds=timeout_sec, task_id=task_id)
        if res.returncode == -9:
            dl = DeadLetterExceptionRecord(
                control_number=control_number,
                rel_path=rel_path,
                sha256_hex=sha256_hex,
                reason_code="SUBPROCESS_TIMEOUT_KILLED",
                detail=f"Processo encerrado apos exceder timeout; temporarios removidos ({res.stderr}).",
            )
            return False, "", {k: str(v) for k, v in asdict(dl).items()}
        if res.returncode != 0:
            dl = DeadLetterExceptionRecord(
                control_number=control_number,
                rel_path=rel_path,
                sha256_hex=sha256_hex,
                reason_code="SUBPROCESS_NONZERO_EXIT",
                detail=f"Exit {res.returncode}: {(res.stderr or res.stdout)[:240]}",
            )
            return False, res.stdout, {k: str(v) for k, v in asdict(dl).items()}
        return True, res.stdout, None
