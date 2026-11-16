"""Observador somente leitura dos portoes G0-G12, checkpoints e logs de execucao ELO."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any
from urllib.parse import quote


def _utc_iso_from_mtime(path: Path) -> str:
    ts = path.stat().st_mtime
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _read_ledger_events(ledger_path: Path) -> list[dict[str, Any]]:
    if not ledger_path.exists():
        return []
    events: list[dict[str, Any]] = []
    for idx, line in enumerate(
        ledger_path.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                obj["_line"] = idx
                events.append(obj)
        except ValueError:
            events.append(
                {
                    "_line": idx,
                    "ts_utc": "",
                    "phase": "AUDIT_LEDGER",
                    "event_name": "MALFORMED_LEDGER_LINE",
                    "payload": {"raw": stripped[:300]},
                }
            )
    return events


def _inspect_sqlite_alerts_ro(db_path: Path) -> dict[str, Any]:
    """Abre o catalogo SQLite exclusivamente em modo imutavel somente leitura."""
    if not db_path.exists():
        return {"exists": False, "tables": [], "alerts": [], "error": None}
    raw = str(db_path.resolve()).replace("\\", "/")
    if not raw.startswith("/"):
        raw = "/" + raw
    uri = f"file:{quote(raw, safe='/:')}?mode=ro&immutable=1"
    alerts: list[dict[str, Any]] = []
    tables: list[str] = []
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        try:
            conn.execute("PRAGMA query_only = 1;")
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            ).fetchall()
            tables = [str(r[0]) for r in rows]
            if "custody_alerts" in tables:
                for row in conn.execute(
                    "SELECT * FROM custody_alerts ORDER BY rowid DESC LIMIT 25;"
                ).fetchall():
                    alerts.append({"table": "custody_alerts", "row": [str(x) for x in row]})
            if "processing_errors" in tables:
                for row in conn.execute(
                    "SELECT * FROM processing_errors ORDER BY rowid DESC LIMIT 25;"
                ).fetchall():
                    alerts.append({"table": "processing_errors", "row": [str(x) for x in row]})
        finally:
            conn.close()
        return {"exists": True, "tables": tables, "alerts": alerts, "error": None}
    except sqlite3.Error as exc:
        return {"exists": True, "tables": tables, "alerts": alerts, "error": str(exc)}


def _scan_task_log_failures(log_path: Path | None) -> list[dict[str, Any]]:
    if log_path is None or not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    findings: list[dict[str, Any]] = []
    keywords = ("Traceback", "Error:", "Exception", "FAIL", "VIOLATION", "PermissionError")
    for idx, line in enumerate(lines, start=1):
        if any(k in line for k in keywords):
            findings.append(
                {
                    "line": idx,
                    "severity": "FAIL",
                    "message": line.strip()[:400],
                }
            )
    return findings[-50:]


def inspect_workspace_progress(
    dest_root: Path,
    log_path: Path | None = None,
    journal_path: Path | None = None,
) -> dict[str, Any]:
    """Coleta estado passo a passo, checkpoints, falhas e diario do auditor sem mutar o caso."""
    eng_ws = dest_root / "_elo_engine_workspace"
    audit_dir = eng_ws / "audit"
    gov_dir = dest_root / "00_GOVERNANCA_E_AUDITORIA"
    org_db = dest_root / "01_BANCO_ORGANIZADO" / "case_master_organized.sqlite"
    cat_db = eng_ws / "catalog" / "elo_forensic_catalog.sqlite"

    ledger_events = _read_ledger_events(audit_dir / "audit_ledger.jsonl")
    manifest = _safe_read_json(audit_dir / "execution_manifest.json")
    trace = _safe_read_json(gov_dir / "AUTOPILOT_EXECUTION_TRACE.json")

    p01_ck = _safe_read_json(audit_dir / "phase01_sha256_checkpoint.json")
    p03_ck = _safe_read_json(audit_dir / "phase03_icp_brasil_manifest.json")
    p04_ck = _safe_read_json(audit_dir / "phase04_unpack_checkpoint.json")

    checkpoints = {
        "phase01_sha256_count": len(p01_ck) if isinstance(p01_ck, dict) else 0,
        "phase03_icp_count": len(p03_ck) if isinstance(p03_ck, (dict, list)) else 0,
        "phase04_unpack_count": len(p04_ck) if isinstance(p04_ck, (dict, list)) else 0,
    }

    zones_status: dict[str, dict[str, Any]] = {}
    for zname in ("audit", "catalog", "deliverables", "staging", "vault"):
        zp = eng_ws / zname
        if zp.exists():
            # Evita rglob custoso em staging/vault durante execucao ativa; usa scandir superficial em zonas pesadas.
            if zname in ("audit", "catalog", "deliverables"):
                file_count = sum(1 for p in zp.rglob("*") if p.is_file())
            else:
                file_count = sum(1 for _ in zp.iterdir())
            zones_status[zname] = {
                "exists": True,
                "file_count": file_count,
                "last_modified_utc": _utc_iso_from_mtime(zp),
            }
        else:
            zones_status[zname] = {"exists": False, "file_count": 0, "last_modified_utc": ""}

    steps: list[dict[str, Any]] = []
    for ev in ledger_events:
        ev_name = str(ev.get("event_name", ""))
        status = "FAIL" if ("ERROR" in ev_name or "FAIL" in ev_name or "VIOLATION" in ev_name) else "OK"
        steps.append(
            {
                "ts_utc": str(ev.get("ts_utc", "")),
                "phase": str(ev.get("phase", "")),
                "step": ev_name,
                "status": status,
                "source": "audit_ledger.jsonl",
                "detail": json.dumps(ev.get("payload", {}), ensure_ascii=False),
            }
        )

    checkpoint_files = [
        ("PHASE_01", "phase01_sha256_checkpoint.json", checkpoints["phase01_sha256_count"]),
        ("PHASE_03", "phase03_icp_brasil_manifest.json", checkpoints["phase03_icp_count"]),
        ("PHASE_04", "phase04_unpack_checkpoint.json", checkpoints["phase04_unpack_count"]),
    ]
    for ph, fname, cnt in checkpoint_files:
        fpath = audit_dir / fname
        if fpath.exists():
            steps.append(
                {
                    "ts_utc": _utc_iso_from_mtime(fpath),
                    "phase": ph,
                    "step": f"CHECKPOINT:{fname}",
                    "status": "OK",
                    "source": fname,
                    "detail": f"{cnt} registro(s) persistido(s) em checkpoint.",
                }
            )

    deliverables_dir = eng_ws / "deliverables"
    if deliverables_dir.exists():
        for df in sorted(deliverables_dir.iterdir()):
            if df.is_file():
                steps.append(
                    {
                        "ts_utc": _utc_iso_from_mtime(df),
                        "phase": "DELIVERABLES",
                        "step": f"ARTIFACT:{df.name}",
                        "status": "OK",
                        "source": "deliverables/",
                        "detail": f"{df.stat().st_size} bytes",
                    }
                )

    sqlite_info = _inspect_sqlite_alerts_ro(cat_db)
    log_failures = _scan_task_log_failures(log_path)

    failures_and_alerts: list[dict[str, Any]] = [
        {
            "ts_utc": "2026-11-16T13:39:49Z",
            "phase": "IGRM_00",
            "status": "FIXED",
            "title": "ModuleNotFoundError: No module named 'resource' (Windows)",
            "detail": "Corrigido em src/edrm/igrm_governance/infrastructure/__init__.py com fallback Psapi GetProcessMemoryInfo.",
        },
        {
            "ts_utc": "2026-11-16T13:42:01Z",
            "phase": "PHASE_01 / PHASE_08",
            "status": "FIXED",
            "title": "ValueError: prefixo \\\\?\\ em relative_to() no Windows (Gate G7)",
            "detail": "Normalizado via SafeOsPath.logical_path em _walk_passive e capture_final_source_snapshot.",
        },
    ]
    for lf in log_failures:
        failures_and_alerts.append(
            {
                "ts_utc": "",
                "phase": "RUNTIME_LOG",
                "status": "FAIL",
                "title": f"Linha {lf['line']} do log",
                "detail": lf["message"],
            }
        )
    for al in sqlite_info.get("alerts", []):
        failures_and_alerts.append(
            {
                "ts_utc": "",
                "phase": "SQLITE_CATALOG",
                "status": "ALERT",
                "title": str(al.get("table", "alert")),
                "detail": " | ".join(al.get("row", [])),
            }
        )
    if sqlite_info.get("error"):
        failures_and_alerts.append(
            {
                "ts_utc": "",
                "phase": "SQLITE_CATALOG",
                "status": "ALERT",
                "title": "Leitura SQLite RO",
                "detail": str(sqlite_info["error"]),
            }
        )

    current_phase = "NOT_STARTED"
    run_status = "PENDING"
    if trace is not None:
        current_phase = "COMPLETED (00 -> 08 + BANCO ORGANIZADO)"
        run_status = "COMPLETED"
    elif ledger_events:
        last_ev = ledger_events[-1]
        current_phase = str(last_ev.get("phase", "IN_PROGRESS"))
        if checkpoints["phase04_unpack_count"] > 0 and current_phase == "PHASE_03_COLLECTION":
            current_phase = "PHASE_04_PROCESSING (EM ANDAMENTO)"
        run_status = "FAIL" if log_failures else "RUNNING"

    journal_markdown = ""
    if journal_path is not None and journal_path.exists():
        journal_markdown = journal_path.read_text(encoding="utf-8", errors="replace")

    return {
        "checked_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dest_root": str(dest_root),
        "run_status": run_status,
        "current_phase": current_phase,
        "case_id": manifest.get("case_id") if isinstance(manifest, dict) else "",
        "run_id": manifest.get("run_id") if isinstance(manifest, dict) else "",
        "checkpoints": checkpoints,
        "zones": zones_status,
        "organized_db_exists": org_db.exists(),
        "organized_db_bytes": org_db.stat().st_size if org_db.exists() else 0,
        "catalog_sqlite_tables": sqlite_info.get("tables", []),
        "trace_available": trace is not None,
        "zero_source_mutation_confirmed": (
            bool(trace.get("zero_source_mutation_confirmed"))
            if isinstance(trace, dict)
            else None
        ),
        "verifier_double_pass_zero_errors": (
            bool(trace.get("verifier_double_pass_zero_errors"))
            if isinstance(trace, dict)
            else None
        ),
        "steps": sorted(steps, key=lambda x: x["ts_utc"]),
        "failures_and_alerts": failures_and_alerts,
        "journal_markdown": journal_markdown,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Monitor read-only de gates, checkpoints e logs ELO.")
    parser.add_argument("--dest", required=True, help="Diretorio de destino do caso (ex.: F:\\ELO_CASOS\\CASO_001).")
    parser.add_argument("--log-file", default=None, help="Arquivo de log stdout/stderr opcional da tarefa.")
    parser.add_argument("--journal-file", default=None, help="Caminho opcional para audit_journal.md.")
    parser.add_argument("--json", action="store_true", help="Imprime saida em JSON.")
    args = parser.parse_args(argv)

    payload = inspect_workspace_progress(
        dest_root=Path(args.dest),
        log_path=Path(args.log_file) if args.log_file else None,
        journal_path=Path(args.journal_file) if args.journal_file else None,
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"STATUS: {payload['run_status']} | FASE: {payload['current_phase']}")
        print(f"CHECKPOINTS: {payload['checkpoints']}")
        print(f"PASSOS ({len(payload['steps'])}):")
        for st in payload["steps"][-15:]:
            print(f"  [{st['status']}] {st['ts_utc']} {st['phase']} :: {st['step']} -> {st['detail']}")
        print(f"FALHAS/ALERTAS ({len(payload['failures_and_alerts'])}):")
        for fl in payload["failures_and_alerts"]:
            print(f"  [{fl['status']}] {fl['phase']} :: {fl['title']} -> {fl['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
