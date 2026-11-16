"""Instalador & Bootstrapper CLI Real da Plataforma Forense ELO (Delta v2.2)."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from edrm.bootstrap.container import EloForensicContainer
from edrm.interfaces.ai_autopilot_agent import EloAutopilotAgent
from edrm.interfaces.disk_router_wizard import MountedVolumeDetector, format_bytes_human_int
from edrm.interfaces.skills_and_mcp_installer import SkillsAndMcpInstaller


def check_sqlite_fts5_support() -> bool:
    """Verifica empiricamente se o binario SQLite do Python 3.12+ possui suporte nativo a FTS5."""
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE _fts5_probe USING fts5(body);")
        conn.execute("INSERT INTO _fts5_probe(body) VALUES ('probe fts5 ok');")
        row = conn.execute(
            "SELECT COUNT(*) FROM _fts5_probe WHERE _fts5_probe MATCH 'probe';"
        ).fetchone()
        return bool(row and int(row[0]) == 1)
    except sqlite3.Error:
        return False
    finally:
        conn.close()


def run_environment_diagnostics(llm_endpoint: str = "http://127.0.0.1:11434") -> dict[str, object]:
    """Executa diagnostico completo da estacao forense (`--check-env` / `elo doctor`)."""
    py_supported = sys.version_info >= (3, 10)
    py_312_plus = sys.version_info >= (3, 12)
    fts5_ok = check_sqlite_fts5_support()
    volumes = MountedVolumeDetector.detect_volumes()

    optional_binaries = ("ollama", "tesseract", "ffmpeg", "iped", "git")
    detected_tools: dict[str, str | None] = {
        tool: shutil.which(tool) for tool in optional_binaries
    }

    llm_probe = EloAutopilotAgent.probe_local_llm_endpoint(llm_endpoint=llm_endpoint)

    return {
        "environment_healthy": bool(py_supported and fts5_ok),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_runtime_supported": py_supported,
        "python_312_recommended": py_312_plus,
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_fts5_enabled": fts5_ok,
        "mounted_volumes_count": len(volumes),
        "mounted_volumes": [
            {
                **asdict(v),
                "free_human": format_bytes_human_int(v.free_bytes),
                "total_human": format_bytes_human_int(v.total_bytes),
            }
            for v in volumes
        ],
        "optional_external_tools": detected_tools,
        "local_llm_probe": llm_probe,
    }


def _write_cli_wrappers(target_dir: Path, repo_root: Path) -> dict[str, str]:
    """Gera wrappers executaveis offline `bin/elo` (POSIX) e `bin/elo.cmd` (Windows)."""
    bin_dir = target_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    src_path = (repo_root / "src").resolve()
    py_exec = sys.executable

    posix_wrapper = bin_dir / "elo"
    posix_content = (
        "#!/usr/bin/env sh\n"
        f'export PYTHONPATH="{src_path}:${{PYTHONPATH:-}}"\n'
        'export PYTHONHASHSEED="42"\n'
        f'exec "{py_exec}" -m edrm.interfaces.cli "$@"\n'
    )
    posix_wrapper.write_text(posix_content, encoding="utf-8")
    current_mode = posix_wrapper.stat().st_mode
    os.chmod(posix_wrapper, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    win_wrapper = bin_dir / "elo.cmd"
    win_content = (
        "@echo off\r\n"
        f'set "PYTHONPATH={src_path};%PYTHONPATH%"\r\n'
        'set "PYTHONHASHSEED=42"\r\n'
        f'"{py_exec}" -m edrm.interfaces.cli %*\r\n'
    )
    win_wrapper.write_text(win_content, encoding="utf-8")

    return {
        "posix_wrapper": str(posix_wrapper),
        "windows_wrapper": str(win_wrapper),
    }


def run_full_cli_installation(
    target_dir: Path,
    attempt_editable_pip: bool = False,
    llm_endpoint: str = "http://127.0.0.1:11434",
) -> dict[str, object]:
    """Instala wrappers `elo`, calibra ISO 27041, gera `.mcp.json` e instala as 6 Skills de Agente."""
    resolved_target = target_dir.resolve()
    resolved_target.mkdir(parents=True, exist_ok=True)

    env_report = run_environment_diagnostics(llm_endpoint=llm_endpoint)
    if not env_report["environment_healthy"]:
        raise RuntimeError("Ambiente reprovado: requer Python 3.12+ com SQLite FTS5 habilitado.")

    pip_editable_installed = False
    if attempt_editable_pip and (REPO_ROOT / "pyproject.toml").is_file():
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", str(REPO_ROOT)],
            capture_output=True,
            text=True,
            check=False,
        )
        pip_editable_installed = proc.returncode == 0

    wrappers = _write_cli_wrappers(target_dir=resolved_target, repo_root=REPO_ROOT)

    container = EloForensicContainer()
    calibration_receipt = container.calibrate_uc.execute()

    skills_bundle = SkillsAndMcpInstaller.install_into_directory(
        target_root=resolved_target,
        platform_repo_root=REPO_ROOT,
        python_executable=sys.executable,
    )

    return {
        "installed": True,
        "target_dir": str(resolved_target),
        "pip_editable_installed": pip_editable_installed,
        "cli_wrappers": wrappers,
        "iso27041_calibration": asdict(calibration_receipt),
        "mcp_and_skills": skills_bundle,
        "environment": env_report,
    }


def build_installer_parser() -> argparse.ArgumentParser:
    """Constroi parser CLI de `install_elo.py`."""
    parser = argparse.ArgumentParser(
        prog="install_elo.py",
        description="Instalador & Bootstrapper CLI Real da Plataforma Forense ELO (EDRM 2.0 / v2.2)",
    )
    parser.add_argument(
        "--check-env",
        action="store_true",
        help="Executa diagnostico completo de Python 3.12+, SQLite FTS5, discos montados e ferramentas.",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Instala wrappers CLI `elo`, calibra ISO 27041, grava `.mcp.json` e instala as 6 Skills.",
    )
    parser.add_argument(
        "--setup-all",
        action="store_true",
        help="Executa --check-env seguido de --install completo em uma unica chamada.",
    )
    parser.add_argument(
        "--target-dir",
        default=str(REPO_ROOT),
        help="Diretorio alvo onde `.mcp.json`, `.claude/skills/`, `.opencode/skills/` e `bin/elo` serao instalados.",
    )
    parser.add_argument(
        "--llm-endpoint",
        default="http://127.0.0.1:11434",
        help="Endpoint local 127.0.0.1 opcional para sondagem de modelos (ex.: Ollama).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada executavel de `install_elo.py`."""
    parser = build_installer_parser()
    args = parser.parse_args(argv)

    if not (args.check_env or args.install or args.setup_all):
        parser.print_help()
        return 1

    if args.install or args.setup_all:
        report = run_full_cli_installation(
            target_dir=Path(args.target_dir),
            llm_endpoint=args.llm_endpoint,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if bool(report.get("installed")) else 1

    diag = run_environment_diagnostics(llm_endpoint=args.llm_endpoint)
    print(json.dumps(diag, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if bool(diag.get("environment_healthy")) else 1


if __name__ == "__main__":
    sys.exit(main())
