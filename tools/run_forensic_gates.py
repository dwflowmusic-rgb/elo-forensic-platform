"""Executor autonomo cumulativo dos Portoes Forenses G0 a G10 (Homologacao EDRM 2.0)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from edrm.bootstrap.container import EloForensicContainer
from edrm.shared_kernel.enums import ParityState
from tests.architecture import (
    audit_g0_code_hygiene,
    audit_g1_clean_hexagonal_solid_and_forensic_locks,
)
from tests.contract import run_all_liskov_contract_suites
from tests.e2e_synthetic import materialize_synthetic_unknown_forensic_hd
from tests.unit import (
    run_g2_iso27041_calibration_tests,
    run_g3_igrm_and_phase01_tests,
    run_g4_phase02_and_phase03_tests,
    run_g5_phase04_processing_tests,
    run_g6_continuous_analysis_and_phase05_tests,
    run_g7_phases_06_07_08_tests,
)
from tests.unit.test_g11_v21 import run_g11_delta_v2_1_tests
from tests.unit.test_g12_v22 import run_g12_delta_v2_2_tests


def _all_project_python_files() -> list[Path]:
    targets: list[Path] = []
    for folder in ("src/edrm", "tests", "tools"):
        base = REPO_ROOT / folder
        if base.exists():
            targets.extend(sorted(base.rglob("*.py")))
    for root_script in ("install_elo.py", "materialize_elo_platform.py", "materialize_docs.py"):
        mat = REPO_ROOT / root_script
        if mat.exists():
            targets.append(mat)
    return targets


def gate_g0() -> str:
    """G0 — Higiene Total de Codigo via AST."""
    files = _all_project_python_files()
    issues = audit_g0_code_hygiene(files)
    if issues:
        raise AssertionError("Violacoes G0:\n" + "\n".join(issues))
    return f"{len(files)} modulos Python auditados com 0 pendencias/pass/ellipsis."


def gate_g1() -> str:
    """G1 — Auditoria Estatica AST de Clean Architecture, Hexagonal, SOLID e Travas Forenses."""
    issues = audit_g1_clean_hexagonal_solid_and_forensic_locks(SRC_DIR / "edrm")
    if issues:
        raise AssertionError("Violacoes G1:\n" + "\n".join(issues))
    return "Pureza domain/application, zero acoplamento cruzado, Protocol, frozen e zero float/hash() provados."


def gate_g2() -> str:
    """G2 — Calibracao Previa ISO/IEC 27041."""
    run_g2_iso27041_calibration_tests()
    return "1 controle positivo aprovado e 2 controles negativos bloqueados com sucesso."


def gate_g3() -> str:
    """G3 — Camada 00 (IGRM v4.1) e Fase 01 (Autodescoberta do HD)."""
    run_g3_igrm_and_phase01_tests()
    return "SourceWriteBlockerGuard, Magic Bytes 16B, camuflagem, Paridade 7 Estados e Cochran aprovados."


def gate_g4() -> str:
    """G4 — Fases 02 (Preservacao) e 03 (Coleta Verificada)."""
    run_g4_phase02_and_phase03_tests()
    return "Deteccao -wal, quick_check imutavel, 6 Eixos, homografos de lacre e releitura fria os.fsync aprovados."


def gate_g5() -> str:
    """G5 — Fase 04 (Processamento EDRM 1.0 a 5.0)."""
    run_g5_phase04_processing_tests()
    return "Anti-Zip-Bomb/Traversal, De-NIST parent-only, Dedup Logica, Epocas 1970/2001/1904, SIMBA BIGINT e IPED CLI aprovados."


def gate_g6() -> str:
    """G6 — Analise Continua e Fase 05 (Revisao)."""
    run_g6_continuous_analysis_and_phase05_tests()
    return "Busca Hibrida RRF (k=60), Timeline UTC, Escudo Anti-Injection, Verificador Bloqueante e Regra do 3 aprovados."


def gate_g7() -> str:
    """G7 — Fases 06 (Producao), 07 (Apresentacao) e 08 (Destinacao Final)."""
    run_g7_phases_06_07_08_tests()
    return "Parecer 7 Blocos (dupla passagem 0 erros), Load Files, Quesitos POP 2024, HTML5 Offline e NIST 800-88 aprovados."


def gate_g8() -> str:
    """G8 — Substituicao de Liskov (InMemory == Infraestrutura Fisica Real)."""
    run_all_liskov_contract_suites()
    return "Suites de contrato executadas identicamente em adaptadores InMemory e Fisicos."


def gate_g9() -> str:
    """G9 — Verificacao dos Instaladores Autocontidos materialize_elo_platform.py e materialize_docs.py."""
    with tempfile.TemporaryDirectory() as tmp_target:
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "materialize_elo_platform.py"),
                "--target",
                str(Path(tmp_target) / "platform"),
                "--verify",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(f"Falha no instalador G9: {proc.stderr or proc.stdout}")
        payload = json.loads(proc.stdout)
        if not payload.get("verified"):
            raise AssertionError(f"Mismatches SHA-256 em G9: {payload}")

        docs_script = REPO_ROOT / "materialize_docs.py"
        docs_count = 0
        if docs_script.exists():
            proc_docs = subprocess.run(
                [
                    sys.executable,
                    str(docs_script),
                    "--target",
                    str(Path(tmp_target) / "docs_bundle"),
                    "--verify",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc_docs.returncode != 0:
                raise AssertionError(f"Falha em materialize_docs.py G9: {proc_docs.stderr or proc_docs.stdout}")
            docs_payload = json.loads(proc_docs.stdout)
            if not docs_payload.get("verified"):
                raise AssertionError(f"Mismatches SHA-256 em materialize_docs.py: {docs_payload}")
            docs_count = int(docs_payload["materialized_docs_count"])

        return (
            f"Instaladores reconstruiram e verificaram por SHA-256 "
            f"{payload['materialized_files_count']} arquivos da plataforma e {docs_count} da suite documental."
        )


def gate_g10() -> str:
    """G10 — Simulacao Ponta a Ponta Plug-and-Analyze de HD Bruto Desconhecido (00 -> 08)."""
    with tempfile.TemporaryDirectory() as tmp_e2e:
        hd_path = materialize_synthetic_unknown_forensic_hd(Path(tmp_e2e) / "unknown_hd")
        ws_path = Path(tmp_e2e) / "case_workspace"

        container = EloForensicContainer()
        res = container.plug_and_run_all(
            case_id="CASO-G10-E2E",
            source_paths=(str(hd_path),),
            workspace_path=str(ws_path),
        )

        p01_final = res.phase04.updated_phase01_bundle
        assert p01_final.revision_number >= 2, "Loop iterativo 04 -> 01 nao incrementou revisao!"
        assert len(p01_final.divergences) >= 1, "Divergencia de lacre Auto vs Laudo nao detectada!"
        assert "02_extracoes_moveis/system32_cache.dll" in p01_final.discovery_blueprint.spoofed_files
        assert len(p01_final.discovery_blueprint.dynamic_schemas) >= 2

        states = {r.parity_state for r in p01_final.parity_matrix}
        assert ParityState.DECLARED_RAW_NOT_DELIVERED in states
        assert ParityState.DELIVERED_ENCRYPTED_OR_CORRUPTED in states

        assert res.phase04.post_seizure_events_count >= 1
        assert res.phase04.pdf_multi_eof_count >= 1
        assert res.phase04.financial_duplicates_count >= 1
        assert res.phase04.impossible_erb_jumps_count >= 1
        assert res.phase04.cgnat_missing_port_count >= 1
        assert len(res.phase05.material_contradictions) >= 3
        assert res.phase06.verifier_double_pass_zero_errors is True
        assert res.phase08.source_pre_post_snapshot_identical is True
        assert (
            res.phase01_initial.pre_scan_snapshot.snapshot_sha256
            == res.phase08.post_scan_snapshot.snapshot_sha256
        )

        return (
            f"Fluxo 00->08 concluido (Rev P01={p01_final.revision_number}, "
            f"PreScan==PostScan SHA-256={res.phase08.post_scan_snapshot.snapshot_sha256[:16]}...)."
        )


def gate_g11() -> str:
    """G11 — Homologacao Cumulativa Delta v2.1 (IPED Clean-Room, NIST SSDF v1.1, P0->P4, BR/Cripto)."""
    return run_g11_delta_v2_1_tests()


def gate_g12() -> str:
    """G12 — Homologacao Operacional Delta v2.2 (Cross-Disk, Banco Organizado, CLI, MCP e 6 Skills)."""
    return run_g12_delta_v2_2_tests()


def run_all_gates() -> tuple[bool, list[dict[str, object]]]:
    """Executa sequencialmente os 13 portoes (G0 a G12) medindo tempo e diagnosticos."""
    gates = (
        ("G0", "Higiene Total de Codigo (AST)", gate_g0),
        ("G1", "Clean Architecture, Hexagonal, SOLID e Travas Forenses (AST + NIST SSDF v1.1)", gate_g1),
        ("G2", "Auto-Calibracao ISO/IEC 27041 (1 Positivo + 2 Negativos)", gate_g2),
        ("G3", "Camada 00 (IGRM v4.1) & Fase 01 (Autodescoberta do HD)", gate_g3),
        ("G4", "Fase 02 (Preservacao 6 Eixos) & Fase 03 (Coleta Releitura Fria)", gate_g4),
        ("G5", "Fase 04 (Processamento EDRM 1.0–5.0, 11 Extratores + SQLite Dinamico)", gate_g5),
        ("G6", "Analise Continua (Busca RRF k=60, Verificador, Regra do 3) & Fase 05", gate_g6),
        ("G7", "Fases 06 (Parecer 7 Blocos), 07 (Quesitos & HTML5 Offline) & 08 (NIST 800-88)", gate_g7),
        ("G8", "Substituicao de Liskov (Adaptadores InMemory == Fisicos Reais)", gate_g8),
        ("G9", "Instalador Autocontido Verificado por SHA-256", gate_g9),
        ("G10", "Simulacao Ponta a Ponta Plug-and-Analyze HD Bruto Desconhecido (00 -> 08)", gate_g10),
        ("G11", "Delta v2.1 — IPED Clean-Room, NIST SSDF v1.1, Filas P0->P4, SQLite Undelete, .lnk e BR/Cripto", gate_g11),
        ("G12", "Delta v2.2 — Roteamento Cross-Disk, Banco Organizado (8 Views), CLI, MCP (10 Tools) e 6 Skills", gate_g12),
    )

    results: list[dict[str, object]] = []
    all_passed = True
    for code, title, fn in gates:
        t0 = time.monotonic_ns()
        try:
            detail = fn()
            elapsed_ms = (time.monotonic_ns() - t0) // 1_000_000
            results.append(
                {
                    "gate": code,
                    "title": title,
                    "passed": True,
                    "elapsed_ms": elapsed_ms,
                    "detail": detail,
                }
            )
        except Exception as exc:
            all_passed = False
            elapsed_ms = (time.monotonic_ns() - t0) // 1_000_000
            results.append(
                {
                    "gate": code,
                    "title": title,
                    "passed": False,
                    "elapsed_ms": elapsed_ms,
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            break

    return all_passed, results


def main(argv: list[str] | None = None) -> int:
    """Executa todos os portoes forenses e imprime relatorio JSON ou tabular."""
    parser = argparse.ArgumentParser(description="Executor dos Portoes Forenses G0 a G10")
    parser.add_argument("--json", action="store_true", help="Emite resultado estruturado JSON")
    args = parser.parse_args(argv)

    ok, results = run_all_gates()
    if args.json:
        print(json.dumps({"all_passed": ok, "exit_code": 0 if ok else 1, "gates": results}, ensure_ascii=False))
    else:
        print("=" * 88)
        print("ELO FORENSIC PLATFORM (EDRM 2.0 + DELTA v2.2) — HOMOLOGACAO PORTOES G0 A G12")
        print("=" * 88)
        for r in results:
            badge = "PASS" if r["passed"] else "FAIL"
            print(f"[{badge}] {r['gate']} ({r['elapsed_ms']} ms) — {r['title']}")
            print(f"       -> {r['detail']}")
        print("=" * 88)
        print(f"RESULTADO GLOBAL: {'HOMOLOGADO (EXIT CODE 0)' if ok else 'REPROVADO (EXIT CODE 1)'}")
        print("=" * 88)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
