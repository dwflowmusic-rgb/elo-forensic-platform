"""CLI Unificada Plug-and-Analyze da Plataforma Forense ELO (EDRM 2.0)."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

from edrm.bootstrap.container import EloForensicContainer, FullPipelineExecutionResult


def serialize_full_result_summary(res: FullPipelineExecutionResult) -> dict[str, object]:
    """Serializa um sumario rico e auditavel de todas as fases (00 -> 08) em JSON."""
    p01_final = res.phase04.updated_phase01_bundle
    return {
        "case_id": res.governance.case_id,
        "run_id": res.governance.run_id,
        "workspace_root": res.governance.workspace_root,
        "codebase_sha256": res.governance.codebase_sha256,
        "calibration_receipt": asdict(res.governance.calibration_receipt),
        "pre_scan_snapshot_sha256": res.phase01_initial.pre_scan_snapshot.snapshot_sha256,
        "post_scan_snapshot_sha256": res.phase08.post_scan_snapshot.snapshot_sha256,
        "zero_source_mutation_confirmed": res.phase08.source_pre_post_snapshot_identical,
        "phase01_initial_revision": res.phase01_initial.revision_number,
        "phase01_final_revision": p01_final.revision_number,
        "extension_census": list(p01_final.discovery_blueprint.extension_census),
        "signature_census": list(p01_final.discovery_blueprint.signature_census),
        "spoofed_files": list(p01_final.discovery_blueprint.spoofed_files),
        "encrypted_or_corrupted_files": list(p01_final.discovery_blueprint.encrypted_or_corrupted_files),
        "dynamic_schemas": [asdict(ds) for ds in p01_final.discovery_blueprint.dynamic_schemas],
        "custodians": [asdict(c) for c in p01_final.custodians],
        "divergences": [asdict(d) for d in p01_final.divergences],
        "parity_matrix": [asdict(r) for r in p01_final.parity_matrix],
        "cochran_plan": asdict(p01_final.cochran_plan),
        "state_iped_audit": (
            asdict(p01_final.state_iped_audit)
            if p01_final.state_iped_audit is not None
            else None
        ),
        "six_axes_findings": [asdict(ax) for ax in res.phase02.six_axes_findings],
        "structural_findings": [asdict(sf) for sf in res.phase02.structural_findings],
        "vault_entries": [asdict(ve) for ve in res.phase03.vault_entries],
        "state_collection_findings": [asdict(cf) for cf in res.phase03.state_collection_findings],
        "processing_metrics": {
            "total_inventory_items": res.phase04.total_inventory_items,
            "denisted_parent_count": res.phase04.denisted_parent_count,
            "logical_duplicates_count": res.phase04.logical_duplicates_count,
            "post_seizure_events_count": res.phase04.post_seizure_events_count,
            "pdf_multi_eof_count": res.phase04.pdf_multi_eof_count,
            "financial_duplicates_count": res.phase04.financial_duplicates_count,
            "impossible_erb_jumps_count": res.phase04.impossible_erb_jumps_count,
            "cgnat_missing_port_count": res.phase04.cgnat_missing_port_count,
            "recovered_deleted_sqlite_rows_count": len(res.phase04.recovered_sqlite_records),
            "physical_link_tracker_findings_count": len(res.phase04.link_provenance_records),
            "tier_execution_order": [list(t) for t in res.phase04.tier_execution_order],
            "indexed_chunks_count": res.indexed_chunks_count,
        },
        "timeline_events": [asdict(ev) for ev in res.phase04.timeline_events],
        "recovered_sqlite_records": [asdict(rs) for rs in res.phase04.recovered_sqlite_records],
        "link_provenance_records": [asdict(lp) for lp in res.phase04.link_provenance_records],
        "financial_entries": [asdict(fe) for fe in res.phase04.financial_entries],
        "telecom_records": [asdict(tr) for tr in res.phase04.telecom_records],
        "cgnat_records": [asdict(cg) for cg in res.phase04.cgnat_records],
        "dead_letter_items": [asdict(dl) for dl in res.phase04.dead_letter_items],
        "material_contradictions": [asdict(mc) for mc in res.phase05.material_contradictions],
        "classified_nullities": [asdict(cn) for cn in res.phase05.classified_nullities],
        "qc_summary": asdict(res.phase05.qc_summary),
        "expert_opinion_path": res.phase06.expert_opinion_path,
        "expert_opinion_sha256": res.phase06.expert_opinion_sha256,
        "reproduction_script_path": res.phase06.reproduction_script_path,
        "quesitos": [asdict(q) for q in res.phase07.quesitos],
        "offline_html_dossier_path": res.phase07.offline_html_dossier_path,
        "offline_html_dossier_sha256": res.phase07.offline_html_dossier_sha256,
        "all_deliverables": list(res.phase07.all_deliverables),
        "disposition": {
            "staging_purged_files_count": res.phase08.staging_purged_files_count,
            "staging_purged_bytes": res.phase08.staging_purged_bytes,
            "vault_intact_verified": res.phase08.vault_intact_verified,
            "manifest_sha256_path": res.phase08.manifest_sha256_path,
            "recovery_bundle_path": res.phase08.recovery_bundle_path,
            "nist_certificate_path": res.phase08.nist_certificate_path,
        },
    }


def build_arg_parser() -> argparse.ArgumentParser:
    """Constroi o parser de argumentos da CLI unificada."""
    parser = argparse.ArgumentParser(
        prog="elo",
        description="ELO — Motor Universal Plug-and-Analyze de Auditoria Probatoria (EDRM 2.0)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-case", help="Inicializa e blinda o workspace de um novo caso.")
    p_init.add_argument("--case-id", required=True)
    p_init.add_argument("--source", action="append", required=True)
    p_init.add_argument("--workspace", required=True)

    p_plug = sub.add_parser("plug-hd", help="Sonda um HD conectado e executa a Fase 01.")
    p_plug.add_argument("--case-id", required=True)
    p_plug.add_argument("--source", action="append", required=True)
    p_plug.add_argument("--workspace", required=True)

    p_phase = sub.add_parser("run-phase", help="Executa ate uma fase especifica (1..8).")
    p_phase.add_argument("--phase", type=int, choices=range(1, 9), required=True)
    p_phase.add_argument("--case-id", required=True)
    p_phase.add_argument("--source", action="append", required=True)
    p_phase.add_argument("--workspace", required=True)

    p_all = sub.add_parser(
        "plug-and-run-all",
        help="Conecta o HD e executa da Camada 00 ate a Fase 08 com verificacao integral.",
    )
    p_all.add_argument("--case-id", default="CASO-PENAL-EDRM2")
    p_all.add_argument("--source", action="append", required=True)
    p_all.add_argument("--workspace", required=True)
    p_all.add_argument("--json", action="store_true")

    p_search = sub.add_parser("search", help="Executa busca hibrida RRF (BM25 + Vetorial).")
    p_search.add_argument("--workspace", required=True)
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--top-n", type=int, default=10)

    p_verify = sub.add_parser("verify", help="Confere MANIFESTO_SHA256.txt contra o workspace.")
    p_verify.add_argument("--workspace", required=True)

    p_doctor = sub.add_parser("doctor", help="Diagnostica Python 3.12+, SQLite FTS5, discos e ferramentas locais.")
    p_doctor.add_argument("--llm-endpoint", default="http://127.0.0.1:11434")

    sub.add_parser("drives", help="Lista todos os HDs/volumes conectados e espaco livre em bytes inteiros.")
    sub.add_parser("mount", help="Alias de drives: lista volumes conectados para roteamento Cross-Disk.")

    p_wizard = sub.add_parser("wizard", help="Assistente interativo de terminal para abertura guiada entre HDs.")
    p_wizard.add_argument("--plan-only", action="store_true", help="Apenas valida o plano sem disparar o Autopilot.")

    p_auto = sub.add_parser(
        "autopilot",
        help="Executa autonomamente Calibracao ISO 27041 + Fases 00..08 + Banco Organizado no outro HD.",
    )
    p_auto.add_argument("--case-id", default="CASO-AUTOPILOT-EDRM22")
    p_auto.add_argument("--source", action="append", required=True, help="Caminho(s) do HD de prova bruta (RO).")
    p_auto.add_argument("--dest", required=True, help="Caminho no outro HD para gravar o caso e o Banco Organizado.")
    p_auto.add_argument("--staging", default=None, help="3o HD/pasta opcional para rascunho pesado temporario.")
    p_auto.add_argument("--llm-endpoint", default="http://127.0.0.1:11434")
    p_auto.add_argument("--strict-separate-drive", action="store_true")

    p_mcp = sub.add_parser("mcp-serve", help="Inicia o Servidor MCP JSON-RPC 2.0 nativo via stdio.")
    p_mcp.add_argument("--dest", default=None, help="Diretorio de caso organizado padrao opcional.")

    p_skills = sub.add_parser(
        "install-skills",
        help="Gera .mcp.json e instala as 6 Skills Operacionais em .claude/skills/ e .opencode/skills/.",
    )
    p_skills.add_argument("--target-dir", default=".")

    p_setup = sub.add_parser(
        "setup",
        help="Configura wrappers CLI, calibra ISO 27041 e instala .mcp.json + 6 Skills no diretorio alvo.",
    )
    p_setup.add_argument("--target-dir", default=".")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada principal da CLI unificada."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command in ("drives", "mount"):
        from edrm.interfaces.disk_router_wizard import MountedVolumeDetector, format_bytes_human_int

        vols = MountedVolumeDetector.detect_volumes()
        payload = [
            {
                **asdict(v),
                "free_human": format_bytes_human_int(v.free_bytes),
                "total_human": format_bytes_human_int(v.total_bytes),
            }
            for v in vols
        ]
        print(json.dumps({"volumes_count": len(payload), "volumes": payload}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "doctor":
        import sqlite3

        from edrm.interfaces.ai_autopilot_agent import EloAutopilotAgent
        from edrm.interfaces.disk_router_wizard import MountedVolumeDetector

        vols = MountedVolumeDetector.detect_volumes()
        llm_info = EloAutopilotAgent.probe_local_llm_endpoint(llm_endpoint=args.llm_endpoint)
        doc_payload = {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "sqlite_version": sqlite3.sqlite_version,
            "volumes_detected": len(vols),
            "llm_probe": llm_info,
        }
        print(json.dumps(doc_payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "wizard":
        from edrm.interfaces.disk_router_wizard import run_interactive_cli_wizard

        wiz_res = run_interactive_cli_wizard(execute_immediately=not bool(args.plan_only))
        print(json.dumps(wiz_res, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "autopilot":
        from edrm.interfaces.ai_autopilot_agent import EloAutopilotAgent

        agent = EloAutopilotAgent()
        auto_res = agent.run_autopilot(
            source_paths=tuple(args.source),
            dest_path=args.dest,
            case_id=args.case_id,
            staging_path=args.staging,
            llm_endpoint=args.llm_endpoint,
            strict_separate_physical_drive=bool(args.strict_separate_drive),
        )
        print(json.dumps(auto_res, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "mcp-serve":
        from edrm.interfaces.mcp_server import EloForensicMcpServer

        server = EloForensicMcpServer(default_dest_path=args.dest)
        return server.serve_stdio()

    if args.command in ("install-skills", "setup"):
        from edrm.interfaces.skills_and_mcp_installer import SkillsAndMcpInstaller

        installed = SkillsAndMcpInstaller.install_into_directory(target_root=Path(args.target_dir))
        if args.command == "setup":
            cal_receipt = EloForensicContainer().calibrate_uc.execute()
            installed["iso27041_calibration"] = asdict(cal_receipt)
        print(json.dumps(installed, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    container = EloForensicContainer()

    if args.command == "init-case":
        gov = container.init_workspace_uc.execute(
            case_id=args.case_id,
            workspace_path=args.workspace,
            source_paths=tuple(args.source),
        )
        print(json.dumps(asdict(gov), ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "plug-hd":
        gov = container.init_workspace_uc.execute(
            case_id=args.case_id,
            workspace_path=args.workspace,
            source_paths=tuple(args.source),
        )
        p01 = container.phase01_uc.execute(gov)
        print(json.dumps({"case_id": gov.case_id, "phase01_sha256": p01.contract_sha256()}, indent=2))
        return 0

    if args.command == "run-phase":
        res = container.plug_and_run_all(
            case_id=args.case_id,
            source_paths=tuple(args.source),
            workspace_path=args.workspace,
        )
        print(json.dumps({"executed_up_to_phase": args.phase, "run_id": res.governance.run_id}))
        return 0

    if args.command == "plug-and-run-all":
        res = container.plug_and_run_all(
            case_id=args.case_id,
            source_paths=tuple(args.source),
            workspace_path=args.workspace,
        )
        summary = serialize_full_result_summary(res)
        if args.json:
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    if args.command == "search":
        db_path = str(Path(args.workspace).resolve() / "catalog" / "elo_forensic_catalog.sqlite")
        hits = container.hybrid_search_uc.search(db_path, args.query, top_n=args.top_n)
        out = [
            {
                "chunk_id": h.chunk.chunk_id,
                "origin_cn": h.chunk.origin_cn,
                "locator": h.chunk.locator,
                "rrf_score": str(h.rrf_score),
                "lexical_rank": h.lexical_rank,
                "vector_rank": h.vector_rank,
                "origin_sha256": h.chunk.origin_sha256,
                "text_clean": h.chunk.text_clean,
            }
            for h in hits
        ]
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    if args.command == "verify":
        ws = Path(args.workspace).resolve()
        man = ws / "audit" / "MANIFESTO_SHA256.txt"
        if not man.exists():
            print(json.dumps({"verified": False, "error": "MANIFESTO_SHA256.txt ausente"}))
            return 1
        mismatches: list[str] = []
        checked = 0
        for line in man.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            expected_sha, rel_p = line.split("  ", 1)
            target = ws / rel_p
            checked += 1
            if not target.exists():
                mismatches.append(f"MISSING:{rel_p}")
            else:
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual != expected_sha:
                    mismatches.append(f"HASH_DIFF:{rel_p}")
        ok = len(mismatches) == 0
        print(json.dumps({"verified": ok, "checked_files": checked, "mismatches": mismatches}))
        return 0 if ok else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
