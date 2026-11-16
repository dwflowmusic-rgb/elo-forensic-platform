"""Suite de Homologacao do Portao G12 — Delta v2.2 (Cross-Disk, Banco Organizado, CLI, MCP e 6 Skills)."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

from edrm.interfaces import cli as elo_cli
from edrm.interfaces.disk_router_wizard import (
    CrossDiskWorkspaceRouter,
    SmartAcquisitionPlanner,
    run_interactive_cli_wizard,
)
from edrm.interfaces.mcp_server import EloForensicMcpServer
from edrm.interfaces.organized_db_publisher import EXECUTIVE_VIEWS_NAMES
from edrm.shared_kernel.exceptions import WorkspaceOverlapError
from edrm.shared_kernel.value_objects import SafeOsPath
from tests.e2e_synthetic import materialize_synthetic_unknown_forensic_hd


def _snapshot_directory_cold(root: Path) -> dict[str, tuple[int, str]]:
    """Calcula mapa imutavel rel_path -> (size_bytes, sha256) para provar zero mutacao na origem."""
    snap: dict[str, tuple[int, str]] = {}
    for item in sorted(root.rglob("*")):
        if item.is_file():
            raw = item.read_bytes()
            rel = item.relative_to(root).as_posix()
            snap[rel] = (len(raw), hashlib.sha256(raw).hexdigest())
    return snap


def run_g12_delta_v2_2_tests() -> str:
    """Executa G12.1, G12.2, G12.3 e G12.4 em diretorios hermeticos temporarios."""
    repo_root = Path(__file__).resolve().parents[2]

    with tempfile.TemporaryDirectory() as tmp_root_str:
        tmp_root = Path(tmp_root_str)
        hd_prova_a = materialize_synthetic_unknown_forensic_hd(tmp_root / "simulated_hd_prova_A")
        hd_destino_b = tmp_root / "simulated_hd_destino_B"
        hd_staging_c = tmp_root / "simulated_hd_staging_C"

        snap_before = _snapshot_directory_cold(hd_prova_a)
        assert len(snap_before) >= 8, "HD sintetico de prova A nao foi materializado!"

        # =====================================================================
        # G12.1 — Simulacao Real de 2 HDs Separados + Trava Anti-Contaminacao
        # =====================================================================
        overlap_blocked = False
        try:
            CrossDiskWorkspaceRouter.plan_and_validate_route(
                source_paths=(str(hd_prova_a),),
                dest_path=str(hd_prova_a / "subpasta_ilegal_dentro_da_prova"),
            )
        except WorkspaceOverlapError:
            overlap_blocked = True
        assert overlap_blocked, "G12.1 FALHOU: --dest dentro de --source nao foi bloqueado!"

        staging_overlap_blocked = False
        try:
            CrossDiskWorkspaceRouter.plan_and_validate_route(
                source_paths=(str(hd_prova_a),),
                dest_path=str(hd_destino_b),
                staging_path=str(hd_prova_a / "_staging_ilegal"),
            )
        except WorkspaceOverlapError:
            staging_overlap_blocked = True
        assert staging_overlap_blocked, "G12.1 FALHOU: --staging dentro de --source nao foi bloqueado!"

        strat_full, _ = SmartAcquisitionPlanner.choose_strategy(
            source_total_bytes=10_000_000,
            dest_free_bytes=500_000_000,
        )
        assert strat_full == "FULL_VAULT_COPY"
        strat_ref, _ = SmartAcquisitionPlanner.choose_strategy(
            source_total_bytes=1_000_000_000_000,
            dest_free_bytes=250_000_000_000,
        )
        assert strat_ref == "REFERENCED_MANIFEST_STREAMING"

        # Teste do Wizard interativo em modo plan-only
        wizard_inputs = iter(
            [
                str(hd_prova_a),
                str(hd_destino_b),
                str(hd_staging_c),
                "CASO-G12-WIZARD",
                "http://127.0.0.1:11434",
            ]
        )
        wizard_logs: list[str] = []
        wiz_plan = run_interactive_cli_wizard(
            input_fn=lambda _prompt: next(wizard_inputs),
            output_fn=wizard_logs.append,
            execute_immediately=False,
        )
        assert wiz_plan["case_id"] == "CASO-G12-WIZARD"

        # Execucao real via CLI `elo autopilot --source A --dest B --staging C`
        cli_stdout_buf = io.StringIO()
        with contextlib.redirect_stdout(cli_stdout_buf):
            rc_auto = elo_cli.main(
                [
                    "autopilot",
                    "--case-id",
                    "CASO-G12-CROSSDISK",
                    "--source",
                    str(hd_prova_a),
                    "--dest",
                    str(hd_destino_b),
                    "--staging",
                    str(hd_staging_c),
                ]
            )
        assert rc_auto == 0, f"G12.1 FALHOU: elo autopilot retornou codigo {rc_auto}"
        auto_cli_json = json.loads(cli_stdout_buf.getvalue())
        assert auto_cli_json["zero_source_mutation_confirmed"] is True

        for zone_dir in (
            "00_GOVERNANCA_E_AUDITORIA",
            "01_BANCO_ORGANIZADO",
            "02_COFRE_OU_REFERENCIA",
            "03_RELATORIOS_E_DOSSIE",
        ):
            assert (hd_destino_b / zone_dir).is_dir(), f"Zona padronizada ausente: {zone_dir}"

        org_db_path = hd_destino_b / "01_BANCO_ORGANIZADO" / "case_master_organized.sqlite"
        schema_md_path = hd_destino_b / "01_BANCO_ORGANIZADO" / "SCHEMA_PARA_HUMANO_E_IA.md"
        resumo_json_path = hd_destino_b / "01_BANCO_ORGANIZADO" / "RESUMO_EXECUTIVO_BANCO.json"
        assert org_db_path.is_file(), "case_master_organized.sqlite nao criado no HD B!"
        assert schema_md_path.is_file(), "SCHEMA_PARA_HUMANO_E_IA.md nao criado no HD B!"
        assert resumo_json_path.is_file(), "RESUMO_EXECUTIVO_BANCO.json nao criado no HD B!"

        # Confirma limpeza do 3o HD de staging e ZERO mutacao no HD de prova A
        leftover_staging = [p for p in hd_staging_c.rglob("*") if p.is_file()] if hd_staging_c.exists() else []
        assert len(leftover_staging) == 0, f"Arquivos residuais em --staging: {leftover_staging}"
        snap_after = _snapshot_directory_cold(hd_prova_a)
        assert snap_before == snap_after, "G12.1 VIOLACAO CRITICA: mutacao detectada em simulated_hd_prova_A!"

        # =====================================================================
        # G12.2 — Auditoria das 8 SQL Views e FTS5 em mode=ro&immutable=1
        # =====================================================================
        ro_uri = SafeOsPath(str(org_db_path.resolve())).to_sqlite_immutable_uri()
        conn_ro = sqlite3.connect(ro_uri, uri=True)
        view_counts: dict[str, int] = {}
        try:
            conn_ro.execute("PRAGMA query_only = 1;")
            for view_name in EXECUTIVE_VIEWS_NAMES:
                rows = conn_ro.execute(f"SELECT * FROM {view_name} LIMIT 25").fetchall()
                cnt_row = conn_ro.execute(f"SELECT COUNT(*) FROM {view_name}").fetchone()
                view_counts[view_name] = int(cnt_row[0]) if cnt_row else 0
                _ = rows

            assert view_counts["vw_01_indice_geral_provas"] >= 8
            assert view_counts["vw_02_matriz_declarado_vs_entregue"] >= 2
            assert view_counts["vw_03_alertas_cadeia_custodia_e_pericia"] >= 2
            assert view_counts["vw_04_comunicacoes_unificadas_utc"] >= 2
            assert view_counts["vw_05_financeiro_consolidado"] >= 2
            assert view_counts["vw_06_telecom_erb_deslocamentos"] >= 2
            assert view_counts["vw_08_linha_do_tempo_mestra_utc"] >= 6

            fts_hits = conn_ro.execute(
                """
                SELECT doc_ref, origin_cn, source_domain, origin_sha256
                FROM fts_global_evidence_index
                WHERE fts_global_evidence_index MATCH 'aluguel OR SIMBA OR custodia'
                LIMIT 10
                """
            ).fetchall()
            assert len(fts_hits) >= 1, "G12.2 FALHOU: FTS5 MATCH nao retornou resultados!"
        finally:
            conn_ro.close()

        schema_md_text = schema_md_path.read_text(encoding="utf-8")
        for view_name in EXECUTIVE_VIEWS_NAMES:
            assert view_name in schema_md_text, f"View {view_name} ausente em SCHEMA_PARA_HUMANO_E_IA.md"

        # =====================================================================
        # G12.3 — Teste Real do Servidor MCP JSON-RPC 2.0 + Bloqueio DROP/INSERT
        # =====================================================================
        mcp_srv = EloForensicMcpServer(default_dest_path=str(hd_destino_b))

        # 1) Teste via protocolo stdio real (linha JSON-RPC + Content-Length)
        req_init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        req_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        raw_cl_body = json.dumps(req_list).encode("utf-8")
        stdio_in = io.BytesIO(
            json.dumps(req_init).encode("utf-8")
            + b"\n"
            + f"Content-Length: {len(raw_cl_body)}\r\n\r\n".encode("ascii")
            + raw_cl_body
        )
        stdio_out = io.BytesIO()
        mcp_srv.serve_stdio(stdin_stream=stdio_in, stdout_stream=stdio_out)
        out_raw = stdio_out.getvalue().decode("utf-8")
        assert '"protocolVersion": "2024-11-05"' in out_raw
        assert '"elo_verify_citation_strict"' in out_raw

        # 2) Validacao das 10 tools e chamadas reais
        tools_resp = mcp_srv.handle_jsonrpc_message(req_list)
        assert tools_resp is not None
        tools_list = tools_resp["result"]["tools"]  # type: ignore[index]
        assert len(tools_list) == 10, f"Esperadas 10 tools MCP, obtidas {len(tools_list)}"

        ov_resp = mcp_srv.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "elo_get_case_overview",
                    "arguments": {"dest_path": str(hd_destino_b)},
                },
            }
        )
        assert ov_resp is not None and ov_resp["result"]["isError"] is False  # type: ignore[index]

        hs_resp = mcp_srv.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "elo_hybrid_search",
                    "arguments": {
                        "dest_path": str(hd_destino_b),
                        "query": "aluguel imovel",
                        "top_n": 5,
                    },
                },
            }
        )
        assert hs_resp is not None and hs_resp["result"]["isError"] is False  # type: ignore[index]
        hs_hits = hs_resp["result"]["structuredContent"]["hits"]  # type: ignore[index]
        assert len(hs_hits) >= 1, "elo_hybrid_search nao retornou hits ancorados!"

        vw_ok_resp = mcp_srv.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "elo_query_organized_view",
                    "arguments": {
                        "dest_path": str(hd_destino_b),
                        "sql_query": "SELECT control_number, sha256_hex, origin_rel_path FROM vw_01_indice_geral_provas",
                        "limit": 5,
                    },
                },
            }
        )
        assert vw_ok_resp is not None and vw_ok_resp["result"]["isError"] is False  # type: ignore[index]
        first_row = vw_ok_resp["result"]["structuredContent"]["rows"][0]  # type: ignore[index]
        real_cn = str(first_row["control_number"])
        real_sha = str(first_row["sha256_hex"])
        real_rel = str(first_row["origin_rel_path"])

        # Bloqueio estrito de DROP e INSERT em elo_query_organized_view
        for hostile_sql in (
            "DROP TABLE org_inventory_files",
            "INSERT INTO org_inventory_files VALUES ('X','','','','','',0,0,'',0,0,0,0,'',0,'','')",
            "SELECT * FROM vw_01_indice_geral_provas; DELETE FROM org_inventory_files",
        ):
            bad_resp = mcp_srv.handle_jsonrpc_message(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "elo_query_organized_view",
                        "arguments": {
                            "dest_path": str(hd_destino_b),
                            "sql_query": hostile_sql,
                        },
                    },
                }
            )
            assert bad_resp is not None
            assert bad_resp["result"]["isError"] is True, f"SQL hostil NAO bloqueado: {hostile_sql}"  # type: ignore[index]
            assert "READONLY_SQL_VIOLATION" in str(bad_resp["result"]["structuredContent"]["message"])  # type: ignore[index]

        # Verificacao estrita: citacao real APROVADA vs citacao inventada BLOQUEADA
        ver_pass = mcp_srv.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "elo_verify_citation_strict",
                    "arguments": {
                        "dest_path": str(hd_destino_b),
                        "paragraph_text": (
                            f"Conforme prova {real_cn} (SHA-256 {real_sha}), "
                            f"consta o caminho «{real_rel}» no indice auditado."
                        ),
                    },
                },
            }
        )
        assert ver_pass is not None
        assert ver_pass["result"]["structuredContent"]["passed"] is True  # type: ignore[index]

        ver_fail = mcp_srv.handle_jsonrpc_message(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "elo_verify_citation_strict",
                    "arguments": {
                        "dest_path": str(hd_destino_b),
                        "paragraph_text": (
                            "Conforme CN-99999999 (SHA-256 "
                            + ("f" * 64)
                            + "), consta «frase inventada pela alucinacao»."
                        ),
                    },
                },
            }
        )
        assert ver_fail is not None
        assert ver_fail["result"]["structuredContent"]["passed"] is False  # type: ignore[index]
        assert len(ver_fail["result"]["structuredContent"]["rejected_reasons"]) >= 2  # type: ignore[index]

        # =====================================================================
        # G12.4 — Teste do Instalador CLI install_elo.py e das 6 Skills
        # =====================================================================
        installer_script = repo_root / "install_elo.py"
        proc_check = subprocess.run(
            [sys.executable, str(installer_script), "--check-env"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_check.returncode == 0, f"install_elo.py --check-env falhou: {proc_check.stderr}"
        check_json = json.loads(proc_check.stdout)
        assert check_json["environment_healthy"] is True
        assert check_json["python_runtime_supported"] is True
        assert check_json["sqlite_fts5_enabled"] is True

        tmp_install_dir = tmp_root / "station_install_target"
        proc_inst = subprocess.run(
            [
                sys.executable,
                str(installer_script),
                "--install",
                "--target-dir",
                str(tmp_install_dir),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_inst.returncode == 0, f"install_elo.py --install falhou: {proc_inst.stderr}"

        mcp_cfg_file = tmp_install_dir / ".mcp.json"
        assert mcp_cfg_file.is_file(), ".mcp.json nao foi gerado pelo instalador!"
        mcp_cfg = json.loads(mcp_cfg_file.read_text(encoding="utf-8"))
        assert "elo-forensic" in mcp_cfg["mcpServers"]

        expected_skills = (
            "elo-plugar-hd",
            "elo-panorama-caso",
            "elo-investigar-fato",
            "elo-auditar-custodia",
            "elo-confrontar-laudo",
            "elo-parecer-e-quesitos",
        )
        for sk in expected_skills:
            c_skill = tmp_install_dir / ".claude" / "skills" / sk / "SKILL.md"
            o_skill = tmp_install_dir / ".opencode" / "skills" / sk / "SKILL.md"
            assert c_skill.is_file(), f"Skill Claude ausente: {c_skill}"
            assert o_skill.is_file(), f"Skill OpenCode ausente: {o_skill}"
            txt = c_skill.read_text(encoding="utf-8")
            assert "Coordenador Forense" in txt
            assert "elo_verify_citation_strict" in txt

        return (
            "Cross-Disk 2 HDs (0 mutacoes na prova), 8 SQL Views + FTS5 RO, "
            "MCP JSON-RPC 2.0 (10 tools + bloqueio SQL escrita) e install_elo.py + 6 Skills homologados."
        )
