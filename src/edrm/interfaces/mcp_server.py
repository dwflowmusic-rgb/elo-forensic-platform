"""Servidor MCP (Model Context Protocol) JSON-RPC 2.0 Nativo via stdio (Delta v2.2)."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import sys
from typing import BinaryIO, Callable

from edrm.continuous_analysis.domain import (
    BlockingVerifierEngine,
    DeterministicHashEmbedder,
    HybridRrfFusionEngine,
)
from edrm.interfaces.ai_autopilot_agent import EloAutopilotAgent
from edrm.interfaces.disk_router_wizard import MountedVolumeDetector, format_bytes_human_int
from edrm.interfaces.organized_db_publisher import EXECUTIVE_VIEWS_NAMES
from edrm.shared_kernel.contracts import AnchoredTextChunk
from edrm.shared_kernel.exceptions import BlockingVerificationError, InvalidForensicValueError
from edrm.shared_kernel.value_objects import SafeOsPath
from edrm.shared_kernel.verifier_primitives import (
    CandidateClaim,
    VerifiableSourceCorpusEntry,
    verify_markdown_report_strictly,
)

MCP_PROTOCOL_VERSION: str = "2024-11-05"

ALLOWED_ORGANIZED_RELATIONS: frozenset[str] = frozenset(
    set(EXECUTIVE_VIEWS_NAMES)
    | {
        "fts_global_evidence_index",
        "org_inventory_files",
        "org_parity_matrix",
        "org_custody_and_forensic_alerts",
        "org_communications_utc",
        "org_financial_consolidated",
        "org_telecom_erb_cgnat",
        "org_audio_transcript_segments",
        "org_anchored_chunks",
        "org_material_contradictions",
    }
)

_FORBIDDEN_SQL_VERBS_RE = re.compile(
    r"\b("
    r"DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|REPLACE|TRUNCATE|"
    r"ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE|BEGIN|COMMIT|"
    r"ROLLBACK|SAVEPOINT|LOAD_EXTENSION"
    r")\b",
    re.IGNORECASE,
)

_SQL_RELATION_REF_RE = re.compile(r"\b(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)


def validate_readonly_organized_sql(sql_query: str) -> str:
    """Valida que a consulta SQL e 100% SELECT sem mutacao, comentarios ou tabelas nao autorizadas."""
    cleaned = sql_query.strip()
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if not cleaned:
        raise InvalidForensicValueError("READONLY_SQL_VIOLATION: Consulta SQL vazia.")
    if ";" in cleaned or "--" in cleaned or "/*" in cleaned or "*/" in cleaned:
        raise InvalidForensicValueError(
            "READONLY_SQL_VIOLATION: Multiplas instrucoes ou comentarios SQL sao bloqueados."
        )
    if _FORBIDDEN_SQL_VERBS_RE.search(cleaned):
        raise InvalidForensicValueError(
            "READONLY_SQL_VIOLATION: Operacao mutavel ou administrativa bloqueada (somente SELECT permitido)."
        )
    if not re.match(r"^SELECT\b", cleaned, flags=re.IGNORECASE):
        raise InvalidForensicValueError(
            "READONLY_SQL_VIOLATION: Apenas consultas iniciadas por SELECT sao aceitas."
        )
    referenced = [m.group(1).lower() for m in _SQL_RELATION_REF_RE.finditer(cleaned)]
    if not referenced:
        raise InvalidForensicValueError(
            "READONLY_SQL_VIOLATION: A consulta SELECT deve referenciar ao menos uma View ou tabela autorizada."
        )
    allowed_lower = {r.lower() for r in ALLOWED_ORGANIZED_RELATIONS}
    for rel in referenced:
        if rel not in allowed_lower:
            raise InvalidForensicValueError(
                f"READONLY_SQL_VIOLATION: Relacao SQL nao autorizada na camada MCP: {rel}"
            )
    return cleaned


_DENIED_SQLITE_ACTIONS: frozenset[int] = frozenset(
    {
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_CREATE_TEMP_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_INDEX,
        sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
        sqlite3.SQLITE_CREATE_TEMP_VIEW,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_DROP_TEMP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_INDEX,
        sqlite3.SQLITE_DROP_TEMP_TRIGGER,
        sqlite3.SQLITE_DROP_TEMP_VIEW,
        sqlite3.SQLITE_DROP_VTABLE,
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_REINDEX,
        sqlite3.SQLITE_ANALYZE,
    }
)


def _sqlite_readonly_authorizer(
    action_code: int,
    arg1: str | None,
    arg2: str | None,
    db_name: str | None,
    trigger_name: str | None,
) -> int:
    """Autorizador nativo SQLite bloqueando toda escrita/DDL/transacao e permitindo leitura de Views e FTS5."""
    _ = (arg1, arg2, db_name, trigger_name)
    if action_code in _DENIED_SQLITE_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class EloForensicMcpServer:
    """Servidor oficial MCP JSON-RPC 2.0 em Python puro expondo 10 Ferramentas Forenses Deterministicas."""

    def __init__(
        self,
        default_dest_path: str | None = None,
        autopilot_agent: EloAutopilotAgent | None = None,
    ) -> None:
        self._active_dest_path = default_dest_path
        self._autopilot = autopilot_agent if autopilot_agent is not None else EloAutopilotAgent()
        self._tool_handlers: dict[str, Callable[[dict[str, object]], dict[str, object]]] = {
            "elo_list_mounted_drives": self._tool_list_mounted_drives,
            "elo_autopilot_ingest_hd": self._tool_autopilot_ingest_hd,
            "elo_get_case_overview": self._tool_get_case_overview,
            "elo_hybrid_search": self._tool_hybrid_search,
            "elo_query_organized_view": self._tool_query_organized_view,
            "elo_timeline_window": self._tool_timeline_window,
            "elo_audit_custody_and_parity": self._tool_audit_custody_and_parity,
            "elo_confront_allegation_vs_raw": self._tool_confront_allegation_vs_raw,
            "elo_verify_citation_strict": self._tool_verify_citation_strict,
            "elo_generate_deliverables": self._tool_generate_deliverables,
        }

    def handle_jsonrpc_message(self, message: dict[str, object]) -> dict[str, object] | None:
        """Processa uma mensagem JSON-RPC 2.0 MCP e devolve a resposta ou None para notificacoes."""
        req_id = message.get("id")
        is_notification = "id" not in message
        method = str(message.get("method", ""))
        params_raw = message.get("params")
        params: dict[str, object] = params_raw if isinstance(params_raw, dict) else {}

        if is_notification:
            return None

        try:
            if method == "initialize":
                return self._ok(
                    req_id,
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {"listChanged": False},
                            "resources": {"subscribe": False, "listChanged": False},
                            "prompts": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "elo-forensic-mcp",
                            "version": "2.2.0",
                        },
                    },
                )

            if method == "ping":
                return self._ok(req_id, {})

            if method == "tools/list":
                return self._ok(req_id, {"tools": self._build_tools_catalog()})

            if method == "tools/call":
                tool_name = str(params.get("name", ""))
                args_raw = params.get("arguments")
                tool_args: dict[str, object] = args_raw if isinstance(args_raw, dict) else {}
                handler = self._tool_handlers.get(tool_name)
                if handler is None:
                    return self._err(req_id, -32602, f"Ferramenta MCP desconhecida: {tool_name}")
                try:
                    structured = handler(tool_args)
                    return self._ok(
                        req_id,
                        {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(structured, ensure_ascii=False, sort_keys=True),
                                }
                            ],
                            "structuredContent": structured,
                            "isError": False,
                        },
                    )
                except Exception as tool_exc:
                    err_payload = {
                        "error_type": type(tool_exc).__name__,
                        "message": str(tool_exc),
                    }
                    return self._ok(
                        req_id,
                        {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(err_payload, ensure_ascii=False, sort_keys=True),
                                }
                            ],
                            "structuredContent": err_payload,
                            "isError": True,
                        },
                    )

            if method == "resources/list":
                return self._ok(req_id, {"resources": self._list_resources()})

            if method == "resources/read":
                uri = str(params.get("uri", ""))
                return self._ok(req_id, {"contents": [self._read_resource(uri)]})

            if method == "prompts/list":
                return self._ok(req_id, {"prompts": self._list_prompts()})

            if method == "prompts/get":
                p_name = str(params.get("name", ""))
                return self._ok(req_id, self._get_prompt(p_name))

            return self._err(req_id, -32601, f"Metodo JSON-RPC MCP nao suportado: {method}")
        except Exception as exc:
            return self._err(req_id, -32603, f"Erro interno MCP ({type(exc).__name__}): {exc}")

    def serve_stdio(
        self,
        stdin_stream: BinaryIO | None = None,
        stdout_stream: BinaryIO | None = None,
    ) -> int:
        """Loop continuo stdio compativel com JSON-RPC por linha e enquadramento Content-Length."""
        in_buf = stdin_stream if stdin_stream is not None else sys.stdin.buffer
        out_buf = stdout_stream if stdout_stream is not None else sys.stdout.buffer

        while True:
            first_line = in_buf.readline()
            if not first_line:
                break
            stripped = first_line.strip()
            if not stripped:
                continue

            use_content_length = False
            if stripped.lower().startswith(b"content-length:"):
                use_content_length = True
                length_val = int(stripped.split(b":", 1)[1].strip().decode("ascii"))
                while True:
                    hdr_line = in_buf.readline()
                    if not hdr_line or hdr_line in (b"\r\n", b"\n"):
                        break
                body_bytes = in_buf.read(length_val)
            else:
                body_bytes = stripped

            try:
                parsed = json.loads(body_bytes.decode("utf-8"))
            except ValueError as parse_err:
                resp_err = self._err(None, -32700, f"JSON invalido: {parse_err}")
                self._write_stdio_frame(out_buf, resp_err, use_content_length)
                continue

            if isinstance(parsed, dict):
                resp = self.handle_jsonrpc_message(parsed)
                if resp is not None:
                    self._write_stdio_frame(out_buf, resp, use_content_length)

        return 0

    @staticmethod
    def _write_stdio_frame(out_buf: BinaryIO, payload: dict[str, object], content_length_mode: bool) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if content_length_mode:
            header = f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii")
            out_buf.write(header + encoded)
        else:
            out_buf.write(encoded + b"\n")
        out_buf.flush()

    @staticmethod
    def _ok(req_id: object, result: dict[str, object]) -> dict[str, object]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _err(req_id: object, code: int, message: str) -> dict[str, object]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    def _resolve_dest_and_db(self, args: dict[str, object]) -> tuple[Path, Path]:
        raw_dest = str(args.get("dest_path") or self._active_dest_path or "").strip()
        if not raw_dest:
            raise InvalidForensicValueError(
                "Parametro dest_path obrigatorio (diretorio do caso organizado no HD de destino)."
            )
        dest_root = Path(raw_dest).resolve()
        db_path = dest_root / "01_BANCO_ORGANIZADO" / "case_master_organized.sqlite"
        if not db_path.is_file():
            raise InvalidForensicValueError(
                f"Banco Organizado inexistente em {db_path}. Execute elo_autopilot_ingest_hd primeiro."
            )
        return dest_root, db_path

    @staticmethod
    def _open_organized_db_immutable(db_path: Path) -> sqlite3.Connection:
        uri = SafeOsPath(str(db_path.resolve())).to_sqlite_immutable_uri()
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = 1;")
        conn.execute("SELECT COUNT(*) FROM fts_global_evidence_index").fetchone()
        conn.set_authorizer(_sqlite_readonly_authorizer)
        return conn

    def _tool_list_mounted_drives(self, args: dict[str, object]) -> dict[str, object]:
        _ = args
        vols = MountedVolumeDetector.detect_volumes()
        return {
            "volumes_count": len(vols),
            "volumes": [
                {
                    **asdict(v),
                    "free_human": format_bytes_human_int(v.free_bytes),
                    "total_human": format_bytes_human_int(v.total_bytes),
                }
                for v in vols
            ],
        }

    def _tool_autopilot_ingest_hd(self, args: dict[str, object]) -> dict[str, object]:
        raw_sources = args.get("source_paths")
        if isinstance(raw_sources, list) and raw_sources:
            sources = tuple(str(x) for x in raw_sources)
        elif args.get("source_path"):
            sources = (str(args["source_path"]),)
        else:
            raise InvalidForensicValueError("Informe source_paths (lista) ou source_path (string).")

        dest_path = str(args.get("dest_path", "")).strip()
        if not dest_path:
            raise InvalidForensicValueError("Informe dest_path para o HD/diretorio de destino.")

        case_id = str(args.get("case_id") or "CASO-MCP-AUTOPILOT")
        staging_raw = args.get("staging_path")
        staging_path = str(staging_raw).strip() if staging_raw else None
        llm_endpoint = str(args.get("llm_endpoint") or "http://127.0.0.1:11434")
        strict_sep = bool(args.get("strict_separate_physical_drive", False))

        result = self._autopilot.run_autopilot(
            source_paths=sources,
            dest_path=dest_path,
            case_id=case_id,
            staging_path=staging_path,
            llm_endpoint=llm_endpoint,
            strict_separate_physical_drive=strict_sep,
        )
        self._active_dest_path = str(Path(dest_path).resolve())
        return result

    def _tool_get_case_overview(self, args: dict[str, object]) -> dict[str, object]:
        dest_root, db_path = self._resolve_dest_and_db(args)
        summary_path = dest_root / "01_BANCO_ORGANIZADO" / "RESUMO_EXECUTIVO_BANCO.json"
        summary_data: dict[str, object] = {}
        if summary_path.is_file():
            summary_data = json.loads(summary_path.read_text(encoding="utf-8"))

        conn = self._open_organized_db_immutable(db_path)
        live_counts: dict[str, int] = {}
        try:
            for v_name in EXECUTIVE_VIEWS_NAMES:
                row = conn.execute(f"SELECT COUNT(*) AS total FROM {v_name}").fetchone()
                live_counts[v_name] = int(row["total"]) if row else 0
            fts_r = conn.execute("SELECT COUNT(*) AS total FROM fts_global_evidence_index").fetchone()
            live_counts["fts_global_evidence_index"] = int(fts_r["total"]) if fts_r else 0
        finally:
            conn.close()

        return {
            "dest_root": str(dest_root),
            "organized_db_path": str(db_path),
            "schema_doc_path": str(dest_root / "01_BANCO_ORGANIZADO" / "SCHEMA_PARA_HUMANO_E_IA.md"),
            "executive_summary": summary_data,
            "live_views_row_counts": live_counts,
        }

    def _tool_hybrid_search(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        query = str(args.get("query", "")).strip()
        if not query:
            raise InvalidForensicValueError("Parametro query obrigatorio para elo_hybrid_search.")
        top_n = max(1, min(100, int(args.get("top_n", 10))))

        safe_tokens = [tok for tok in re.findall(r"[A-Za-z0-9À-ÿ_]+", query) if len(tok) >= 2]
        fts_expr = " OR ".join(f'"{t}"' for t in safe_tokens) if safe_tokens else '""'
        q_vec = DeterministicHashEmbedder.embed(query)

        conn = self._open_organized_db_immutable(db_path)
        try:
            chunks_by_id: dict[str, AnchoredTextChunk] = {}
            lex_ids: list[str] = []

            if safe_tokens:
                lex_rows = conn.execute(
                    """
                    SELECT doc_ref, origin_cn, source_domain, locator, origin_sha256, content_text
                    FROM fts_global_evidence_index
                    WHERE fts_global_evidence_index MATCH ?
                    ORDER BY bm25(fts_global_evidence_index) ASC
                    LIMIT ?
                    """,
                    (fts_expr, max(50, top_n * 3)),
                ).fetchall()
                for idx, r in enumerate(lex_rows, start=1):
                    cid = f"{r['source_domain']}::{r['doc_ref']}"
                    if cid not in chunks_by_id:
                        chunks_by_id[cid] = AnchoredTextChunk(
                            chunk_id=cid,
                            origin_cn=str(r["origin_cn"]),
                            origin_path=str(r["source_domain"]),
                            locator=str(r["locator"]),
                            text_clean=str(r["content_text"]),
                            injection_neutralized=False,
                            origin_sha256=str(r["origin_sha256"]),
                        )
                    if cid not in lex_ids:
                        lex_ids.append(cid)
                    _ = idx

            all_rows = conn.execute(
                """
                SELECT doc_ref, origin_cn, source_domain, locator, origin_sha256, content_text
                FROM fts_global_evidence_index
                LIMIT 2000
                """
            ).fetchall()
            scored_vec: list[tuple[int, str]] = []
            for r in all_rows:
                cid = f"{r['source_domain']}::{r['doc_ref']}"
                txt = str(r["content_text"])
                if cid not in chunks_by_id:
                    chunks_by_id[cid] = AnchoredTextChunk(
                        chunk_id=cid,
                        origin_cn=str(r["origin_cn"]),
                        origin_path=str(r["source_domain"]),
                        locator=str(r["locator"]),
                        text_clean=txt,
                        injection_neutralized=False,
                        origin_sha256=str(r["origin_sha256"]),
                    )
                sim = DeterministicHashEmbedder.dot_similarity(q_vec, DeterministicHashEmbedder.embed(txt))
                if sim > 0:
                    scored_vec.append((sim, cid))

            scored_vec.sort(key=lambda pair: (-pair[0], pair[1]))
            vec_ids = tuple(cid for _, cid in scored_vec[: max(50, top_n * 3)])

            fused = HybridRrfFusionEngine.fuse(
                chunks_by_id=chunks_by_id,
                lexical_ordered_ids=tuple(lex_ids),
                vector_ordered_ids=vec_ids,
                top_n=top_n,
            )
        finally:
            conn.close()

        return {
            "query": query,
            "hits_count": len(fused),
            "hits": [
                {
                    "chunk_id": h.chunk.chunk_id,
                    "control_number": h.chunk.origin_cn,
                    "source_domain": h.chunk.origin_path,
                    "locator": h.chunk.locator,
                    "origin_sha256": h.chunk.origin_sha256,
                    "rrf_score": str(h.rrf_score),
                    "lexical_rank": h.lexical_rank,
                    "vector_rank": h.vector_rank,
                    "text_clean": h.chunk.text_clean,
                }
                for h in fused
            ],
        }

    def _tool_query_organized_view(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        limit = max(1, min(500, int(args.get("limit", 50))))
        offset = max(0, int(args.get("offset", 0)))

        raw_sql = str(args.get("sql_query", "")).strip()
        if not raw_sql and args.get("view_name"):
            v_candidate = str(args["view_name"]).strip()
            if v_candidate not in EXECUTIVE_VIEWS_NAMES:
                raise InvalidForensicValueError(f"View desconhecida: {v_candidate}")
            raw_sql = f"SELECT * FROM {v_candidate}"

        validated_sql = validate_readonly_organized_sql(raw_sql)
        has_explicit_limit = bool(re.search(r"\bLIMIT\b", validated_sql, flags=re.IGNORECASE))

        conn = self._open_organized_db_immutable(db_path)
        try:
            if has_explicit_limit:
                cur = conn.execute(validated_sql)
            else:
                paginated_sql = f"{validated_sql} LIMIT ? OFFSET ?"
                cur = conn.execute(paginated_sql, (limit, offset))
            fetched = cur.fetchall()
            columns = [d[0] for d in (cur.description or [])]
            rows = [{col: row[col] for col in columns} for row in fetched]
        finally:
            conn.close()

        return {
            "executed_sql": validated_sql,
            "limit": limit,
            "offset": offset,
            "returned_rows_count": len(rows),
            "columns": columns,
            "rows": rows,
        }

    def _tool_timeline_window(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        start_utc = str(args.get("start_utc") or "0000-01-01T00:00:00Z").strip()
        end_utc = str(args.get("end_utc") or "9999-12-31T23:59:59Z").strip()
        limit = max(1, min(500, int(args.get("limit", 100))))

        conn = self._open_organized_db_immutable(db_path)
        try:
            rows = conn.execute(
                """
                SELECT ts_utc, domain_source, ref_id, origin_cn, actor_primary, actor_secondary,
                       summary_verbatim, anomaly_flag, locator, origin_sha256
                FROM vw_08_linha_do_tempo_mestra_utc
                WHERE ts_utc >= ? AND ts_utc <= ?
                ORDER BY ts_utc ASC, ref_id ASC
                LIMIT ?
                """,
                (start_utc, end_utc, limit),
            ).fetchall()
            events = [dict(r) for r in rows]
        finally:
            conn.close()

        return {
            "start_utc": start_utc,
            "end_utc": end_utc,
            "events_count": len(events),
            "events": events,
        }

    def _tool_audit_custody_and_parity(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        conn = self._open_organized_db_immutable(db_path)
        try:
            parity_rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM vw_02_matriz_declarado_vs_entregue").fetchall()
            ]
            alerts_rows = [
                dict(r)
                for r in conn.execute("SELECT * FROM vw_03_alertas_cadeia_custodia_e_pericia").fetchall()
            ]
        finally:
            conn.close()

        sonegados = [r for r in parity_rows if int(r.get("tema977_sonegado_flag", 0)) == 1]
        return {
            "parity_total_items": len(parity_rows),
            "tema977_missing_or_corrupted_count": len(sonegados),
            "tema977_missing_or_corrupted": sonegados,
            "all_parity_items": parity_rows,
            "custody_and_forensic_alerts_count": len(alerts_rows),
            "custody_and_forensic_alerts": alerts_rows,
        }

    def _tool_confront_allegation_vs_raw(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        allegation = str(args.get("allegation_text", "")).strip()
        if not allegation:
            raise InvalidForensicValueError("Informe allegation_text para confrontar contra a base bruta.")
        neighbor_window = max(1, min(10, int(args.get("neighbor_window", 2))))
        tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9À-ÿ]+", allegation) if len(t) >= 4]

        conn = self._open_organized_db_immutable(db_path)
        try:
            contradictions = [
                dict(r) for r in conn.execute("SELECT * FROM org_material_contradictions").fetchall()
            ]
            all_comms = [
                dict(r)
                for r in conn.execute("SELECT * FROM vw_04_comunicacoes_unificadas_utc").fetchall()
            ]
            dup_fin = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM vw_05_financeiro_consolidado WHERE is_inter_file_duplicate = 1"
                ).fetchall()
            ]
            telecom_defects = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT * FROM vw_06_telecom_erb_deslocamentos
                    WHERE impossible_speed_flag = 1 OR cgnat_missing_port_flag = 1
                    """
                ).fetchall()
            ]
        finally:
            conn.close()

        matched_contradictions = [
            c
            for c in contradictions
            if not tokens
            or any(
                tok in (str(c["state_claim_excerpt"]) + " " + str(c["raw_truth_excerpt"])).lower()
                for tok in tokens
            )
        ]
        if not matched_contradictions:
            matched_contradictions = contradictions

        contextualized_messages: list[dict[str, object]] = []
        for idx, msg in enumerate(all_comms):
            body_l = str(msg.get("content_verbatim", "")).lower()
            if tokens and any(tok in body_l for tok in tokens):
                start_i = max(0, idx - neighbor_window)
                end_i = min(len(all_comms), idx + neighbor_window + 1)
                contextualized_messages.append(
                    {
                        "matched_message": msg,
                        "neighbor_context_utc": all_comms[start_i:end_i],
                    }
                )

        return {
            "allegation_text": allegation,
            "material_contradictions": matched_contradictions,
            "contextualized_communications": contextualized_messages[:15],
            "inter_file_financial_duplicates": dup_fin[:25],
            "telecom_and_cgnat_anomalies": telecom_defects[:25],
        }

    def _tool_verify_citation_strict(self, args: dict[str, object]) -> dict[str, object]:
        _, db_path = self._resolve_dest_and_db(args)
        paragraph_text = str(args.get("paragraph_text", "")).strip()
        raw_claims = args.get("claims")

        corpus, known_sha_set, known_cn_set, all_verbatim_text = self._load_verification_corpus(db_path)
        rejected_reasons: list[str] = []
        checked_count = 0

        if isinstance(raw_claims, list) and raw_claims:
            parsed_claims: list[CandidateClaim] = []
            for idx, item in enumerate(raw_claims, start=1):
                if isinstance(item, dict):
                    num_raw = item.get("numeric_value")
                    num_val = int(num_raw) if isinstance(num_raw, int) and not isinstance(num_raw, bool) else None
                    parsed_claims.append(
                        CandidateClaim(
                            claim_id=str(item.get("claim_id") or f"MCP-CLM-{idx:04d}"),
                            referenced_cn=str(item.get("referenced_cn", "")),
                            referenced_sha256=str(item.get("referenced_sha256", "")),
                            locator=str(item.get("locator", "")),
                            verbatim_quote=str(item.get("verbatim_quote", "")),
                            numeric_value=num_val,
                        )
                    )
            verdict_claims = BlockingVerifierEngine.verify(tuple(parsed_claims), corpus)
            checked_count += verdict_claims.checked_claims_count
            rejected_reasons.extend(verdict_claims.rejected_reasons)

        if paragraph_text:
            try:
                verdict_md = verify_markdown_report_strictly(
                    markdown_text=paragraph_text,
                    known_sha256_set=known_sha_set,
                    known_cn_set=known_cn_set,
                    all_verbatim_corpus_text=all_verbatim_text,
                )
                checked_count += verdict_md.checked_claims_count
            except BlockingVerificationError as bve:
                rejected_reasons.extend([r.strip() for r in str(bve).split(";") if r.strip()])

            for elo_cn in re.findall(r"\b(ELO-\d{6})\b", paragraph_text):
                checked_count += 1
                if known_cn_set and elo_cn not in known_cn_set:
                    rejected_reasons.append(f"ControlNumber fantasma no paragrafo: {elo_cn}")

        if not paragraph_text and not (isinstance(raw_claims, list) and raw_claims):
            raise InvalidForensicValueError(
                "Forneca paragraph_text e/ou claims estruturadas para elo_verify_citation_strict."
            )

        passed = len(rejected_reasons) == 0
        return {
            "passed": passed,
            "checked_items_count": checked_count,
            "rejected_reasons": rejected_reasons,
            "known_control_numbers_total": len(known_cn_set),
            "known_sha256_total": len(known_sha_set),
        }

    def _load_verification_corpus(
        self,
        db_path: Path,
    ) -> tuple[dict[str, VerifiableSourceCorpusEntry], set[str], set[str], str]:
        conn = self._open_organized_db_immutable(db_path)
        texts_by_cn: dict[str, list[str]] = {}
        nums_by_cn: dict[str, set[int]] = {}
        sha_by_cn: dict[str, str] = {}
        known_sha: set[str] = set()
        known_cn: set[str] = set()
        global_fragments: list[str] = []

        try:
            for r in conn.execute(
                "SELECT control_number, sha256_hex, size_bytes, origin_rel_path FROM org_inventory_files"
            ).fetchall():
                cn = str(r["control_number"])
                sh = str(r["sha256_hex"]).lower()
                known_cn.add(cn)
                known_sha.add(sh)
                sha_by_cn[cn] = sh
                texts_by_cn.setdefault(cn, []).append(str(r["origin_rel_path"]))
                nums_by_cn.setdefault(cn, set()).add(int(r["size_bytes"]))
                global_fragments.append(str(r["origin_rel_path"]))

            for r in conn.execute(
                "SELECT origin_cn, origin_sha256, text_clean FROM org_anchored_chunks"
            ).fetchall():
                cn = str(r["origin_cn"])
                sh = str(r["origin_sha256"]).lower()
                txt = str(r["text_clean"])
                known_cn.add(cn)
                known_sha.add(sh)
                sha_by_cn.setdefault(cn, sh)
                texts_by_cn.setdefault(cn, []).append(txt)
                global_fragments.append(txt)

            for r in conn.execute(
                "SELECT origin_cn, origin_sha256, content_verbatim FROM org_communications_utc"
            ).fetchall():
                cn = str(r["origin_cn"])
                sh = str(r["origin_sha256"]).lower()
                txt = str(r["content_verbatim"])
                known_cn.add(cn)
                known_sha.add(sh)
                sha_by_cn.setdefault(cn, sh)
                texts_by_cn.setdefault(cn, []).append(txt)
                global_fragments.append(txt)

            for r in conn.execute(
                "SELECT origin_cn, origin_sha256, amount_cents, amount_brl_formatted FROM org_financial_consolidated"
            ).fetchall():
                cn = str(r["origin_cn"])
                sh = str(r["origin_sha256"]).lower()
                brl = str(r["amount_brl_formatted"])
                known_cn.add(cn)
                known_sha.add(sh)
                sha_by_cn.setdefault(cn, sh)
                texts_by_cn.setdefault(cn, []).append(brl)
                nums_by_cn.setdefault(cn, set()).add(int(r["amount_cents"]))
                global_fragments.append(brl)

            for r in conn.execute(
                "SELECT raw_origin_cn, raw_sha256, raw_truth_excerpt, state_claim_excerpt, financial_inflation_cents FROM org_material_contradictions"
            ).fetchall():
                cn = str(r["raw_origin_cn"])
                sh = str(r["raw_sha256"]).lower()
                known_cn.add(cn)
                known_sha.add(sh)
                sha_by_cn.setdefault(cn, sh)
                texts_by_cn.setdefault(cn, []).extend(
                    [str(r["raw_truth_excerpt"]), str(r["state_claim_excerpt"])]
                )
                nums_by_cn.setdefault(cn, set()).add(int(r["financial_inflation_cents"]))
                global_fragments.extend([str(r["raw_truth_excerpt"]), str(r["state_claim_excerpt"])])
        finally:
            conn.close()

        corpus: dict[str, VerifiableSourceCorpusEntry] = {}
        for cn, sha_val in sha_by_cn.items():
            joined = "\n".join(texts_by_cn.get(cn, []))
            nums = tuple(sorted(nums_by_cn.get(cn, set())))
            corpus[cn] = VerifiableSourceCorpusEntry(
                control_number=cn,
                sha256_hex=sha_val,
                full_text=joined,
                numeric_facts=nums,
            )

        return corpus, known_sha, known_cn, "\n".join(global_fragments)

    def _tool_generate_deliverables(self, args: dict[str, object]) -> dict[str, object]:
        dest_root, _ = self._resolve_dest_and_db(args)
        dir_03 = dest_root / "03_RELATORIOS_E_DOSSIE"
        dir_03.mkdir(parents=True, exist_ok=True)

        engine_deliv = dest_root / "_elo_engine_workspace" / "deliverables"
        if engine_deliv.is_dir():
            for item in sorted(engine_deliv.iterdir()):
                if item.is_file():
                    target = dir_03 / item.name
                    if not target.exists():
                        shutil.copy2(item, target)

        deliverables: list[dict[str, object]] = []
        for f_item in sorted(dir_03.iterdir()):
            if f_item.is_file():
                raw = f_item.read_bytes()
                deliverables.append(
                    {
                        "file_name": f_item.name,
                        "path": str(f_item),
                        "size_bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )

        return {
            "deliverables_dir": str(dir_03),
            "deliverables_count": len(deliverables),
            "deliverables": deliverables,
        }

    def _list_resources(self) -> list[dict[str, object]]:
        resources: list[dict[str, object]] = [
            {
                "uri": "elo://views/catalog",
                "name": "Catalogo das 8 SQL Views Executivas ELO",
                "mimeType": "application/json",
            }
        ]
        if self._active_dest_path:
            resources.append(
                {
                    "uri": "elo://case/schema",
                    "name": "SCHEMA_PARA_HUMANO_E_IA.md do Caso Ativo",
                    "mimeType": "text/markdown",
                }
            )
        return resources

    def _read_resource(self, uri: str) -> dict[str, object]:
        if uri == "elo://views/catalog":
            return {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps({"views": list(EXECUTIVE_VIEWS_NAMES)}, ensure_ascii=False),
            }
        if uri == "elo://case/schema" and self._active_dest_path:
            schema_p = Path(self._active_dest_path) / "01_BANCO_ORGANIZADO" / "SCHEMA_PARA_HUMANO_E_IA.md"
            if schema_p.is_file():
                return {
                    "uri": uri,
                    "mimeType": "text/markdown",
                    "text": schema_p.read_text(encoding="utf-8"),
                }
        raise InvalidForensicValueError(f"Recurso MCP indisponivel: {uri}")

    @staticmethod
    def _list_prompts() -> list[dict[str, object]]:
        return [
            {
                "name": "coordenador-forense-elo",
                "description": "Diretriz de Agente Coordenador Forense (Software 1.0 governando IA via MCP).",
            }
        ]

    @staticmethod
    def _get_prompt(prompt_name: str) -> dict[str, object]:
        if prompt_name != "coordenador-forense-elo":
            raise InvalidForensicValueError(f"Prompt MCP desconhecido: {prompt_name}")
        return {
            "description": "Perfil de Agente Coordenador Forense ELO v2.2",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": (
                            "Atue estritamente como Coordenador Forense ELO: delegue 100% das buscas, "
                            "contagens, somas financeiras e consultas temporais as 10 ferramentas MCP do ELO "
                            "e valide qualquer resposta final com elo_verify_citation_strict."
                        ),
                    },
                }
            ],
        }

    @staticmethod
    def _build_tools_catalog() -> list[dict[str, object]]:
        return [
            {
                "name": "elo_list_mounted_drives",
                "description": "Lista os HDs/volumes conectados, sistema de arquivos e espaco livre em bytes inteiros.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "elo_autopilot_ingest_hd",
                "description": "Executa a leitura imutavel de --source (HD de prova) gravando a arvore e o Banco Organizado em --dest (outro HD).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_paths": {"type": "array", "items": {"type": "string"}},
                        "dest_path": {"type": "string"},
                        "case_id": {"type": "string"},
                        "staging_path": {"type": "string"},
                        "llm_endpoint": {"type": "string"},
                    },
                    "required": ["source_paths", "dest_path"],
                },
            },
            {
                "name": "elo_get_case_overview",
                "description": "Le RESUMO_EXECUTIVO_BANCO.json e contagens ao vivo das 8 SQL Views do Banco Organizado.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"dest_path": {"type": "string"}},
                    "required": ["dest_path"],
                },
            },
            {
                "name": "elo_hybrid_search",
                "description": "Executa busca hibrida RRF (BM25 FTS5 + vetorial deterministica) sobre o Banco Organizado.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dest_path": {"type": "string"},
                        "query": {"type": "string"},
                        "top_n": {"type": "integer"},
                    },
                    "required": ["dest_path", "query"],
                },
            },
            {
                "name": "elo_query_organized_view",
                "description": "Consulta paginada e somente leitura (mode=ro&immutable=1 + SELECT estrito) nas 8 SQL Views executivas.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dest_path": {"type": "string"},
                        "sql_query": {"type": "string"},
                        "view_name": {"type": "string"},
                        "limit": {"type": "integer"},
                        "offset": {"type": "integer"},
                    },
                    "required": ["dest_path"],
                },
            },
            {
                "name": "elo_timeline_window",
                "description": "Recupera eventos multi-fonte em janela cronologica UTC (start_utc a end_utc) na vw_08.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dest_path": {"type": "string"},
                        "start_utc": {"type": "string"},
                        "end_utc": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["dest_path"],
                },
            },
            {
                "name": "elo_audit_custody_and_parity",
                "description": "Retorna quebras de cadeia de custodia, alertas POP Senasp 2024, auditoria .iped e omissao Tema 977/STF.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"dest_path": {"type": "string"}},
                    "required": ["dest_path"],
                },
            },
            {
                "name": "elo_confront_allegation_vs_raw",
                "description": "Confronta afirmacao de laudo ou denuncia contra os dados brutos e contexto vizinho de mensagens.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dest_path": {"type": "string"},
                        "allegation_text": {"type": "string"},
                        "neighbor_window": {"type": "integer"},
                    },
                    "required": ["dest_path", "allegation_text"],
                },
            },
            {
                "name": "elo_verify_citation_strict",
                "description": "Aciona o BlockingVerifierEngine para validar matematicamente hashes SHA-256, ControlNumbers, numeros e citacoes «literais».",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dest_path": {"type": "string"},
                        "paragraph_text": {"type": "string"},
                        "claims": {"type": "array", "items": {"type": "object"}},
                    },
                    "required": ["dest_path"],
                },
            },
            {
                "name": "elo_generate_deliverables",
                "description": "Lista e verifica por SHA-256 os relatorios EDRM, Quesitos, Parecer 7 Blocos e Dossie HTML5 Offline em 03_RELATORIOS_E_DOSSIE.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"dest_path": {"type": "string"}},
                    "required": ["dest_path"],
                },
            },
        ]
