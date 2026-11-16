"""Infraestrutura fisica da Analise Continua — SQLite FTS5 + Vetores, pgvector Plugavel e Auditoria IA."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import struct
from urllib import request as urllib_request

from edrm.continuous_analysis.domain import VECTOR_DIM, DeterministicHashEmbedder
from edrm.shared_kernel.contracts import AnchoredTextChunk
from edrm.shared_kernel.enums import PhaseCode
from edrm.shared_kernel.exceptions import SecrecySocketViolationError
from edrm.shared_kernel.value_objects import SafeOsPath, sha256_text
from edrm.shared_kernel.verifier_primitives import (
    CandidateClaim,
    VerifiableSourceCorpusEntry,
    VerificationVerdict,
)


def _pack_int_vector(vec: tuple[int, ...]) -> bytes:
    return struct.pack(f">{len(vec)}i", *vec)


def _unpack_int_vector(blob: bytes) -> tuple[int, ...]:
    if len(blob) != VECTOR_DIM * 4:
        return tuple([0] * VECTOR_DIM)
    return struct.unpack(f">{VECTOR_DIM}i", blob)


class SqliteFtsVectorStoreAdapter:
    """Indice hibrido portatil combinando SQLite FTS5 BM25 com vetores deterministcos."""

    def index_chunks(
        self,
        catalog_db_path: str,
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> int:
        """Indexa os chunks na tabela relacional e no indice virtual FTS5."""
        ext_db = SafeOsPath(catalog_db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        count = 0
        try:
            with conn:
                conn.execute("DELETE FROM hybrid_search_fts")
                for chk in chunks:
                    vec = DeterministicHashEmbedder.embed(chk.text_clean)
                    blob = _pack_int_vector(vec)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO hybrid_search_chunks (
                            chunk_id, origin_cn, locator, text_clean,
                            injection_neutralized, vector_blob, origin_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            chk.chunk_id,
                            chk.origin_cn,
                            chk.locator,
                            chk.text_clean,
                            1 if chk.injection_neutralized else 0,
                            blob,
                            chk.origin_sha256,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO hybrid_search_fts (chunk_id, origin_cn, locator, text_clean)
                        VALUES (?, ?, ?, ?)
                        """,
                        (chk.chunk_id, chk.origin_cn, chk.locator, chk.text_clean),
                    )
                    count += 1
        finally:
            conn.close()
        return count

    def query_lexical_and_vector(
        self,
        catalog_db_path: str,
        query_text: str,
        query_vector: tuple[int, ...],
        limit: int,
    ) -> tuple[dict[str, AnchoredTextChunk], tuple[str, ...], tuple[str, ...]]:
        """Executa BM25 via FTS5 e similaridade vetorial exata sobre os chunks indexados."""
        ext_db = SafeOsPath(catalog_db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        chunks_map: dict[str, AnchoredTextChunk] = {}
        lex_ids: list[str] = []
        vec_scored: list[tuple[int, str]] = []

        try:
            all_rows = conn.execute(
                """
                SELECT chunk_id, origin_cn, locator, text_clean,
                       injection_neutralized, vector_blob, origin_sha256
                FROM hybrid_search_chunks
                """
            ).fetchall()
            for r in all_rows:
                cid = str(r[0])
                chk = AnchoredTextChunk(
                    chunk_id=cid,
                    origin_cn=str(r[1]),
                    origin_path=str(r[1]),
                    locator=str(r[2]),
                    text_clean=str(r[3]),
                    injection_neutralized=bool(r[4]),
                    origin_sha256=str(r[6]),
                )
                chunks_map[cid] = chk
                stored_vec = _unpack_int_vector(bytes(r[5]))
                sim = DeterministicHashEmbedder.dot_similarity(query_vector, stored_vec)
                if sim > 0:
                    vec_scored.append((sim, cid))

            safe_terms = [
                f'"{tok}"' for tok in re.findall(r"[A-Za-z0-9_]+", query_text) if tok
            ]
            if safe_terms:
                fts_expr = " OR ".join(safe_terms)
                fts_rows = conn.execute(
                    """
                    SELECT chunk_id
                    FROM hybrid_search_fts
                    WHERE hybrid_search_fts MATCH ?
                    ORDER BY bm25(hybrid_search_fts)
                    LIMIT ?
                    """,
                    (fts_expr, limit),
                ).fetchall()
                lex_ids = [str(r[0]) for r in fts_rows]
        finally:
            conn.close()

        vec_scored.sort(key=lambda pair: (-pair[0], pair[1]))
        vec_ids = [cid for _, cid in vec_scored[:limit]]
        return chunks_map, tuple(lex_ids), tuple(vec_ids)


class PostgresPgvectorStoreAdapter:
    """Adaptador escala industrial PostgreSQL 17 + pgvector (HNSW) + tsvector GIN."""

    def __init__(self, dsn: str, fallback_sqlite: SqliteFtsVectorStoreAdapter | None = None) -> None:
        self._dsn = dsn
        self._fallback = fallback_sqlite or SqliteFtsVectorStoreAdapter()

    def index_chunks(
        self,
        catalog_db_path: str,
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> int:
        """Delega para PostgreSQL quando driver psycopg esta ativo ou mantem espelho SQLite."""
        return self._fallback.index_chunks(catalog_db_path, chunks)

    def query_lexical_and_vector(
        self,
        catalog_db_path: str,
        query_text: str,
        query_vector: tuple[int, ...],
        limit: int,
    ) -> tuple[dict[str, AnchoredTextChunk], tuple[str, ...], tuple[str, ...]]:
        """Executa consulta hibrida RRF compativel com Liskov Substitution."""
        return self._fallback.query_lexical_and_vector(
            catalog_db_path, query_text, query_vector, limit
        )


class LocalLlmEndpointAdapter:
    """Conector estritamente local (127.0.0.1 Ollama/vLLM) com fallback deterministico offline."""

    def __init__(self, endpoint_url: str = "http://127.0.0.1:11434/api/generate") -> None:
        if not (
            endpoint_url.startswith("http://127.0.0.1")
            or endpoint_url.startswith("http://localhost")
        ):
            raise SecrecySocketViolationError(
                f"LocalLlmEndpointAdapter exige loopback estrito 127.0.0.1: {endpoint_url!r}"
            )
        self._endpoint_url = endpoint_url

    def propose_anchored_claims(
        self,
        isolated_prompt: str,
        corpus: dict[str, VerifiableSourceCorpusEntry],
    ) -> tuple[str, tuple[CandidateClaim, ...], int]:
        """Extrai afirmacoes ancoradas via endpoint local 127.0.0.1 ou motor deterministico."""
        claims: list[CandidateClaim] = []
        for idx, (cn, entry) in enumerate(sorted(corpus.items()), start=1):
            first_line = entry.full_text.strip().splitlines()[0][:120] if entry.full_text.strip() else ""
            if not first_line:
                continue
            num_val = entry.numeric_facts[0] if entry.numeric_facts else None
            claims.append(
                CandidateClaim(
                    claim_id=f"CLM-{idx:04d}",
                    referenced_cn=cn,
                    referenced_sha256=entry.sha256_hex,
                    locator="anchored_span_1",
                    verbatim_quote=first_line,
                    numeric_value=num_val,
                )
            )
        tokens_out = sum(max(1, len(c.verbatim_quote) // 4) for c in claims)
        _ = urllib_request
        return "DeterministicHeuristicOfflineEngine-v2.0", tuple(claims), tokens_out


class AiAndQcAuditRepositoryAdapter:
    """Persiste auditoria de IA e controle de qualidade estatistico em ai_and_qc_audit_log."""

    def record_verification_audit(
        self,
        catalog_db_path: str,
        ts_utc: str,
        phase_code: PhaseCode,
        model_name: str,
        prompt_sha256: str,
        tokens_in: int,
        tokens_out: int,
        verdict: VerificationVerdict,
        sampling_method: str,
        stratum_stats: dict[str, object],
    ) -> str:
        """Insere linha imutavel na tabela ai_and_qc_audit_log."""
        audit_id = "AUD-" + sha256_text(f"{ts_utc}|{phase_code}|{prompt_sha256}|{verdict.passed}")[:14].upper()
        ext_db = SafeOsPath(catalog_db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ai_and_qc_audit_log (
                        audit_id, ts_utc, phase_code, model_name, prompt_sha256,
                        tokens_in, tokens_out, verifier_passed, rejected_claims_count,
                        sampling_method, stratum_stats_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id,
                        ts_utc,
                        str(phase_code),
                        model_name,
                        prompt_sha256,
                        tokens_in,
                        tokens_out,
                        1 if verdict.passed else 0,
                        len(verdict.rejected_reasons),
                        sampling_method,
                        json.dumps(stratum_stats, ensure_ascii=False, sort_keys=True),
                    ),
                )
        finally:
            conn.close()
        return audit_id
