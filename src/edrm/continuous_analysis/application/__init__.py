"""Camada de aplicacao pura da Analise Continua — Busca RRF, IA Governada e Auditoria."""

from __future__ import annotations

from typing import Protocol

from edrm.continuous_analysis.domain import (
    BlockingVerifierEngine,
    DeterministicHashEmbedder,
    HybridRrfFusionEngine,
    HybridSearchHit,
    PromptInjectionShield,
)
from edrm.shared_kernel.contracts import AnchoredTextChunk
from edrm.shared_kernel.enums import PhaseCode
from edrm.shared_kernel.exceptions import BlockingVerificationError
from edrm.shared_kernel.value_objects import sha256_text
from edrm.shared_kernel.verifier_primitives import (
    CandidateClaim,
    VerifiableSourceCorpusEntry,
    VerificationVerdict,
)


class HybridSearchIndexPort(Protocol):
    """Porta segregada para indexacao e recuperacao FTS5 BM25 + Vetores (SQLite ou pgvector)."""

    def index_chunks(
        self,
        catalog_db_path: str,
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> int:
        """Indexa os chunks sanitizados no FTS5 BM25 e persiste seus vetores deterministcos."""

    def query_lexical_and_vector(
        self,
        catalog_db_path: str,
        query_text: str,
        query_vector: tuple[int, ...],
        limit: int,
    ) -> tuple[dict[str, AnchoredTextChunk], tuple[str, ...], tuple[str, ...]]:
        """Retorna (mapa_chunks, ids_ordenados_bm25, ids_ordenados_vetorial)."""


class LocalGovernedLlmPort(Protocol):
    """Porta segregada para interprete local (127.0.0.1 Ollama/vLLM ou Heuristico Offline)."""

    def propose_anchored_claims(
        self,
        isolated_prompt: str,
        corpus: dict[str, VerifiableSourceCorpusEntry],
    ) -> tuple[str, tuple[CandidateClaim, ...], int]:
        """Gera afirmacoes estritamente ancoradas retornando (model_name, claims, tokens_out)."""


class AiAndQcAuditRepositoryPort(Protocol):
    """Porta segregada para gravacao em ai_and_qc_audit_log (ISO/IEC 42001 / CNJ 615/2025)."""

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
        """Persiste log imutavel de auditoria de IA e controle estatistico."""


class HybridSearchUseCase:
    """Indexa e consulta evidencias combinando busca exata BM25 com vetores via RRF (k=60)."""

    def __init__(self, index_port: HybridSearchIndexPort) -> None:
        self._index_port = index_port

    def build_index(
        self,
        catalog_db_path: str,
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> int:
        """Popula o indice hibrido para todos os chunks extraidos na Fase 04."""
        return self._index_port.index_chunks(catalog_db_path, chunks)

    def search(
        self,
        catalog_db_path: str,
        query: str,
        top_n: int = 20,
    ) -> tuple[HybridSearchHit, ...]:
        """Executa fusao RRF (k=60) retornando os hits ancorados mais relevantes."""
        if not query.strip():
            return ()
        q_vec = DeterministicHashEmbedder.embed(query)
        chunks_map, lex_ids, vec_ids = self._index_port.query_lexical_and_vector(
            catalog_db_path=catalog_db_path,
            query_text=query,
            query_vector=q_vec,
            limit=max(50, top_n * 2),
        )
        return HybridRrfFusionEngine.fuse(
            chunks_by_id=chunks_map,
            lexical_ordered_ids=lex_ids,
            vector_ordered_ids=vec_ids,
            top_n=top_n,
        )


class GovernedAiInterpretAndVerifyUseCase:
    """Executa interpretacao governada sob Escudo Anti-Injection + Verificador Bloqueante."""

    def __init__(
        self,
        llm_port: LocalGovernedLlmPort,
        audit_repo: AiAndQcAuditRepositoryPort,
        shield: PromptInjectionShield | None = None,
    ) -> None:
        self._llm = llm_port
        self._audit = audit_repo
        self._shield = shield or PromptInjectionShield()

    def execute_and_verify(
        self,
        catalog_db_path: str,
        raw_context: str,
        corpus: dict[str, VerifiableSourceCorpusEntry],
        ts_utc: str,
        phase_code: PhaseCode = PhaseCode.CONTINUOUS_ANALYSIS,
    ) -> tuple[CandidateClaim, ...]:
        """Isola texto, obtem afirmacoes candidatas, audita e bloqueia qualquer alucinacao."""
        isolated, _, tokens_in = self._shield.isolate_evidence_text(raw_context)
        prompt_hash = sha256_text(isolated)
        model_name, claims, tokens_out = self._llm.propose_anchored_claims(isolated, corpus)

        verdict = BlockingVerifierEngine.verify(claims, corpus)
        self._audit.record_verification_audit(
            catalog_db_path=catalog_db_path,
            ts_utc=ts_utc,
            phase_code=phase_code,
            model_name=model_name,
            prompt_sha256=prompt_hash,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verdict=verdict,
            sampling_method="DETERMINISTIC_100PCT_BLOCKING_VERIFIER",
            stratum_stats={"checked_claims": verdict.checked_claims_count},
        )
        if not verdict.passed:
            raise BlockingVerificationError(
                f"Verificador Bloqueante rejeitou afirmacao divergente: {verdict.rejected_reasons}"
            )
        return claims
