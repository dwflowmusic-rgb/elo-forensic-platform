"""Dominio puro da Analise Continua — Fusao RRF (k=60), Escudo Anti-Injection, Verificador e Regra do 3."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
import re

from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    QualityControlSummary,
    TimelineEventRecord,
)
from edrm.shared_kernel.exceptions import BudgetCircuitBreakerError
from edrm.shared_kernel.value_objects import sha256_text
from edrm.shared_kernel.verifier_primitives import (
    CandidateClaim,
    VerifiableSourceCorpusEntry,
    VerificationVerdict,
    verify_claims_deterministically,
)

RRF_K_CONSTANT: int = 60
VECTOR_DIM: int = 64

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+all\s+rules", re.IGNORECASE),
    re.compile(r"system\s+prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE),
)


@dataclass(frozen=True, slots=True)
class HybridSearchHit:
    """Resultado ranqueado pela fusao RRF (BM25 Lexico + Similaridade Vetorial)."""

    chunk: AnchoredTextChunk
    lexical_rank: int | None
    vector_rank: int | None
    rrf_score: Decimal


class DeterministicHashEmbedder:
    """Gera vetores deterministcos inteiros de 64 dimensoes via SHA-256 sobre n-gramas."""

    @staticmethod
    def embed(text: str) -> tuple[int, ...]:
        """Converte texto em vetor deterministico de contagens sinalizadas (zero float)."""
        vec = [0] * VECTOR_DIM
        cleaned = re.sub(r"\s+", " ", text.strip().lower())
        if not cleaned:
            return tuple(vec)
        tokens = re.findall(r"[a-z0-9_.,\-]+", cleaned)
        features = list(tokens)
        for tok in tokens:
            if len(tok) >= 4:
                for i in range(len(tok) - 2):
                    features.append(tok[i : i + 3])
        for feat in features:
            digest = bytes.fromhex(sha256_text(feat))
            bucket = digest[0] % VECTOR_DIM
            sign = 1 if (digest[1] % 2 == 0) else -1
            vec[bucket] += sign
        return tuple(vec)

    @staticmethod
    def dot_similarity(left: tuple[int, ...], right: tuple[int, ...]) -> int:
        """Produto escalar inteiro exato entre dois vetores deterministcos."""
        return sum(a * b for a, b in zip(left, right))


class ExactMetricSimilarity:
    """Metrica vetorial algebricamente exata em Decimal (proibida aproximacao quadratica que viola desigualdade triangular)."""

    @staticmethod
    def euclidean_distance_exact(left: tuple[int, ...], right: tuple[int, ...]) -> Decimal:
        """Calcula d(u, v) = sqrt(sum((u_i - v_i)^2)) via Decimal.sqrt() exato (zero float)."""
        sum_sq = sum((a - b) * (a - b) for a, b in zip(left, right))
        if sum_sq <= 0:
            return Decimal("0")
        return Decimal(sum_sq).sqrt()

    @staticmethod
    def cosine_similarity_exact(left: tuple[int, ...], right: tuple[int, ...]) -> Decimal:
        """Calcula similaridade cosseno normalizada em Decimal sem usar ponto flutuante."""
        norm_l_sq = sum(a * a for a in left)
        norm_r_sq = sum(b * b for b in right)
        if norm_l_sq <= 0 or norm_r_sq <= 0:
            return Decimal("0")
        dot_val = sum(a * b for a, b in zip(left, right))
        denom = Decimal(norm_l_sq).sqrt() * Decimal(norm_r_sq).sqrt()
        return (Decimal(dot_val) / denom).quantize(Decimal("0.00000001"))

    @classmethod
    def verify_triangle_inequality_holds(
        cls,
        vec_a: tuple[int, ...],
        vec_b: tuple[int, ...],
        vec_c: tuple[int, ...],
    ) -> bool:
        """Comprova d(a, c) <= d(a, b) + d(b, c) na metrica exata."""
        d_ac = cls.euclidean_distance_exact(vec_a, vec_c)
        d_ab = cls.euclidean_distance_exact(vec_a, vec_b)
        d_bc = cls.euclidean_distance_exact(vec_b, vec_c)
        return d_ac <= (d_ab + d_bc + Decimal("0.0000000001"))


class HybridRrfFusionEngine:
    """Motor de Busca Hibrida Reciprocal Rank Fusion: Score(d) = 1/(k+r_lex) + 1/(k+r_vec)."""

    @staticmethod
    def fuse(
        chunks_by_id: dict[str, AnchoredTextChunk],
        lexical_ordered_ids: tuple[str, ...],
        vector_ordered_ids: tuple[str, ...],
        k: int = RRF_K_CONSTANT,
        top_n: int = 25,
    ) -> tuple[HybridSearchHit, ...]:
        """Funde rankings lexico BM25 e vetorial usando aritmetica Decimal exata."""
        lex_ranks = {cid: idx for idx, cid in enumerate(lexical_ordered_ids, start=1)}
        vec_ranks = {cid: idx for idx, cid in enumerate(vector_ordered_ids, start=1)}
        candidate_ids = sorted(set(lex_ranks.keys()) | set(vec_ranks.keys()))

        hits: list[HybridSearchHit] = []
        k_dec = Decimal(k)
        for cid in candidate_ids:
            chunk = chunks_by_id.get(cid)
            if chunk is None:
                continue
            r_lex = lex_ranks.get(cid)
            r_vec = vec_ranks.get(cid)
            score = Decimal("0")
            if r_lex is not None:
                score += Decimal("1") / (k_dec + Decimal(r_lex))
            if r_vec is not None:
                score += Decimal("1") / (k_dec + Decimal(r_vec))
            hits.append(
                HybridSearchHit(
                    chunk=chunk,
                    lexical_rank=r_lex,
                    vector_rank=r_vec,
                    rrf_score=score.quantize(Decimal("0.00000001")),
                )
            )

        hits.sort(key=lambda h: (-h.rrf_score, h.chunk.chunk_id))
        return tuple(hits[:top_n])


class UnifiedUtcTimelineBuilder:
    """Reune eventos multi-fonte na mesma regua cronologica UTC."""

    @staticmethod
    def merge_and_sort(events: tuple[TimelineEventRecord, ...]) -> tuple[TimelineEventRecord, ...]:
        """Ordena deterministicamente todos os eventos por epoch_seconds e event_id."""
        return tuple(sorted(events, key=lambda ev: (ev.epoch_seconds, ev.event_id)))


class PromptInjectionShield:
    """Escudo estrutural anti-prompt-injection e disjuntor rigido de orcamento de tokens."""

    def __init__(self, max_tokens_per_call: int = 4096) -> None:
        self._max_tokens = max_tokens_per_call

    def isolate_evidence_text(self, raw_evidence_text: str) -> tuple[str, bool, int]:
        """Sanitiza padroes maliciosos, envolve em delimitador passivo e checa orcamento.

        Args:
            raw_evidence_text: Texto extraido de evidencia potencialmente hostil.

        Returns:
            Tupla (prompt_isolado, houve_neutralizacao, estimativa_tokens).

        Raises:
            BudgetCircuitBreakerError: Se o texto exceder o teto estrito de tokens.
        """
        estimated_tokens = max(1, len(raw_evidence_text) // 4)
        if estimated_tokens > self._max_tokens:
            raise BudgetCircuitBreakerError(
                f"Disjuntor de orcamento acionado: {estimated_tokens} tokens > teto {self._max_tokens}"
            )
        neutralized = False
        working = raw_evidence_text
        for pat in _INJECTION_PATTERNS:
            if pat.search(working):
                neutralized = True
                working = pat.sub("[ISOLATED_UNTRUSTED_DIRECTIVE]", working)

        envelope = f"<EVIDENCE_DATA_READONLY>\n{working}\n</EVIDENCE_DATA_READONLY>"
        return envelope, neutralized, estimated_tokens


class BlockingVerifierEngine:
    """Motor do Verificador Deterministico Bloqueante (Software 1.0 governando IA)."""

    @staticmethod
    def verify(
        claims: tuple[CandidateClaim, ...],
        corpus: dict[str, VerifiableSourceCorpusEntry],
    ) -> VerificationVerdict:
        """Executa conferencia caractere por caractere de CN, SHA-256, inteiros e citacoes."""
        return verify_claims_deterministically(claims, corpus)


class CochranElusionRuleOf3Qc:
    """Controle estatistico triplo: Cochran (95%/10%), Teste de Elusao e Regra do 3 (3/n)."""

    @staticmethod
    def evaluate_quality_control(
        classified_population_n: int,
        filtered_or_unselected_n: int,
        observed_elusion_errors: int = 0,
    ) -> QualityControlSummary:
        """Calcula Cochran, amostra de elusao e limite superior IC 95% via Regra do 3 (3/n)."""
        n0 = Decimal("96.04")
        if classified_population_n > 0:
            denom = Decimal("1") + ((n0 - Decimal("1")) / Decimal(classified_population_n))
            cochran_n = min(
                classified_population_n,
                int((n0 / denom).to_integral_value(rounding=ROUND_CEILING)),
            )
        else:
            cochran_n = 0

        elusion_n = max(1, filtered_or_unselected_n) if filtered_or_unselected_n > 0 else max(1, cochran_n)
        if observed_elusion_errors == 0:
            upper_bound = (Decimal("3") / Decimal(elusion_n)) * Decimal("100")
            upper_str = f"{min(Decimal('100.00'), upper_bound).quantize(Decimal('0.01'))}%"
            passed = True
        else:
            err_rate = (Decimal(observed_elusion_errors) / Decimal(elusion_n)) * Decimal("100")
            upper_str = f"{err_rate.quantize(Decimal('0.01'))}%"
            passed = False

        return QualityControlSummary(
            cochran_sample_n=cochran_n,
            elusion_inspected_n=elusion_n,
            elusion_errors_found=observed_elusion_errors,
            rule_of_3_upper_bound_pct=upper_str,
            qc_passed=passed,
        )
