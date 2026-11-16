"""Primitivas puras do Verificador Deterministico Bloqueante (Software 1.0 governando IA)."""

from __future__ import annotations

from dataclasses import dataclass
import re

from edrm.shared_kernel.exceptions import BlockingVerificationError

_GUILLMET_QUOTE_RE = re.compile(r"«([^»]+)»")
_SHA256_TOKEN_RE = re.compile(r"\b([0-9a-f]{64})\b")
_CN_TOKEN_RE = re.compile(r"\b(CN-\d{8}(?:\.\d{4})*)\b")


@dataclass(frozen=True, slots=True)
class VerifiableSourceCorpusEntry:
    """Entrada do corpus factual deterministico usado como gabarito imutavel."""

    control_number: str
    sha256_hex: str
    full_text: str
    numeric_facts: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateClaim:
    """Afirmacao estruturada (humana ou assistida por IA) submetida ao verificador."""

    claim_id: str
    referenced_cn: str
    referenced_sha256: str
    locator: str
    verbatim_quote: str
    numeric_value: int | None = None


@dataclass(frozen=True, slots=True)
class VerificationVerdict:
    """Resultado matematico deterministico da auditoria de afirmacoes ou relatorios."""

    passed: bool
    checked_claims_count: int
    rejected_reasons: tuple[str, ...]


def verify_claims_deterministically(
    claims: tuple[CandidateClaim, ...],
    corpus: dict[str, VerifiableSourceCorpusEntry],
) -> VerificationVerdict:
    """Confere matematicamente IDs, SHA-256, numeros e citacoes literais contra o corpus.

    Args:
        claims: Tupla de afirmacoes candidatas.
        corpus: Mapa indexado por control_number contendo hashes, textos e inteiros reais.

    Returns:
        VerificationVerdict indicando aprovacao integral (0 falhas) ou lista de rejeicoes.
    """
    errors: list[str] = []
    for claim in claims:
        source = corpus.get(claim.referenced_cn)
        if source is None:
            errors.append(
                f"[{claim.claim_id}] ControlNumber inexistente no catalogo: {claim.referenced_cn}"
            )
            continue
        if claim.referenced_sha256.lower() != source.sha256_hex.lower():
            errors.append(
                f"[{claim.claim_id}] Divergencia de SHA-256 para {claim.referenced_cn}: "
                f"declarado={claim.referenced_sha256} real={source.sha256_hex}"
            )
        if not claim.locator.strip():
            errors.append(f"[{claim.claim_id}] Locator vazio para {claim.referenced_cn}")
        if not claim.verbatim_quote or claim.verbatim_quote not in source.full_text:
            errors.append(
                f"[{claim.claim_id}] Citacao literal ausente/adulterada na fonte "
                f"{claim.referenced_cn}: {claim.verbatim_quote!r}"
            )
        if claim.numeric_value is not None and claim.numeric_value not in source.numeric_facts:
            errors.append(
                f"[{claim.claim_id}] Valor numerico {claim.numeric_value} nao consta nos fatos "
                f"deterministcos de {claim.referenced_cn}"
            )
    return VerificationVerdict(
        passed=(len(errors) == 0),
        checked_claims_count=len(claims),
        rejected_reasons=tuple(errors),
    )


def verify_markdown_report_strictly(
    markdown_text: str,
    known_sha256_set: set[str],
    known_cn_set: set[str],
    all_verbatim_corpus_text: str,
) -> VerificationVerdict:
    """Audita um relatorio Markdown exigindo que todo CN, SHA-256 e citacao «...» exista.

    Args:
        markdown_text: Conteudo completo do relatorio pericial ou fase EDRM.
        known_sha256_set: Conjunto de todos os SHA-256 reais registrados no caso.
        known_cn_set: Conjunto de todos os ControlNumbers validos registrados.
        all_verbatim_corpus_text: Concatenacao deterministica das fontes ancoradas.

    Returns:
        VerificationVerdict com resultado da auditoria.

    Raises:
        BlockingVerificationError: Se encontrar qualquer hash, CN ou citacao inventada.
    """
    normalized_hashes = {h.lower() for h in known_sha256_set}
    errors: list[str] = []
    checks = 0

    for match_cn in _CN_TOKEN_RE.finditer(markdown_text):
        checks += 1
        cn_tok = match_cn.group(1)
        if known_cn_set and cn_tok not in known_cn_set:
            errors.append(f"ControlNumber fantasma no relatorio: {cn_tok}")

    for match_hash in _SHA256_TOKEN_RE.finditer(markdown_text):
        checks += 1
        h_tok = match_hash.group(1).lower()
        if normalized_hashes and h_tok not in normalized_hashes:
            errors.append(f"SHA-256 nao registrado citado no relatorio: {h_tok}")

    for match_quote in _GUILLMET_QUOTE_RE.finditer(markdown_text):
        checks += 1
        quote = match_quote.group(1)
        if quote not in all_verbatim_corpus_text:
            errors.append(f"Citacao «{quote}» nao localizada literalmente nas fontes brutas.")

    verdict = VerificationVerdict(
        passed=(len(errors) == 0),
        checked_claims_count=checks,
        rejected_reasons=tuple(errors),
    )
    if not verdict.passed:
        raise BlockingVerificationError("; ".join(verdict.rejected_reasons))
    return verdict
