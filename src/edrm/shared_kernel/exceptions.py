"""Excecoes tipadas explicitas da plataforma forense ELO (Zero except silencioso)."""

from __future__ import annotations


class ForensicPlatformError(Exception):
    """Excecao raiz de todas as violacoes forenses, arquiteturais ou periciais."""


class ReadOnlyViolationError(ForensicPlatformError):
    """Lancada ao detectar tentativa de escrita, mutacao ou truncamento na midia --source."""


class SourceMutationDetectedError(ForensicPlatformError):
    """Lancada quando PreScanSnapshot diverge matematicamente de PostScanSnapshot."""


class WorkspaceOverlapError(ForensicPlatformError):
    """Lancada quando --workspace se sobrepoe ou intersecta uma raiz protegida --source."""


class VerifierCalibrationError(ForensicPlatformError):
    """Lancada quando a suite de auto-calibracao ISO/IEC 27041 falha em bloquear adulteracoes."""


class BlockingVerificationError(ForensicPlatformError):
    """Lancada pelo Verificador Deterministico Bloqueante ao detectar divergencia factual."""


class SecrecySocketViolationError(ForensicPlatformError):
    """Lancada quando ha tentativa de conexao de rede fora de 127.0.0.1 em segredo judicial."""


class CollectionHashMismatchError(ForensicPlatformError):
    """Lancada na Fase 03 quando sha256_source diverge de sha256_vault na releitura fria."""


class ContainerSecurityViolationError(ForensicPlatformError):
    """Lancada ao bloquear Path Traversal (../) ou Zip Bomb durante descompactacao."""


class BudgetCircuitBreakerError(ForensicPlatformError):
    """Lancada quando uma requisicao ao interprete local excede o teto estrito de tokens."""


class HumanAuthorizationRequiredError(ForensicPlatformError):
    """Lancada na Fase 08 quando sanitizacao NIST 800-88 e invocada sem dupla confirmacao."""


class InvalidForensicValueError(ForensicPlatformError):
    """Lancada quando objetos de valor recebem formatos invalidos ou imprecisos."""
