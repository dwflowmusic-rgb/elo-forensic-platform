"""Dominio puro da Camada 00 — Governanca IGRM v4.1 e Auto-Calibracao ISO/IEC 27041."""

from __future__ import annotations

from dataclasses import dataclass

from edrm.shared_kernel.contracts import CalibrationReceipt
from edrm.shared_kernel.enums import SecrecyLevel
from edrm.shared_kernel.exceptions import (
    ReadOnlyViolationError,
    SecrecySocketViolationError,
    VerifierCalibrationError,
    WorkspaceOverlapError,
)
from edrm.shared_kernel.value_objects import sha256_text
from edrm.shared_kernel.verifier_primitives import (
    CandidateClaim,
    VerifiableSourceCorpusEntry,
    verify_claims_deterministically,
)

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_WRITE_MODE_CHARS: frozenset[str] = frozenset({"w", "a", "+", "x"})


def _normalize_Comparable_path(raw_path: str) -> str:
    """Normaliza separadores para comparacao deterministica pura sem I/O."""
    unified = raw_path.strip().replace("\\", "/")
    while "//" in unified and not unified.startswith("//"):
        unified = unified.replace("//", "/")
    if len(unified) > 1 and unified.endswith("/"):
        unified = unified.rstrip("/")
    return unified


@dataclass(frozen=True, slots=True)
class CaseWorkspaceLayout:
    """Arvore isolada de cinco zonas obrigatorias do caso (Secao 3.1)."""

    workspace_root: str
    vault_dir: str
    staging_dir: str
    catalog_dir: str
    deliverables_dir: str
    audit_dir: str
    catalog_db_path: str

    @classmethod
    def build(cls, workspace_root: str) -> CaseWorkspaceLayout:
        """Constroi os caminhos canonicos das 5 zonas a partir da raiz do workspace.

        Args:
            workspace_root: Caminho raiz limpo informado em --workspace.

        Returns:
            CaseWorkspaceLayout imutavel.
        """
        root = _normalize_Comparable_path(workspace_root)
        return cls(
            workspace_root=root,
            vault_dir=f"{root}/vault",
            staging_dir=f"{root}/staging",
            catalog_dir=f"{root}/catalog",
            deliverables_dir=f"{root}/deliverables",
            audit_dir=f"{root}/audit",
            catalog_db_path=f"{root}/catalog/elo_forensic_catalog.sqlite",
        )


@dataclass(frozen=True, slots=True)
class SourceWriteBlockerPolicy:
    """Politica pura de protecao contra escrita ou sobreposicao com midias --source."""

    protected_roots: tuple[str, ...]

    def validate_no_workspace_overlap(self, workspace_root: str) -> None:
        """Garante que o workspace nao coincida nem intersecte nenhuma raiz --source.

        Args:
            workspace_root: Caminho resolvido do workspace.

        Raises:
            WorkspaceOverlapError: Se houver intersecao de hierarquia de diretorios.
        """
        ws = _normalize_Comparable_path(workspace_root)
        for src in self.protected_roots:
            norm_src = _normalize_Comparable_path(src)
            if (
                ws == norm_src
                or ws.startswith(norm_src + "/")
                or norm_src.startswith(ws + "/")
            ):
                raise WorkspaceOverlapError(
                    f"Sobreposicao proibida entre --workspace ({ws}) e --source ({norm_src})"
                )

    def is_protected_path(self, candidate_path: str) -> bool:
        """Verifica se um caminho pertence a qualquer raiz protegida --source.

        Args:
            candidate_path: Caminho alvo da operacao.

        Returns:
            True se o caminho estiver sob uma midia protegida.
        """
        norm_cand = _normalize_Comparable_path(candidate_path)
        for src in self.protected_roots:
            norm_src = _normalize_Comparable_path(src)
            if norm_cand == norm_src or norm_cand.startswith(norm_src + "/"):
                return True
        return False

    def assert_open_allowed(self, candidate_path: str, mode: str) -> None:
        """Bloqueia qualquer modo de escrita sobre arquivos de --source.

        Args:
            candidate_path: Caminho sendo aberto.
            mode: String de modo do Python ('r', 'rb', 'w', 'wb', 'a', 'r+', etc.).

        Raises:
            ReadOnlyViolationError: Se o caminho for protegido e o modo contiver escrita.
        """
        if self.is_protected_path(candidate_path):
            if any(ch in mode for ch in _WRITE_MODE_CHARS):
                raise ReadOnlyViolationError(
                    f"Tentativa de abertura mutavel ({mode!r}) bloqueada em --source: "
                    f"{candidate_path}"
                )

    def assert_mutation_forbidden(self, candidate_path: str, operation_name: str) -> None:
        """Impede unlink, rename, chmod, truncate ou mkdir sobre --source.

        Args:
            candidate_path: Caminho alvo.
            operation_name: Nome descritivo da syscall bloqueada.

        Raises:
            ReadOnlyViolationError: Sempre que o alvo pertencer a --source.
        """
        if self.is_protected_path(candidate_path):
            raise ReadOnlyViolationError(
                f"Operacao mutavel {operation_name} bloqueada em --source: {candidate_path}"
            )


@dataclass(frozen=True, slots=True)
class SecrecyNetworkPolicy:
    """Politica de soberania de dados e bloqueio de rede externa (CNJ 615/2025 e 674/2026)."""

    secrecy_level: SecrecyLevel

    def assert_endpoint_allowed(self, host: str) -> None:
        """Permite apenas loopback 127.0.0.1/localhost quando em segredo de justica.

        Args:
            host: Endereco IP ou hostname de destino.

        Raises:
            SecrecySocketViolationError: Se host nao for loopback sob sigilo judicial.
        """
        if self.secrecy_level == SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY:
            cleaned = host.strip().lower()
            if cleaned not in _LOOPBACK_HOSTS:
                raise SecrecySocketViolationError(
                    f"Conexao externa bloqueada sob sigilo judicial: {host!r}"
                )


class SelfCalibrationSuite:
    """Bateria de auto-calibracao previa ISO/IEC 27041 (Pilar 1 — Confiabilidade)."""

    @staticmethod
    def run_calibration(calibrated_at_utc: str) -> CalibrationReceipt:
        """Executa 1 controle positivo e 2 controles negativos contra o verificador.

        Args:
            calibrated_at_utc: Instante UTC ISO-8601 da execucao.

        Returns:
            CalibrationReceipt assinado por SHA-256.

        Raises:
            VerifierCalibrationError: Se o controle positivo falhar ou se qualquer
                adulteracao negativa deixar de ser bloqueada.
        """
        ref_hash = sha256_text("AUTO DE APREENSAO LACRE 0098412 VALOR R$ 1.540,90")
        corpus = {
            "CN-00000001": VerifiableSourceCorpusEntry(
                control_number="CN-00000001",
                sha256_hex=ref_hash,
                full_text="AUTO DE APREENSAO LACRE 0098412 VALOR R$ 1.540,90",
                numeric_facts=(154090, 98412),
            )
        }

        positive_claim = CandidateClaim(
            claim_id="CAL-POS-01",
            referenced_cn="CN-00000001",
            referenced_sha256=ref_hash,
            locator="p. 1",
            verbatim_quote="LACRE 0098412 VALOR R$ 1.540,90",
            numeric_value=154090,
        )
        pos_verdict = verify_claims_deterministically((positive_claim,), corpus)
        if not pos_verdict.passed:
            raise VerifierCalibrationError(
                f"Falha no controle positivo ISO 27041: {pos_verdict.rejected_reasons}"
            )

        tampered_hash = sha256_text("HASH_ADULTERADO_NEGATIVO")
        negative_numeric_claim = CandidateClaim(
            claim_id="CAL-NEG-NUM-01",
            referenced_cn="CN-00000001",
            referenced_sha256=tampered_hash,
            locator="p. 1",
            verbatim_quote="LACRE 0098412 VALOR R$ 1.540,90",
            numeric_value=999999,
        )
        neg_num_verdict = verify_claims_deterministically((negative_numeric_claim,), corpus)
        if neg_num_verdict.passed:
            raise VerifierCalibrationError(
                "Controle negativo 1 falhou: adulteracao numerica/hash nao foi bloqueada!"
            )

        negative_entity_claim = CandidateClaim(
            claim_id="CAL-NEG-ENT-02",
            referenced_cn="CN-00000001",
            referenced_sha256=ref_hash,
            locator="p. 1",
            verbatim_quote="CUSTODIANTE FANTASMA INEXISTENTE NOS AUTOS",
            numeric_value=154090,
        )
        neg_ent_verdict = verify_claims_deterministically((negative_entity_claim,), corpus)
        if neg_ent_verdict.passed:
            raise VerifierCalibrationError(
                "Controle negativo 2 falhou: entidade textual fantasma nao foi bloqueada!"
            )

        receipt_sig = sha256_text(
            f"{calibrated_at_utc}|POS=1|NEG_NUM=1|NEG_ENT=1|{ref_hash}"
        )
        return CalibrationReceipt(
            calibrated_at_utc=calibrated_at_utc,
            positive_control_passed=True,
            negative_numeric_mutation_blocked=True,
            negative_phantom_entity_blocked=True,
            calibration_sha256=receipt_sig,
        )
