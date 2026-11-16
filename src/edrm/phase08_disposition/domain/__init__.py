"""Dominio puro da Fase 08 — Politica de Expurgo Staging e Certificado NIST SP 800-88 Rev. 2."""

from __future__ import annotations

from dataclasses import dataclass

from edrm.shared_kernel.enums import SanitizationMethod
from edrm.shared_kernel.exceptions import HumanAuthorizationRequiredError
from edrm.shared_kernel.value_objects import sha256_text


@dataclass(frozen=True, slots=True)
class Nist80088Certificate:
    """Certificado formal de sanitizacao pos-transito em julgado (NIST SP 800-88 Rev. 2)."""

    certificate_id: str
    case_id: str
    standard: str
    sanitization_method: SanitizationMethod
    authorized_by_human: str
    confirmation_phrase_hash: str
    sanitized_target_scope: str
    issued_at_utc: str
    igrm_reconnected: bool


class PostJudgmentDispositionPolicy:
    """Etapa 8.3 — Exige dupla confirmacao humana explicita antes de sanitizar copias."""

    EXPECTED_PHRASE_PREFIX: str = "CONFIRMO_TRANSITO_EM_JULGADO:"

    @classmethod
    def build_certificate(
        cls,
        case_id: str,
        method: SanitizationMethod,
        require_explicit_human_authorization: bool,
        human_operator_name: str,
        second_confirmation_phrase: str,
        target_scope: str,
        issued_at_utc: str,
    ) -> Nist80088Certificate:
        """Valida dupla confirmacao explicita e emite o Certificado NIST SP 800-88 Rev. 2.

        Raises:
            HumanAuthorizationRequiredError: Se faltar autorizacao booleana ou frase de confirmacao.
        """
        expected_token = f"{cls.EXPECTED_PHRASE_PREFIX}{case_id}"
        if (
            not require_explicit_human_authorization
            or not human_operator_name.strip()
            or second_confirmation_phrase.strip() != expected_token
        ):
            raise HumanAuthorizationRequiredError(
                "Sanitizacao NIST SP 800-88 Rev. 2 bloqueada: exige dupla confirmacao humana explicita."
            )

        phrase_hash = sha256_text(second_confirmation_phrase.strip())
        cert_id = "NIST80088-" + sha256_text(f"{case_id}|{issued_at_utc}|{phrase_hash}")[:12].upper()
        return Nist80088Certificate(
            certificate_id=cert_id,
            case_id=case_id,
            standard="NIST_SP_800-88_Rev2_2025_&_IEEE_2883-2022",
            sanitization_method=method,
            authorized_by_human=human_operator_name.strip(),
            confirmation_phrase_hash=phrase_hash,
            sanitized_target_scope=target_scope,
            issued_at_utc=issued_at_utc,
            igrm_reconnected=True,
        )
