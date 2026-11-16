"""Dominio puro da Fase 02 — SPOF, Homografos de Lacre e os 6 Eixos da Preservacao Estatal."""

from __future__ import annotations

from dataclasses import dataclass

from edrm.shared_kernel.contracts import (
    DeclaredEvidenceItem,
    DivergenceRecord,
    PreservationAxisFinding,
    ProbedFileRecord,
    SpofRiskEntry,
    StructuralHealthFinding,
)
from edrm.shared_kernel.enums import AcquisitionMode, MagicSignature, PreservationAxis
from edrm.shared_kernel.value_objects import sha256_text

REFERENCED_LARGE_THRESHOLD_BYTES: int = 10 * 1024 * 1024 * 1024

_CONFUSABLE_MAP: dict[str, str] = {
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "O": "0",
    "I": "1",
    "L": "1",
}


@dataclass(frozen=True, slots=True)
class LegalHoldRecord:
    """Termo Tecnico de Preservacao Defensiva (Legal Hold) emitido na Subetapa 2.4."""

    hold_id: str
    case_id: str
    issued_at_utc: str
    total_protected_files: int
    spof_critical_count: int


def detect_seal_homograph_or_mismatch(
    seals_in: tuple[str, ...],
    seals_out: tuple[str, ...],
    divergences: tuple[DivergenceRecord, ...],
) -> bool:
    """Detecta caracteres homografos Unicode (nao ASCII), ambiguidade O/0 ou quebra de lacre."""
    all_seals = seals_in + seals_out
    for s in all_seals:
        if any(ord(ch) > 127 for ch in s):
            return True
        has_digit = any(ch.isdigit() for ch in s)
        has_ambiguous_letter = any(ch in ("O", "o", "I", "l") for ch in s)
        if has_digit and has_ambiguous_letter:
            skeleton = "".join(_CONFUSABLE_MAP.get(ch.upper(), ch.upper()) for ch in s)
            if skeleton != s.upper():
                return True
    if divergences:
        return True
    return False


class SpofRedundancyEvaluator:
    """Subetapa 2.2 — Avalia risco de copia unica (SPOF) e modo recomendado de aquisicao."""

    @staticmethod
    def evaluate(
        probed_files: tuple[ProbedFileRecord, ...],
        existing_vault_rel_paths: set[str],
    ) -> tuple[SpofRiskEntry, ...]:
        """Gera o mapa SPOF para cada arquivo sondado no HD."""
        entries: list[SpofRiskEntry] = []
        for pf in probed_files:
            in_vault = pf.rel_path in existing_vault_rel_paths
            is_spof = not in_vault
            if pf.size_bytes >= REFERENCED_LARGE_THRESHOLD_BYTES:
                rec_mode = AcquisitionMode.IMMUTABLE_REFERENCED_INDEX
            else:
                rec_mode = AcquisitionMode.FULL_VAULT_COPY
            entries.append(
                SpofRiskEntry(
                    rel_path=pf.rel_path,
                    sha256_hex=pf.sha256_hex,
                    in_vault=in_vault,
                    is_os_readonly=pf.is_os_readonly,
                    is_spof_critical=is_spof,
                    recommended_mode=rec_mode,
                )
            )
        return tuple(entries)


class StateOriginPreservation6AxesEvaluator:
    """Subetapa 2.3 — Avalia atomicamente os 6 Eixos Obrigatorios por vestigio declarado."""

    @staticmethod
    def evaluate_all(
        declared_items: tuple[DeclaredEvidenceItem, ...],
        divergences: tuple[DivergenceRecord, ...],
        structural_by_path: dict[str, StructuralHealthFinding],
        probed_by_path: dict[str, ProbedFileRecord],
    ) -> tuple[PreservationAxisFinding, ...]:
        """Gera 6 avaliacoes atomicas ancoradas por vestigio (zero fusao heuristica)."""
        findings: list[PreservationAxisFinding] = []

        for decl in declared_items:
            matched_struct: StructuralHealthFinding | None = None
            matched_probe: ProbedFileRecord | None = None
            exp_tok = decl.expected_raw_format.lower()
            for p_rel, pf in probed_by_path.items():
                if (decl.state_sha256 != "explicit_gap" and pf.sha256_hex == decl.state_sha256) or (
                    exp_tok != "explicit_gap" and exp_tok in p_rel.lower()
                ):
                    matched_probe = pf
                    matched_struct = structural_by_path.get(p_rel)
                    break

            rf_ok = decl.rf_isolation.upper() not in ("EXPLICIT_GAP", "NAO", "NENHUM", "SEM ISOLAMENTO")
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX1-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.ISOLAMENTO_RADIOELETRICO_E_VOLATILIDADE,
                    compliant=rf_ok,
                    homograph_or_seal_mismatch=False,
                    legal_tags=() if rf_ok else ("CPP_ART_158_B_II", "POP_SENASP_2024_5_05", "RFC_3227"),
                    summary=(
                        f"Isolamento RF documentado ({decl.rf_isolation})."
                        if rf_ok
                        else "Ausencia de comprovacao de bolsa Faraday/aluminio ou ordem de volatilidade RFC 3227."
                    ),
                    anchor=decl.anchor,
                )
            )

            lock_ok = decl.lock_state.upper() in ("BFU", "AFU", "DESLIGADO", "BLOQUEADO_BFU", "BLOQUEADO_AFU")
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX2-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.ESTADO_ENERGETICO_BLOQUEIO_E_RELOGIO,
                    compliant=lock_ok and (decl.seizure_utc != "EXPLICIT_GAP"),
                    homograph_or_seal_mismatch=False,
                    legal_tags=() if lock_ok else ("POP_SENASP_2024_5_02", "RFC_3227_CLOCK_DRIFT"),
                    summary=(
                        f"Estado BFU/AFU ({decl.lock_state}) e apreensao ({decl.seizure_utc}) registrados."
                        if lock_ok and decl.seizure_utc != "EXPLICIT_GAP"
                        else f"Omissao de estado BFU/AFU ({decl.lock_state}) ou clock drift UTC ({decl.seizure_utc})."
                    ),
                    anchor=decl.anchor,
                )
            )

            rel_divs = tuple(
                d
                for d in divergences
                if d.left_anchor.origin_path == decl.anchor.origin_path
                or d.right_anchor.origin_path == decl.anchor.origin_path
            )
            homograph_flag = detect_seal_homograph_or_mismatch(decl.seals_in, decl.seals_out, rel_divs)
            seals_ok = len(decl.seals_in) > 0 and (not homograph_flag)
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX3-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.CADEIA_DE_LACRES_E_FAV,
                    compliant=seals_ok,
                    homograph_or_seal_mismatch=homograph_flag,
                    legal_tags=() if seals_ok else ("CPP_ART_158_B_V", "CPP_ART_158_D_LACRE"),
                    summary=(
                        f"Cadeia de lacres integra ({','.join(decl.seals_in)})."
                        if seals_ok
                        else "Quebra, omissao ou divergencia/homografo na numeracao de lacres/FAV."
                    ),
                    anchor=decl.anchor,
                )
            )

            hash_ok = len(decl.state_sha256) == 64 and decl.master_hashlist_sha256 != "explicit_gap"
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX4-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.CERTIFICACAO_DE_HASH_NA_ORIGEM,
                    compliant=hash_ok,
                    homograph_or_seal_mismatch=False,
                    legal_tags=() if hash_ok else ("POP_SENASP_2024_5_01", "STJ_EDICAO_281"),
                    summary=(
                        "SHA-256 individual e hash da lista mestre lavrados na origem."
                        if hash_ok
                        else "Omissao de SHA-256 na coleta ou falta do hash da lista mestre (POP 5.01/5.02)."
                    ),
                    anchor=decl.anchor,
                )
            )

            struct_ok = True
            struct_detail = "Estrutura logica integra."
            if matched_struct is not None:
                if (
                    not matched_struct.is_healthy
                    or matched_struct.has_unconsolidated_wal_frames
                    or matched_struct.pdf_incremental_revisions > 1
                ):
                    struct_ok = False
                    struct_detail = matched_struct.detail
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX5-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.INTEGRIDADE_FISICA_E_LOGICA_DO_VESTIGIO,
                    compliant=struct_ok,
                    homograph_or_seal_mismatch=False,
                    legal_tags=() if struct_ok else ("ISO_27037_INTEGRIDADE", "SWGDE_SQLITE_WAL"),
                    summary=struct_detail,
                    anchor=decl.anchor,
                )
            )

            access_ok = True
            is_headerless_vol = (
                matched_probe is not None
                and matched_probe.magic_signature == MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED
            )
            if matched_probe is None or matched_probe.is_encrypted_or_corrupted or is_headerless_vol:
                access_ok = False
            ax6_tags = (
                ()
                if access_ok
                else (
                    ("STJ_RHC_184003_SP", "CPP_ART_159_P6", "VERACRYPT_BITLOCKER_RAW_SEM_CHAVE")
                    if is_headerless_vol
                    else ("STJ_RHC_184003_SP", "CPP_ART_159_P6")
                )
            )
            ax6_summary = (
                "Vestigio acessivel para exame contraditorio da defesa."
                if access_ok
                else (
                    "Volume cifrado sem cabecalho (VeraCrypt/BitLocker raw >= 995 permille) sem chave nos autos."
                    if is_headerless_vol
                    else "Vestigio inacessivel, omitido ou cifrado sem disponibilizacao de chave."
                )
            )
            findings.append(
                PreservationAxisFinding(
                    finding_id="AX6-" + sha256_text(decl.declared_id)[:10].upper(),
                    declared_id=decl.declared_id,
                    axis=PreservationAxis.ACESSIBILIDADE_E_CIFRAGEM,
                    compliant=access_ok,
                    homograph_or_seal_mismatch=False,
                    legal_tags=ax6_tags,
                    summary=ax6_summary,
                    anchor=decl.anchor,
                )
            )

        return tuple(findings)
