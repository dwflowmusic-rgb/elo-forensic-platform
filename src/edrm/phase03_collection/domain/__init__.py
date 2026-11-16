"""Dominio puro da Fase 03 — Plano de Aquisicao, Genealogia ControlNumber e Coleta Estatal."""

from __future__ import annotations

from dataclasses import dataclass

from edrm.shared_kernel.contracts import (
    DeclaredEvidenceItem,
    ProbedFileRecord,
    SpofRiskEntry,
    StateCollectionFinding,
)
from edrm.shared_kernel.enums import AcquisitionMode, StateCollectionMethod
from edrm.shared_kernel.value_objects import ControlNumber


@dataclass(frozen=True, slots=True)
class PlannedAcquisitionItem:
    """Item planejado para aquisicao rumo ao cofre workspace/vault/."""

    control_number: ControlNumber
    source_id: str
    origin_rel_path: str
    origin_abs_path: str
    vault_rel_path: str
    expected_sha256: str
    expected_bytes: int
    mtime_utc_ns: int
    mode: AcquisitionMode


class AcquisitionPlanner:
    """Etapa 3.1 — Constroi o plano deterministico de aquisicao para o cofre do caso."""

    @staticmethod
    def build_plan(
        probed_files: tuple[ProbedFileRecord, ...],
        spof_map: tuple[SpofRiskEntry, ...],
    ) -> tuple[PlannedAcquisitionItem, ...]:
        """Atribui ControlNumbers raiz (CN-00000001) e define o modo de aquisicao."""
        mode_by_path = {s.rel_path: s.recommended_mode for s in spof_map}
        planned: list[PlannedAcquisitionItem] = []
        for seq, pf in enumerate(probed_files, start=1):
            cn = ControlNumber.root(seq)
            mode = mode_by_path.get(pf.rel_path, AcquisitionMode.FULL_VAULT_COPY)
            safe_vault_rel = f"{cn.code}_{pf.rel_path.replace('/', '__')}"
            planned.append(
                PlannedAcquisitionItem(
                    control_number=cn,
                    source_id=pf.source_id,
                    origin_rel_path=pf.rel_path,
                    origin_abs_path=pf.abs_path,
                    vault_rel_path=safe_vault_rel,
                    expected_sha256=pf.sha256_hex,
                    expected_bytes=pf.size_bytes,
                    mtime_utc_ns=pf.mtime_utc_ns,
                    mode=mode,
                )
            )
        return tuple(planned)


class StateCollectionMethodAuditor:
    """Etapa 3.4 — Audita o metodo estatal de extracao (CPP arts. 158-C/D e POP Senasp 5.02)."""

    @staticmethod
    def audit_all(
        declared_items: tuple[DeclaredEvidenceItem, ...],
    ) -> tuple[StateCollectionFinding, ...]:
        """Avalia perito oficial, metodo de extracao, exame no original e transito mensageiro."""
        findings: list[StateCollectionFinding] = []
        for decl in declared_items:
            expert_ok = decl.extracted_by_official_expert.upper() in ("SIM", "TRUE", "PERITO_OFICIAL")
            raw_m = decl.collection_method_declared.upper()
            if "FISICA" in raw_m or "BITSTREAM" in raw_m:
                method = StateCollectionMethod.PHYSICAL_BITSTREAM
            elif "FULL" in raw_m or "FFS" in raw_m:
                method = StateCollectionMethod.FULL_FILE_SYSTEM
            elif "LOGICA" in raw_m:
                method = StateCollectionMethod.LOGICAL_PARTIAL
            elif "TELA" in raw_m or "FOTO" in raw_m or "VIDEO" in raw_m:
                method = StateCollectionMethod.MANUAL_SCREEN_RECORDING_HIGH_RISK
            else:
                method = StateCollectionMethod.UNDOCUMENTED_METHOD

            on_original = decl.working_copy_examined.upper() in ("NAO", "NÃO", "ORIGINAL", "DIRETO_NO_APARELHO")
            high_risk = (
                (not expert_ok)
                or method in (
                    StateCollectionMethod.MANUAL_SCREEN_RECORDING_HIGH_RISK,
                    StateCollectionMethod.UNDOCUMENTED_METHOD,
                )
                or on_original
                or decl.transited_via_messenger
            )

            tags: list[str] = []
            notes: list[str] = []
            if not expert_ok:
                tags.append("CPP_ART_158_C_AGENTE_NAO_PERITO")
                notes.append("Coleta sem comprovacao de perito oficial.")
            if method == StateCollectionMethod.MANUAL_SCREEN_RECORDING_HIGH_RISK:
                tags.append("POP_SENASP_5_02_ALTO_RISCO_TELA")
                notes.append("Gravacao manual de tela tratada como alto risco de manipulacao.")
            elif method == StateCollectionMethod.UNDOCUMENTED_METHOD:
                tags.append("POP_SENASP_5_02_METODO_OMISSO")
                notes.append("Metodo tecnico de extracao nao documentado.")
            if on_original:
                tags.append("ISO_27037_EXAME_DIRETO_NO_ORIGINAL")
                notes.append("Exame executado diretamente sobre o aparelho original.")
            if decl.transited_via_messenger:
                tags.append("DESTRUICAO_METADADOS_MENSAGEIRO")
                notes.append("Evidencia transitou por aplicativo mensageiro perdendo metadados.")
            if not notes:
                notes.append("Coleta estatal documentada em conformidade tecnica.")

            findings.append(
                StateCollectionFinding(
                    declared_id=decl.declared_id,
                    official_expert_verified=expert_ok,
                    method_used=str(method),
                    examined_on_original_device=on_original,
                    messenger_transit_detected=decl.transited_via_messenger,
                    high_risk_flag=high_risk,
                    legal_tags=tuple(tags),
                    notes=" ".join(notes),
                    anchor=decl.anchor,
                )
            )
        return tuple(findings)
