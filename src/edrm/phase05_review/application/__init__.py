"""Camada de aplicacao pura da Fase 05 — Revisao e Congelamento do Conjunto Relevante."""

from __future__ import annotations

from typing import Protocol

from edrm.phase05_review.domain import (
    EvidentiaryDefectClassifier,
    MaterialContradictionDetector,
    PrivilegeShieldFilter,
    compute_review_qc_summary,
)
from edrm.shared_kernel.contracts import (
    ClassifiedNullityRecord,
    MaterialContradictionRecord,
    Phase04ToPhase05Contract,
    Phase05ToPhase06Contract,
    QualityControlSummary,
)
from edrm.shared_kernel.value_objects import canonical_json_sha256


class Phase05ReviewPersistencePort(Protocol):
    """Porta segregada para persistencia das nulidades e compilacao do Relatorio Fase 05."""

    def persist_and_export_review(
        self,
        phase04_bundle: Phase04ToPhase05Contract,
        privileged_cns: tuple[str, ...],
        selected_cns: tuple[str, ...],
        contradictions: tuple[MaterialContradictionRecord, ...],
        nullities: tuple[ClassifiedNullityRecord, ...],
        qc_summary: QualityControlSummary,
        frozen_sha256: str,
    ) -> tuple[str, str]:
        """Atualiza defect_category no catalogo e grava phase05_review_report.md verificado."""


class Phase05ClockPort(Protocol):
    """Porta de relogio UTC da Fase 05."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase05ReviewUseCase:
    """Orquestra as Etapas 5.1 a 5.4 da Fase 05 (Nexo Central de Relevancia Juridica)."""

    def __init__(
        self,
        persistence: Phase05ReviewPersistencePort,
        clock: Phase05ClockPort,
    ) -> None:
        self._persistence = persistence
        self._clock = clock

    def execute(self, phase04_bundle: Phase04ToPhase05Contract) -> Phase05ToPhase06Contract:
        """Filtra prerrogativas, confronta Laudo x Bruto, classifica nulidades e congela."""
        now_utc = self._clock.now_iso_utc()
        p01 = phase04_bundle.updated_phase01_bundle
        p02 = phase04_bundle.phase03_bundle.phase02_bundle
        p03 = phase04_bundle.phase03_bundle

        priv_cns, selected_cns = PrivilegeShieldFilter.partition_privileged_chunks(
            phase04_bundle.anchored_chunks
        )
        contradictions = MaterialContradictionDetector.detect(
            primary_docs=p01.discovery_blueprint.primary_doc_candidates,
            timeline_events=phase04_bundle.timeline_events,
            financial_entries=phase04_bundle.financial_entries,
            telecom_records=phase04_bundle.telecom_records,
            captured_at_utc=now_utc,
        )
        nullities = EvidentiaryDefectClassifier.classify_all(
            parity_rows=p01.parity_matrix,
            six_axes=p02.six_axes_findings,
            collection_findings=p03.state_collection_findings,
            timeline_events=phase04_bundle.timeline_events,
            cgnat_records=phase04_bundle.cgnat_records,
            captured_at_utc=now_utc,
            state_iped_audit=p01.state_iped_audit,
            recovered_sqlite_records=phase04_bundle.recovered_sqlite_records,
            link_provenance_records=phase04_bundle.link_provenance_records,
        )
        qc_summary = compute_review_qc_summary(
            selected_count=len(selected_cns),
            excluded_count=len(priv_cns) + phase04_bundle.denisted_parent_count,
        )

        _, frozen_sha = canonical_json_sha256(
            {
                "selected_cns": list(selected_cns),
                "privileged_cns": list(priv_cns),
                "nullity_ids": [n.nullity_id for n in nullities],
                "contradiction_ids": [c.contradiction_id for c in contradictions],
            }
        )

        rep_path, rep_sha = self._persistence.persist_and_export_review(
            phase04_bundle=phase04_bundle,
            privileged_cns=priv_cns,
            selected_cns=selected_cns,
            contradictions=contradictions,
            nullities=nullities,
            qc_summary=qc_summary,
            frozen_sha256=frozen_sha,
        )

        return Phase05ToPhase06Contract(
            phase04_bundle=phase04_bundle,
            privileged_excluded_cns=priv_cns,
            selected_review_cns=selected_cns,
            material_contradictions=contradictions,
            classified_nullities=nullities,
            qc_summary=qc_summary,
            frozen_review_sha256=frozen_sha,
            phase05_report_path=rep_path,
            phase05_report_sha256=rep_sha,
        )
