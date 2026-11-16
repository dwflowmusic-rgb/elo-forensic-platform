"""Camada de aplicacao pura da Fase 04 — Subetapas Oficiais EDRM 1.0 a 5.0."""

from __future__ import annotations

from typing import Protocol

from edrm.phase04_processing.domain import (
    DeNistAndLogicalDedupPolicy,
    ExtractionBatchOutput,
    InventoryWorkingItem,
)
from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    CgnatAuditRecord,
    DeadLetterExceptionRecord,
    DynamicSchemaBlueprint,
    FinancialLedgerEntryRecord,
    IterativeDiscoveryFeedbackPayload,
    IterativeDiscoveryFeedbackPort,
    MediaSnapshot,
    Phase03ToPhase04Contract,
    Phase04ToPhase05Contract,
    PrimaryDocumentCandidate,
    TelecomCdrRecord,
    TimelineEventRecord,
)
from edrm.shared_kernel.exceptions import SourceMutationDetectedError
from edrm.shared_kernel.time_normalizer import parse_timestamp_to_utc


class SafeUnpackAndIpedPort(Protocol):
    """Porta segregada para Subetapa 4.1 (Descompactacao recursiva + Ponte IPED CLI)."""

    def ingest_and_unpack_to_staging(
        self,
        phase03_bundle: Phase03ToPhase04Contract,
    ) -> tuple[tuple[InventoryWorkingItem, ...], tuple[DeadLetterExceptionRecord, ...]]:
        """Expande pacotes em staging/ com checkpoint idempotente e ponte opcional IPED CLI."""


class UniversalExtractorRunnerPort(Protocol):
    """Porta segregada para Subetapa 4.3 (Extratores das 11 categorias + SQLite Dinamico)."""

    def run_extractors_on_inventory(
        self,
        items: tuple[InventoryWorkingItem, ...],
        dynamic_schemas: tuple[DynamicSchemaBlueprint, ...],
        seizure_epoch_seconds: int | None,
        captured_at_utc: str,
        catalog_db_path: str = "",
    ) -> tuple[ExtractionBatchOutput, int]:
        """Executa extratores registrados nas 5 filas P0->P4 e retorna (output, pdf_multi_eof)."""


class Phase04CatalogAndFiveReportsPort(Protocol):
    """Porta segregada para Subetapas 4.4 e 4.5 (Persistencia + 5 Relatorios EDRM 5.0)."""

    def persist_and_generate_five_reports(
        self,
        phase03_bundle: Phase03ToPhase04Contract,
        filtered_items: tuple[InventoryWorkingItem, ...],
        dead_letters: tuple[DeadLetterExceptionRecord, ...],
        extracted: ExtractionBatchOutput,
    ) -> tuple[tuple[str, str, str], ...]:
        """Grava no catalogo unificado e compila os 5 Relatorios Oficiais EDRM 5.0."""

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Recaptura snapshot passivo de --source."""


class Phase04ClockPort(Protocol):
    """Porta de relogio UTC da Fase 04."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase04ProcessingUseCase:
    """Orquestra as 5 Subetapas Oficiais EDRM 1.0 a 5.0 e realimentacao 04 -> 01."""

    def __init__(
        self,
        unpacker: SafeUnpackAndIpedPort,
        extractor_runner: UniversalExtractorRunnerPort,
        persistence_and_reports: Phase04CatalogAndFiveReportsPort,
        feedback_port: IterativeDiscoveryFeedbackPort,
        clock: Phase04ClockPort,
    ) -> None:
        self._unpacker = unpacker
        self._extractor_runner = extractor_runner
        self._persistence = persistence_and_reports
        self._feedback_port = feedback_port
        self._clock = clock

    def execute(self, phase03_bundle: Phase03ToPhase04Contract) -> Phase04ToPhase05Contract:
        """Executa EDRM 1.0 -> 5.0, dispara feedback iterativo e valida fonte intacta."""
        p01 = phase03_bundle.phase02_bundle.phase01_bundle

        seizure_epoch: int | None = None
        for decl in p01.declared_items:
            if decl.seizure_utc != "EXPLICIT_GAP":
                ts = parse_timestamp_to_utc(decl.seizure_utc)
                if seizure_epoch is None or ts.epoch_seconds < seizure_epoch:
                    seizure_epoch = ts.epoch_seconds

        raw_inventory, dead_letters = self._unpacker.ingest_and_unpack_to_staging(phase03_bundle)
        filtered_inventory = DeNistAndLogicalDedupPolicy.apply(raw_inventory)

        now_utc = self._clock.now_iso_utc()
        extracted, pdf_multi_eof = self._extractor_runner.run_extractors_on_inventory(
            items=filtered_inventory,
            dynamic_schemas=p01.discovery_blueprint.dynamic_schemas,
            seizure_epoch_seconds=seizure_epoch,
            captured_at_utc=now_utc,
            catalog_db_path=p01.governance.catalog_db_path,
        )

        updated_p01 = p01
        if extracted.new_primary_docs:
            feedback_payload = IterativeDiscoveryFeedbackPayload(
                case_id=p01.governance.case_id,
                discovered_in_phase="PHASE_04_PROCESSING",
                new_primary_docs=extracted.new_primary_docs,
                new_custodians=(),
                new_declared_items=(),
            )
            updated_p01 = self._feedback_port.receive_feedback(p01, feedback_payload)

        five_reports = self._persistence.persist_and_generate_five_reports(
            phase03_bundle=phase03_bundle,
            filtered_items=filtered_inventory,
            dead_letters=dead_letters,
            extracted=extracted,
        )

        post_snap = self._persistence.capture_snapshot(
            p01.governance.protected_source_roots,
            self._clock.now_iso_utc(),
        )
        if post_snap.snapshot_sha256 != p01.pre_scan_snapshot.snapshot_sha256:
            raise SourceMutationDetectedError(
                "Mutacao detectada em --source ao final da Fase 04!"
            )

        denist_cnt = sum(1 for i in filtered_inventory if i.is_denist_logical)
        dup_cnt = sum(1 for i in filtered_inventory if i.duplicate_of_cn is not None)
        post_seizure_cnt = sum(1 for ev in extracted.timeline_events if ev.is_post_seizure)
        fin_dup_cnt = sum(1 for f in extracted.financial_entries if f.is_inter_file_duplicate)
        erb_jump_cnt = sum(1 for c in extracted.telecom_records if c.impossible_speed_flag)
        cgnat_defect_cnt = sum(1 for g in extracted.cgnat_records if g.missing_logical_port_defect)

        return Phase04ToPhase05Contract(
            phase03_bundle=phase03_bundle,
            updated_phase01_bundle=updated_p01,
            total_inventory_items=len(filtered_inventory),
            denisted_parent_count=denist_cnt,
            logical_duplicates_count=dup_cnt,
            post_seizure_events_count=post_seizure_cnt,
            pdf_multi_eof_count=pdf_multi_eof,
            financial_duplicates_count=fin_dup_cnt,
            impossible_erb_jumps_count=erb_jump_cnt,
            cgnat_missing_port_count=cgnat_defect_cnt,
            dead_letter_items=dead_letters,
            timeline_events=extracted.timeline_events,
            financial_entries=extracted.financial_entries,
            telecom_records=extracted.telecom_records,
            cgnat_records=extracted.cgnat_records,
            anchored_chunks=extracted.anchored_chunks,
            official_five_reports=five_reports,
            recovered_deleted_sqlite_rows_count=len(extracted.recovered_sqlite_records),
            physical_link_tracker_findings_count=len(extracted.link_provenance_records),
            recovered_sqlite_records=extracted.recovered_sqlite_records,
            link_provenance_records=extracted.link_provenance_records,
            tier_execution_order=extracted.tier_execution_order,
        )
