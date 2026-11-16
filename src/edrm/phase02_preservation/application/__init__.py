"""Camada de aplicacao pura da Fase 02 — Preservacao Defensiva e Estatal."""

from __future__ import annotations

from typing import Protocol

from edrm.phase02_preservation.domain import (
    LegalHoldRecord,
    SpofRedundancyEvaluator,
    StateOriginPreservation6AxesEvaluator,
)
from edrm.shared_kernel.contracts import (
    MediaSnapshot,
    Phase01ToPhase02Contract,
    Phase02ToPhase03Contract,
    PreservationAxisFinding,
    ProbedFileRecord,
    SpofRiskEntry,
    StructuralHealthFinding,
)
from edrm.shared_kernel.exceptions import SourceMutationDetectedError
from edrm.shared_kernel.value_objects import sha256_text


class StructuralHealthRunnerPort(Protocol):
    """Porta segregada para checagem imutavel SQLite quick_check, -wal e CRC de pacotes."""

    def audit_structural_health(
        self,
        probed_files: tuple[ProbedFileRecord, ...],
    ) -> tuple[StructuralHealthFinding, ...]:
        """Audita bancos SQLite (immutable=1 + -wal frames) e arquivos compactados."""

    def list_existing_vault_files(self, vault_dir: str) -> set[str]:
        """Lista caminhos relativos ja existentes no cofre defensivo."""

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Recaptura snapshot passivo para provar zero mutacao em --source."""


class Phase02PersistenceAndReportPort(Protocol):
    """Porta segregada para persistencia e compilacao verificada do relatorio Fase 02."""

    def persist_and_compile(
        self,
        phase01_bundle: Phase01ToPhase02Contract,
        structural_findings: tuple[StructuralHealthFinding, ...],
        spof_map: tuple[SpofRiskEntry, ...],
        six_axes_findings: tuple[PreservationAxisFinding, ...],
        legal_hold: LegalHoldRecord,
    ) -> tuple[str, str]:
        """Persiste achados dos 6 Eixos, valida relatorio no Verificador e retorna (path, sha256)."""


class Phase02ClockPort(Protocol):
    """Porta minima de relogio UTC para Fase 02."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase02PreservationUseCase:
    """Orquestra as Subetapas 2.1 a 2.4 da Fase 02 sem mutar nenhum bit da fonte."""

    def __init__(
        self,
        health_runner: StructuralHealthRunnerPort,
        repo_and_compiler: Phase02PersistenceAndReportPort,
        clock: Phase02ClockPort,
    ) -> None:
        self._health_runner = health_runner
        self._repo_and_compiler = repo_and_compiler
        self._clock = clock

    def execute(self, phase01_bundle: Phase01ToPhase02Contract) -> Phase02ToPhase03Contract:
        """Audita saude estrutural, SPOF, 6 Eixos Estatais, emite Legal Hold e lacra."""
        probed = phase01_bundle.discovery_blueprint.probed_files
        structural = self._health_runner.audit_structural_health(probed)
        existing_vault = self._health_runner.list_existing_vault_files(
            phase01_bundle.governance.vault_dir
        )
        spof_map = SpofRedundancyEvaluator.evaluate(probed, existing_vault)

        struct_by_path = {s.rel_path: s for s in structural}
        probed_by_path = {p.rel_path: p for p in probed}
        six_axes = StateOriginPreservation6AxesEvaluator.evaluate_all(
            declared_items=phase01_bundle.declared_items,
            divergences=phase01_bundle.divergences,
            structural_by_path=struct_by_path,
            probed_by_path=probed_by_path,
        )

        now_utc = self._clock.now_iso_utc()
        hold_id = "LH-" + sha256_text(f"{phase01_bundle.governance.case_id}|{now_utc}")[:12].upper()
        legal_hold = LegalHoldRecord(
            hold_id=hold_id,
            case_id=phase01_bundle.governance.case_id,
            issued_at_utc=now_utc,
            total_protected_files=len(probed),
            spof_critical_count=sum(1 for e in spof_map if e.is_spof_critical),
        )

        rep_path, rep_sha = self._repo_and_compiler.persist_and_compile(
            phase01_bundle=phase01_bundle,
            structural_findings=structural,
            spof_map=spof_map,
            six_axes_findings=six_axes,
            legal_hold=legal_hold,
        )

        post_snap = self._health_runner.capture_snapshot(
            phase01_bundle.governance.protected_source_roots,
            self._clock.now_iso_utc(),
        )
        if post_snap.snapshot_sha256 != phase01_bundle.pre_scan_snapshot.snapshot_sha256:
            raise SourceMutationDetectedError(
                "Mutacao detectada em --source ao final da Fase 02!"
            )

        approved_paths = tuple(p.rel_path for p in probed)
        return Phase02ToPhase03Contract(
            phase01_bundle=phase01_bundle,
            structural_findings=structural,
            spof_map=spof_map,
            six_axes_findings=six_axes,
            legal_hold_id=hold_id,
            approved_for_acquisition=approved_paths,
            phase02_report_path=rep_path,
            phase02_report_sha256=rep_sha,
        )
