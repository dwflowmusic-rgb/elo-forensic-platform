"""Camada de aplicacao pura da Fase 03 — Coleta Verificada e Manifesto ICP-Brasil."""

from __future__ import annotations

from typing import Protocol

from edrm.phase03_collection.domain import (
    AcquisitionPlanner,
    PlannedAcquisitionItem,
    StateCollectionMethodAuditor,
)
from edrm.shared_kernel.contracts import (
    MediaSnapshot,
    Phase02ToPhase03Contract,
    Phase03ToPhase04Contract,
    StateCollectionFinding,
    VaultAcquiredEntry,
)
from edrm.shared_kernel.exceptions import SourceMutationDetectedError


class VerifiedVaultCopierPort(Protocol):
    """Porta segregada para copia forense 4MiB + os.fsync + releitura fria e trava Read-Only."""

    def acquire_into_vault(
        self,
        vault_dir: str,
        item: PlannedAcquisitionItem,
    ) -> VaultAcquiredEntry:
        """Executa copia verificada ou indexacao imutavel lancando CollectionHashMismatchError."""

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Recaptura fotografia fisica de --source."""


class Phase03ManifestAndReportPort(Protocol):
    """Porta segregada para manifesto ICP-Brasil, persistencia SQLite e Relatorio Fase 03."""

    def finalize_phase03_artifacts(
        self,
        phase02_bundle: Phase02ToPhase03Contract,
        vault_entries: tuple[VaultAcquiredEntry, ...],
        state_findings: tuple[StateCollectionFinding, ...],
        issued_at_utc: str,
    ) -> tuple[str, str, str, str]:
        """Grava manifesto ICP, persiste vault_rel_path e retorna (icp_p, icp_sha, rep_p, rep_sha)."""


class Phase03ClockPort(Protocol):
    """Porta minima de relogio UTC da Fase 03."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase03CollectionUseCase:
    """Orquestra as Etapas 3.1 a 3.4 da Fase 03 garantindo mesmidade bit a bit."""

    def __init__(
        self,
        copier: VerifiedVaultCopierPort,
        manifest_writer: Phase03ManifestAndReportPort,
        clock: Phase03ClockPort,
    ) -> None:
        self._copier = copier
        self._manifest_writer = manifest_writer
        self._clock = clock

    def execute(self, phase02_bundle: Phase02ToPhase03Contract) -> Phase03ToPhase04Contract:
        """Planeja, copia para vault/ com releitura fria, trava em Read-Only e audita coleta."""
        probed = phase02_bundle.phase01_bundle.discovery_blueprint.probed_files
        plan = AcquisitionPlanner.build_plan(probed, phase02_bundle.spof_map)

        vault_dir = phase02_bundle.phase01_bundle.governance.vault_dir
        acquired: list[VaultAcquiredEntry] = []
        for item in plan:
            entry = self._copier.acquire_into_vault(vault_dir, item)
            acquired.append(entry)

        state_findings = StateCollectionMethodAuditor.audit_all(
            phase02_bundle.phase01_bundle.declared_items
        )

        now_utc = self._clock.now_iso_utc()
        icp_path, icp_sha, rep_path, rep_sha = self._manifest_writer.finalize_phase03_artifacts(
            phase02_bundle=phase02_bundle,
            vault_entries=tuple(acquired),
            state_findings=state_findings,
            issued_at_utc=now_utc,
        )

        post_snap = self._copier.capture_snapshot(
            phase02_bundle.phase01_bundle.governance.protected_source_roots,
            self._clock.now_iso_utc(),
        )
        if (
            post_snap.snapshot_sha256
            != phase02_bundle.phase01_bundle.pre_scan_snapshot.snapshot_sha256
        ):
            raise SourceMutationDetectedError(
                "Mutacao detectada em --source ao final da Fase 03!"
            )

        return Phase03ToPhase04Contract(
            phase02_bundle=phase02_bundle,
            vault_entries=tuple(acquired),
            state_collection_findings=state_findings,
            icp_manifest_path=icp_path,
            icp_manifest_sha256=icp_sha,
            phase03_report_path=rep_path,
            phase03_report_sha256=rep_sha,
        )
