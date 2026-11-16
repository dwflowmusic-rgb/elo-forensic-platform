"""Composition Root (Container) conectando as camadas 00 a 08 e Analise Continua."""

from __future__ import annotations

from dataclasses import dataclass

from edrm.continuous_analysis.application import (
    GovernedAiInterpretAndVerifyUseCase,
    HybridSearchUseCase,
)
from edrm.continuous_analysis.infrastructure import (
    AiAndQcAuditRepositoryAdapter,
    LocalLlmEndpointAdapter,
    SqliteFtsVectorStoreAdapter,
)
from edrm.igrm_governance.application import (
    CalibrateToolsUseCase,
    InitializeCaseWorkspaceUseCase,
)
from edrm.igrm_governance.infrastructure import (
    AppendOnlyLedgerAdapter,
    FsWorkspaceProvisionerAdapter,
    FsWriteBlockerGuard,
    SystemUtcClockAdapter,
)
from edrm.phase01_identification.application import (
    ExecutePhase01IdentificationUseCase,
    ReceiveIterativeFeedbackUseCase,
)
from edrm.phase01_identification.infrastructure import (
    Phase01MarkdownCompilerAdapter,
    ReadOnlyMediaScannerAdapter,
    SqliteCatalog01RepositoryAdapter,
)
from edrm.phase02_preservation.application import ExecutePhase02PreservationUseCase
from edrm.phase02_preservation.infrastructure import (
    ImmutableStructuralHealthAdapter,
    Phase02CatalogAndMarkdownAdapter,
)
from edrm.phase03_collection.application import ExecutePhase03CollectionUseCase
from edrm.phase03_collection.infrastructure import (
    FsyncColdVerifyCopierAdapter,
    Phase03ManifestAndReportAdapter,
)
from edrm.phase04_processing.application import ExecutePhase04ProcessingUseCase
from edrm.phase04_processing.infrastructure import (
    Phase04CatalogAndFiveReportsAdapter,
    SafeContainerUnpackerAdapter,
    UniversalExtractorRunnerAdapter,
)
from edrm.phase05_review.application import ExecutePhase05ReviewUseCase
from edrm.phase05_review.infrastructure import Phase05ReviewStoreAdapter
from edrm.phase06_production.application import ExecutePhase06ProductionUseCase
from edrm.phase06_production.infrastructure import Phase06DeliverablesWriterAdapter
from edrm.phase07_presentation.application import ExecutePhase07PresentationUseCase
from edrm.phase07_presentation.infrastructure import Phase07PresenterWriterAdapter
from edrm.phase08_disposition.application import ExecutePhase08DispositionUseCase
from edrm.phase08_disposition.infrastructure import (
    Nist80088SanitizerAdapter,
    StagingCleanerAndBundleAdapter,
)
from edrm.shared_kernel.contracts import (
    CaseGovernanceContract,
    FinalDispositionReceipt,
    Phase01ToPhase02Contract,
    Phase02ToPhase03Contract,
    Phase03ToPhase04Contract,
    Phase04ToPhase05Contract,
    Phase05ToPhase06Contract,
    Phase06ToPhase07Contract,
    Phase07ToPhase08Contract,
)
from edrm.shared_kernel.enums import PhaseCode, SanitizationMethod, SecrecyLevel


@dataclass(frozen=True, slots=True)
class FullPipelineExecutionResult:
    """Resultado completo auditado da execucao ponta a ponta (Camada 00 -> Fase 08)."""

    governance: CaseGovernanceContract
    phase01_initial: Phase01ToPhase02Contract
    phase02: Phase02ToPhase03Contract
    phase03: Phase03ToPhase04Contract
    phase04: Phase04ToPhase05Contract
    phase05: Phase05ToPhase06Contract
    phase06: Phase06ToPhase07Contract
    phase07: Phase07ToPhase08Contract
    phase08: FinalDispositionReceipt
    indexed_chunks_count: int


class EloForensicContainer:
    """Composition Root instanciando todos os adaptadores fisicos sem estado global."""

    def __init__(self) -> None:
        self._clock = SystemUtcClockAdapter()
        self._ledger = AppendOnlyLedgerAdapter()
        self._provisioner = FsWorkspaceProvisionerAdapter()

        self.calibrate_uc = CalibrateToolsUseCase(clock=self._clock)
        self.init_workspace_uc = InitializeCaseWorkspaceUseCase(
            provisioner=self._provisioner,
            ledger=self._ledger,
            clock=self._clock,
        )

        p01_scanner = ReadOnlyMediaScannerAdapter()
        p01_repo = SqliteCatalog01RepositoryAdapter()
        p01_compiler = Phase01MarkdownCompilerAdapter()

        self.phase01_uc = ExecutePhase01IdentificationUseCase(
            sensor=p01_scanner,
            catalog_repo=p01_repo,
            report_compiler=p01_compiler,
            clock=self._clock,
        )
        self.feedback_04_to_01_uc = ReceiveIterativeFeedbackUseCase(
            catalog_repo=p01_repo,
            report_compiler=p01_compiler,
            clock=self._clock,
        )

        self.phase02_uc = ExecutePhase02PreservationUseCase(
            health_runner=ImmutableStructuralHealthAdapter(),
            repo_and_compiler=Phase02CatalogAndMarkdownAdapter(),
            clock=self._clock,
        )
        self.phase03_uc = ExecutePhase03CollectionUseCase(
            copier=FsyncColdVerifyCopierAdapter(),
            manifest_writer=Phase03ManifestAndReportAdapter(),
            clock=self._clock,
        )
        self.phase04_uc = ExecutePhase04ProcessingUseCase(
            unpacker=SafeContainerUnpackerAdapter(),
            extractor_runner=UniversalExtractorRunnerAdapter(),
            persistence_and_reports=Phase04CatalogAndFiveReportsAdapter(),
            feedback_port=self.feedback_04_to_01_uc,
            clock=self._clock,
        )
        self.hybrid_search_uc = HybridSearchUseCase(
            index_port=SqliteFtsVectorStoreAdapter(),
        )
        self.governed_ai_uc = GovernedAiInterpretAndVerifyUseCase(
            llm_port=LocalLlmEndpointAdapter(),
            audit_repo=AiAndQcAuditRepositoryAdapter(),
        )
        self.phase05_uc = ExecutePhase05ReviewUseCase(
            persistence=Phase05ReviewStoreAdapter(),
            clock=self._clock,
        )
        self.phase06_uc = ExecutePhase06ProductionUseCase(
            writer=Phase06DeliverablesWriterAdapter(),
            clock=self._clock,
        )
        self.phase07_uc = ExecutePhase07PresentationUseCase(
            writer=Phase07PresenterWriterAdapter(),
        )
        self.phase08_uc = ExecutePhase08DispositionUseCase(
            purge_and_bundle=StagingCleanerAndBundleAdapter(),
            nist_writer=Nist80088SanitizerAdapter(),
            clock=self._clock,
        )

    def plug_and_run_all(
        self,
        case_id: str,
        source_paths: tuple[str, ...],
        workspace_path: str,
        secrecy_level: SecrecyLevel = SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY,
        post_judgment_nist: bool = False,
        human_operator: str = "",
        confirmation_phrase: str = "",
    ) -> FullPipelineExecutionResult:
        """Executa o fluxo completo Plug-and-Analyze sob FsWriteBlockerGuard (00 -> 08)."""
        governance = self.init_workspace_uc.execute(
            case_id=case_id,
            workspace_path=workspace_path,
            source_paths=source_paths,
            secrecy_level=secrecy_level,
        )

        with FsWriteBlockerGuard(
            source_roots=governance.protected_source_roots,
            secrecy_level=secrecy_level,
        ):
            p01 = self.phase01_uc.execute(governance)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_01_IDENTIFICATION,
                "PHASE_01_SEALED",
                {"contract_sha256": p01.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            p02 = self.phase02_uc.execute(p01)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_02_PRESERVATION,
                "PHASE_02_SEALED",
                {"contract_sha256": p02.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            p03 = self.phase03_uc.execute(p02)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_03_COLLECTION,
                "PHASE_03_SEALED",
                {"contract_sha256": p03.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            p04 = self.phase04_uc.execute(p03)
            indexed_cnt = self.hybrid_search_uc.build_index(
                governance.catalog_db_path, p04.anchored_chunks
            )
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_04_PROCESSING,
                "PHASE_04_AND_RRF_INDEX_SEALED",
                {
                    "contract_sha256": p04.contract_sha256(),
                    "indexed_chunks": indexed_cnt,
                    "phase01_revision": p04.updated_phase01_bundle.revision_number,
                },
                self._clock.now_iso_utc(),
            )

            p05 = self.phase05_uc.execute(p04)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_05_REVIEW,
                "PHASE_05_SEALED",
                {"contract_sha256": p05.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            p06 = self.phase06_uc.execute(p05)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_06_PRODUCTION,
                "PHASE_06_SEALED",
                {"contract_sha256": p06.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            p07 = self.phase07_uc.execute(p06)
            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_07_PRESENTATION,
                "PHASE_07_SEALED",
                {"contract_sha256": p07.contract_sha256()},
                self._clock.now_iso_utc(),
            )

            self._ledger.append_event(
                governance.audit_dir,
                PhaseCode.PHASE_08_DISPOSITION,
                "PHASE_08_DISPOSITION_SEALING",
                {
                    "phase07_contract_sha256": p07.contract_sha256(),
                    "post_judgment_nist": post_judgment_nist,
                },
                self._clock.now_iso_utc(),
            )
            p08 = self.phase08_uc.execute(
                phase07_bundle=p07,
                execute_post_judgment_nist=post_judgment_nist,
                require_explicit_human_authorization=post_judgment_nist,
                human_operator_name=human_operator,
                second_confirmation_phrase=confirmation_phrase,
                sanitization_method=SanitizationMethod.PURGE_CRYPTOGRAPHIC_ERASE,
            )

        return FullPipelineExecutionResult(
            governance=governance,
            phase01_initial=p01,
            phase02=p02,
            phase03=p03,
            phase04=p04,
            phase05=p05,
            phase06=p06,
            phase07=p07,
            phase08=p08,
            indexed_chunks_count=indexed_cnt,
        )
