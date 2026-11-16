"""Camada de aplicacao pura da Fase 01 — Identificacao e Autodescoberta do HD."""

from __future__ import annotations

from typing import Protocol

from edrm.phase01_identification.domain import (
    CochranFiniteSampler,
    ParityMatrixEngine,
    PrimaryDocumentClassifierAndExtractor,
    SchemaDiscoveryEngine,
    SignatureRegistry,
    StateIpedCaseAuditor,
)
from edrm.shared_kernel.contracts import (
    CaseGovernanceContract,
    CustodianRecord,
    DeclaredEvidenceItem,
    DivergenceRecord,
    IterativeDiscoveryFeedbackPayload,
    MediaAutoDiscoveryBlueprint,
    MediaSnapshot,
    ParityMatrixRow,
    Phase01ToPhase02Contract,
    ProbedFileRecord,
)
from edrm.shared_kernel.enums import MagicSignature
from edrm.shared_kernel.exceptions import SourceMutationDetectedError


class MediaSensorProbePort(Protocol):
    """Porta segregada para captura de Snapshot e censo binario passivo em streaming."""

    def capture_physical_snapshot(
        self,
        source_roots: tuple[str, ...],
        captured_at_utc: str,
    ) -> MediaSnapshot:
        """Captura fotografia os.stat passiva (tamanho, mtime_ns, inode, readonly)."""

    def probe_all_files_streaming(
        self,
        source_roots: tuple[str, ...],
        audit_dir: str,
        signature_registry: SignatureRegistry,
    ) -> tuple[ProbedFileRecord, ...]:
        """Executa SHA-256 em blocos de 4 MiB com checkpoint e radiografia sem extracao."""


class Phase01CatalogRepositoryPort(Protocol):
    """Porta segregada para persistencia da Fase 01 no catalogo unificado."""

    def persist_phase01_results(self, contract: Phase01ToPhase02Contract) -> None:
        """Persiste fontes, custodiantes, declarados, inventario inicial, schemas e paridade."""


class Phase01ReportCompilerPort(Protocol):
    """Porta segregada para compilacao verificada do Relatorio Oficial da Fase 01."""

    def compile_and_verify_report(
        self,
        deliverables_dir: str,
        blueprint: MediaAutoDiscoveryBlueprint,
        custodians: tuple[CustodianRecord, ...],
        declared_items: tuple[DeclaredEvidenceItem, ...],
        divergences: tuple[DivergenceRecord, ...],
        parity_matrix: tuple[ParityMatrixRow, ...],
        revision_number: int,
    ) -> tuple[str, str]:
        """Compila o Markdown da Fase 01, audita no Verificador Bloqueante e retorna (path, sha256)."""


class Phase01ClockPort(Protocol):
    """Porta de relogio UTC da Fase 01."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase01IdentificationUseCase:
    """Orquestra integralmente as 4 Etapas e 11 Microfases da Fase 01."""

    def __init__(
        self,
        sensor: MediaSensorProbePort,
        catalog_repo: Phase01CatalogRepositoryPort,
        report_compiler: Phase01ReportCompilerPort,
        clock: Phase01ClockPort,
        signature_registry: SignatureRegistry | None = None,
        cochran_seed: int = 20260901,
    ) -> None:
        self._sensor = sensor
        self._catalog_repo = catalog_repo
        self._report_compiler = report_compiler
        self._clock = clock
        self._registry = signature_registry if signature_registry is not None else SignatureRegistry()
        self._cochran_seed = cochran_seed

    def execute(self, governance: CaseGovernanceContract) -> Phase01ToPhase02Contract:
        """Sonda o HD desconhecido, autodescobre schemas/autos, calcula paridade e lacra."""
        pre_ts = self._clock.now_iso_utc()
        pre_snapshot = self._sensor.capture_physical_snapshot(
            governance.protected_source_roots, pre_ts
        )

        probed_files = self._sensor.probe_all_files_streaming(
            source_roots=governance.protected_source_roots,
            audit_dir=governance.audit_dir,
            signature_registry=self._registry,
        )

        ext_counts: dict[str, int] = {}
        sig_counts: dict[str, int] = {}
        spoofed: list[str] = []
        enc_or_corr: list[str] = []
        headerless_enc: list[str] = []

        for pf in probed_files:
            lower_p = pf.rel_path.lower()
            ext = lower_p[lower_p.rfind(".") :] if "." in lower_p.rsplit("/", 1)[-1] else "(no_ext)"
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            sig_key = str(pf.magic_signature)
            sig_counts[sig_key] = sig_counts.get(sig_key, 0) + 1
            if pf.extension_spoofed:
                spoofed.append(pf.rel_path)
            if pf.is_encrypted_or_corrupted:
                enc_or_corr.append(pf.rel_path)
            if pf.magic_signature == MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED:
                headerless_enc.append(pf.rel_path)

        dynamic_schemas = SchemaDiscoveryEngine.build_dynamic_blueprints(probed_files)
        primary_candidates = PrimaryDocumentClassifierAndExtractor.detect_primary_documents(
            probed_files, pre_ts
        )
        iped_audit = StateIpedCaseAuditor.audit(probed_files, pre_ts)
        sorted_headerless = tuple(sorted(headerless_enc))

        priority_plan = (
            "PHASE_02_PRESERVATION",
            "PHASE_03_COLLECTION",
            "PHASE_04_PROCESSING",
            "CONTINUOUS_ANALYSIS",
            "PHASE_05_REVIEW",
            "PHASE_06_PRODUCTION",
            "PHASE_07_PRESENTATION",
            "PHASE_08_DISPOSITION",
        )

        blueprint = MediaAutoDiscoveryBlueprint(
            case_id=governance.case_id,
            extension_census=tuple(sorted(ext_counts.items())),
            signature_census=tuple(sorted(sig_counts.items())),
            spoofed_files=tuple(sorted(spoofed)),
            encrypted_or_corrupted_files=tuple(sorted(enc_or_corr)),
            probed_files=probed_files,
            dynamic_schemas=dynamic_schemas,
            primary_doc_candidates=primary_candidates,
            recommended_phase_priority=priority_plan,
            state_iped_audit=iped_audit,
            headerless_encrypted_files=sorted_headerless,
        )

        custodians, declared_items, divergences = (
            PrimaryDocumentClassifierAndExtractor.extract_declarations_and_divergences(
                primary_candidates, pre_ts
            )
        )

        primary_paths = {c.rel_path for c in primary_candidates}
        parity_rows = ParityMatrixEngine.compute(
            declared_items=declared_items,
            probed_files=probed_files,
            primary_doc_paths=primary_paths,
            captured_at_utc=pre_ts,
        )

        crit_ids = tuple(r.finding_id for r in parity_rows if r.is_judicial_critical)
        non_crit_ids = tuple(r.finding_id for r in parity_rows if not r.is_judicial_critical)
        cochran_plan = CochranFiniteSampler.build_plan(
            critical_ids=crit_ids,
            non_critical_ids=non_crit_ids,
            seed=self._cochran_seed,
        )

        report_path, report_sha256 = self._report_compiler.compile_and_verify_report(
            deliverables_dir=governance.deliverables_dir,
            blueprint=blueprint,
            custodians=custodians,
            declared_items=declared_items,
            divergences=divergences,
            parity_matrix=parity_rows,
            revision_number=1,
        )

        post_ts = self._clock.now_iso_utc()
        post_snapshot = self._sensor.capture_physical_snapshot(
            governance.protected_source_roots, post_ts
        )
        if pre_snapshot.snapshot_sha256 != post_snapshot.snapshot_sha256:
            raise SourceMutationDetectedError(
                f"Violacao PreScanSnapshot != PostScanSnapshot na Fase 01: "
                f"{pre_snapshot.snapshot_sha256} != {post_snapshot.snapshot_sha256}"
            )

        contract = Phase01ToPhase02Contract(
            governance=governance,
            pre_scan_snapshot=pre_snapshot,
            discovery_blueprint=blueprint,
            custodians=custodians,
            declared_items=declared_items,
            divergences=divergences,
            parity_matrix=parity_rows,
            cochran_plan=cochran_plan,
            phase01_report_path=report_path,
            phase01_report_sha256=report_sha256,
            revision_number=1,
            state_iped_audit=iped_audit,
            headerless_encrypted_candidates=sorted_headerless,
        )
        self._catalog_repo.persist_phase01_results(contract)
        return contract


class ReceiveIterativeFeedbackUseCase:
    """Implementa IterativeDiscoveryFeedbackPort (realimentacao 04/05 -> 01 sem acoplamento)."""

    def __init__(
        self,
        catalog_repo: Phase01CatalogRepositoryPort,
        report_compiler: Phase01ReportCompilerPort,
        clock: Phase01ClockPort,
        cochran_seed: int = 20260901,
    ) -> None:
        self._catalog_repo = catalog_repo
        self._report_compiler = report_compiler
        self._clock = clock
        self._cochran_seed = cochran_seed

    def receive_feedback(
        self,
        current_contract: Phase01ToPhase02Contract,
        feedback: IterativeDiscoveryFeedbackPayload,
    ) -> Phase01ToPhase02Contract:
        """Funde novas pecas primarias descompactadas no HD e recalcula a Matriz de Paridade."""
        if (
            not feedback.new_primary_docs
            and not feedback.new_custodians
            and not feedback.new_declared_items
        ):
            return current_contract

        now_utc = self._clock.now_iso_utc()
        existing_doc_paths = {d.rel_path for d in current_contract.discovery_blueprint.primary_doc_candidates}
        merged_docs = list(current_contract.discovery_blueprint.primary_doc_candidates)
        for nd in feedback.new_primary_docs:
            if nd.rel_path not in existing_doc_paths:
                merged_docs.append(nd)
                existing_doc_paths.add(nd.rel_path)

        custodians, declared_items, divergences = (
            PrimaryDocumentClassifierAndExtractor.extract_declarations_and_divergences(
                tuple(merged_docs), now_utc
            )
        )

        cust_map = {c.custodian_id: c for c in custodians}
        for extra_c in feedback.new_custodians:
            cust_map.setdefault(extra_c.custodian_id, extra_c)

        decl_map = {d.declared_id: d for d in declared_items}
        for extra_d in feedback.new_declared_items:
            decl_map.setdefault(extra_d.declared_id, extra_d)

        final_custodians = tuple(cust_map.values())
        final_declared = tuple(decl_map.values())

        updated_blueprint = MediaAutoDiscoveryBlueprint(
            case_id=current_contract.discovery_blueprint.case_id,
            extension_census=current_contract.discovery_blueprint.extension_census,
            signature_census=current_contract.discovery_blueprint.signature_census,
            spoofed_files=current_contract.discovery_blueprint.spoofed_files,
            encrypted_or_corrupted_files=current_contract.discovery_blueprint.encrypted_or_corrupted_files,
            probed_files=current_contract.discovery_blueprint.probed_files,
            dynamic_schemas=current_contract.discovery_blueprint.dynamic_schemas,
            primary_doc_candidates=tuple(merged_docs),
            recommended_phase_priority=current_contract.discovery_blueprint.recommended_phase_priority,
            state_iped_audit=current_contract.discovery_blueprint.state_iped_audit,
            headerless_encrypted_files=current_contract.discovery_blueprint.headerless_encrypted_files,
        )

        parity_rows = ParityMatrixEngine.compute(
            declared_items=final_declared,
            probed_files=updated_blueprint.probed_files,
            primary_doc_paths=existing_doc_paths,
            captured_at_utc=now_utc,
        )

        crit_ids = tuple(r.finding_id for r in parity_rows if r.is_judicial_critical)
        non_crit_ids = tuple(r.finding_id for r in parity_rows if not r.is_judicial_critical)
        cochran_plan = CochranFiniteSampler.build_plan(
            critical_ids=crit_ids,
            non_critical_ids=non_crit_ids,
            seed=self._cochran_seed,
        )

        next_rev = current_contract.revision_number + 1
        rep_path, rep_sha = self._report_compiler.compile_and_verify_report(
            deliverables_dir=current_contract.governance.deliverables_dir,
            blueprint=updated_blueprint,
            custodians=final_custodians,
            declared_items=final_declared,
            divergences=divergences,
            parity_matrix=parity_rows,
            revision_number=next_rev,
        )

        revised = Phase01ToPhase02Contract(
            governance=current_contract.governance,
            pre_scan_snapshot=current_contract.pre_scan_snapshot,
            discovery_blueprint=updated_blueprint,
            custodians=final_custodians,
            declared_items=final_declared,
            divergences=divergences,
            parity_matrix=parity_rows,
            cochran_plan=cochran_plan,
            phase01_report_path=rep_path,
            phase01_report_sha256=rep_sha,
            revision_number=next_rev,
            state_iped_audit=current_contract.state_iped_audit,
            headerless_encrypted_candidates=current_contract.headerless_encrypted_candidates,
        )
        self._catalog_repo.persist_phase01_results(revised)
        return revised
