"""Camada de aplicacao pura da Fase 08 — Expurgo de Staging, Recovery Bundle e NIST 800-88."""

from __future__ import annotations

from typing import Protocol

from edrm.phase08_disposition.domain import (
    Nist80088Certificate,
    PostJudgmentDispositionPolicy,
)
from edrm.shared_kernel.contracts import (
    FinalDispositionReceipt,
    MediaSnapshot,
    Phase07ToPhase08Contract,
)
from edrm.shared_kernel.enums import SanitizationMethod
from edrm.shared_kernel.exceptions import SourceMutationDetectedError


class StagingPurgeAndBundlePort(Protocol):
    """Porta segregada para expurgo exclusivo de staging/, MANIFESTO_SHA256 e git bundle."""

    def verify_deliverables_and_purge_staging(
        self,
        bundle: Phase07ToPhase08Contract,
    ) -> tuple[int, int, bool]:
        """Confere hashes de deliverables/ e vault/, limpa apenas staging/ e retorna contagens."""

    def build_manifest_and_recovery_bundle(
        self,
        workspace_root: str,
        audit_dir: str,
        deliverables_dir: str,
    ) -> tuple[str, str]:
        """Gera MANIFESTO_SHA256.txt e pacote anti-perda git bundle."""

    def capture_final_source_snapshot(
        self,
        source_roots: tuple[str, ...],
        ts_utc: str,
    ) -> MediaSnapshot:
        """Captura PostScanSnapshot final de --source para prova matematica de integridade."""


class NistSanitizerWriterPort(Protocol):
    """Porta segregada para emissao de CertificateOfDisposition.json (NIST SP 800-88 Rev. 2)."""

    def execute_and_write_certificate(
        self,
        audit_dir: str,
        target_dir_to_purge: str | None,
        certificate: Nist80088Certificate,
    ) -> str:
        """Executa sanitizacao autorizada sobre copia descartavel e grava o certificado JSON."""


class Phase08ClockPort(Protocol):
    """Porta minima de relogio UTC da Fase 08."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase08DispositionUseCase:
    """Orquestra as Etapas 8.1 a 8.3 reconectando o encerramento a base IGRM v4.1."""

    def __init__(
        self,
        purge_and_bundle: StagingPurgeAndBundlePort,
        nist_writer: NistSanitizerWriterPort,
        clock: Phase08ClockPort,
    ) -> None:
        self._purge_and_bundle = purge_and_bundle
        self._nist_writer = nist_writer
        self._clock = clock

    def execute(
        self,
        phase07_bundle: Phase07ToPhase08Contract,
        execute_post_judgment_nist: bool = False,
        require_explicit_human_authorization: bool = False,
        human_operator_name: str = "",
        second_confirmation_phrase: str = "",
        sanitization_method: SanitizationMethod = SanitizationMethod.PURGE_CRYPTOGRAPHIC_ERASE,
    ) -> FinalDispositionReceipt:
        """Expurga staging/, gera Recovery Bundle, opcionalmente emite NIST 800-88 e prova 0 mutacao."""
        p01 = (
            phase07_bundle.phase06_bundle.phase05_bundle.phase04_bundle.updated_phase01_bundle
        )
        gov = p01.governance

        purged_files, purged_bytes, vault_ok = (
            self._purge_and_bundle.verify_deliverables_and_purge_staging(phase07_bundle)
        )
        manifest_path, bundle_path = self._purge_and_bundle.build_manifest_and_recovery_bundle(
            workspace_root=gov.workspace_root,
            audit_dir=gov.audit_dir,
            deliverables_dir=gov.deliverables_dir,
        )

        nist_cert_path: str | None = None
        if execute_post_judgment_nist:
            cert = PostJudgmentDispositionPolicy.build_certificate(
                case_id=gov.case_id,
                method=sanitization_method,
                require_explicit_human_authorization=require_explicit_human_authorization,
                human_operator_name=human_operator_name,
                second_confirmation_phrase=second_confirmation_phrase,
                target_scope="EPHEMERAL_STAGING_WORKING_COPIES",
                issued_at_utc=self._clock.now_iso_utc(),
            )
            nist_cert_path = self._nist_writer.execute_and_write_certificate(
                audit_dir=gov.audit_dir,
                target_dir_to_purge=None,
                certificate=cert,
            )

        final_snapshot = self._purge_and_bundle.capture_final_source_snapshot(
            gov.protected_source_roots,
            self._clock.now_iso_utc(),
        )
        identical = final_snapshot.snapshot_sha256 == p01.pre_scan_snapshot.snapshot_sha256
        if not identical:
            raise SourceMutationDetectedError(
                f"VIOLACAO CRITICA: PreScanSnapshot ({p01.pre_scan_snapshot.snapshot_sha256}) "
                f"!= PostScanSnapshot ({final_snapshot.snapshot_sha256})"
            )

        return FinalDispositionReceipt(
            case_id=gov.case_id,
            staging_purged_files_count=purged_files,
            staging_purged_bytes=purged_bytes,
            vault_intact_verified=vault_ok,
            source_pre_post_snapshot_identical=identical,
            post_scan_snapshot=final_snapshot,
            manifest_sha256_path=manifest_path,
            recovery_bundle_path=bundle_path,
            nist_certificate_path=nist_cert_path,
        )
