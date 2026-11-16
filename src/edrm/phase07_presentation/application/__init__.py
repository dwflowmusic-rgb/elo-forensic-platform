"""Camada de aplicacao pura da Fase 07 — Apresentacao Pericial e Dossie Offline."""

from __future__ import annotations

from typing import Protocol

from edrm.phase07_presentation.domain import (
    OfflineHtmlDossierCompiler,
    StrategicInterrogatoryBuilder,
)
from edrm.shared_kernel.contracts import (
    CustomQuesitoRecord,
    Phase06ToPhase07Contract,
    Phase07ToPhase08Contract,
)


class Phase07PresenterWriterPort(Protocol):
    """Porta segregada para escrita verificada dos quesitos, anexos e HTML5 offline."""

    def write_presentation_deliverables(
        self,
        deliverables_dir: str,
        quesitos: tuple[CustomQuesitoRecord, ...],
        tema977_markdown: str,
        offline_html: str,
    ) -> tuple[str, str, str, str, str, tuple[tuple[str, str], ...]]:
        """Grava entregaveis da Fase 07 e inventaria todos os SHA-256 de deliverables/."""


class ExecutePhase07PresentationUseCase:
    """Orquestra as Etapas 7.1 a 7.3 da Fase 07."""

    def __init__(self, writer: Phase07PresenterWriterPort) -> None:
        self._writer = writer

    def execute(self, phase06_bundle: Phase06ToPhase07Contract) -> Phase07ToPhase08Contract:
        """Gera quesitos sob medida, anexo Tema 977 e Dossie HTML5 100% offline."""
        quesitos = StrategicInterrogatoryBuilder.generate_quesitos(phase06_bundle)
        exhibit_md = StrategicInterrogatoryBuilder.build_tema977_motion_exhibit(phase06_bundle)
        html_doc = OfflineHtmlDossierCompiler.compile_single_file_html(phase06_bundle, quesitos)

        deliv_dir = (
            phase06_bundle.phase05_bundle.phase04_bundle.updated_phase01_bundle.governance.deliverables_dir
        )
        (
            q_path,
            q_sha,
            ex_path,
            html_path,
            html_sha,
            all_deliv,
        ) = self._writer.write_presentation_deliverables(
            deliverables_dir=deliv_dir,
            quesitos=quesitos,
            tema977_markdown=exhibit_md,
            offline_html=html_doc,
        )

        return Phase07ToPhase08Contract(
            phase06_bundle=phase06_bundle,
            quesitos=quesitos,
            quesitos_path=q_path,
            quesitos_sha256=q_sha,
            tema977_exhibit_path=ex_path,
            offline_html_dossier_path=html_path,
            offline_html_dossier_sha256=html_sha,
            all_deliverables=all_deliv,
            authorize_staging_purge=True,
        )
