"""Camada de aplicacao pura da Fase 06 — Producao Pericial e Dupla Passagem no Verificador."""

from __future__ import annotations

from typing import Protocol

from edrm.phase06_production.domain import LoadFileBuilder, SevenBlockExpertOpinionBuilder
from edrm.shared_kernel.contracts import Phase05ToPhase06Contract, Phase06ToPhase07Contract


class Phase06DeliverablesWriterPort(Protocol):
    """Porta segregada para dupla validacao no Verificador Bloqueante e escrita de entregaveis."""

    def verify_double_pass_and_write(
        self,
        bundle: Phase05ToPhase06Contract,
        opinion_markdown: str,
        repro_script: str,
        concordance_dat: str,
        edrm_xml: str,
        issued_at_utc: str,
    ) -> tuple[str, str, str, str, str, str, str]:
        """Executa dupla passagem no Verificador e retorna os caminhos e hashes gravados."""


class Phase06ClockPort(Protocol):
    """Porta minima de relogio UTC da Fase 06."""

    def now_iso_utc(self) -> str:
        """Retorna instante atual em formato ISO-8601 UTC."""


class ExecutePhase06ProductionUseCase:
    """Orquestra as Etapas 6.1 a 6.3 da Fase 06 (Parecer 7 Blocos + Load Files + ICP-Brasil)."""

    def __init__(
        self,
        writer: Phase06DeliverablesWriterPort,
        clock: Phase06ClockPort,
    ) -> None:
        self._writer = writer
        self._clock = clock

    def execute(self, phase05_bundle: Phase05ToPhase06Contract) -> Phase06ToPhase07Contract:
        """Compila o Parecer, Load Files, valida duas vezes com 0 erros e lacra."""
        now_utc = self._clock.now_iso_utc()
        opinion_md, repro_sh = SevenBlockExpertOpinionBuilder.compile_opinion_and_repro_script(
            phase05_bundle, now_utc
        )
        dat_str, xml_str = LoadFileBuilder.build_concordance_dat_and_edrm_xml(phase05_bundle)

        (
            op_path,
            op_sha,
            rep_sh_path,
            rep_sh_sha,
            dat_path,
            xml_path,
            icp_det_path,
        ) = self._writer.verify_double_pass_and_write(
            bundle=phase05_bundle,
            opinion_markdown=opinion_md,
            repro_script=repro_sh,
            concordance_dat=dat_str,
            edrm_xml=xml_str,
            issued_at_utc=now_utc,
        )

        return Phase06ToPhase07Contract(
            phase05_bundle=phase05_bundle,
            expert_opinion_path=op_path,
            expert_opinion_sha256=op_sha,
            reproduction_script_path=rep_sh_path,
            reproduction_script_sha256=rep_sh_sha,
            concordance_dat_path=dat_path,
            edrm_xml_path=xml_path,
            icp_detached_manifest_path=icp_det_path,
            verifier_double_pass_zero_errors=True,
        )
