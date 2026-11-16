"""Camada de aplicacao pura da Camada 00 — Governanca IGRM v4.1."""

from __future__ import annotations

from typing import Protocol

from edrm.igrm_governance.domain import (
    CaseWorkspaceLayout,
    SecrecyNetworkPolicy,
    SelfCalibrationSuite,
    SourceWriteBlockerPolicy,
)
from edrm.shared_kernel.contracts import CalibrationReceipt, CaseGovernanceContract
from edrm.shared_kernel.enums import PhaseCode, SecrecyLevel
from edrm.shared_kernel.value_objects import sha256_text


class WorkspaceProvisionerPort(Protocol):
    """Porta minima para criacao fisica e resolucao canonica do workspace."""

    def resolve_real_path(self, raw_path: str) -> str:
        """Resolve o caminho real absoluto sem tocar em arquivos de prova.

        Args:
            raw_path: Caminho informado pelo usuario.

        Returns:
            Caminho canonico resolvido.
        """

    def create_workspace_zones(self, layout: CaseWorkspaceLayout) -> None:
        """Cria fisicamente as 5 zonas isoladas do workspace e inicializa o catalogo.

        Args:
            layout: Estrutura validada de CaseWorkspaceLayout.
        """

    def compute_codebase_sha256(self) -> str:
        """Calcula o SHA-256 deterministico do proprio codigo-fonte executado.

        Returns:
            Digest hexadecimal de 64 caracteres.
        """


class AuditLedgerPort(Protocol):
    """Porta segregada para o livro de auditoria append-only e manifesto de execucao."""

    def append_event(
        self,
        audit_dir: str,
        phase: PhaseCode,
        event_name: str,
        payload: dict[str, object],
        ts_utc: str,
    ) -> str:
        """Registra um evento imutavel em audit_ledger.jsonl.

        Args:
            audit_dir: Pasta audit/ do caso.
            phase: Codigo da fase EDRM.
            event_name: Identificador do evento.
            payload: Metadados auditaveis.
            ts_utc: Carimbo UTC.

        Returns:
            SHA-256 da linha gravada.
        """

    def write_execution_manifest(
        self,
        contract: CaseGovernanceContract,
        started_at_utc: str,
    ) -> str:
        """Grava execution_manifest.json assinado na zona audit/.

        Args:
            contract: Contrato de governanca vigente.
            started_at_utc: Horario UTC de inicio.

        Returns:
            Caminho logico do manifesto gravado.
        """


class ClockPort(Protocol):
    """Porta minima de relogio UTC deterministico."""

    def now_iso_utc(self) -> str:
        """Retorna o instante atual em formato ISO-8601 terminado em Z."""


class CalibrateToolsUseCase:
    """Caso de uso da Microfase 0.3 — Auto-calibracao previa ISO/IEC 27041."""

    def __init__(self, clock: ClockPort) -> None:
        self._clock = clock

    def execute(self) -> CalibrationReceipt:
        """Executa a suite de auto-calibracao retornando o recibo criptografico.

        Returns:
            CalibrationReceipt validado.
        """
        return SelfCalibrationSuite.run_calibration(self._clock.now_iso_utc())


class InitializeCaseWorkspaceUseCase:
    """Caso de uso das Microfases 0.1 a 0.4 — Inicializacao blindada do caso."""

    def __init__(
        self,
        provisioner: WorkspaceProvisionerPort,
        ledger: AuditLedgerPort,
        clock: ClockPort,
    ) -> None:
        self._provisioner = provisioner
        self._ledger = ledger
        self._clock = clock

    def execute(
        self,
        case_id: str,
        workspace_path: str,
        source_paths: tuple[str, ...],
        secrecy_level: SecrecyLevel = SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY,
    ) -> CaseGovernanceContract:
        """Valida isolamento, calibra ferramentas ISO 27041 e provisiona o workspace.

        Args:
            case_id: Identificador do caso criminal.
            workspace_path: Diretorio raiz de trabalho (--workspace).
            source_paths: Midias conectadas (--source).
            secrecy_level: Nivel de sigilo aplicavel.

        Returns:
            CaseGovernanceContract imutavel assinado.
        """
        now_utc = self._clock.now_iso_utc()
        receipt = SelfCalibrationSuite.run_calibration(now_utc)
        SecrecyNetworkPolicy(secrecy_level=secrecy_level).assert_endpoint_allowed("127.0.0.1")

        resolved_ws = self._provisioner.resolve_real_path(workspace_path)
        resolved_sources = tuple(self._provisioner.resolve_real_path(p) for p in source_paths)

        blocker_policy = SourceWriteBlockerPolicy(protected_roots=resolved_sources)
        blocker_policy.validate_no_workspace_overlap(resolved_ws)

        layout = CaseWorkspaceLayout.build(resolved_ws)
        self._provisioner.create_workspace_zones(layout)
        codebase_hash = self._provisioner.compute_codebase_sha256()
        run_id = "RUN-" + sha256_text(f"{case_id}|{now_utc}|{codebase_hash}")[:16].upper()

        contract = CaseGovernanceContract(
            case_id=case_id,
            run_id=run_id,
            workspace_root=layout.workspace_root,
            vault_dir=layout.vault_dir,
            staging_dir=layout.staging_dir,
            catalog_dir=layout.catalog_dir,
            deliverables_dir=layout.deliverables_dir,
            audit_dir=layout.audit_dir,
            catalog_db_path=layout.catalog_db_path,
            protected_source_roots=resolved_sources,
            secrecy_level=secrecy_level,
            codebase_sha256=codebase_hash,
            calibration_receipt=receipt,
        )

        self._ledger.write_execution_manifest(contract, now_utc)
        self._ledger.append_event(
            audit_dir=contract.audit_dir,
            phase=PhaseCode.IGRM_00,
            event_name="CASE_WORKSPACE_INITIALIZED",
            payload={
                "case_id": case_id,
                "run_id": run_id,
                "codebase_sha256": codebase_hash,
                "calibration_sha256": receipt.calibration_sha256,
                "secrecy_level": str(secrecy_level),
            },
            ts_utc=now_utc,
        )
        return contract
