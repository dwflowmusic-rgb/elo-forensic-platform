"""Testes de Contrato de Substituicao de Liskov (InMemory == Infraestrutura Fisica Real)."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import tempfile

from edrm.continuous_analysis.application import HybridSearchUseCase
from edrm.continuous_analysis.infrastructure import (
    AiAndQcAuditRepositoryAdapter,
    SqliteFtsVectorStoreAdapter,
)
from edrm.igrm_governance.application import InitializeCaseWorkspaceUseCase
from edrm.igrm_governance.infrastructure import (
    AppendOnlyLedgerAdapter,
    FsWorkspaceProvisionerAdapter,
)
from edrm.phase03_collection.domain import PlannedAcquisitionItem
from edrm.phase03_collection.infrastructure import FsyncColdVerifyCopierAdapter
from edrm.shared_kernel.contracts import AnchoredTextChunk
from edrm.shared_kernel.enums import AcquisitionMode, PhaseCode
from edrm.shared_kernel.exceptions import CollectionHashMismatchError
from edrm.shared_kernel.schema_sql import CANONICAL_CATALOG_DDL_STATEMENTS
from edrm.shared_kernel.value_objects import ControlNumber, sha256_text
from edrm.shared_kernel.verifier_primitives import VerificationVerdict
from tests.fakes import (
    FixedUtcClockFake,
    InMemoryAiAuditRepositoryFake,
    InMemoryAuditLedgerFake,
    InMemoryHybridSearchIndexFake,
    InMemoryVerifiedVaultCopierFake,
    InMemoryWorkspaceProvisionerFake,
)


def run_all_liskov_contract_suites() -> None:
    """Executa identicamente os contratos sobre adaptadores InMemory e Fisicos."""
    clock = FixedUtcClockFake("2026-09-01T15:30:00Z")

    mem_uc = InitializeCaseWorkspaceUseCase(
        provisioner=InMemoryWorkspaceProvisionerFake(),
        ledger=InMemoryAuditLedgerFake(),
        clock=clock,
    )
    mem_gov = mem_uc.execute("CASO-LSP", "/virtual/ws", ("/virtual/hd",))
    assert mem_gov.calibration_receipt.positive_control_passed is True
    assert mem_gov.vault_dir.endswith("/vault")

    with tempfile.TemporaryDirectory() as tmp:
        ws_dir = Path(tmp) / "ws"
        hd_dir = Path(tmp) / "hd"
        hd_dir.mkdir()
        real_uc = InitializeCaseWorkspaceUseCase(
            provisioner=FsWorkspaceProvisionerAdapter(),
            ledger=AppendOnlyLedgerAdapter(),
            clock=clock,
        )
        real_gov = real_uc.execute("CASO-LSP", str(ws_dir), (str(hd_dir),))
        assert real_gov.calibration_receipt.positive_control_passed is True
        assert real_gov.vault_dir.endswith("/vault")

        sample_bytes = b"EVIDENCIA_BINARIA_TESTE_LISKOV_0123456789"
        sample_sha = hashlib.sha256(sample_bytes).hexdigest()
        src_file = hd_dir / "item.bin"
        src_file.write_bytes(sample_bytes)

        plan_item = PlannedAcquisitionItem(
            control_number=ControlNumber.root(1),
            source_id="SRC-01",
            origin_rel_path="item.bin",
            origin_abs_path=str(src_file),
            vault_rel_path="CN-00000001_item.bin",
            expected_sha256=sample_sha,
            expected_bytes=len(sample_bytes),
            mtime_utc_ns=1_700_000_000,
            mode=AcquisitionMode.FULL_VAULT_COPY,
        )

        for copier in (
            InMemoryVerifiedVaultCopierFake({str(src_file): sample_bytes}),
            FsyncColdVerifyCopierAdapter(),
        ):
            res_entry = copier.acquire_into_vault(real_gov.vault_dir, plan_item)
            assert res_entry.source_sha256 == sample_sha
            assert res_entry.vault_cold_sha256 == sample_sha
            assert res_entry.vault_locked_readonly is True

        for corrupt_copier in (
            InMemoryVerifiedVaultCopierFake({str(src_file): sample_bytes}, corrupt_flip=True),
            FsyncColdVerifyCopierAdapter(fault_injector=lambda b: bytes([b[0] ^ 0xFF]) + b[1:]),
        ):
            blocked = False
            try:
                corrupt_copier.acquire_into_vault(str(Path(tmp) / "vault_err"), plan_item)
            except CollectionHashMismatchError:
                blocked = True
            assert blocked is True

        chunks = (
            AnchoredTextChunk(
                chunk_id="CHK-LSP-001",
                origin_cn="CN-00000001",
                origin_path="auto.txt",
                locator="p. 1",
                text_clean="Transferencia PIX de R$ 1.540,90 referente ao lacre 0098412",
                injection_neutralized=False,
                origin_sha256=sample_sha,
            ),
            AnchoredTextChunk(
                chunk_id="CHK-LSP-002",
                origin_cn="CN-00000002",
                origin_path="outro.txt",
                locator="p. 2",
                text_clean="Documento administrativo ordinario sem valores",
                injection_neutralized=False,
                origin_sha256=sample_sha,
            ),
        )

        db_lsp = str(Path(tmp) / "lsp_catalog.sqlite")
        conn = sqlite3.connect(db_lsp)
        try:
            with conn:
                for ddl in CANONICAL_CATALOG_DDL_STATEMENTS:
                    conn.execute(ddl)
        finally:
            conn.close()

        for search_port in (InMemoryHybridSearchIndexFake(), SqliteFtsVectorStoreAdapter()):
            uc_s = HybridSearchUseCase(search_port)
            indexed = uc_s.build_index(db_lsp, chunks)
            assert indexed == 2
            hits = uc_s.search(db_lsp, "0098412 1540", top_n=5)
            assert len(hits) >= 1
            assert hits[0].chunk.chunk_id == "CHK-LSP-001"

        verdict = VerificationVerdict(passed=True, checked_claims_count=3, rejected_reasons=())
        for audit_port in (InMemoryAiAuditRepositoryFake(), AiAndQcAuditRepositoryAdapter()):
            aid = audit_port.record_verification_audit(
                catalog_db_path=db_lsp,
                ts_utc="2026-09-01T15:30:00Z",
                phase_code=PhaseCode.CONTINUOUS_ANALYSIS,
                model_name="TestModel",
                prompt_sha256=sha256_text("prompt"),
                tokens_in=10,
                tokens_out=20,
                verdict=verdict,
                sampling_method="COCHRAN",
                stratum_stats={"n": 2},
            )
            assert aid.startswith("AUD-")
