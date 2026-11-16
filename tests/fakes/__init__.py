"""Adaptadores InMemory completos para verificacao de Substituicao de Liskov (Portao G8)."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import re

from edrm.continuous_analysis.domain import DeterministicHashEmbedder
from edrm.igrm_governance.domain import CaseWorkspaceLayout
from edrm.phase03_collection.domain import PlannedAcquisitionItem
from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    CaseGovernanceContract,
    FileStatEntry,
    MediaSnapshot,
    VaultAcquiredEntry,
)
from edrm.shared_kernel.enums import AcquisitionMode, PhaseCode
from edrm.shared_kernel.exceptions import CollectionHashMismatchError
from edrm.shared_kernel.value_objects import canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import VerificationVerdict


class FixedUtcClockFake:
    """Relogio UTC deterministico em memoria para testes hermeticos."""

    def __init__(self, fixed_iso: str = "2026-09-01T12:00:00Z") -> None:
        self._iso = fixed_iso

    def now_iso_utc(self) -> str:
        """Retorna instante UTC deterministico fixo."""
        return self._iso


class InMemoryWorkspaceProvisionerFake:
    """Provisionador em memoria implementando WorkspaceProvisionerPort."""

    def __init__(self) -> None:
        self.created_zones: list[str] = []

    def resolve_real_path(self, raw_path: str) -> str:
        """Normaliza caminho logico sem acessar disco."""
        cleaned = raw_path.strip().replace("\\", "/").rstrip("/")
        return cleaned or "/"

    def create_workspace_zones(self, layout: CaseWorkspaceLayout) -> None:
        """Registra zonas criadas em memoria."""
        self.created_zones.extend(
            [
                layout.workspace_root,
                layout.vault_dir,
                layout.staging_dir,
                layout.catalog_dir,
                layout.deliverables_dir,
                layout.audit_dir,
            ]
        )

    def compute_codebase_sha256(self) -> str:
        """Retorna SHA-256 deterministico do codebase."""
        return sha256_text("IN_MEMORY_CODEBASE_V2")


class InMemoryAuditLedgerFake:
    """Livro append-only em memoria implementando AuditLedgerPort."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []
        self.manifests: dict[str, dict[str, object]] = {}

    def append_event(
        self,
        audit_dir: str,
        phase: PhaseCode,
        event_name: str,
        payload: dict[str, object],
        ts_utc: str,
    ) -> str:
        """Anexa evento encadeado em memoria."""
        prev = str(self.events[-1]["entry_sha256"]) if self.events else "0" * 64
        core = {
            "audit_dir": audit_dir,
            "phase": str(phase),
            "event_name": event_name,
            "prev_entry_sha256": prev,
            "payload": payload,
            "ts_utc": ts_utc,
        }
        _, digest = canonical_json_sha256(core)
        entry = dict(core)
        entry["entry_sha256"] = digest
        self.events.append(entry)
        return digest

    def write_execution_manifest(
        self,
        contract: CaseGovernanceContract,
        started_at_utc: str,
    ) -> str:
        """Grava manifesto em memoria."""
        key = f"{contract.audit_dir}/execution_manifest.json"
        self.manifests[key] = {"started_at_utc": started_at_utc, "contract": asdict(contract)}
        return key


class InMemoryVerifiedVaultCopierFake:
    """Copiador verificado em memoria implementando VerifiedVaultCopierPort."""

    def __init__(self, source_blobs: dict[str, bytes], corrupt_flip: bool = False) -> None:
        self._blobs = dict(source_blobs)
        self._vault_blobs: dict[str, bytes] = {}
        self._corrupt = corrupt_flip

    def acquire_into_vault(
        self,
        vault_dir: str,
        item: PlannedAcquisitionItem,
    ) -> VaultAcquiredEntry:
        """Simula copia + releitura fria verificando SHA-256 bit a bit."""
        raw = self._blobs[item.origin_abs_path]
        src_sha = hashlib.sha256(raw).hexdigest()
        vault_data = (bytes([raw[0] ^ 0xFF]) + raw[1:]) if (self._corrupt and raw) else bytes(raw)
        cold_sha = hashlib.sha256(vault_data).hexdigest()

        if src_sha != cold_sha or cold_sha != item.expected_sha256 or len(vault_data) != item.expected_bytes:
            raise CollectionHashMismatchError(
                f"InMemory mismatch em {item.origin_rel_path}: {src_sha} != {cold_sha}"
            )
        v_abs = f"{vault_dir}/{item.vault_rel_path}"
        self._vault_blobs[v_abs] = vault_data
        return VaultAcquiredEntry(
            control_number=item.control_number.code,
            source_id=item.source_id,
            origin_rel_path=item.origin_rel_path,
            vault_rel_path=item.vault_rel_path,
            vault_abs_path=v_abs,
            acquisition_mode=AcquisitionMode.FULL_VAULT_COPY,
            size_bytes=len(vault_data),
            mtime_utc_ns=item.mtime_utc_ns,
            source_sha256=src_sha,
            vault_cold_sha256=cold_sha,
            vault_locked_readonly=True,
        )

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Retorna snapshot deterministico das fontes em memoria."""
        entries = [
            FileStatEntry(
                source_id="SRC-01",
                rel_path=k.rsplit("/", 1)[-1],
                size_bytes=len(v),
                mtime_utc_ns=1_700_000_000_000_000_000,
                mode_octal="0o444",
                inode_or_file_index=idx,
                is_os_readonly=True,
            )
            for idx, (k, v) in enumerate(sorted(self._blobs.items()), start=1)
        ]
        _ = source_roots
        _, snap_sha = canonical_json_sha256([asdict(e) for e in entries])
        return MediaSnapshot(
            captured_at_utc=ts_utc,
            entries=tuple(entries),
            snapshot_sha256=snap_sha,
        )


class InMemoryHybridSearchIndexFake:
    """Indice hibrido BM25-like + Vetorial em memoria implementando HybridSearchIndexPort."""

    def __init__(self) -> None:
        self._store: dict[str, dict[str, AnchoredTextChunk]] = {}
        self._vecs: dict[str, dict[str, tuple[int, ...]]] = {}

    def index_chunks(
        self,
        catalog_db_path: str,
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> int:
        """Indexa chunks e vetores em memoria."""
        bucket = self._store.setdefault(catalog_db_path, {})
        v_bucket = self._vecs.setdefault(catalog_db_path, {})
        for chk in chunks:
            bucket[chk.chunk_id] = chk
            v_bucket[chk.chunk_id] = DeterministicHashEmbedder.embed(chk.text_clean)
        return len(chunks)

    def query_lexical_and_vector(
        self,
        catalog_db_path: str,
        query_text: str,
        query_vector: tuple[int, ...],
        limit: int,
    ) -> tuple[dict[str, AnchoredTextChunk], tuple[str, ...], tuple[str, ...]]:
        """Pontua ocorrencias lexicas exatas e similaridade vetorial em memoria."""
        bucket = dict(self._store.get(catalog_db_path, {}))
        v_bucket = self._vecs.get(catalog_db_path, {})
        terms = [t.lower() for t in re.findall(r"[A-Za-z0-9_]+", query_text) if t]

        lex_scored: list[tuple[int, str]] = []
        vec_scored: list[tuple[int, str]] = []

        for cid, chk in bucket.items():
            low_txt = chk.text_clean.lower()
            tf = sum(low_txt.count(t) for t in terms)
            if tf > 0:
                lex_scored.append((tf, cid))
            sim = DeterministicHashEmbedder.dot_similarity(query_vector, v_bucket[cid])
            if sim > 0:
                vec_scored.append((sim, cid))

        lex_scored.sort(key=lambda p: (-p[0], p[1]))
        vec_scored.sort(key=lambda p: (-p[0], p[1]))
        return (
            bucket,
            tuple(cid for _, cid in lex_scored[:limit]),
            tuple(cid for _, cid in vec_scored[:limit]),
        )


class InMemoryAiAuditRepositoryFake:
    """Repositorio de auditoria de IA em memoria implementando AiAndQcAuditRepositoryPort."""

    def __init__(self) -> None:
        self.logs: list[dict[str, object]] = []

    def record_verification_audit(
        self,
        catalog_db_path: str,
        ts_utc: str,
        phase_code: PhaseCode,
        model_name: str,
        prompt_sha256: str,
        tokens_in: int,
        tokens_out: int,
        verdict: VerificationVerdict,
        sampling_method: str,
        stratum_stats: dict[str, object],
    ) -> str:
        """Registra auditoria de verificacao em memoria."""
        aid = "AUD-MEM-" + sha256_text(f"{ts_utc}|{prompt_sha256}")[:10].upper()
        self.logs.append(
            {
                "audit_id": aid,
                "catalog_db_path": catalog_db_path,
                "phase_code": str(phase_code),
                "model_name": model_name,
                "passed": verdict.passed,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "sampling_method": sampling_method,
                "stratum_stats": stratum_stats,
            }
        )
        return aid
