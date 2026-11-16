"""Infraestrutura fisica da Fase 04 — Unpacker Seguro, IPED CLI Bridge, 11 Extratores + SQLite Dinamico."""

from __future__ import annotations

from dataclasses import asdict
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
from typing import Callable
import wave
import xml.etree.ElementTree as ET
import zipfile

from edrm.phase04_processing.domain import (
    ExtractionBatchOutput,
    ExtractorRegistry,
    InventoryWorkingItem,
    PureTabularForensicParsers,
    RegisteredExtractorSpec,
    build_sanitized_chunk,
    detect_primary_doc_in_unpacked_text,
    is_event_post_seizure,
    validate_safe_archive_member,
)
from edrm.phase04_processing.domain.v21_orchestrator import (
    PriorityTierScheduler,
    build_overlapping_sanitized_chunks,
)
from edrm.phase04_processing.infrastructure.v21_extractors import (
    AudioTranscriptDeduplicatedCache,
    ContainerExpansionCheckpointManager,
    SQLiteDeletedRecordsInspector,
    StateIpedStorageReaderAdapter,
    WindowsArtifactProvenanceExtractor,
    extract_contacts_from_wa_db,
    resolve_whatsapp_modern_lids_and_view_once,
)
from edrm.shared_kernel.compressibility_probe import filter_compressible_windows_for_bm25
from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    CgnatAuditRecord,
    DeadLetterExceptionRecord,
    DynamicSchemaBlueprint,
    FileStatEntry,
    FinancialLedgerEntryRecord,
    MediaSnapshot,
    Phase03ToPhase04Contract,
    PrimaryDocumentCandidate,
    RecoveredSqliteRecord,
    TelecomCdrRecord,
    TimelineEventRecord,
    WindowsLinkProvenanceRecord,
)
from edrm.shared_kernel.enums import MagicSignature, ProcessingPriorityTier
from edrm.shared_kernel.exceptions import ContainerSecurityViolationError
from edrm.shared_kernel.time_normalizer import (
    from_cocoa_seconds,
    from_unix_milliseconds,
    from_unix_seconds,
    parse_timestamp_to_utc,
)
from edrm.shared_kernel.value_objects import ControlNumber, SafeOsPath, canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly

_PDF_TEXT_STREAM_RE = re.compile(rb"\(([^()]{3,400})\)")
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _classify_header_quick(header: bytes, name: str) -> MagicSignature:
    low = name.lower()
    if header.startswith(b"SQLite format 3\x00"):
        return MagicSignature.SQLITE3
    if len(header) >= 8 and header[:8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00":
        return MagicSignature.WINDOWS_LNK_SHORTCUT
    if header.startswith(b"%PDF-"):
        return MagicSignature.PDF_DOCUMENT
    if header.startswith(b"PK\x03\x04"):
        return (
            MagicSignature.CELLEBRITE_UFDR_UFDX
            if low.endswith((".ufdr", ".ufdx"))
            else MagicSignature.ZIP_CONTAINER
        )
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE":
        return MagicSignature.WAV_AUDIO
    if header.lstrip().startswith(b"<?xml") or low.endswith(".xml"):
        return MagicSignature.XML_DOCUMENT
    if header.startswith(b"\xff\xd8\xff"):
        return MagicSignature.JPEG_IMAGE
    if header.startswith(b"\x89PNG"):
        return MagicSignature.PNG_IMAGE
    if b"\x00" not in header:
        return MagicSignature.UTF8_TEXT_OR_CSV
    return MagicSignature.UNKNOWN_BINARY


class IpedCliExternalBridge:
    """Ponte limpa via linha de comando com IPED 4.3.x (--nogui -profile fastmode/triage)."""

    def __init__(self, iped_binary: str | None = None) -> None:
        self._iped_bin = iped_binary or shutil.which("iped")

    def is_available(self) -> bool:
        """Indica se o executavel externo do IPED esta disponivel no ambiente."""
        return self._iped_bin is not None

    def run_and_import_sleuth_db(
        self,
        source_ro_path: str,
        staging_out_dir: str,
        profile: str = "fastmode",
    ) -> list[dict[str, object]]:
        """Executa IPED --nogui (ou importa sleuth.db preexistente) em mode=ro&immutable=1."""
        sleuth_candidate = Path(staging_out_dir) / "sleuth.db"
        if self._iped_bin is not None and not sleuth_candidate.exists():
            cmd = [
                self._iped_bin,
                "--nogui",
                "-d",
                source_ro_path,
                "-o",
                staging_out_dir,
                "-profile",
                profile,
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=300)

        if not sleuth_candidate.exists():
            return []

        uri = SafeOsPath(str(sleuth_candidate.resolve())).to_sqlite_immutable_uri(
            is_windows=(os.name == "nt")
        )
        imported: list[dict[str, object]] = []
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("PRAGMA query_only = 1;")
            tables = {
                str(r[0])
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if " tsk_files" in tables or "tsk_files" in tables:
                rows = conn.execute(
                    "SELECT name, size, md5, sha256 FROM tsk_files LIMIT 5000"
                ).fetchall()
                for r in rows:
                    imported.append(
                        {
                            "name": str(r[0] or ""),
                            "size": int(r[1] or 0),
                            "md5": str(r[2] or ""),
                            "sha256": str(r[3] or ""),
                        }
                    )
        finally:
            conn.close()
        return imported


class SafeContainerUnpackerAdapter:
    """Subetapa 4.1 — Fila idempotente com checkpoint resiliente, semaforo e ponte de 16 shards IPED."""

    def __init__(
        self,
        iped_bridge: IpedCliExternalBridge | None = None,
        max_expanding_containers: int = 2,
        interrupt_after_children: int | None = None,
    ) -> None:
        self._iped_bridge = iped_bridge or IpedCliExternalBridge()
        self._max_expanding_containers = max_expanding_containers
        self._interrupt_after_children = interrupt_after_children

    def ingest_and_unpack_to_staging(
        self,
        phase03_bundle: Phase03ToPhase04Contract,
    ) -> tuple[tuple[InventoryWorkingItem, ...], tuple[DeadLetterExceptionRecord, ...]]:
        """Cria itens de trabalho raiz, retoma conteineres interrompidos e importa shards .iped."""
        p01 = phase03_bundle.phase02_bundle.phase01_bundle
        gov = p01.governance
        staging_root = Path(gov.staging_dir)
        os.makedirs(str(staging_root), exist_ok=True)

        ckpt_mgr = ContainerExpansionCheckpointManager(
            catalog_db_path=gov.catalog_db_path,
            max_expanding_containers=self._max_expanding_containers,
        )

        checkpoint_path = Path(gov.audit_dir) / "phase04_unpack_checkpoint.json"
        completed_cns: set[str] = set()
        if checkpoint_path.exists():
            completed_cns = set(json.loads(checkpoint_path.read_text(encoding="utf-8")))

        probed_by_rel = {pf.rel_path: pf for pf in p01.discovery_blueprint.probed_files}
        default_custs = tuple(c.custodian_id for c in p01.custodians)

        inventory: list[InventoryWorkingItem] = []
        dead_letters: list[DeadLetterExceptionRecord] = []

        for ve in phase03_bundle.vault_entries:
            pf = probed_by_rel.get(ve.origin_rel_path)
            magic = pf.magic_signature if pf else MagicSignature.UNKNOWN_BINARY
            spoofed = pf.extension_spoofed if pf else False
            is_enc = pf.is_encrypted_or_corrupted if pf else False
            eof_cnt = pf.pdf_eof_count if pf else 0
            has_wal = (pf.has_wal_sibling or pf.has_shm_sibling) if pf else False

            parent_item = InventoryWorkingItem(
                control_number=ve.control_number,
                parent_control_number=None,
                source_id=ve.source_id,
                origin_rel_path=ve.origin_rel_path,
                staging_or_vault_path=ve.vault_abs_path,
                size_bytes=ve.size_bytes,
                mtime_utc_ns=ve.mtime_utc_ns,
                is_os_readonly=ve.vault_locked_readonly,
                sha256_hex=ve.vault_cold_sha256,
                magic_signature=magic,
                extension_spoofed=spoofed,
                is_encrypted_or_corrupted=is_enc,
                pdf_eof_count=eof_cnt,
                has_wal_shm_sibling=has_wal,
                custodian_ids=default_custs,
            )
            inventory.append(parent_item)

            if is_enc:
                reason = (
                    "HEADERLESS_ENCRYPTED_VOLUME_WITHOUT_KEY"
                    if magic == MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED
                    else "ENCRYPTED_OR_CORRUPTED_CONTAINER"
                )
                dead_letters.append(
                    DeadLetterExceptionRecord(
                        control_number=ve.control_number,
                        rel_path=ve.origin_rel_path,
                        sha256_hex=ve.vault_cold_sha256,
                        reason_code=reason,
                        detail="Arquivo criptografado sem chave ou corrompido encaminhado a Dead-Letter Queue.",
                    )
                )
                continue

            if magic in (MagicSignature.ZIP_CONTAINER, MagicSignature.CELLEBRITE_UFDR_UFDX):
                with ckpt_mgr.semaphore:
                    children, child_dls, fully_done = self._unpack_zip_recursive(
                        archive_path=Path(ve.vault_abs_path),
                        parent_cn=ControlNumber(ve.control_number),
                        parent_sha256=ve.vault_cold_sha256,
                        parent_rel_path=ve.origin_rel_path,
                        source_id=ve.source_id,
                        staging_root=staging_root,
                        custodian_ids=default_custs,
                        depth=1,
                        ckpt_mgr=ckpt_mgr,
                        updated_at_utc=p01.pre_scan_snapshot.captured_at_utc,
                    )
                inventory.extend(children)
                dead_letters.extend(child_dls)
                if not fully_done:
                    continue
            elif magic == MagicSignature.EWF_E01 and self._iped_bridge.is_available():
                iped_out = staging_root / f"iped_{ve.control_number}"
                os.makedirs(str(iped_out), exist_ok=True)
                self._iped_bridge.run_and_import_sleuth_db(ve.vault_abs_path, str(iped_out))

            completed_cns.add(ve.control_number)
            checkpoint_path.write_text(
                json.dumps(sorted(completed_cns), indent=2),
                encoding="utf-8",
            )

        if p01.state_iped_audit is not None and p01.state_iped_audit.sleuth_db_present:
            iped_children = self._import_state_iped_shards_readonly(
                source_roots=gov.protected_source_roots,
                case_root_rel=p01.state_iped_audit.case_root_rel_path,
                staging_root=staging_root,
                base_cn_seq=len(phase03_bundle.vault_entries) + 1,
                custodian_ids=default_custs,
            )
            inventory.extend(iped_children)

        return tuple(inventory), tuple(dead_letters)

    def _import_state_iped_shards_readonly(
        self,
        source_roots: tuple[str, ...],
        case_root_rel: str,
        staging_root: Path,
        base_cn_seq: int,
        custodian_ids: tuple[str, ...],
    ) -> list[InventoryWorkingItem]:
        imported_items: list[InventoryWorkingItem] = []
        for src_idx, root_str in enumerate(source_roots, start=1):
            base_dir = Path(root_str) if case_root_rel in ("", ".") else Path(root_str) / case_root_rel
            sleuth_entries = StateIpedStorageReaderAdapter.read_sleuth_items(str(base_dir))
            if not sleuth_entries:
                continue
            parent_cn = ControlNumber.root(base_cn_seq + src_idx - 1)
            seq = 0
            for entry in sleuth_entries:
                hash_ref = entry.md5_hex or entry.sha256_hex
                if not hash_ref:
                    continue
                raw_data, calc_sha = StateIpedStorageReaderAdapter.read_full_verified_blob(
                    str(base_dir), hash_ref, entry.storage_id
                )
                if not raw_data:
                    continue
                seq += 1
                child_cn = parent_cn.child(seq)
                safe_name = entry.name.replace("/", "_").replace("\\", "_") or f"obj_{entry.obj_id}.bin"
                out_file = staging_root / "iped_shards" / child_cn.code / safe_name
                os.makedirs(str(out_file.parent), exist_ok=True)
                out_file.write_bytes(raw_data)
                child_magic = _classify_header_quick(raw_data[:64], safe_name)
                imported_items.append(
                    InventoryWorkingItem(
                        control_number=child_cn.code,
                        parent_control_number=None,
                        source_id=f"SRC-{src_idx:02d}",
                        origin_rel_path=f"iped_storage!/{safe_name}",
                        staging_or_vault_path=str(out_file),
                        size_bytes=len(raw_data),
                        mtime_utc_ns=0,
                        is_os_readonly=False,
                        sha256_hex=calc_sha,
                        magic_signature=child_magic,
                        extension_spoofed=False,
                        is_encrypted_or_corrupted=False,
                        pdf_eof_count=raw_data.count(b"%%EOF") if child_magic == MagicSignature.PDF_DOCUMENT else 0,
                        has_wal_shm_sibling=False,
                        custodian_ids=custodian_ids,
                    )
                )
        return imported_items

    def _unpack_zip_recursive(
        self,
        archive_path: Path,
        parent_cn: ControlNumber,
        parent_sha256: str,
        parent_rel_path: str,
        source_id: str,
        staging_root: Path,
        custodian_ids: tuple[str, ...],
        depth: int,
        ckpt_mgr: ContainerExpansionCheckpointManager,
        updated_at_utc: str,
    ) -> tuple[list[InventoryWorkingItem], list[DeadLetterExceptionRecord], bool]:
        if depth > 4:
            return [], [], True
        children: list[InventoryWorkingItem] = []
        dls: list[DeadLetterExceptionRecord] = []
        ext_arch = SafeOsPath(str(archive_path)).to_os_extended(is_windows=(os.name == "nt"))

        try:
            with open(ext_arch, "rb") as raw_fh:
                with zipfile.ZipFile(raw_fh, mode="r") as zf:
                    members = [m for m in zf.infolist() if not m.is_dir()]
                    expected_cnt = len(members)
                    ckpt_mgr.mark_progress(
                        parent_cn=parent_cn.code,
                        parent_sha256=parent_sha256,
                        state="EXPANDING",
                        expected_children=expected_cnt,
                        unpacked_children=0,
                        completed_all=False,
                        updated_at_utc=updated_at_utc,
                    )
                    seq = 0
                    for info in members:
                        seq += 1
                        child_cn = parent_cn.child(seq)
                        safe_rel = validate_safe_archive_member(
                            info.filename, info.compress_size, info.file_size
                        )
                        if info.flag_bits & 0x1:
                            dls.append(
                                DeadLetterExceptionRecord(
                                    control_number=child_cn.code,
                                    rel_path=f"{parent_rel_path}!/{safe_rel}",
                                    sha256_hex="0" * 64,
                                    reason_code="ZIP_PASSWORD_PROTECTED",
                                    detail="Membro protegido por senha sem credencial nos autos.",
                                )
                            )
                            continue

                        target_file = staging_root / child_cn.code / safe_rel
                        os.makedirs(str(target_file.parent), exist_ok=True)

                        if target_file.exists() and int(target_file.stat().st_size) == int(info.file_size):
                            existing_bytes = target_file.read_bytes()
                            child_sha = hashlib.sha256(existing_bytes).hexdigest()
                            header_buf = existing_bytes[:64]
                            written = len(existing_bytes)
                        else:
                            hasher = hashlib.sha256()
                            header_buf = b""
                            written = 0
                            with zf.open(info, mode="r") as member_stream, open(target_file, "wb") as out_fh:
                                while True:
                                    chunk = member_stream.read(262144)
                                    if not chunk:
                                        break
                                    if not header_buf:
                                        header_buf = chunk[:64]
                                    written += len(chunk)
                                    if written > 512 * 1024 * 1024:
                                        raise ContainerSecurityViolationError(
                                            f"Tamanho real descompactado excedeu limite em {safe_rel}"
                                        )
                                    hasher.update(chunk)
                                    out_fh.write(chunk)
                            child_sha = hasher.hexdigest()

                        if PriorityTierScheduler.is_recursive_self_clone(parent_sha256, child_sha):
                            if target_file.exists():
                                target_file.unlink()
                            dls.append(
                                DeadLetterExceptionRecord(
                                    control_number=child_cn.code,
                                    rel_path=f"{parent_rel_path}!/{safe_rel}",
                                    sha256_hex=child_sha,
                                    reason_code="RECURSIVE_CLONE_BLOCKED",
                                    detail="Subitem com mesmo SHA-256 do conteiner pai bloqueado contra recursao infinita.",
                                )
                            )
                            continue

                        child_magic = _classify_header_quick(header_buf, safe_rel)
                        eof_cnt = 0
                        if child_magic == MagicSignature.PDF_DOCUMENT:
                            eof_cnt = target_file.read_bytes().count(b"%%EOF")

                        child_item = InventoryWorkingItem(
                            control_number=child_cn.code,
                            parent_control_number=parent_cn.code,
                            source_id=source_id,
                            origin_rel_path=f"{parent_rel_path}!/{safe_rel}",
                            staging_or_vault_path=str(target_file),
                            size_bytes=written,
                            mtime_utc_ns=0,
                            is_os_readonly=False,
                            sha256_hex=child_sha,
                            magic_signature=child_magic,
                            extension_spoofed=False,
                            is_encrypted_or_corrupted=False,
                            pdf_eof_count=eof_cnt,
                            has_wal_shm_sibling=False,
                            custodian_ids=custodian_ids,
                        )
                        children.append(child_item)

                        ckpt_mgr.mark_progress(
                            parent_cn=parent_cn.code,
                            parent_sha256=parent_sha256,
                            state="EXPANDING",
                            expected_children=expected_cnt,
                            unpacked_children=seq,
                            completed_all=False,
                            updated_at_utc=updated_at_utc,
                        )

                        if (
                            self._interrupt_after_children is not None
                            and seq >= self._interrupt_after_children
                        ):
                            return children, dls, False

                        if child_magic in (
                            MagicSignature.ZIP_CONTAINER,
                            MagicSignature.CELLEBRITE_UFDR_UFDX,
                        ):
                            sub_children, sub_dls, _ = self._unpack_zip_recursive(
                                archive_path=target_file,
                                parent_cn=child_cn,
                                parent_sha256=child_sha,
                                parent_rel_path=child_item.origin_rel_path,
                                source_id=source_id,
                                staging_root=staging_root,
                                custodian_ids=custodian_ids,
                                depth=depth + 1,
                                ckpt_mgr=ckpt_mgr,
                                updated_at_utc=updated_at_utc,
                            )
                            children.extend(sub_children)
                            dls.extend(sub_dls)

                    ckpt_mgr.mark_progress(
                        parent_cn=parent_cn.code,
                        parent_sha256=parent_sha256,
                        state="COMPLETED",
                        expected_children=expected_cnt,
                        unpacked_children=expected_cnt,
                        completed_all=True,
                        updated_at_utc=updated_at_utc,
                    )
        except zipfile.BadZipFile as exc:
            dls.append(
                DeadLetterExceptionRecord(
                    control_number=parent_cn.code,
                    rel_path=parent_rel_path,
                    sha256_hex="0" * 64,
                    reason_code="CORRUPTED_ZIP_CONTAINER",
                    detail=str(exc),
                )
            )
        return children, dls, True


class UniversalExtractorRunnerAdapter:
    """Subetapa 4.3 — Executa os extratores nas 5 filas P0->P4 + upgrades forenses Delta v2.1."""

    def __init__(
        self,
        custom_registry: ExtractorRegistry | None = None,
        audio_transcriber_fn: Callable[[str, int, int], str] | None = None,
    ) -> None:
        self._custom_registry = custom_registry
        self._audio_transcriber_fn = audio_transcriber_fn
        self.last_audio_cache: AudioTranscriptDeduplicatedCache | None = None
        self.execution_trace: list[tuple[str, str]] = []

    def run_extractors_on_inventory(
        self,
        items: tuple[InventoryWorkingItem, ...],
        dynamic_schemas: tuple[DynamicSchemaBlueprint, ...],
        seizure_epoch_seconds: int | None,
        captured_at_utc: str,
        catalog_db_path: str = "",
    ) -> tuple[ExtractionBatchOutput, int]:
        """Despacha os itens seguindo estritamente a barreira P0 -> P1 -> P2 -> P3 -> P4."""
        timeline_all: list[TimelineEventRecord] = []
        financial_all: list[FinancialLedgerEntryRecord] = []
        telecom_all: list[TelecomCdrRecord] = []
        cgnat_all: list[CgnatAuditRecord] = []
        chunks_all: list[AnchoredTextChunk] = []
        new_docs_all: list[PrimaryDocumentCandidate] = []
        recovered_sqlite_all: list[RecoveredSqliteRecord] = []
        link_prov_all: list[WindowsLinkProvenanceRecord] = []
        seen_fin_sigs: set[str] = set()
        pdf_multi_eof = 0

        self.execution_trace = []
        contact_directory: dict[str, str] = {}
        audio_cache = AudioTranscriptDeduplicatedCache(
            catalog_db_path=catalog_db_path,
            transcriber_fn=self._audio_transcriber_fn,
        )
        self.last_audio_cache = audio_cache

        schemas_by_rel: dict[str, list[DynamicSchemaBlueprint]] = {}
        for ds in dynamic_schemas:
            if ds.approved_by_verifier:
                schemas_by_rel.setdefault(ds.origin_rel_path, []).append(ds)

        registry = self._build_registry(schemas_by_rel, contact_directory, audio_cache)
        scheduled_tiers = PriorityTierScheduler.schedule_tiers(items)
        tier_order: list[tuple[str, int]] = []

        for tier, tier_items in scheduled_tiers:
            tier_order.append((str(tier), len(tier_items)))
            if tier == ProcessingPriorityTier.P4_CROSS_BACKUP_MERGE_TIMELINE:
                timeline_all.sort(key=lambda ev: (ev.epoch_seconds, ev.event_id))
                continue

            for item in tier_items:
                if item.is_denist_logical or item.is_encrypted_or_corrupted:
                    continue
                if (
                    item.duplicate_of_cn is not None
                    and item.magic_signature != MagicSignature.WAV_AUDIO
                ):
                    continue
                if item.pdf_eof_count > 1:
                    pdf_multi_eof += 1

                self.execution_trace.append((str(tier), item.origin_rel_path))

                if (
                    tier == ProcessingPriorityTier.P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS
                    and item.magic_signature == MagicSignature.SQLITE3
                ):
                    uri_c = SafeOsPath(str(Path(item.staging_or_vault_path).resolve())).to_sqlite_immutable_uri(
                        is_windows=(os.name == "nt")
                    )
                    contact_directory.update(extract_contacts_from_wa_db(uri_c))

                for spec in registry.specs:
                    if spec.predicate(item):
                        out = spec.handler(item, seizure_epoch_seconds, seen_fin_sigs, captured_at_utc)
                        timeline_all.extend(out.timeline_events)
                        financial_all.extend(out.financial_entries)
                        telecom_all.extend(out.telecom_records)
                        cgnat_all.extend(out.cgnat_records)
                        chunks_all.extend(out.anchored_chunks)
                        new_docs_all.extend(out.new_primary_docs)
                        recovered_sqlite_all.extend(out.recovered_sqlite_records)
                        link_prov_all.extend(out.link_provenance_records)

        merged = ExtractionBatchOutput(
            timeline_events=tuple(timeline_all),
            financial_entries=tuple(financial_all),
            telecom_records=tuple(telecom_all),
            cgnat_records=tuple(cgnat_all),
            anchored_chunks=tuple(chunks_all),
            new_primary_docs=tuple(new_docs_all),
            recovered_sqlite_records=tuple(recovered_sqlite_all),
            link_provenance_records=tuple(link_prov_all),
            tier_execution_order=tuple(tier_order),
        )
        return merged, pdf_multi_eof

    def _build_registry(
        self,
        schemas_by_rel: dict[str, list[DynamicSchemaBlueprint]],
        contact_directory: dict[str, str],
        audio_cache: AudioTranscriptDeduplicatedCache,
    ) -> ExtractorRegistry:
        reg = ExtractorRegistry()
        if self._custom_registry is not None:
            for s in self._custom_registry.specs:
                reg.register(s)

        reg.register(
            RegisteredExtractorSpec(
                name="PdfBinaryAndOcrExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.PDF_DOCUMENT,
                handler=self._extract_pdf,
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="MobileAndDynamicSqliteExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.SQLITE3,
                handler=lambda it, sez, fin_s, cap: self._extract_sqlite_known_and_dynamic(
                    it, schemas_by_rel, contact_directory, sez, cap
                ),
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="WindowsLnkProvenanceExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.WINDOWS_LNK_SHORTCUT,
                handler=self._extract_windows_lnk,
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="CellebriteUfdrXmlStreamExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.XML_DOCUMENT,
                handler=self._extract_cellebrite_xml_streaming,
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="TabularEmailAndPrimaryTextExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.UTF8_TEXT_OR_CSV,
                handler=self._extract_text_tabular_email,
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="AudioWaveVadWhisperExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.WAV_AUDIO,
                handler=lambda it, sez, fin_s, cap: self._extract_wav_audio_cached(
                    it, audio_cache, cap
                ),
            )
        )
        reg.register(
            RegisteredExtractorSpec(
                name="CompressibleUnknownBinaryStringsExtractor",
                predicate=lambda it: it.magic_signature == MagicSignature.UNKNOWN_BINARY,
                handler=self._extract_compressible_binary_strings,
            )
        )
        return reg

    def _extract_windows_lnk(
        self,
        item: InventoryWorkingItem,
        _seizure_epoch: int | None,
        _seen_fin: set[str],
        _captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        recs, chks = WindowsArtifactProvenanceExtractor.extract_lnk_file(
            file_path=item.staging_or_vault_path,
            origin_cn=item.control_number,
            origin_rel_path=item.origin_rel_path,
            origin_sha256=item.sha256_hex,
        )
        return ExtractionBatchOutput(
            anchored_chunks=chks,
            link_provenance_records=recs,
        )

    def _extract_compressible_binary_strings(
        self,
        item: InventoryWorkingItem,
        _seizure_epoch: int | None,
        _seen_fin: set[str],
        _captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        ext_p = SafeOsPath(item.staging_or_vault_path).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_p, "rb") as fh:
            raw = fh.read(524_288)
        filtered = filter_compressible_windows_for_bm25(raw)
        if not filtered:
            return ExtractionBatchOutput()
        ascii_runs = [
            m.group(0).decode("ascii", errors="ignore")
            for m in re.finditer(rb"[\x20-\x7e]{8,256}", filtered)
        ]
        if not ascii_runs:
            return ExtractionBatchOutput()
        joined = "\n".join(ascii_runs[:100])
        chunks = build_overlapping_sanitized_chunks(
            origin_cn=item.control_number,
            origin_path=item.origin_rel_path,
            base_locator="compressible_binary_strings",
            raw_text=joined,
            origin_sha256=item.sha256_hex,
        )
        return ExtractionBatchOutput(anchored_chunks=chunks)

    def _extract_pdf(
        self,
        item: InventoryWorkingItem,
        seizure_epoch: int | None,
        _seen_fin: set[str],
        captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        ext_p = SafeOsPath(item.staging_or_vault_path).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_p, "rb") as fh:
            raw = fh.read(8 * 1024 * 1024)
        pages = raw.split(b"/Type /Page")
        chunks: list[AnchoredTextChunk] = []
        full_parts: list[str] = []

        for pg_idx, pg_bytes in enumerate(pages if len(pages) > 1 else [raw], start=1):
            parts = [
                m.group(1).decode("utf-8", errors="ignore")
                for m in _PDF_TEXT_STREAM_RE.finditer(pg_bytes)
            ]
            pg_text = " ".join(p.strip() for p in parts if p.strip())
            if not pg_text and shutil.which("tesseract"):
                pg_text = ""
            if pg_text:
                full_parts.append(pg_text)
                chunks.extend(
                    build_overlapping_sanitized_chunks(
                        origin_cn=item.control_number,
                        origin_path=item.origin_rel_path,
                        base_locator=f"p. {pg_idx}",
                        raw_text=pg_text,
                        origin_sha256=item.sha256_hex,
                    )
                )

        joined = "\n".join(full_parts)
        new_docs: list[PrimaryDocumentCandidate] = []
        if item.parent_control_number is not None and joined:
            cand = detect_primary_doc_in_unpacked_text(
                rel_path=item.origin_rel_path,
                origin_cn=item.control_number,
                sha256_hex=item.sha256_hex,
                text=joined,
                captured_at_utc=captured_at_utc,
                source_id=item.source_id,
            )
            if cand is not None:
                new_docs.append(cand)

        info_xmp_conflict = (b"/ModDate" in raw and b"xmp:ModifyDate" in raw)
        events: list[TimelineEventRecord] = []
        if item.pdf_eof_count > 1:
            ev_id = "EV-PDF-" + sha256_text(f"{item.control_number}|EOF")[:12].upper()
            events.append(
                TimelineEventRecord(
                    event_id=ev_id,
                    origin_cn=item.control_number,
                    event_type="PDF_INCREMENTAL_UPDATE_DETECTED",
                    raw_ts=captured_at_utc,
                    epoch_kind="ISO8601_OFFSET",
                    tz_declared="UTC",
                    ts_utc=captured_at_utc,
                    epoch_seconds=parse_timestamp_to_utc(captured_at_utc).epoch_seconds,
                    is_post_seizure=False,
                    actor_origin="PDF_PRODUCER",
                    actor_target="DOCUMENT_STREAM",
                    content_verbatim=f"PDF contem {item.pdf_eof_count} marcadores %%EOF",
                    locator="trailer_eof",
                    origin_sha256=item.sha256_hex,
                )
            )
        return ExtractionBatchOutput(
            timeline_events=tuple(events),
            anchored_chunks=tuple(chunks),
            new_primary_docs=tuple(new_docs),
            pdf_info_xmp_conflict=info_xmp_conflict,
        )

    def _extract_sqlite_known_and_dynamic(
        self,
        item: InventoryWorkingItem,
        schemas_by_rel: dict[str, list[DynamicSchemaBlueprint]],
        contact_directory: dict[str, str],
        seizure_epoch: int | None,
        _captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        uri = SafeOsPath(str(Path(item.staging_or_vault_path).resolve())).to_sqlite_immutable_uri(
            is_windows=(os.name == "nt")
        )
        events: list[TimelineEventRecord] = []
        chunks: list[AnchoredTextChunk] = []
        active_texts: set[str] = set()

        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("PRAGMA query_only = 1;")
            tables = {
                str(r[0]).lower(): str(r[0])
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            lid_to_phone, view_once_ids = resolve_whatsapp_modern_lids_and_view_once(conn, tables)

            if "messages" in tables or "message" in tables:
                tbl = tables.get("messages") or tables["message"]
                cols = {
                    str(c[1]).lower()
                    for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()
                }
                if {"timestamp", "text_data"}.issubset(cols) or {"timestamp", "data"}.issubset(cols):
                    txt_col = "text_data" if "text_data" in cols else "data"
                    sender_col = "sender_jid" if "sender_jid" in cols else ("key_remote_jid" if "key_remote_jid" in cols else "rowid")
                    rows = conn.execute(
                        f"SELECT rowid, timestamp, {sender_col}, {txt_col} FROM {tbl} ORDER BY rowid"
                    ).fetchall()
                    for rowid, raw_ms, sender, body in rows:
                        ts_utc = from_unix_milliseconds(int(raw_ms))
                        post_flag = is_event_post_seizure(ts_utc.epoch_seconds, seizure_epoch)
                        raw_sender = str(sender or "LOCAL_USER")
                        resolved_jid = lid_to_phone.get(raw_sender, raw_sender)
                        enriched_actor = contact_directory.get(resolved_jid, resolved_jid)
                        base_body = str(body or "")
                        if base_body:
                            active_texts.add(base_body)
                        vo_prefix = "[VIEW_ONCE_EPHEMERAL] " if int(rowid) in view_once_ids else ""
                        verbatim = f"{vo_prefix}{base_body}".strip()
                        loc = f"table={tbl} rowid={rowid}"
                        events.append(
                            TimelineEventRecord(
                                event_id="EV-WA-AND-" + sha256_text(f"{item.control_number}|{rowid}")[:12].upper(),
                                origin_cn=item.control_number,
                                event_type="WHATSAPP_ANDROID_MSG",
                                raw_ts=str(raw_ms),
                                epoch_kind=str(ts_utc.epoch_kind),
                                tz_declared="UTC",
                                ts_utc=ts_utc.iso_utc,
                                epoch_seconds=ts_utc.epoch_seconds,
                                is_post_seizure=post_flag,
                                actor_origin=enriched_actor,
                                actor_target="CHAT",
                                content_verbatim=verbatim,
                                locator=loc,
                                origin_sha256=item.sha256_hex,
                            )
                        )
                        chunks.extend(
                            build_overlapping_sanitized_chunks(
                                item.control_number, item.origin_rel_path, loc, verbatim, item.sha256_hex
                            )
                        )

            if "zwamessage" in tables:
                tbl_ios = tables["zwamessage"]
                rows_ios = conn.execute(
                    f"SELECT Z_PK, ZMESSAGEDATE, ZFROMJID, ZTEXT FROM {tbl_ios} ORDER BY Z_PK"
                ).fetchall()
                for zpk, cocoa_s, from_jid, ztext in rows_ios:
                    ts_utc = from_cocoa_seconds(int(cocoa_s))
                    post_flag = is_event_post_seizure(ts_utc.epoch_seconds, seizure_epoch)
                    verbatim = str(ztext or "")
                    if verbatim:
                        active_texts.add(verbatim)
                    raw_ios_sender = str(from_jid or "IOS_USER")
                    enriched_ios = contact_directory.get(raw_ios_sender, raw_ios_sender)
                    loc = f"table={tbl_ios} Z_PK={zpk}"
                    events.append(
                        TimelineEventRecord(
                            event_id="EV-WA-IOS-" + sha256_text(f"{item.control_number}|{zpk}")[:12].upper(),
                            origin_cn=item.control_number,
                            event_type="WHATSAPP_IOS_MSG",
                            raw_ts=str(cocoa_s),
                            epoch_kind=str(ts_utc.epoch_kind),
                            tz_declared="UTC",
                            ts_utc=ts_utc.iso_utc,
                            epoch_seconds=ts_utc.epoch_seconds,
                            is_post_seizure=post_flag,
                            actor_origin=enriched_ios,
                            actor_target="CHAT",
                            content_verbatim=verbatim,
                            locator=loc,
                            origin_sha256=item.sha256_hex,
                        )
                    )
                    chunks.extend(
                        build_overlapping_sanitized_chunks(
                            item.control_number, item.origin_rel_path, loc, verbatim, item.sha256_hex
                        )
                    )

            dyn_list = list(schemas_by_rel.get(item.origin_rel_path, ()))
            if not dyn_list:
                for tbl_low, tbl_real in tables.items():
                    if tbl_low in (
                        "messages",
                        "message",
                        "zwamessage",
                        "sqlite_sequence",
                        "android_metadata",
                        "jid",
                        "jid_map",
                        "lid_me_mapping",
                        "message_view_once_media",
                        "wa_contacts",
                    ):
                        continue
                    if not _SAFE_IDENT_RE.match(tbl_real):
                        continue
                    col_rows = conn.execute(f"PRAGMA table_info({tbl_real})").fetchall()
                    c_names = [str(c[1]) for c in col_rows if _SAFE_IDENT_RE.match(str(c[1]))]
                    if len(c_names) >= 2:
                        ts_c = next((c for c in c_names if any(k in c.lower() for k in ("ts", "time", "date", "utc"))), c_names[0])
                        act_c = next((c for c in c_names if any(k in c.lower() for k in ("sender", "user", "actor", "author"))), c_names[0])
                        cnt_c = next((c for c in c_names if any(k in c.lower() for k in ("body", "text", "msg", "content", "payload", "note"))), c_names[-1])
                        dyn_list.append(
                            DynamicSchemaBlueprint(
                                schema_hash=sha256_text(f"{item.origin_rel_path}|{tbl_real}"),
                                origin_rel_path=item.origin_rel_path,
                                table_name=tbl_real,
                                columns=tuple(c_names),
                                timestamp_column=ts_c,
                                actor_column=act_c,
                                content_column=cnt_c,
                                inferred_domain="DYNAMIC_SQLITE_TABLE",
                                extraction_sql_template=f"SELECT {ts_c}, {act_c}, {cnt_c} FROM {tbl_real}",
                                approved_by_verifier=True,
                            )
                        )

            for bp in dyn_list:
                if not (
                    _SAFE_IDENT_RE.match(bp.table_name)
                    and _SAFE_IDENT_RE.match(bp.timestamp_column)
                    and _SAFE_IDENT_RE.match(bp.actor_column)
                    and _SAFE_IDENT_RE.match(bp.content_column)
                ):
                    continue
                dyn_rows = conn.execute(
                    f"SELECT rowid, {bp.timestamp_column}, {bp.actor_column}, {bp.content_column} "
                    f"FROM {bp.table_name} ORDER BY rowid"
                ).fetchall()
                for r_id, raw_t, actor_v, content_v in dyn_rows:
                    ts_parsed = self._coerce_dynamic_timestamp(raw_t)
                    post_flag = is_event_post_seizure(ts_parsed.epoch_seconds, seizure_epoch)
                    verbatim = str(content_v or "")
                    if verbatim:
                        active_texts.add(verbatim)
                    loc = f"dynamic_table={bp.table_name} rowid={r_id}"
                    events.append(
                        TimelineEventRecord(
                            event_id="EV-DYN-" + sha256_text(f"{item.control_number}|{bp.table_name}|{r_id}")[:12].upper(),
                            origin_cn=item.control_number,
                            event_type=f"DYNAMIC_SQLITE::{bp.table_name}",
                            raw_ts=str(raw_t),
                            epoch_kind=str(ts_parsed.epoch_kind),
                            tz_declared=ts_parsed.tz_declared,
                            ts_utc=ts_parsed.iso_utc,
                            epoch_seconds=ts_parsed.epoch_seconds,
                            is_post_seizure=post_flag,
                            actor_origin=str(actor_v or "UNKNOWN"),
                            actor_target=bp.table_name,
                            content_verbatim=verbatim,
                            locator=loc,
                            origin_sha256=item.sha256_hex,
                        )
                    )
                    chunks.extend(
                        build_overlapping_sanitized_chunks(
                            item.control_number, item.origin_rel_path, loc, verbatim, item.sha256_hex
                        )
                    )
        finally:
            conn.close()

        recovered_recs = SQLiteDeletedRecordsInspector.inspect_database_file(
            db_path=item.staging_or_vault_path,
            origin_cn=item.control_number,
            origin_rel_path=item.origin_rel_path,
            origin_sha256=item.sha256_hex,
            active_texts=frozenset(active_texts),
        )
        for r_rec in recovered_recs:
            chunks.append(
                build_sanitized_chunk(
                    origin_cn=item.control_number,
                    origin_path=item.origin_rel_path,
                    locator=f"[{r_rec.allocation_state}] {r_rec.page_or_frame_locator}",
                    raw_text=f"[{r_rec.allocation_state}] {r_rec.recovered_text}",
                    origin_sha256=item.sha256_hex,
                )
            )

        return ExtractionBatchOutput(
            timeline_events=tuple(events),
            anchored_chunks=tuple(chunks),
            recovered_sqlite_records=recovered_recs,
        )

    def _coerce_dynamic_timestamp(self, raw_val: object):
        if isinstance(raw_val, int):
            if raw_val > 10_000_000_000:
                return from_unix_milliseconds(raw_val)
            return from_unix_seconds(raw_val)
        raw_str = str(raw_val or "").strip()
        if raw_str.isdigit():
            val_int = int(raw_str)
            if val_int > 10_000_000_000:
                return from_unix_milliseconds(val_int)
            return from_unix_seconds(val_int)
        try:
            return parse_timestamp_to_utc(raw_str)
        except (ValueError, TypeError):
            return from_unix_seconds(0, raw_str)

    def _extract_cellebrite_xml_streaming(
        self,
        item: InventoryWorkingItem,
        seizure_epoch: int | None,
        _seen_fin: set[str],
        _captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        ext_p = SafeOsPath(item.staging_or_vault_path).to_os_extended(is_windows=(os.name == "nt"))
        events: list[TimelineEventRecord] = []
        chunks: list[AnchoredTextChunk] = []
        msg_idx = 0

        try:
            with open(ext_p, "rb") as fh:
                for _, elem in ET.iterparse(fh, events=("end",)):
                    tag_clean = elem.tag.rsplit("}", 1)[-1].lower()
                    if tag_clean in ("instantmessage", "message", "call"):
                        msg_idx += 1
                        body = (elem.findtext("body") or elem.findtext("Body") or elem.text or "").strip()
                        raw_ts = (elem.get("timestamp") or elem.findtext("timestamp") or "2026-01-01T00:00:00Z").strip()
                        sender = (elem.get("from") or elem.findtext("from") or "UFDR_ACTOR").strip()
                        ts_u = parse_timestamp_to_utc(raw_ts)
                        post = is_event_post_seizure(ts_u.epoch_seconds, seizure_epoch)
                        loc = f"xml_node={tag_clean}[{msg_idx}]"
                        events.append(
                            TimelineEventRecord(
                                event_id="EV-UFDR-" + sha256_text(f"{item.control_number}|{msg_idx}")[:12].upper(),
                                origin_cn=item.control_number,
                                event_type="CELLEBRITE_UFDR_STREAM",
                                raw_ts=raw_ts,
                                epoch_kind=str(ts_u.epoch_kind),
                                tz_declared=ts_u.tz_declared,
                                ts_utc=ts_u.iso_utc,
                                epoch_seconds=ts_u.epoch_seconds,
                                is_post_seizure=post,
                                actor_origin=sender,
                                actor_target="UFDR_TARGET",
                                content_verbatim=body,
                                locator=loc,
                                origin_sha256=item.sha256_hex,
                            )
                        )
                        if body:
                            chunks.append(
                                build_sanitized_chunk(
                                    item.control_number, item.origin_rel_path, loc, body, item.sha256_hex
                                )
                            )
                        elem.clear()
        except ET.ParseError:
            return ExtractionBatchOutput()

        return ExtractionBatchOutput(timeline_events=tuple(events), anchored_chunks=tuple(chunks))

    def _extract_text_tabular_email(
        self,
        item: InventoryWorkingItem,
        seizure_epoch: int | None,
        seen_fin_sigs: set[str],
        captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        ext_p = SafeOsPath(item.staging_or_vault_path).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_p, "rb") as fh:
            raw_bytes = fh.read(4 * 1024 * 1024)
        text = raw_bytes.decode("utf-8", errors="replace")

        fin_entries = PureTabularForensicParsers.parse_simba_or_financial_csv(
            text, item.control_number, item.sha256_hex, seen_fin_sigs
        )
        cdr_entries = PureTabularForensicParsers.parse_cdr_erb_csv(
            text, item.control_number, item.sha256_hex
        )
        cgnat_entries = PureTabularForensicParsers.parse_cgnat_logs(
            text, item.control_number, item.sha256_hex
        )

        events: list[TimelineEventRecord] = []
        chunks: list[AnchoredTextChunk] = list(
            build_overlapping_sanitized_chunks(
                item.control_number, item.origin_rel_path, "full_text", text, item.sha256_hex
            )
        )

        if item.origin_rel_path.lower().endswith((".eml", ".mbox")) or "Message-ID:" in text:
            msg = BytesParser(policy=email_policy.default).parsebytes(raw_bytes)
            msg_id = str(msg.get("Message-ID", "NO_MSG_ID"))
            auth_res = str(msg.get("Authentication-Results", "NONE"))
            subj = str(msg.get("Subject", ""))
            date_hdr = str(msg.get("Date", ""))
            try:
                ts_u = parse_timestamp_to_utc(date_hdr)
            except Exception:
                ts_u = parse_timestamp_to_utc(captured_at_utc)
            events.append(
                TimelineEventRecord(
                    event_id="EV-EML-" + sha256_text(f"{item.control_number}|{msg_id}")[:12].upper(),
                    origin_cn=item.control_number,
                    event_type="EMAIL_MESSAGE",
                    raw_ts=date_hdr or captured_at_utc,
                    epoch_kind=str(ts_u.epoch_kind),
                    tz_declared=ts_u.tz_declared,
                    ts_utc=ts_u.iso_utc,
                    epoch_seconds=ts_u.epoch_seconds,
                    is_post_seizure=is_event_post_seizure(ts_u.epoch_seconds, seizure_epoch),
                    actor_origin=str(msg.get("From", "")),
                    actor_target=str(msg.get("To", "")),
                    content_verbatim=f"{subj} [Auth:{auth_res}]",
                    locator=f"Message-ID={msg_id}",
                    origin_sha256=item.sha256_hex,
                )
            )

        for fe in fin_entries:
            ts_f = parse_timestamp_to_utc(fe.tx_utc)
            events.append(
                TimelineEventRecord(
                    event_id="EV-FIN-" + fe.entry_id[4:],
                    origin_cn=fe.origin_cn,
                    event_type="SIMBA_FINANCIAL_TX",
                    raw_ts=fe.tx_utc,
                    epoch_kind="ISO8601_OFFSET",
                    tz_declared="UTC",
                    ts_utc=fe.tx_utc,
                    epoch_seconds=ts_f.epoch_seconds,
                    is_post_seizure=is_event_post_seizure(ts_f.epoch_seconds, seizure_epoch),
                    actor_origin=fe.holder_tax_id,
                    actor_target=fe.counterparty_tax_id,
                    content_verbatim=f"{fe.debit_credit} {fe.raw_amount_text} ({fe.amount_cents} cents)",
                    locator=fe.locator,
                    origin_sha256=fe.origin_sha256,
                )
            )

        for cdr in cdr_entries:
            events.append(
                TimelineEventRecord(
                    event_id="EV-CDR-" + cdr.cdr_id[4:],
                    origin_cn=cdr.origin_cn,
                    event_type="TELECOM_CDR_ERB",
                    raw_ts=cdr.start_utc,
                    epoch_kind="ISO8601_OFFSET",
                    tz_declared="UTC",
                    ts_utc=cdr.start_utc,
                    epoch_seconds=cdr.epoch_seconds,
                    is_post_seizure=is_event_post_seizure(cdr.epoch_seconds, seizure_epoch),
                    actor_origin=cdr.caller,
                    actor_target=cdr.callee,
                    content_verbatim=f"CGI={cdr.cell_cgi} Azimute={cdr.azimuth_deg} Jump={cdr.impossible_speed_flag}",
                    locator=cdr.locator,
                    origin_sha256=cdr.origin_sha256,
                )
            )

        new_docs: list[PrimaryDocumentCandidate] = []
        if item.parent_control_number is not None:
            cand = detect_primary_doc_in_unpacked_text(
                rel_path=item.origin_rel_path,
                origin_cn=item.control_number,
                sha256_hex=item.sha256_hex,
                text=text,
                captured_at_utc=captured_at_utc,
                source_id=item.source_id,
            )
            if cand is not None:
                new_docs.append(cand)

        return ExtractionBatchOutput(
            timeline_events=tuple(events),
            financial_entries=fin_entries,
            telecom_records=cdr_entries,
            cgnat_records=cgnat_entries,
            anchored_chunks=tuple(chunks),
            new_primary_docs=tuple(new_docs),
        )

    def _extract_wav_audio_cached(
        self,
        item: InventoryWorkingItem,
        audio_cache: AudioTranscriptDeduplicatedCache,
        captured_at_utc: str,
    ) -> ExtractionBatchOutput:
        try:
            chks = audio_cache.get_or_transcribe_wav(
                wav_path=item.staging_or_vault_path,
                origin_cn=item.control_number,
                origin_rel_path=item.origin_rel_path,
                audio_sha256=item.sha256_hex,
                captured_at_utc=captured_at_utc,
            )
            return ExtractionBatchOutput(anchored_chunks=chks)
        except wave.Error:
            return ExtractionBatchOutput()


class Phase04CatalogAndFiveReportsAdapter:
    """Subetapas 4.4 e 4.5 — Persistencia unificada idempotente + 5 Relatorios Oficiais EDRM 5.0."""

    def persist_and_generate_five_reports(
        self,
        phase03_bundle: Phase03ToPhase04Contract,
        filtered_items: tuple[InventoryWorkingItem, ...],
        dead_letters: tuple[DeadLetterExceptionRecord, ...],
        extracted: ExtractionBatchOutput,
    ) -> tuple[tuple[str, str, str], ...]:
        """Persiste inventario pai-filho, eventos, financas, telecom, chunks e gera os 5 relatorios."""
        gov = phase03_bundle.phase02_bundle.phase01_bundle.governance
        is_win = os.name == "nt"
        db_ext = SafeOsPath(gov.catalog_db_path).to_os_extended(is_windows=is_win)

        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                for it in filtered_items:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO evidence_inventory_tree (
                            control_number, parent_control_number, source_id, origin_rel_path,
                            vault_rel_path, size_bytes, mtime_utc_ns, is_os_readonly,
                            sha256_hex, magic_signature, extension_spoofed,
                            is_encrypted_or_corrupted, pdf_eof_count, has_wal_shm_sibling,
                            is_denist_logical, duplicate_of_cn, all_custodians_json,
                            all_source_paths_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            it.control_number,
                            it.parent_control_number,
                            it.source_id,
                            it.origin_rel_path,
                            it.staging_or_vault_path,
                            it.size_bytes,
                            it.mtime_utc_ns,
                            1 if it.is_os_readonly else 0,
                            it.sha256_hex,
                            str(it.magic_signature),
                            1 if it.extension_spoofed else 0,
                            1 if it.is_encrypted_or_corrupted else 0,
                            it.pdf_eof_count,
                            1 if it.has_wal_shm_sibling else 0,
                            1 if it.is_denist_logical else 0,
                            it.duplicate_of_cn,
                            json.dumps(list(it.all_custodians)),
                            json.dumps(list(it.all_source_paths)),
                        ),
                    )

                for ev in extracted.timeline_events:
                    conn.execute(
                        """
                        INSERT INTO unified_timeline_events (
                            event_id, origin_cn, event_type, raw_ts, epoch_kind,
                            tz_declared, ts_utc, is_post_seizure, actor_origin,
                            actor_target, content_verbatim, locator, origin_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(event_id) DO NOTHING
                        """,
                        (
                            ev.event_id,
                            ev.origin_cn,
                            ev.event_type,
                            ev.raw_ts,
                            ev.epoch_kind,
                            ev.tz_declared,
                            ev.ts_utc,
                            1 if ev.is_post_seizure else 0,
                            ev.actor_origin,
                            ev.actor_target,
                            ev.content_verbatim,
                            ev.locator,
                            ev.origin_sha256,
                        ),
                    )

                for fe in extracted.financial_entries:
                    conn.execute(
                        """
                        INSERT INTO financial_ledger_entries (
                            entry_id, origin_cn, bank_code, branch, account,
                            holder_tax_id, counterparty_tax_id, tx_utc, debit_credit,
                            amount_cents, raw_amount_text, is_inter_file_duplicate,
                            locator, origin_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(entry_id) DO NOTHING
                        """,
                        (
                            fe.entry_id,
                            fe.origin_cn,
                            fe.bank_code,
                            fe.branch,
                            fe.account,
                            fe.holder_tax_id,
                            fe.counterparty_tax_id,
                            fe.tx_utc,
                            fe.debit_credit,
                            fe.amount_cents,
                            fe.raw_amount_text,
                            1 if fe.is_inter_file_duplicate else 0,
                            fe.locator,
                            fe.origin_sha256,
                        ),
                    )

                for cdr in extracted.telecom_records:
                    conn.execute(
                        """
                        INSERT INTO telecom_cdr_erb_events (
                            cdr_id, origin_cn, caller, callee, imei, start_utc,
                            duration_sec, cell_cgi, lat_microdeg, lon_microdeg,
                            azimuth_deg, impossible_speed_flag, locator, origin_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(cdr_id) DO NOTHING
                        """,
                        (
                            cdr.cdr_id,
                            cdr.origin_cn,
                            cdr.caller,
                            cdr.callee,
                            cdr.imei,
                            cdr.start_utc,
                            cdr.duration_sec,
                            cdr.cell_cgi,
                            cdr.lat_microdeg,
                            cdr.lon_microdeg,
                            cdr.azimuth_deg,
                            1 if cdr.impossible_speed_flag else 0,
                            cdr.locator,
                            cdr.origin_sha256,
                        ),
                    )

                for chk in extracted.anchored_chunks:
                    conn.execute(
                        """
                        INSERT INTO hybrid_search_chunks (
                            chunk_id, origin_cn, locator, text_clean,
                            injection_neutralized, vector_blob, origin_sha256
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(chunk_id) DO NOTHING
                        """,
                        (
                            chk.chunk_id,
                            chk.origin_cn,
                            chk.locator,
                            chk.text_clean,
                            1 if chk.injection_neutralized else 0,
                            b"",
                            chk.origin_sha256,
                        ),
                    )
        finally:
            conn.close()

        known_hashes = {it.sha256_hex for it in filtered_items} | {"0" * 64}
        known_cns = {it.control_number for it in filtered_items} | {dl.control_number for dl in dead_letters}
        corpus = "\n".join(chk.text_clean for chk in extracted.anchored_chunks)

        def _build_r1() -> str:
            return "\n".join(
                [
                    "# Relatorio EDRM 5.0 (1/5) — Inventario Completo de Arquivos",
                    *[
                        f"- `{i.control_number}` | `{i.origin_rel_path}` | `{i.size_bytes}` B | `{i.sha256_hex}`"
                        for i in filtered_items
                    ],
                ]
            ) + "\n"

        def _format_paths_preview(item: FilteredEvidenceItem) -> str:
            if item.duplicate_of_cn:
                return f"{item.origin_rel_path} (duplicata de {item.duplicate_of_cn}; total={len(item.all_source_paths)})"
            if len(item.all_source_paths) > 10:
                head = ",".join(item.all_source_paths[:10])
                return f"{head} (+{len(item.all_source_paths) - 10} caminhos no catalogo SQLite)"
            return ",".join(item.all_source_paths)

        def _build_r2() -> str:
            return "\n".join(
                [
                    "# Relatorio EDRM 5.0 (2/5) — Distribuicao por Custodiante e Aparelho",
                    *[
                        f"- `{i.control_number}` | Custodiantes: `{','.join(i.all_custodians)}` | Caminhos: `{_format_paths_preview(i)}`"
                        for i in filtered_items
                    ],
                ]
            ) + "\n"

        def _build_r3() -> str:
            return "\n".join(
                [
                    "# Relatorio EDRM 5.0 (3/5) — Filtragem Auditavel (De-NIST e Deduplicacao Logica)",
                    *[
                        f"- `{i.control_number}` | De-NIST Parent: `{i.is_denist_logical}` | Duplicata de: `{i.duplicate_of_cn or 'CANONICAL'}`"
                        for i in filtered_items
                    ],
                ]
            ) + "\n"

        def _build_r4() -> str:
            return "\n".join(
                [
                    "# Relatorio EDRM 5.0 (4/5) — Cadeia de Custodia do Processamento e Eventos Criticos (Piso Funcional EDRM 1.0–5.0 | Filas P0->P4)",
                    f"- Total de Eventos UTC Extraidos: `{len(extracted.timeline_events)}`",
                    f"- Eventos Pos-Apreensao: `{sum(1 for e in extracted.timeline_events if e.is_post_seizure)}`",
                    f"- Lancamentos Financeiros SIMBA/CSV: `{len(extracted.financial_entries)}`",
                    f"- Registros Telecom CDR/ERB: `{len(extracted.telecom_records)}`",
                    f"- Registros CGNAT sem Porta Logica: `{sum(1 for c in extracted.cgnat_records if c.missing_logical_port_defect)}`",
                    f"- Registros SQLite Recuperados (Freelist/Unallocated/WAL NIST IR 8354): `{len(extracted.recovered_sqlite_records)}`",
                    f"- Artefatos Fisicos de Autoria (.lnk DroidBirth MAC): `{len(extracted.link_provenance_records)}`",
                ]
            ) + "\n"

        def _build_r5() -> str:
            return "\n".join(
                [
                    "# Relatorio EDRM 5.0 (5/5) — Fila Completa de Excecoes (Dead-Letter Queue)",
                    *(
                        [f"- `{dl.control_number}` | `{dl.rel_path}` | `{dl.reason_code}` | {dl.detail}" for dl in dead_letters]
                        if dead_letters
                        else ["- Nenhuma excecao registrada."]
                    ),
                ]
            ) + "\n"

        report_builders = (
            ("edrm5_01_file_inventory.md", _build_r1),
            ("edrm5_02_custodian_report.md", _build_r2),
            ("edrm5_03_denist_dedup_audit.md", _build_r3),
            ("edrm5_04_processing_custody.md", _build_r4),
            ("edrm5_05_dead_letter_exceptions.md", _build_r5),
        )

        saved_meta: list[tuple[str, str, str]] = []
        for fname, builder in report_builders:
            content = builder()
            verify_markdown_report_strictly(content, known_hashes, known_cns, corpus)
            out_p = Path(gov.deliverables_dir) / fname
            ext_out = SafeOsPath(str(out_p)).to_os_extended(is_windows=is_win)
            with open(ext_out, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            saved_meta.append((fname, str(out_p), sha256_text(content)))
            del content

        return tuple(saved_meta)

    def capture_snapshot(self, source_roots: tuple[str, ...], ts_utc: str) -> MediaSnapshot:
        """Recaptura snapshot passivo de --source."""
        entries: list[FileStatEntry] = []
        is_win = os.name == "nt"
        for src_idx, root_str in enumerate(source_roots, start=1):
            source_id = f"SRC-{src_idx:02d}"
            root_path = Path(root_str).resolve()
            all_files = sorted(p for p in root_path.rglob("*") if p.is_file() and not p.is_symlink())
            for abs_f in all_files:
                ext_f = SafeOsPath(str(abs_f)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_f, follow_symlinks=False)
                entries.append(
                    FileStatEntry(
                        source_id=source_id,
                        rel_path=abs_f.relative_to(root_path).as_posix(),
                        size_bytes=int(st.st_size),
                        mtime_utc_ns=int(st.st_mtime_ns),
                        mode_octal=oct(st.st_mode & 0o777),
                        inode_or_file_index=int(st.st_ino),
                        is_os_readonly=not bool(st.st_mode & stat.S_IWUSR),
                    )
                )
        _, snap_sha = canonical_json_sha256([asdict(e) for e in entries])
        return MediaSnapshot(
            captured_at_utc=ts_utc,
            entries=tuple(entries),
            snapshot_sha256=snap_sha,
        )
