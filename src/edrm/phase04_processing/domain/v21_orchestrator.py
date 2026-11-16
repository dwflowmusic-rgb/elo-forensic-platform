"""Orquestrador P0->P4, Chunking com Overlap e Parsers Binarios Puros (.lnk e SQLite Freelist/WAL) — Delta v2.1."""

from __future__ import annotations

from dataclasses import dataclass
import random
import re
import struct

from edrm.phase04_processing.domain import InventoryWorkingItem, build_sanitized_chunk
from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    RecoveredSqliteRecord,
    WindowsLinkProvenanceRecord,
)
from edrm.shared_kernel.enums import (
    MagicSignature,
    ProcessingPriorityTier,
    SqliteRowAllocationState,
)
from edrm.shared_kernel.value_objects import sha256_text

_LNK_CLSID_BYTES: bytes = bytes.fromhex("0114020000000000c000000000000046")
_PRINTABLE_FORENSIC_RUN_RE = re.compile(
    rb"(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]"
    rb"|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
    rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}"
    rb"|\xf4[\x80-\x8f][\x80-\xbf]{2}){6,512}"
)


class PriorityTierScheduler:
    """Escalonador deterministico em 5 filas de dependencia (P0 -> P4) evitando race conditions cross-DB."""

    CONTACT_AND_ACCOUNT_DBS: frozenset[str] = frozenset(
        {
            "wa.db",
            "contactsv2.sqlite",
            "addressbook.sqlitedb",
            "contacts2.db",
            "accounts.db",
            "accounts_ce.db",
        }
    )

    @classmethod
    def classify_tier(cls, item: InventoryWorkingItem) -> ProcessingPriorityTier:
        """Classifica um item na fila de prioridade correspondente (P0 a P3; P4 e consolidacao final)."""
        low_path = item.origin_rel_path.lower()
        base = low_path.rsplit("/", 1)[-1]

        if (
            base.endswith(("-wal", "-shm", ".opus", ".ogg", ".mp3"))
            or "unalloc" in base
            or item.magic_signature
            in (
                MagicSignature.JPEG_IMAGE,
                MagicSignature.PNG_IMAGE,
                MagicSignature.MP4_VIDEO,
                MagicSignature.WAV_AUDIO,
            )
        ):
            return ProcessingPriorityTier.P0_ATOMIC_MEDIA_WAL_UNALLOCATED

        if item.magic_signature in (
            MagicSignature.ZIP_CONTAINER,
            MagicSignature.CELLEBRITE_UFDR_UFDX,
            MagicSignature.EWF_E01,
            MagicSignature.TAR_ARCHIVE,
            MagicSignature.GZIP,
            MagicSignature.RAR_V4_V5,
            MagicSignature.SEVEN_ZIP,
        ):
            return ProcessingPriorityTier.P1_EXPANDABLE_CONTAINERS_IMAGES

        if item.magic_signature == MagicSignature.SQLITE3:
            if base in cls.CONTACT_AND_ACCOUNT_DBS:
                return ProcessingPriorityTier.P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS
            return ProcessingPriorityTier.P3_PRIMARY_MESSAGING_CHATS

        return ProcessingPriorityTier.P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS

    @classmethod
    def schedule_tiers(
        cls,
        items: tuple[InventoryWorkingItem, ...],
        seed: int = 20260901,
    ) -> tuple[tuple[ProcessingPriorityTier, tuple[InventoryWorkingItem, ...]], ...]:
        """Agrupa itens em P0..P3 com swap-and-pop deterministico intra-estagio e barreira final P4."""
        ordered_tiers: tuple[ProcessingPriorityTier, ...] = (
            ProcessingPriorityTier.P0_ATOMIC_MEDIA_WAL_UNALLOCATED,
            ProcessingPriorityTier.P1_EXPANDABLE_CONTAINERS_IMAGES,
            ProcessingPriorityTier.P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS,
            ProcessingPriorityTier.P3_PRIMARY_MESSAGING_CHATS,
        )
        buckets: dict[ProcessingPriorityTier, list[InventoryWorkingItem]] = {
            t: [] for t in ordered_tiers
        }
        for it in items:
            tier = cls.classify_tier(it)
            buckets[tier].append(it)

        scheduled: list[tuple[ProcessingPriorityTier, tuple[InventoryWorkingItem, ...]]] = []
        for idx, tier in enumerate(ordered_tiers):
            pool = sorted(buckets[tier], key=lambda x: x.control_number)
            rng = random.Random(seed + idx)
            randomized: list[InventoryWorkingItem] = []
            while pool:
                pick = rng.randrange(len(pool))
                chosen = pool[pick]
                pool[pick] = pool[-1]
                pool.pop()
                randomized.append(chosen)
            scheduled.append((tier, tuple(randomized)))

        scheduled.append((ProcessingPriorityTier.P4_CROSS_BACKUP_MERGE_TIMELINE, ()))
        return tuple(scheduled)

    @staticmethod
    def is_recursive_self_clone(parent_sha256: str, child_sha256: str) -> bool:
        """Trava anti-loop infinito caso um subitem extraido possua o mesmo SHA-256 do pai."""
        return bool(parent_sha256) and parent_sha256.lower() == child_sha256.lower()


def build_overlapping_sanitized_chunks(
    origin_cn: str,
    origin_path: str,
    base_locator: str,
    raw_text: str,
    origin_sha256: str,
    chunk_size_chars: int = 4096,
    chunk_overlap_chars: int = 512,
) -> tuple[AnchoredTextChunk, ...]:
    """Fragmenta textos longos com sobreposicao obrigatoria para preservar entidades nas bordas."""
    if len(raw_text) <= chunk_size_chars:
        return (
            build_sanitized_chunk(
                origin_cn=origin_cn,
                origin_path=origin_path,
                locator=base_locator,
                raw_text=raw_text,
                origin_sha256=origin_sha256,
            ),
        )

    step = max(1, chunk_size_chars - chunk_overlap_chars)
    chunks: list[AnchoredTextChunk] = []
    offset = 0
    part_idx = 1
    while offset < len(raw_text):
        window = raw_text[offset : offset + chunk_size_chars]
        loc = base_locator if part_idx == 1 else f"{base_locator}#part{part_idx}"
        chunks.append(
            build_sanitized_chunk(
                origin_cn=origin_cn,
                origin_path=origin_path,
                locator=loc,
                raw_text=window,
                origin_sha256=origin_sha256,
            )
        )
        if offset + chunk_size_chars >= len(raw_text):
            break
        offset += step
        part_idx += 1
    return tuple(chunks)


def _format_le_guid(guid_16b: bytes) -> str:
    if len(guid_16b) != 16:
        return "00000000-0000-0000-0000-000000000000"
    d1, d2, d3 = struct.unpack_from("<IHH", guid_16b, 0)
    d4 = guid_16b[8:10].hex()
    d5 = guid_16b[10:16].hex()
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4}-{d5}"


class PureWindowsLnkBinaryParser:
    """Decodificador binario puro MS-SHLLINK (.lnk) extraindo VolumeSerial, MachineID e DroidBirth MAC."""

    TRACKER_BLOCK_SIGNATURE: int = 0xA0000003

    @classmethod
    def parse_lnk_bytes(
        cls,
        raw: bytes,
        origin_cn: str,
        origin_path: str,
        origin_sha256: str,
    ) -> WindowsLinkProvenanceRecord | None:
        """Extrai metadados de autoria fisica de um atalho Windows .lnk sem bibliotecas externas."""
        if len(raw) < 76:
            return None
        hdr_size = struct.unpack_from("<I", raw, 0)[0]
        if hdr_size != 0x4C or raw[4:20] != _LNK_CLSID_BYTES:
            return None

        link_flags = struct.unpack_from("<I", raw, 20)[0]
        pos = 76

        if (link_flags & 0x01) and pos + 2 <= len(raw):
            id_list_size = struct.unpack_from("<H", raw, pos)[0]
            pos += 2 + id_list_size

        vol_serial_hex = "EXPLICIT_GAP"
        target_path = ""

        if (link_flags & 0x02) and pos + 28 <= len(raw):
            li_size, _li_hdr, li_flags, vol_off, base_off = struct.unpack_from(
                "<IIIII", raw, pos
            )
            if li_flags & 0x01:
                if vol_off > 0 and pos + vol_off + 12 <= len(raw):
                    serial_int = struct.unpack_from("<I", raw, pos + vol_off + 8)[0]
                    vol_serial_hex = f"{serial_int:08X}"
                if base_off > 0 and pos + base_off < len(raw):
                    end_cap = min(len(raw), pos + max(28, li_size))
                    nul_idx = raw.find(b"\x00", pos + base_off, end_cap)
                    end_pos = nul_idx if nul_idx != -1 else end_cap
                    target_path = raw[pos + base_off : end_pos].decode("latin-1", errors="ignore")
            pos += max(28, li_size)

        is_unicode = bool(link_flags & 0x80)
        char_width = 2 if is_unicode else 1
        for str_flag in (0x04, 0x08, 0x10, 0x20, 0x40):
            if (link_flags & str_flag) and pos + 2 <= len(raw):
                char_cnt = struct.unpack_from("<H", raw, pos)[0]
                byte_len = char_cnt * char_width
                str_bytes = raw[pos + 2 : pos + 2 + byte_len]
                if str_flag == 0x08 and not target_path:
                    target_path = str_bytes.decode(
                        "utf-16-le" if is_unicode else "latin-1", errors="ignore"
                    )
                pos += 2 + byte_len

        tracker_block = cls._locate_tracker_block(raw, pos)
        machine_id = "EXPLICIT_GAP"
        droid_vol = "00000000-0000-0000-0000-000000000000"
        droid_file = "00000000-0000-0000-0000-000000000000"
        birth_mac = "EXPLICIT_GAP"

        if tracker_block is not None and len(tracker_block) >= 96:
            raw_machine = tracker_block[16:32].split(b"\x00", 1)[0]
            decoded_machine = raw_machine.decode("ascii", errors="ignore").strip()
            if decoded_machine:
                machine_id = decoded_machine
            droid_vol = _format_le_guid(tracker_block[32:48])
            droid_file = _format_le_guid(tracker_block[48:64])
            birth_file_node = tracker_block[90:96]
            birth_vol_node = tracker_block[74:80]
            node_bytes = birth_file_node if any(birth_file_node) else birth_vol_node
            if any(node_bytes):
                birth_mac = ":".join(f"{b:02x}" for b in node_bytes)

        art_id = "LNK-" + sha256_text(f"{origin_cn}|{origin_sha256}")[:12].upper()
        return WindowsLinkProvenanceRecord(
            artifact_id=art_id,
            origin_cn=origin_cn,
            origin_path=origin_path,
            artifact_kind="WINDOWS_LNK_TRACKER",
            machine_id=machine_id,
            volume_serial_hex=vol_serial_hex,
            droid_volume_guid=droid_vol,
            droid_file_guid=droid_file,
            droid_birth_mac_address=birth_mac,
            target_path=target_path or "EXPLICIT_GAP",
            origin_sha256=origin_sha256,
        )

    @classmethod
    def _locate_tracker_block(cls, raw: bytes, start_pos: int) -> bytes | None:
        cur = start_pos
        while cur + 8 <= len(raw):
            blk_size, blk_sig = struct.unpack_from("<II", raw, cur)
            if blk_size < 8:
                break
            if blk_sig == cls.TRACKER_BLOCK_SIGNATURE and cur + 96 <= len(raw):
                return raw[cur : cur + 96]
            cur += blk_size

        sig_bytes = struct.pack("<I", cls.TRACKER_BLOCK_SIGNATURE)
        idx = raw.find(sig_bytes, 76)
        if idx >= 4 and idx - 4 + 96 <= len(raw):
            cand_size = struct.unpack_from("<I", raw, idx - 4)[0]
            if cand_size >= 96:
                return raw[idx - 4 : idx - 4 + 96]
        return None


@dataclass(frozen=True, slots=True)
class CarvedHeaderCandidate:
    """Candidato de cabecalho binario localizado pelo automato Aho-Corasick em blocos de 1 MiB."""

    signature_name: str
    byte_offset: int
    estimated_size_bytes: int


def inspect_carved_sqlite_header_size(buf_from_sig: bytes) -> int:
    """Calcula page_size * page_count de um cabecalho SQLite 3 localizado em espaco nao alocado."""
    if len(buf_from_sig) < 32 or not buf_from_sig.startswith(b"SQLite format 3\x00"):
        return 0
    raw_ps = struct.unpack_from(">H", buf_from_sig, 16)[0]
    page_size = 65536 if raw_ps == 1 else raw_ps
    if page_size < 512 or (page_size & (page_size - 1)) != 0:
        return 0
    page_count = struct.unpack_from(">I", buf_from_sig, 28)[0]
    return page_size * page_count


class PureSqliteBinaryForensicCarver:
    """Inspetor binario Read-Only de freelist, freeblocks, slack B-Tree e frames WAL (NIST IR 8354)."""

    @classmethod
    def inspect_sqlite_and_wal_bytes(
        cls,
        db_bytes: bytes,
        wal_bytes: bytes,
        origin_cn: str,
        origin_path: str,
        origin_sha256: str,
        active_texts: frozenset[str],
    ) -> tuple[RecoveredSqliteRecord, ...]:
        """Recupera registros deletados/nao consolidados rotulando estritamente seu estado de alocacao."""
        if len(db_bytes) < 100 or not db_bytes.startswith(b"SQLite format 3\x00"):
            return ()

        raw_ps = struct.unpack_from(">H", db_bytes, 16)[0]
        page_size = 65536 if raw_ps == 1 else raw_ps
        if page_size < 512 or (page_size & (page_size - 1)) != 0:
            return ()

        total_pages = len(db_bytes) // page_size
        first_trunk = struct.unpack_from(">I", db_bytes, 32)[0]
        recovered: list[RecoveredSqliteRecord] = []
        seen_keys: set[str] = set()

        freelist_pages = cls._collect_freelist_page_numbers(db_bytes, page_size, total_pages, first_trunk)
        for pno in freelist_pages:
            pg_start = (pno - 1) * page_size
            pg_buf = db_bytes[pg_start : pg_start + page_size]
            for frag in cls._extract_printable_fragments(pg_buf, active_texts):
                dedup_k = f"FREE|{pno}|{frag}"
                if dedup_k in seen_keys:
                    continue
                seen_keys.add(dedup_k)
                rec_id = "REC-SQL-" + sha256_text(f"{origin_cn}|{dedup_k}")[:12].upper()
                recovered.append(
                    RecoveredSqliteRecord(
                        record_id=rec_id,
                        origin_cn=origin_cn,
                        origin_path=origin_path,
                        allocation_state=SqliteRowAllocationState.CARVED_FREELIST_OR_UNALLOCATED,
                        page_or_frame_locator=f"freelist_page={pno}",
                        recovered_text=frag,
                        origin_sha256=origin_sha256,
                    )
                )

        for pno in range(1, total_pages + 1):
            if pno in freelist_pages:
                continue
            pg_start = (pno - 1) * page_size
            pg_buf = db_bytes[pg_start : pg_start + page_size]
            hdr_off = 100 if pno == 1 else 0
            if hdr_off + 8 > len(pg_buf):
                continue
            page_type = pg_buf[hdr_off]
            if page_type != 0x0D:
                continue

            first_fb = struct.unpack_from(">H", pg_buf, hdr_off + 1)[0]
            cell_count = struct.unpack_from(">H", pg_buf, hdr_off + 3)[0]
            raw_cell_start = struct.unpack_from(">H", pg_buf, hdr_off + 5)[0]
            cell_start = 65536 if raw_cell_start == 0 else raw_cell_start
            ptr_end = hdr_off + 8 + (cell_count * 2)

            slack_slices: list[bytes] = []
            if ptr_end < cell_start <= len(pg_buf):
                slack_slices.append(pg_buf[ptr_end:cell_start])

            visited_fb: set[int] = set()
            fb_cur = first_fb
            while 0 < fb_cur <= len(pg_buf) - 4 and fb_cur not in visited_fb:
                visited_fb.add(fb_cur)
                next_fb, fb_size = struct.unpack_from(">HH", pg_buf, fb_cur)
                if fb_size > 4 and fb_cur + fb_size <= len(pg_buf):
                    slack_slices.append(pg_buf[fb_cur + 4 : fb_cur + fb_size])
                fb_cur = next_fb

            for sl_buf in slack_slices:
                for frag in cls._extract_printable_fragments(sl_buf, active_texts):
                    dedup_k = f"SLACK|{pno}|{frag}"
                    if dedup_k in seen_keys:
                        continue
                    seen_keys.add(dedup_k)
                    rec_id = "REC-SQL-" + sha256_text(f"{origin_cn}|{dedup_k}")[:12].upper()
                    recovered.append(
                        RecoveredSqliteRecord(
                            record_id=rec_id,
                            origin_cn=origin_cn,
                            origin_path=origin_path,
                            allocation_state=SqliteRowAllocationState.CARVED_FREELIST_OR_UNALLOCATED,
                            page_or_frame_locator=f"btree_unallocated_page={pno}",
                            recovered_text=frag,
                            origin_sha256=origin_sha256,
                        )
                    )

        if len(wal_bytes) >= 32:
            wal_magic = struct.unpack_from(">I", wal_bytes, 0)[0]
            wal_ps = struct.unpack_from(">I", wal_bytes, 8)[0]
            if wal_magic in (0x377F0682, 0x377F0683) and wal_ps >= 512:
                frame_stride = 24 + wal_ps
                f_off = 32
                f_idx = 0
                while f_off + frame_stride <= len(wal_bytes):
                    f_idx += 1
                    f_pno = struct.unpack_from(">I", wal_bytes, f_off)[0]
                    f_payload = wal_bytes[f_off + 24 : f_off + frame_stride]
                    for frag in cls._extract_printable_fragments(f_payload, active_texts):
                        dedup_k = f"WAL|{f_idx}|{frag}"
                        if dedup_k in seen_keys:
                            continue
                        seen_keys.add(dedup_k)
                        rec_id = "REC-WAL-" + sha256_text(f"{origin_cn}|{dedup_k}")[:12].upper()
                        recovered.append(
                            RecoveredSqliteRecord(
                                record_id=rec_id,
                                origin_cn=origin_cn,
                                origin_path=origin_path,
                                allocation_state=SqliteRowAllocationState.WAL_UNCOMMITTED_FRAME,
                                page_or_frame_locator=f"wal_frame={f_idx}_page={f_pno}",
                                recovered_text=frag,
                                origin_sha256=origin_sha256,
                            )
                        )
                    f_off += frame_stride

        return tuple(recovered)

    @staticmethod
    def _collect_freelist_page_numbers(
        db_bytes: bytes,
        page_size: int,
        total_pages: int,
        first_trunk: int,
    ) -> set[int]:
        pages: set[int] = set()
        trunk = first_trunk
        while 1 <= trunk <= total_pages and trunk not in pages:
            pages.add(trunk)
            t_off = (trunk - 1) * page_size
            if t_off + 8 > len(db_bytes):
                break
            next_trunk, leaf_cnt = struct.unpack_from(">II", db_bytes, t_off)
            max_leaves = (page_size - 8) // 4
            bounded_cnt = min(leaf_cnt, max_leaves)
            for idx in range(bounded_cnt):
                leaf_pno = struct.unpack_from(">I", db_bytes, t_off + 8 + idx * 4)[0]
                if 1 <= leaf_pno <= total_pages:
                    pages.add(leaf_pno)
            trunk = next_trunk
        return pages

    @staticmethod
    def _extract_printable_fragments(buf: bytes, active_texts: frozenset[str]) -> list[str]:
        results: list[str] = []
        for match in _PRINTABLE_FORENSIC_RUN_RE.finditer(buf):
            try:
                txt = match.group(0).decode("utf-8").strip()
            except UnicodeDecodeError:
                continue
            if len(txt) < 6:
                continue
            low = txt.lower()
            if low.startswith(("create table", "create index", "sqlite_")):
                continue
            if txt in active_texts:
                continue
            if any(ch.isalpha() for ch in txt):
                results.append(txt)
        return results
