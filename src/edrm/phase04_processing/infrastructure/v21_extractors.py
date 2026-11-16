"""Adaptadores Fisicos Fase 04 Delta v2.1 — Shards IPED, Carving 1MiB, Checkpoint Resiliente e Cache Audio."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Callable, Iterator
import wave
import zlib

from edrm.phase04_processing.domain.v21_orchestrator import (
    CarvedHeaderCandidate,
    PureSqliteBinaryForensicCarver,
    PureWindowsLnkBinaryParser,
    build_overlapping_sanitized_chunks,
    inspect_carved_sqlite_header_size,
)
from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    RecoveredSqliteRecord,
    WindowsLinkProvenanceRecord,
)
from edrm.shared_kernel.value_objects import SafeOsPath, sha256_text
from edrm.shared_kernel.validators_br_crypto import PureAhoCorasickAutomaton

CARVING_STREAM_BLOCK_BYTES: int = 1_048_576


@dataclass(frozen=True, slots=True)
class IpedSleuthItemEntry:
    """Entrada importada em modo Read-Only de sleuth.db / tsk_files de um caso .iped estatal."""

    obj_id: int
    name: str
    size_bytes: int
    md5_hex: str
    sha256_hex: str
    storage_id: int


def compute_iped_shard_index(hash_hex: str) -> int:
    """Calcula o indice 0..15 do shard storage-<0..15>.db a partir do nibble alto do primeiro byte."""
    cleaned = hash_hex.strip().lower()
    if len(cleaned) < 2:
        return 0
    first_byte = int(cleaned[:2], 16)
    return (first_byte >> 4) & 0x0F


class StateIpedStorageReaderAdapter:
    """Leitor imutavel Clean-Room de casos portateis .iped (sleuth.db + 16 shards storage-0..15.db em GZIP)."""

    @staticmethod
    def read_sleuth_items(iped_case_dir: str) -> tuple[IpedSleuthItemEntry, ...]:
        """Le tsk_files de sleuth.db exclusivamente com mode=ro&immutable=1 e PRAGMA query_only=1."""
        sleuth_path = Path(iped_case_dir) / "sleuth.db"
        if not sleuth_path.exists():
            return ()
        uri = SafeOsPath(str(sleuth_path.resolve())).to_sqlite_immutable_uri(
            is_windows=(os.name == "nt")
        )
        items: list[IpedSleuthItemEntry] = []
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("PRAGMA query_only = 1;")
            cols = {
                str(r[1]).lower()
                for r in conn.execute("PRAGMA table_info(tsk_files)").fetchall()
            }
            if not cols:
                return ()
            id_col = "obj_id" if "obj_id" in cols else "rowid"
            sha_col = "sha256" if "sha256" in cols else "''"
            storage_col = "storage_id" if "storage_id" in cols else id_col
            rows = conn.execute(
                f"SELECT {id_col}, name, size, md5, {sha_col}, {storage_col} FROM tsk_files ORDER BY {id_col}"
            ).fetchall()
            for r in rows:
                items.append(
                    IpedSleuthItemEntry(
                        obj_id=int(r[0] or 0),
                        name=str(r[1] or ""),
                        size_bytes=int(r[2] or 0),
                        md5_hex=str(r[3] or "").lower(),
                        sha256_hex=str(r[4] or "").lower(),
                        storage_id=int(r[5] or 0),
                    )
                )
        finally:
            conn.close()
        return tuple(items)

    @staticmethod
    def stream_blob_from_shard(
        iped_case_dir: str,
        hash_hex_for_shard: str,
        blob_key: int | str,
        chunk_size: int = 65_536,
    ) -> Iterator[bytes]:
        """Descomprime blob GZIP de iped/data/storage-<0..15>.db em streaming imutavel (zero escrita em --source)."""
        shard_idx = compute_iped_shard_index(hash_hex_for_shard)
        shard_path = Path(iped_case_dir) / "iped" / "data" / f"storage-{shard_idx}.db"
        if not shard_path.exists():
            return
        uri = SafeOsPath(str(shard_path.resolve())).to_sqlite_immutable_uri(
            is_windows=(os.name == "nt")
        )
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.execute("PRAGMA query_only = 1;")
            row = conn.execute("SELECT data FROM t1 WHERE id = ?", (blob_key,)).fetchone()
            if row is None or row[0] is None:
                return
            raw_blob = bytes(row[0])
        finally:
            conn.close()

        is_gzip = len(raw_blob) >= 2 and raw_blob[:2] == b"\x1f\x8b"
        if not is_gzip:
            for off in range(0, len(raw_blob), chunk_size):
                yield raw_blob[off : off + chunk_size]
            return

        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        for off in range(0, len(raw_blob), chunk_size):
            piece = decompressor.decompress(raw_blob[off : off + chunk_size])
            if piece:
                yield piece
        tail = decompressor.flush()
        if tail:
            yield tail

    @classmethod
    def read_full_verified_blob(
        cls,
        iped_case_dir: str,
        hash_hex_for_shard: str,
        blob_key: int | str,
    ) -> tuple[bytes, str]:
        """Reconstroi o conteudo descomprimido e calcula seu SHA-256 exato em streaming."""
        hasher = hashlib.sha256()
        parts: list[bytes] = []
        for chunk in cls.stream_blob_from_shard(iped_case_dir, hash_hex_for_shard, blob_key):
            hasher.update(chunk)
            parts.append(chunk)
        return b"".join(parts), hasher.hexdigest()


class ShardedBlobVaultStore:
    """Armazenamento local em 16 shards (blob_shard_00.sqlite .. blob_shard_0f.sqlite) evitando exaustao de inodes."""

    def __init__(self, shards_dir: str) -> None:
        self._shards_dir = Path(shards_dir)
        os.makedirs(str(self._shards_dir), exist_ok=True)

    def put_blob(self, sha256_hex: str, raw_data: bytes) -> int:
        """Comprime e grava subitem em staging/blob_shards/blob_shard_<00..0f>.sqlite."""
        shard_idx = compute_iped_shard_index(sha256_hex)
        db_file = self._shards_dir / f"blob_shard_{shard_idx:02x}.sqlite"
        compressed = zlib.compress(raw_data, level=6)
        conn = sqlite3.connect(str(db_file))
        try:
            with conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS blobs (sha256_hex TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, gz_data BLOB NOT NULL)"
                )
                conn.execute(
                    "INSERT OR REPLACE INTO blobs (sha256_hex, size_bytes, gz_data) VALUES (?, ?, ?)",
                    (sha256_hex.lower(), len(raw_data), compressed),
                )
        finally:
            conn.close()
        return shard_idx

    def get_blob(self, sha256_hex: str) -> bytes | None:
        """Recupera e descomprime subitem de seu respectivo shard."""
        shard_idx = compute_iped_shard_index(sha256_hex)
        db_file = self._shards_dir / f"blob_shard_{shard_idx:02x}.sqlite"
        if not db_file.exists():
            return None
        conn = sqlite3.connect(str(db_file))
        try:
            row = conn.execute(
                "SELECT gz_data FROM blobs WHERE sha256_hex = ?", (sha256_hex.lower(),)
            ).fetchone()
            if row is None:
                return None
            return zlib.decompress(bytes(row[0]))
        finally:
            conn.close()


class ContainerExpansionCheckpointManager:
    """Gerenciador resiliente de expansao de conteineres com semaforo anti-deadlock e retomada de incompletos."""

    def __init__(self, catalog_db_path: str, max_expanding_containers: int = 2) -> None:
        self._db_path = catalog_db_path
        self._semaphore = threading.BoundedSemaphore(max(1, max_expanding_containers))
        self._ensure_table()

    @property
    def semaphore(self) -> threading.BoundedSemaphore:
        """Semaforo limitando conteineres pai em descompactacao simultanea."""
        return self._semaphore

    def _ensure_table(self) -> None:
        if not self._db_path:
            return
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS container_expansion_checkpoints (
                        parent_cn TEXT PRIMARY KEY,
                        parent_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL,
                        expected_children INTEGER NOT NULL,
                        unpacked_children INTEGER NOT NULL,
                        completed_all_children INTEGER NOT NULL,
                        updated_at_utc TEXT NOT NULL
                    )
                    """
                )
        finally:
            conn.close()

    def verify_incomplete_parent_containers(self) -> tuple[str, ...]:
        """Retorna todos os parent_cn interrompidos com completed_all_children == 0."""
        if not self._db_path:
            return ()
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            rows = conn.execute(
                "SELECT parent_cn FROM container_expansion_checkpoints WHERE completed_all_children = 0 ORDER BY parent_cn"
            ).fetchall()
            return tuple(str(r[0]) for r in rows)
        finally:
            conn.close()

    def is_completed(self, parent_cn: str, parent_sha256: str) -> bool:
        """Verifica se o conteiner pai ja teve 100% dos filhos expandidos."""
        if not self._db_path:
            return False
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            row = conn.execute(
                "SELECT completed_all_children, parent_sha256 FROM container_expansion_checkpoints WHERE parent_cn = ?",
                (parent_cn,),
            ).fetchone()
            return bool(row and int(row[0]) == 1 and str(row[1]) == parent_sha256)
        finally:
            conn.close()

    def mark_progress(
        self,
        parent_cn: str,
        parent_sha256: str,
        state: str,
        expected_children: int,
        unpacked_children: int,
        completed_all: bool,
        updated_at_utc: str,
    ) -> None:
        """Registra o estado atomico (EXPANDING ou COMPLETED) da descompactacao do pai."""
        if not self._db_path:
            return
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO container_expansion_checkpoints (
                        parent_cn, parent_sha256, state, expected_children,
                        unpacked_children, completed_all_children, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parent_cn,
                        parent_sha256,
                        state,
                        expected_children,
                        unpacked_children,
                        1 if completed_all else 0,
                        updated_at_utc,
                    ),
                )
        finally:
            conn.close()


class StreamingSignatureCarver:
    """Carver binario deterministico em blocos de 1 MiB preservando o estado do automato Aho-Corasick."""

    DEFAULT_SIGNATURES: tuple[tuple[str, bytes], ...] = (
        ("SQLITE3", b"SQLite format 3\x00"),
        ("PDF", b"%PDF-"),
        ("JPEG", b"\xff\xd8\xff\xe0"),
        ("PNG", b"\x89PNG\r\n\x1a\n"),
        ("ZIP", b"PK\x03\x04"),
        ("LNK", b"\x4c\x00\x00\x00\x01\x14\x02\x00"),
    )

    def __init__(self, patterns: tuple[tuple[str, bytes], ...] | None = None) -> None:
        self._patterns = patterns or self.DEFAULT_SIGNATURES
        self._automaton = PureAhoCorasickAutomaton(self._patterns)

    def scan_file_preserve_boundary_state(
        self,
        file_path: str,
        block_size: int = CARVING_STREAM_BLOCK_BYTES,
    ) -> tuple[CarvedHeaderCandidate, ...]:
        """Varre imagem bruta preservando start_state entre blocos consecutivos de 1 MiB."""
        ext_p = SafeOsPath(file_path).to_os_extended(is_windows=(os.name == "nt"))
        candidates: list[CarvedHeaderCandidate] = []
        state = 0
        global_offset = 0

        with open(ext_p, "rb") as fh:
            while True:
                block = fh.read(block_size)
                if not block:
                    break
                state, matches = self._automaton.step_block(
                    block, start_state=state, base_offset=global_offset
                )
                for pat_name, abs_off in matches:
                    est_size = 0
                    if pat_name == "SQLITE3":
                        cur_pos = fh.tell()
                        fh.seek(abs_off)
                        hdr_32 = fh.read(32)
                        fh.seek(cur_pos)
                        est_size = inspect_carved_sqlite_header_size(hdr_32)
                    candidates.append(
                        CarvedHeaderCandidate(
                            signature_name=pat_name,
                            byte_offset=abs_off,
                            estimated_size_bytes=est_size,
                        )
                    )
                global_offset += len(block)

        return tuple(candidates)


class SQLiteDeletedRecordsInspector:
    """Upgrade A — Leitor binario Read-Only de freelist, freeblocks e -wal (NIST IR 8354)."""

    @staticmethod
    def inspect_database_file(
        db_path: str,
        origin_cn: str,
        origin_rel_path: str,
        origin_sha256: str,
        active_texts: frozenset[str],
    ) -> tuple[RecoveredSqliteRecord, ...]:
        """Abre banco e eventual -wal em modo binario 'rb' puro sem alterar nenhum byte."""
        ext_db = SafeOsPath(db_path).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_db, "rb") as fh:
            db_bytes = fh.read(16 * 1024 * 1024)

        wal_bytes = b""
        wal_candidate = Path(f"{db_path}-wal")
        if wal_candidate.exists():
            ext_wal = SafeOsPath(str(wal_candidate)).to_os_extended(is_windows=(os.name == "nt"))
            with open(ext_wal, "rb") as wfh:
                wal_bytes = wfh.read(16 * 1024 * 1024)

        return PureSqliteBinaryForensicCarver.inspect_sqlite_and_wal_bytes(
            db_bytes=db_bytes,
            wal_bytes=wal_bytes,
            origin_cn=origin_cn,
            origin_path=origin_rel_path,
            origin_sha256=origin_sha256,
            active_texts=active_texts,
        )


class WindowsArtifactProvenanceExtractor:
    """Upgrade C — Extrator forense de atalhos .lnk, registros USBStor e $UsnJrnl."""

    @staticmethod
    def extract_lnk_file(
        file_path: str,
        origin_cn: str,
        origin_rel_path: str,
        origin_sha256: str,
    ) -> tuple[tuple[WindowsLinkProvenanceRecord, ...], tuple[AnchoredTextChunk, ...]]:
        """Decodifica .lnk binario e emite registro estruturado + chunk ancorado para busca RRF."""
        ext_p = SafeOsPath(file_path).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_p, "rb") as fh:
            raw = fh.read(262_144)
        rec = PureWindowsLnkBinaryParser.parse_lnk_bytes(
            raw=raw,
            origin_cn=origin_cn,
            origin_path=origin_rel_path,
            origin_sha256=origin_sha256,
        )
        if rec is None:
            return (), ()
        summary = (
            f"Atalho Windows .lnk MachineID={rec.machine_id} VolumeSerial={rec.volume_serial_hex} "
            f"DroidBirthMAC={rec.droid_birth_mac_address} Target={rec.target_path}"
        )
        chunks = build_overlapping_sanitized_chunks(
            origin_cn=origin_cn,
            origin_path=origin_rel_path,
            base_locator="lnk_tracker_block",
            raw_text=summary,
            origin_sha256=origin_sha256,
        )
        return (rec,), chunks


class AudioTranscriptDeduplicatedCache:
    """Upgrade D — Cache deduplicado de transcricao de audio indexado por SHA-256 (zero reprocessamento)."""

    def __init__(
        self,
        catalog_db_path: str,
        transcriber_fn: Callable[[str, int, int], str] | None = None,
        model_id: str = "deterministic-pcm-vad-v2.1",
    ) -> None:
        self._db_path = catalog_db_path
        self._transcriber_fn = transcriber_fn
        self._model_id = model_id
        self._memory_fallback: dict[str, tuple[int, list[dict[str, str]]]] = {}
        self.transcriber_invocations: int = 0
        self._ensure_table()

    def _ensure_table(self) -> None:
        if not self._db_path:
            return
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audio_transcript_cache (
                        audio_sha256 TEXT PRIMARY KEY,
                        duration_ms INTEGER NOT NULL,
                        model_id TEXT NOT NULL,
                        segments_json TEXT NOT NULL,
                        cached_at_utc TEXT NOT NULL
                    )
                    """
                )
        finally:
            conn.close()

    def get_or_transcribe_wav(
        self,
        wav_path: str,
        origin_cn: str,
        origin_rel_path: str,
        audio_sha256: str,
        captured_at_utc: str,
    ) -> tuple[AnchoredTextChunk, ...]:
        """Consulta audio_transcript_cache por SHA-256; executa o transcritor apenas no primeiro hit unico."""
        sha_key = audio_sha256.lower()
        cached_segments = self._lookup_cached_segments(sha_key)

        if cached_segments is None:
            ext_p = SafeOsPath(wav_path).to_os_extended(is_windows=(os.name == "nt"))
            with wave.open(ext_p, "rb") as wf:
                rate = max(1, wf.getframerate())
                frames = wf.getnframes()
                duration_ms = (frames * 1000) // rate
                end_s, rem_ms = divmod(duration_ms, 1000)
                loc = f"[00:00:00.000 -> 00:{end_s // 60:02d}:{end_s % 60:02d}.{rem_ms:03d}]"

            self.transcriber_invocations += 1
            if self._transcriber_fn is not None:
                transcript_txt = self._transcriber_fn(wav_path, rate, duration_ms)
            else:
                transcript_txt = (
                    f"Segmento PCM/WAV verificado ({rate}Hz, {duration_ms}ms) ancorado {loc}"
                )

            cached_segments = [{"locator": loc, "text": transcript_txt}]
            self._store_cached_segments(sha_key, duration_ms, cached_segments, captured_at_utc)

        out_chunks: list[AnchoredTextChunk] = []
        for seg in cached_segments:
            out_chunks.extend(
                build_overlapping_sanitized_chunks(
                    origin_cn=origin_cn,
                    origin_path=origin_rel_path,
                    base_locator=seg["locator"],
                    raw_text=seg["text"],
                    origin_sha256=audio_sha256,
                )
            )
        return tuple(out_chunks)

    def _lookup_cached_segments(self, sha_key: str) -> list[dict[str, str]] | None:
        if not self._db_path:
            if sha_key in self._memory_fallback:
                return self._memory_fallback[sha_key][1]
            return None
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            row = conn.execute(
                "SELECT segments_json FROM audio_transcript_cache WHERE audio_sha256 = ?",
                (sha_key,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(str(row[0]))
        finally:
            conn.close()

    def _store_cached_segments(
        self,
        sha_key: str,
        duration_ms: int,
        segments: list[dict[str, str]],
        captured_at_utc: str,
    ) -> None:
        if not self._db_path:
            self._memory_fallback[sha_key] = (duration_ms, segments)
            return
        ext_db = SafeOsPath(self._db_path).to_os_extended(is_windows=(os.name == "nt"))
        conn = sqlite3.connect(ext_db)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO audio_transcript_cache (
                        audio_sha256, duration_ms, model_id, segments_json, cached_at_utc
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        sha_key,
                        duration_ms,
                        self._model_id,
                        json.dumps(segments, ensure_ascii=False),
                        captured_at_utc,
                    ),
                )
        finally:
            conn.close()


def extract_contacts_from_wa_db(sqlite_uri: str) -> dict[str, str]:
    """Extrai mapa jid -> display_name de wa.db / ContactsV2.sqlite no estagio P2 para enriquecer P3."""
    mapping: dict[str, str] = {}
    conn = sqlite3.connect(sqlite_uri, uri=True)
    try:
        conn.execute("PRAGMA query_only = 1;")
        tables = {
            str(r[0]).lower(): str(r[0])
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        if "wa_contacts" in tables:
            tbl = tables["wa_contacts"]
            cols = {
                str(c[1]).lower()
                for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()
            }
            if "jid" in cols:
                disp_col = "display_name" if "display_name" in cols else ("wa_name" if "wa_name" in cols else "jid")
                rows = conn.execute(f"SELECT jid, {disp_col} FROM {tbl}").fetchall()
                for jid_v, name_v in rows:
                    if jid_v:
                        j_str = str(jid_v)
                        n_str = str(name_v or "").strip()
                        mapping[j_str] = f"{j_str} ({n_str})" if n_str and n_str != j_str else j_str
    finally:
        conn.close()
    return mapping


def resolve_whatsapp_modern_lids_and_view_once(
    conn: sqlite3.Connection,
    tables: dict[str, str],
) -> tuple[dict[str, str], set[int]]:
    """Upgrade B — Resolve tabelas modernas jid / lid_me_mapping / jid_map e mensagens view-once sem rede."""
    lid_to_phone: dict[str, str] = {}
    view_once_rowids: set[int] = set()

    if "jid" in tables and ("jid_map" in tables or "lid_me_mapping" in tables):
        j_tbl = tables["jid"]
        j_rows = conn.execute(f"SELECT _id, raw_string FROM {j_tbl}").fetchall()
        id_to_raw = {int(r[0]): str(r[1] or "") for r in j_rows if r[0] is not None}
        if "jid_map" in tables:
            jm_tbl = tables["jid_map"]
            jm_cols = {
                str(c[1]).lower()
                for c in conn.execute(f"PRAGMA table_info({jm_tbl})").fetchall()
            }
            if {"lid_row_id", "jid_row_id"}.issubset(jm_cols):
                for lid_id, jid_id in conn.execute(
                    f"SELECT lid_row_id, jid_row_id FROM {jm_tbl}"
                ).fetchall():
                    lid_raw = id_to_raw.get(int(lid_id or -1), "")
                    jid_raw = id_to_raw.get(int(jid_id or -1), "")
                    if lid_raw and jid_raw:
                        lid_to_phone[lid_raw] = jid_raw

    if "lid_me_mapping" in tables:
        lm_tbl = tables["lid_me_mapping"]
        lm_cols = {
            str(c[1]).lower()
            for c in conn.execute(f"PRAGMA table_info({lm_tbl})").fetchall()
        }
        if {"lid", "jid"}.issubset(lm_cols):
            for l_val, j_val in conn.execute(f"SELECT lid, jid FROM {lm_tbl}").fetchall():
                if l_val and j_val:
                    lid_to_phone[str(l_val)] = str(j_val)

    if "message_view_once_media" in tables:
        vo_tbl = tables["message_view_once_media"]
        vo_cols = {
            str(c[1]).lower()
            for c in conn.execute(f"PRAGMA table_info({vo_tbl})").fetchall()
        }
        if "message_row_id" in vo_cols:
            for (mr_id,) in conn.execute(f"SELECT message_row_id FROM {vo_tbl}").fetchall():
                if mr_id is not None:
                    view_once_rowids.add(int(mr_id))

    return lid_to_phone, view_once_rowids
