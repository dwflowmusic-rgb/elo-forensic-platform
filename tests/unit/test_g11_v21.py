"""Portao Cumulativo G11 (G11.1 a G11.5) — Validacao Empirica Completa Delta v2.1 (IPED Clean-Room + NIST SSDF v1.1)."""

from __future__ import annotations

import gzip
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import wave
import zipfile

from edrm.bootstrap.container import EloForensicContainer
from edrm.continuous_analysis.domain import ExactMetricSimilarity
from edrm.igrm_governance.infrastructure import (
    SubprocessSandboxSupervisor,
    write_execution_manifest,
)
from edrm.interfaces.local_api import SESSION_TOKEN_HEADER, create_loopback_http_server
from edrm.phase04_processing.domain import InventoryWorkingItem
from edrm.phase04_processing.domain.v21_orchestrator import PureWindowsLnkBinaryParser
from edrm.phase04_processing.infrastructure import (
    SafeContainerUnpackerAdapter,
    UniversalExtractorRunnerAdapter,
)
from edrm.phase04_processing.infrastructure.v21_extractors import (
    CARVING_STREAM_BLOCK_BYTES,
    ContainerExpansionCheckpointManager,
    StreamingSignatureCarver,
    compute_iped_shard_index,
)
from edrm.phase05_review.domain import CompressedRoaringBitset
from edrm.shared_kernel.compressibility_probe import probe_headerless_encryption_bytes
from edrm.shared_kernel.enums import (
    MagicSignature,
    SqliteRowAllocationState,
    StateIpedProfileRisk,
)
from edrm.shared_kernel.exceptions import SecrecySocketViolationError
from edrm.shared_kernel.validators_br_crypto import (
    LinearForensicEntityScanner,
    validate_bip39_seed_checksum,
    validate_bitcoin_address,
    validate_boleto_linha_digitavel,
    validate_chave_nfe_danfe,
    validate_cnh,
    validate_cnpj,
    validate_cpf,
    validate_credit_card_luhn,
    validate_ethereum_eip55,
    validate_mercosul_plate,
    validate_pis_pasep,
    validate_renavam,
    validate_titulo_eleitor,
    validate_tron_address,
)
from tests.architecture import audit_nist_ssdf_v1_1_ast_security


def _build_deterministic_pseudo_random_bytes(length: int, seed_label: str) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(f"{seed_label}:{counter}".encode("ascii")).digest())
        counter += 1
    return bytes(out[:length])


def _mutate_last_digit_plus_one(digits: str) -> str:
    last = (int(digits[-1]) + 1) % 10
    return digits[:-1] + str(last)


def _build_valid_boleto_47(amount_cents: int = 154320) -> str:
    def mod10(field: str) -> str:
        total = 0
        mult = 2
        for ch in reversed(field):
            prod = int(ch) * mult
            total += (prod // 10) + (prod % 10)
            mult = 1 if mult == 2 else 2
        rem = total % 10
        return str(0 if rem == 0 else (10 - rem))

    bank_curr = "0019"
    due_factor = "9876"
    val_str = f"{amount_cents:010d}"
    free_25 = "1234567890123456789012345"
    bar_no_dv = bank_curr + due_factor + val_str + free_25

    acc = 0
    w = 2
    for ch in reversed(bar_no_dv):
        acc += int(ch) * w
        w = 2 if w == 9 else w + 1
    rem11 = acc % 11
    dv_gen = 1 if (11 - rem11) in (0, 10, 11) else (11 - rem11)

    f1 = bank_curr + free_25[0:5]
    f2 = free_25[5:15]
    f3 = free_25[15:25]
    return f"{f1}{mod10(f1)}{f2}{mod10(f2)}{f3}{mod10(f3)}{dv_gen}{due_factor}{val_str}"


def _build_valid_nfe_key_44() -> str:
    base_43 = "35" + "2605" + "11222333000181" + "55" + "001" + "000001234" + "1" + "87654321"
    w = 2
    acc = 0
    for ch in reversed(base_43):
        acc += int(ch) * w
        w = 2 if w == 9 else w + 1
    rem = acc % 11
    dv = 0 if rem in (0, 1) else (11 - rem)
    return f"{base_43}{dv}"


def _build_synthetic_lnk_bytes(
    machine_id: str,
    volume_serial: int,
    birth_mac_hex: str,
    local_target: str,
) -> bytes:
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    # HasLinkInfo = 0x02
    struct.pack_into("<I", header, 20, 0x02)

    vol_label = b"EVID_USB\x00"
    vol_id_size = 16 + len(vol_label)
    vol_id = bytearray(vol_id_size)
    struct.pack_into("<IIII", vol_id, 0, vol_id_size, 2, volume_serial, 16)
    vol_id[16:] = vol_label

    target_bytes = local_target.encode("latin-1") + b"\x00"
    li_hdr_size = 28
    vol_off = li_hdr_size
    base_off = li_hdr_size + len(vol_id)
    li_size = base_off + len(target_bytes)
    link_info = bytearray(li_hdr_size)
    struct.pack_into("<IIIIIII", link_info, 0, li_size, li_hdr_size, 0x01, vol_off, base_off, 0, li_size)
    link_info.extend(vol_id)
    link_info.extend(target_bytes)

    tracker = bytearray(96)
    struct.pack_into("<IIII", tracker, 0, 0x60, 0xA0000003, 0x58, 0)
    mach_b = machine_id.encode("ascii")[:15]
    tracker[16 : 16 + len(mach_b)] = mach_b

    mac_bytes = bytes.fromhex(birth_mac_hex.replace(":", ""))
    birth_vol_guid = b"\x11" * 10 + mac_bytes
    birth_file_guid = b"\x22" * 10 + mac_bytes
    tracker[32:48] = birth_vol_guid
    tracker[48:64] = birth_file_guid
    tracker[64:80] = birth_vol_guid
    tracker[80:96] = birth_file_guid

    terminal = struct.pack("<I", 0)
    return bytes(header) + bytes(link_info) + bytes(tracker) + terminal


def _write_tiny_wav(path: Path, sample_byte: int = 0x42) -> None:
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(bytes([sample_byte, 0x00]) * 800)


def _run_g11_1_nist_ssdf_and_loopback() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        bad_py = Path(tmp) / "bad_sec.py"
        bad_py.write_text(
            "import pickle\nimport urllib.request\nurllib.request.urlopen('https://x', verify=False)\n",
            encoding="utf-8",
        )
        violations = audit_nist_ssdf_v1_1_ast_security([bad_py])
        assert len(violations) >= 2

        manifest_dir = Path(tmp) / "audit"
        manifest_dir.mkdir()
        src_sample = Path(tmp) / "sample_mod.py"
        src_sample.write_text("X = 1\n", encoding="utf-8")
        mf_path = write_execution_manifest(
            str(manifest_dir),
            run_id="RUN-G11",
            case_id="CASE-G11",
            source_files=[src_sample],
            started_at_utc="2026-09-01T00:00:00Z",
        )
        mf_json = json.loads(Path(mf_path).read_text(encoding="utf-8"))
        assert "mini_sbom" in mf_json
        assert mf_json["mini_sbom"]["nist_ssdf_version"] == "1.1"

        staging_dir = Path(tmp) / "staging"
        staging_dir.mkdir()
        sup = SubprocessSandboxSupervisor(str(staging_dir))
        res = sup.run_isolated([sys.executable, "-c", "print('OK_SANDBOX')"], timeout_seconds=5)
        assert res.returncode == 0
        assert "OK_SANDBOX" in res.stdout
        assert list(staging_dir.glob("subproc_*")) == []

    blocked_bind = False
    try:
        create_loopback_http_server(host="0.0.0.0", port=0)
    except SecrecySocketViolationError:
        blocked_bind = True
    assert blocked_bind is True

    srv = create_loopback_http_server(host="127.0.0.1", port=0)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        conn_unauth = HTTPConnection("127.0.0.1", port, timeout=5)
        conn_unauth.request("GET", "/health")
        resp_unauth = conn_unauth.getresponse()
        resp_unauth.read()
        assert resp_unauth.status == 401
        conn_unauth.close()

        conn_auth = HTTPConnection("127.0.0.1", port, timeout=5)
        conn_auth.request("GET", "/health", headers={SESSION_TOKEN_HEADER: srv.session_token})
        resp_auth = conn_auth.getresponse()
        body_auth = json.loads(resp_auth.read().decode("utf-8"))
        assert resp_auth.status == 200
        assert body_auth["authenticated"] is True
        conn_auth.close()
    finally:
        srv.shutdown()
        srv.server_close()


def _run_g11_2_state_iped_audit_and_16_shards() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        iped_src = Path(tmp) / "caso_iped_estatal"
        (iped_src / "iped" / "conf").mkdir(parents=True)
        (iped_src / "iped" / "data").mkdir(parents=True)

        (iped_src / "iped" / "conf" / "IPEDConfig.txt").write_text(
            "profile = fastmode\n"
            "enableCarving = false\n"
            "enableSQLiteUndelete = false\n"
            "excludeKnown = true\n"
            "deleteIgnoredItemData = true\n"
            "hash = md5\n",
            encoding="utf-8",
        )
        (iped_src / "IPED-2026.log").write_text(
            "INFO Starting IPED --nogui -profile fastmode --downloadInternetData\n"
            "INFO Manager.filterKeywords() active\n",
            encoding="utf-8",
        )
        (iped_src / "palavras-chave.txt").write_text("propina\nlaranja\n", encoding="utf-8")

        secret_doc_bytes = (
            "AUTO DE APREENSAO OCULTO NO SHARD IPED\n"
            "CUSTODIANTE: Roberto Investigado\n"
            "DATA_HORA_APREENSAO: 2026-05-10T10:00:00Z\n"
            "ITEM: 01\nMARCA: Samsung\nMODELO: S24\nLACRE_ENTRADA: 778899\n"
        ).encode("utf-8")
        doc_md5 = hashlib.md5(secret_doc_bytes).hexdigest()
        doc_sha256 = hashlib.sha256(secret_doc_bytes).hexdigest()
        target_shard = compute_iped_shard_index(doc_md5)

        for s_idx in range(16):
            shard_db = iped_src / "iped" / "data" / f"storage-{s_idx}.db"
            conn = sqlite3.connect(str(shard_db))
            try:
                with conn:
                    conn.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY, data BLOB)")
                    if s_idx == target_shard:
                        gz_blob = gzip.compress(secret_doc_bytes)
                        conn.execute("INSERT INTO t1 (id, data) VALUES (?, ?)", (101, gz_blob))
            finally:
                conn.close()

        sleuth_db = iped_src / "sleuth.db"
        s_conn = sqlite3.connect(str(sleuth_db))
        try:
            with s_conn:
                s_conn.execute(
                    "CREATE TABLE tsk_files (obj_id INTEGER PRIMARY KEY, name TEXT, size INTEGER, md5 TEXT, sha256 TEXT, storage_id INTEGER)"
                )
                s_conn.execute(
                    "INSERT INTO tsk_files VALUES (1, 'auto_apreensao_shard.txt', ?, ?, ?, 101)",
                    (len(secret_doc_bytes), doc_md5, doc_sha256),
                )
        finally:
            s_conn.close()

        pre_mtimes = {
            p.relative_to(iped_src).as_posix(): p.stat().st_mtime_ns
            for p in sorted(iped_src.rglob("*"))
            if p.is_file()
        }

        ws = Path(tmp) / "ws_iped"
        res = EloForensicContainer().plug_and_run_all(
            case_id="CASO-IPED-G11",
            source_paths=(str(iped_src),),
            workspace_path=str(ws),
        )

        post_mtimes = {
            p.relative_to(iped_src).as_posix(): p.stat().st_mtime_ns
            for p in sorted(iped_src.rglob("*"))
            if p.is_file()
        }
        assert pre_mtimes == post_mtimes
        assert res.phase08.source_pre_post_snapshot_identical is True

        audit = res.phase01_initial.state_iped_audit
        assert audit is not None and audit.is_iped_case is True
        assert audit.profile_risk == StateIpedProfileRisk.FASTMODE_OR_TRIAGE_OMISSIVE
        assert "enableCarving" in audit.disabled_critical_tasks
        assert "hash:sha-256_omitted" in audit.disabled_critical_tasks
        assert audit.internet_download_contamination is True
        assert audit.keywords_negative_proof_warning is True
        assert audit.storage_shards_found == 16
        assert audit.sleuth_db_present is True

        assert any("Roberto Investigado" in chk.text_clean for chk in res.phase04.anchored_chunks)

        q_texts = "\n".join(q.question_text for q in res.phase07.quesitos)
        assert "filterKeywords" in q_texts
        assert "--downloadInternetData" in q_texts


def _run_g11_3_headerless_encryption_and_br_crypto_validators() -> None:
    raw_128k = _build_deterministic_pseudo_random_bytes(131_072, "VERACRYPT_RAW_VOL")
    probe_enc = probe_headerless_encryption_bytes(raw_128k, MagicSignature.UNKNOWN_BINARY)
    assert probe_enc.is_headerless_encrypted is True
    assert probe_enc.resolved_signature == MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED
    assert probe_enc.mean_permille >= 995

    probe_jpg = probe_headerless_encryption_bytes(raw_128k, MagicSignature.JPEG_IMAGE)
    assert probe_jpg.is_headerless_encrypted is False
    assert probe_jpg.resolved_signature == MagicSignature.JPEG_IMAGE

    valid_cpf = "52998224725"
    assert validate_cpf(valid_cpf) is True
    assert validate_cpf(_mutate_last_digit_plus_one(valid_cpf)) is False

    valid_cnpj = "11222333000181"
    assert validate_cnpj(valid_cnpj) is True
    assert validate_cnpj(_mutate_last_digit_plus_one(valid_cnpj)) is False

    valid_alpha_cnpj = "12ABC34501DE35"
    assert validate_cnpj(valid_alpha_cnpj) is True
    assert validate_cnpj(_mutate_last_digit_plus_one(valid_alpha_cnpj)) is False

    valid_cnh = "02650306461"
    assert validate_cnh(valid_cnh) is True
    assert validate_cnh(_mutate_last_digit_plus_one(valid_cnh)) is False

    valid_pis = "12056874107"
    assert validate_pis_pasep(valid_pis) is True
    assert validate_pis_pasep(_mutate_last_digit_plus_one(valid_pis)) is False

    valid_titulo = "146709740183"
    assert validate_titulo_eleitor(valid_titulo) is True
    assert validate_titulo_eleitor(_mutate_last_digit_plus_one(valid_titulo)) is False

    valid_renavam = "639884962"
    assert validate_renavam(valid_renavam) is True
    assert validate_renavam("00639884963") is False

    assert validate_mercosul_plate("BRA2E19") is True
    assert validate_mercosul_plate("BRA2219") is False

    valid_boleto = _build_valid_boleto_47(amount_cents=275990)
    bol_res = validate_boleto_linha_digitavel(valid_boleto)
    assert bol_res.is_valid is True
    assert bol_res.amount_cents == 275990
    bad_bol = valid_boleto[:9] + str((int(valid_boleto[9]) + 1) % 10) + valid_boleto[10:]
    assert validate_boleto_linha_digitavel(bad_bol).is_valid is False

    valid_nfe = _build_valid_nfe_key_44()
    assert validate_chave_nfe_danfe(valid_nfe) is True
    assert validate_chave_nfe_danfe(_mutate_last_digit_plus_one(valid_nfe)) is False

    valid_card = "4539148803436467"
    assert validate_credit_card_luhn(valid_card) is True
    assert validate_credit_card_luhn(_mutate_last_digit_plus_one(valid_card)) is False

    valid_btc_b58 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    valid_btc_bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert validate_bitcoin_address(valid_btc_b58) is True
    assert validate_bitcoin_address(valid_btc_b58[:-1] + "b") is False
    assert validate_bitcoin_address(valid_btc_bech32) is True
    assert validate_bitcoin_address(valid_btc_bech32[:-1] + "5") is False

    assert validate_ethereum_eip55("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae") is True
    assert validate_tron_address("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb") is True

    valid_bip39 = ("abandon",) * 11 + ("about",)
    bad_bip39 = ("abandon",) * 12
    assert validate_bip39_seed_checksum(valid_bip39) is True
    assert validate_bip39_seed_checksum(bad_bip39) is False

    scanner = LinearForensicEntityScanner(max_hits=3)
    sample_doc = f"CPF {valid_cpf} CNPJ {valid_cnpj} NFE {valid_nfe} BTC {valid_btc_bech32}"
    hits = scanner.scan_text(sample_doc)
    assert len(hits) == 3


def _run_g11_4_priority_queues_resume_and_audio_cache() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t_dir = Path(tmp)
        wa_db = t_dir / "wa.db"
        c_wa = sqlite3.connect(str(wa_db))
        try:
            with c_wa:
                c_wa.execute("CREATE TABLE wa_contacts (jid TEXT, display_name TEXT)")
                c_wa.execute(
                    "INSERT INTO wa_contacts VALUES ('5511988887777@s.whatsapp.net', 'Contato Enriquecido P2')"
                )
        finally:
            c_wa.close()

        msg_db = t_dir / "msgstore.db"
        c_msg = sqlite3.connect(str(msg_db))
        try:
            with c_msg:
                c_msg.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
                c_msg.execute("INSERT INTO jid VALUES (1, '99112233@lid')")
                c_msg.execute("INSERT INTO jid VALUES (2, '5511988887777@s.whatsapp.net')")
                c_msg.execute("CREATE TABLE jid_map (lid_row_id INTEGER, jid_row_id INTEGER)")
                c_msg.execute("INSERT INTO jid_map VALUES (1, 2)")
                c_msg.execute("CREATE TABLE message_view_once_media (message_row_id INTEGER)")
                c_msg.execute("INSERT INTO message_view_once_media VALUES (1)")
                c_msg.execute(
                    "CREATE TABLE message (timestamp INTEGER, sender_jid TEXT, text_data TEXT)"
                )
                c_msg.execute(
                    "INSERT INTO message VALUES (1715000000000, '99112233@lid', 'Prova efemera resolvida')"
                )
        finally:
            c_msg.close()

        wav_1 = t_dir / "audio1.wav"
        wav_2 = t_dir / "audio2.wav"
        wav_3 = t_dir / "audio3.wav"
        for w_p in (wav_1, wav_2, wav_3):
            _write_tiny_wav(w_p, sample_byte=0x55)
        wav_sha = hashlib.sha256(wav_1.read_bytes()).hexdigest()

        items = (
            InventoryWorkingItem(
                control_number="CN-00000001",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="msgstore.db",
                staging_or_vault_path=str(msg_db),
                size_bytes=int(msg_db.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=hashlib.sha256(msg_db.read_bytes()).hexdigest(),
                magic_signature=MagicSignature.SQLITE3,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
            ),
            InventoryWorkingItem(
                control_number="CN-00000002",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="wa.db",
                staging_or_vault_path=str(wa_db),
                size_bytes=int(wa_db.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=hashlib.sha256(wa_db.read_bytes()).hexdigest(),
                magic_signature=MagicSignature.SQLITE3,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
            ),
            InventoryWorkingItem(
                control_number="CN-00000003",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="ptt_1.wav",
                staging_or_vault_path=str(wav_1),
                size_bytes=int(wav_1.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=wav_sha,
                magic_signature=MagicSignature.WAV_AUDIO,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
            ),
            InventoryWorkingItem(
                control_number="CN-00000004",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="ptt_2.wav",
                staging_or_vault_path=str(wav_2),
                size_bytes=int(wav_2.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=wav_sha,
                magic_signature=MagicSignature.WAV_AUDIO,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
                duplicate_of_cn="CN-00000003",
            ),
            InventoryWorkingItem(
                control_number="CN-00000005",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="ptt_3.wav",
                staging_or_vault_path=str(wav_3),
                size_bytes=int(wav_3.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=wav_sha,
                magic_signature=MagicSignature.WAV_AUDIO,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
                duplicate_of_cn="CN-00000003",
            ),
        )

        cat_db = str(t_dir / "catalog_audio.sqlite")
        calls = 0

        def fake_transcriber(_p: str, rate: int, dur: int) -> str:
            nonlocal calls
            calls += 1
            return f"Transcricao unica auditada ({rate}Hz/{dur}ms)"

        runner = UniversalExtractorRunnerAdapter(audio_transcriber_fn=fake_transcriber)
        out, _ = runner.run_extractors_on_inventory(
            items=items,
            dynamic_schemas=(),
            seizure_epoch_seconds=None,
            captured_at_utc="2026-09-01T00:00:00Z",
            catalog_db_path=cat_db,
        )

        trace_paths = [p for _, p in runner.execution_trace]
        assert trace_paths.index("ptt_1.wav") < trace_paths.index("wa.db")
        assert trace_paths.index("wa.db") < trace_paths.index("msgstore.db")

        wa_events = [e for e in out.timeline_events if e.event_type == "WHATSAPP_ANDROID_MSG"]
        assert len(wa_events) == 1
        assert "Contato Enriquecido P2" in wa_events[0].actor_origin
        assert "[VIEW_ONCE_EPHEMERAL]" in wa_events[0].content_verbatim
        assert calls == 1
        assert runner.last_audio_cache is not None
        assert runner.last_audio_cache.transcriber_invocations == 1

        # Teste de retomada resiliente de .zip com 5 filhos interrompido no 2o
        src_zip_dir = t_dir / "src_zip"
        src_zip_dir.mkdir()
        zip_p = src_zip_dir / "pacote_5_filhos.zip"
        with zipfile.ZipFile(zip_p, "w") as zf:
            for idx in range(1, 6):
                zf.writestr(f"filho_{idx}.txt", f"Conteudo do filho {idx}".encode("utf-8"))

        ws_zip = t_dir / "ws_zip"
        cont = EloForensicContainer()
        gov = cont.init_workspace_uc.execute("CASO-ZIP-RESUME", str(ws_zip), (str(src_zip_dir),))
        p01 = cont.phase01_uc.execute(gov)
        p02 = cont.phase02_uc.execute(p01)
        p03 = cont.phase03_uc.execute(p02)

        unpacker_interrupted = SafeContainerUnpackerAdapter(interrupt_after_children=2)
        inv_partial, _ = unpacker_interrupted.ingest_and_unpack_to_staging(p03)
        partial_children = [i for i in inv_partial if i.parent_control_number is not None]
        assert len(partial_children) == 2

        ckpt_mgr = ContainerExpansionCheckpointManager(gov.catalog_db_path)
        incomplete_parents = ckpt_mgr.verify_incomplete_parent_containers()
        assert len(incomplete_parents) == 1

        unpacker_resumed = SafeContainerUnpackerAdapter(interrupt_after_children=None)
        inv_full, _ = unpacker_resumed.ingest_and_unpack_to_staging(p03)
        full_children = [i for i in inv_full if i.parent_control_number is not None]
        assert len(full_children) == 5
        assert len({c.control_number for c in full_children}) == 5
        assert ckpt_mgr.verify_incomplete_parent_containers() == ()

        # Teste de preservacao de estado Aho-Corasick na exata fronteira de 1 MiB
        carve_img = t_dir / "boundary_1mib.raw"
        sqlite_hdr = b"SQLite format 3\x00" + struct.pack(">H", 4096) + (b"\x00" * 10) + struct.pack(">I", 3)
        split_pos = CARVING_STREAM_BLOCK_BYTES - 7
        raw_img = (b"\x00" * split_pos) + sqlite_hdr + (b"\x00" * 4096)
        carve_img.write_bytes(raw_img)
        carved_hits = StreamingSignatureCarver().scan_file_preserve_boundary_state(str(carve_img))
        sqlite_hits = [h for h in carved_hits if h.signature_name == "SQLITE3"]
        assert len(sqlite_hits) == 1
        assert sqlite_hits[0].byte_offset == split_pos
        assert sqlite_hits[0].estimated_size_bytes == 4096 * 3


def _run_g11_5_sqlite_deleted_lnk_and_roaring_bitset() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t_dir = Path(tmp)
        del_db = t_dir / "chat_deletado.db"
        conn = sqlite3.connect(str(del_db))
        try:
            conn.execute("PRAGMA secure_delete = OFF;")
            with conn:
                conn.execute("CREATE TABLE message (timestamp INTEGER, sender_jid TEXT, text_data TEXT)")
                conn.execute(
                    "INSERT INTO message VALUES (1715000001000, 'userA', 'MENSAGEM_ATIVA_PERMANENTE')"
                )
                conn.execute(
                    "INSERT INTO message VALUES (1715000002000, 'userB', 'SEGREDO_DELETADO_SEM_VACUUM_9911')"
                )
            with conn:
                conn.execute("DELETE FROM message WHERE sender_jid = 'userB'")
        finally:
            conn.close()

        lnk_file = t_dir / "atalho_evidencia.lnk"
        lnk_bytes = _build_synthetic_lnk_bytes(
            machine_id="NOTEBOOK-ALVO",
            volume_serial=0xCAFEBABE,
            birth_mac_hex="00:1a:2b:3c:4d:5e",
            local_target="E:\\Provas\\planilha_oculta.xlsx",
        )
        lnk_file.write_bytes(lnk_bytes)

        lnk_parsed = PureWindowsLnkBinaryParser.parse_lnk_bytes(
            lnk_bytes, "CN-00000002", "atalho_evidencia.lnk", hashlib.sha256(lnk_bytes).hexdigest()
        )
        assert lnk_parsed is not None
        assert lnk_parsed.machine_id == "NOTEBOOK-ALVO"
        assert lnk_parsed.volume_serial_hex == "CAFEBABE"
        assert lnk_parsed.droid_birth_mac_address == "00:1a:2b:3c:4d:5e"

        items = (
            InventoryWorkingItem(
                control_number="CN-00000001",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="chat_deletado.db",
                staging_or_vault_path=str(del_db),
                size_bytes=int(del_db.stat().st_size),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=hashlib.sha256(del_db.read_bytes()).hexdigest(),
                magic_signature=MagicSignature.SQLITE3,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
            ),
            InventoryWorkingItem(
                control_number="CN-00000002",
                parent_control_number=None,
                source_id="SRC-01",
                origin_rel_path="atalho_evidencia.lnk",
                staging_or_vault_path=str(lnk_file),
                size_bytes=len(lnk_bytes),
                mtime_utc_ns=1,
                is_os_readonly=True,
                sha256_hex=hashlib.sha256(lnk_bytes).hexdigest(),
                magic_signature=MagicSignature.WINDOWS_LNK_SHORTCUT,
                extension_spoofed=False,
                is_encrypted_or_corrupted=False,
                pdf_eof_count=0,
                has_wal_shm_sibling=False,
                custodian_ids=("C1",),
            ),
        )

        out, _ = UniversalExtractorRunnerAdapter().run_extractors_on_inventory(
            items=items,
            dynamic_schemas=(),
            seizure_epoch_seconds=None,
            captured_at_utc="2026-09-01T00:00:00Z",
        )
        assert len(out.timeline_events) == 1
        assert out.timeline_events[0].sqlite_allocation_state == SqliteRowAllocationState.ACTIVE_BTREE_ROW
        assert "SEGREDO_DELETADO_SEM_VACUUM_9911" not in out.timeline_events[0].content_verbatim

        assert any(
            "SEGREDO_DELETADO_SEM_VACUUM_9911" in r.recovered_text
            and r.allocation_state == SqliteRowAllocationState.CARVED_FREELIST_OR_UNALLOCATED
            for r in out.recovered_sqlite_records
        )
        assert len(out.link_provenance_records) == 1
        assert out.link_provenance_records[0].droid_birth_mac_address == "00:1a:2b:3c:4d:5e"

    b_a = CompressedRoaringBitset.from_iterable(range(0, 100_000, 2))
    b_b = CompressedRoaringBitset.from_iterable(range(0, 100_000, 3))
    t0 = time.monotonic_ns()
    inter = b_a & b_b
    union = b_a | b_b
    diff = b_a - b_b
    elapsed_ms = (time.monotonic_ns() - t0) // 1_000_000
    assert elapsed_ms < 50
    assert len(inter) == 16_667
    assert len(union) == 66_667
    assert len(diff) == 33_333
    assert 6 in inter and 4 in diff and 3 in union

    assert ExactMetricSimilarity.verify_triangle_inequality_holds(
        (1, 0, 5, -2), (3, 4, 1, 0), (-2, 7, 0, 3)
    ) is True


def run_g11_delta_v2_1_tests() -> str:
    """Executa integralmente os subportoes G11.1 a G11.5 da evolucao Delta v2.1."""
    _run_g11_1_nist_ssdf_and_loopback()
    _run_g11_2_state_iped_audit_and_16_shards()
    _run_g11_3_headerless_encryption_and_br_crypto_validators()
    _run_g11_4_priority_queues_resume_and_audio_cache()
    _run_g11_5_sqlite_deleted_lnk_and_roaring_bitset()
    return (
        "G11.1 (NIST SSDF + Loopback Token), G11.2 (.iped 16 Shards RO + Quesitos), "
        "G11.3 (64KiB Raw Entropy + Validadores BR/Cripto/BIP-39), G11.4 (Filas P0->P4 + Resume + Cache Audio) "
        "e G11.5 (SQLite Freelist NIST IR 8354 + .lnk DroidBirth MAC + RoaringBitset) aprovados."
    )
