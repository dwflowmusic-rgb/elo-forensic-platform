"""Dominio puro da Fase 04 — De-NIST, Deduplicacao, Pos-Apreensao, SIMBA, ERB e CGNAT."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import re
from typing import Callable

from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    CgnatAuditRecord,
    DeadLetterExceptionRecord,
    FinancialLedgerEntryRecord,
    PrimaryDocumentCandidate,
    RecoveredSqliteRecord,
    TelecomCdrRecord,
    TimelineEventRecord,
    WindowsLinkProvenanceRecord,
)
from edrm.shared_kernel.enums import MagicSignature, PrimaryDocType
from edrm.shared_kernel.exceptions import ContainerSecurityViolationError
from edrm.shared_kernel.money_parser import parse_money_to_cents
from edrm.shared_kernel.time_normalizer import parse_timestamp_to_utc
from edrm.shared_kernel.value_objects import ControlNumber, SourceAnchor, sha256_text

DEFAULT_NSRL_SYSTEM_HASHES: frozenset[str] = frozenset(
    {
        sha256_text("WINDOWS_SYSTEM32_KERNEL32_KNOWN_NSRL_STUB"),
        sha256_text("MACOS_DS_STORE_KNOWN_NSRL_STUB"),
    }
)

MAX_UNPACK_RATIO: int = 100
MAX_SINGLE_MEMBER_BYTES: int = 512 * 1024 * 1024

_PROMPT_INJ_RE = re.compile(
    r"(ignore\s+previous\s+instructions|system\s+prompt|disregard\s+all\s+rules)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class InventoryWorkingItem:
    """Representacao em memoria de um item da arvore pai-filho durante EDRM 1.0-4.0."""

    control_number: str
    parent_control_number: str | None
    source_id: str
    origin_rel_path: str
    staging_or_vault_path: str
    size_bytes: int
    mtime_utc_ns: int
    is_os_readonly: bool
    sha256_hex: str
    magic_signature: MagicSignature
    extension_spoofed: bool
    is_encrypted_or_corrupted: bool
    pdf_eof_count: int
    has_wal_shm_sibling: bool
    custodian_ids: tuple[str, ...]
    is_denist_logical: bool = False
    duplicate_of_cn: str | None = None
    all_custodians: tuple[str, ...] = ()
    all_source_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExtractionBatchOutput:
    """Resultado imutavel agregado de um extrator especializado."""

    timeline_events: tuple[TimelineEventRecord, ...] = ()
    financial_entries: tuple[FinancialLedgerEntryRecord, ...] = ()
    telecom_records: tuple[TelecomCdrRecord, ...] = ()
    cgnat_records: tuple[CgnatAuditRecord, ...] = ()
    anchored_chunks: tuple[AnchoredTextChunk, ...] = ()
    new_primary_docs: tuple[PrimaryDocumentCandidate, ...] = ()
    pdf_info_xmp_conflict: bool = False
    recovered_sqlite_records: tuple[RecoveredSqliteRecord, ...] = ()
    link_provenance_records: tuple[WindowsLinkProvenanceRecord, ...] = ()
    tier_execution_order: tuple[tuple[str, int], ...] = ()


def validate_safe_archive_member(
    member_name: str,
    compressed_size: int,
    uncompressed_size: int,
) -> str:
    """Defesa deterministica contra Path Traversal (../) e Zip Bomb (Subetapa 4.1).

    Args:
        member_name: Caminho interno declarado no arquivo compactado.
        compressed_size: Tamanho comprimido em bytes.
        uncompressed_size: Tamanho descomprimido declarado em bytes.

    Returns:
        Caminho relativo sanitizado seguro.

    Raises:
        ContainerSecurityViolationError: Em caso de traversal ou razao explosiva.
    """
    unified = member_name.replace("\\", "/").strip()
    if unified.startswith("/") or re.match(r"^[A-Za-z]:", unified):
        raise ContainerSecurityViolationError(
            f"Path Traversal absoluto bloqueado em contêiner: {member_name!r}"
        )
    segments = [seg for seg in unified.split("/") if seg and seg != "."]
    if ".." in segments or not segments:
        raise ContainerSecurityViolationError(
            f"Path Traversal relativo ('..') bloqueado em contêiner: {member_name!r}"
        )
    if uncompressed_size > MAX_SINGLE_MEMBER_BYTES:
        raise ContainerSecurityViolationError(
            f"Membro excede teto anti-Zip-Bomb ({uncompressed_size} bytes): {member_name!r}"
        )
    effective_comp = max(1, compressed_size)
    if uncompressed_size > 1024 * 1024 and (uncompressed_size // effective_comp) > MAX_UNPACK_RATIO:
        raise ContainerSecurityViolationError(
            f"Razao de compressao suspeita de Zip Bomb ({uncompressed_size // effective_comp}x): "
            f"{member_name!r}"
        )
    return "/".join(segments)


class DeNistAndLogicalDedupPolicy:
    """Subetapa 4.2 (EDRM 2.0) — De-NIST seguro de familia e deduplicacao preservando prova negativa."""

    @staticmethod
    def apply(
        items: tuple[InventoryWorkingItem, ...],
        nsrl_hashes: frozenset[str] = DEFAULT_NSRL_SYSTEM_HASHES,
    ) -> tuple[InventoryWorkingItem, ...]:
        """Marca De-NIST apenas em pais raiz e consolida duplicatas sem apagar registros."""
        by_sha_canonical_cn: dict[str, str] = {}
        by_sha_custodians: dict[str, list[str]] = {}
        by_sha_paths: dict[str, list[str]] = {}

        for it in items:
            sha = it.sha256_hex.lower()
            if sha not in by_sha_canonical_cn:
                by_sha_canonical_cn[sha] = it.control_number
            cust_list = by_sha_custodians.setdefault(sha, [])
            for cid in it.custodian_ids:
                if cid not in cust_list:
                    cust_list.append(cid)
            path_list = by_sha_paths.setdefault(sha, [])
            if it.origin_rel_path not in path_list:
                path_list.append(it.origin_rel_path)

        processed: list[InventoryWorkingItem] = []
        for it in items:
            sha = it.sha256_hex.lower()
            cn_obj = ControlNumber(it.control_number)
            denist_flag = cn_obj.is_top_level and (sha in nsrl_hashes)
            first_cn = by_sha_canonical_cn[sha]
            dup_of = None if first_cn == it.control_number else first_cn

            processed.append(
                InventoryWorkingItem(
                    control_number=it.control_number,
                    parent_control_number=it.parent_control_number,
                    source_id=it.source_id,
                    origin_rel_path=it.origin_rel_path,
                    staging_or_vault_path=it.staging_or_vault_path,
                    size_bytes=it.size_bytes,
                    mtime_utc_ns=it.mtime_utc_ns,
                    is_os_readonly=it.is_os_readonly,
                    sha256_hex=it.sha256_hex,
                    magic_signature=it.magic_signature,
                    extension_spoofed=it.extension_spoofed,
                    is_encrypted_or_corrupted=it.is_encrypted_or_corrupted,
                    pdf_eof_count=it.pdf_eof_count,
                    has_wal_shm_sibling=it.has_wal_shm_sibling,
                    custodian_ids=it.custodian_ids,
                    is_denist_logical=denist_flag,
                    duplicate_of_cn=dup_of,
                    all_custodians=tuple(by_sha_custodians[sha]),
                    all_source_paths=tuple(by_sha_paths[sha]),
                )
            )
        return tuple(processed)


def is_event_post_seizure(event_epoch_seconds: int, seizure_epoch_seconds: int | None) -> bool:
    """Detector automatico de atividade pos-apreensao (ts_utc > seizure_utc)."""
    if seizure_epoch_seconds is None:
        return False
    return event_epoch_seconds > seizure_epoch_seconds


def build_sanitized_chunk(
    origin_cn: str,
    origin_path: str,
    locator: str,
    raw_text: str,
    origin_sha256: str,
) -> AnchoredTextChunk:
    """Cria chunk textual ancorado neutralizando padroes de prompt injection indireto."""
    had_inj = bool(_PROMPT_INJ_RE.search(raw_text))
    cleaned = _PROMPT_INJ_RE.sub("[INJECTION_PATTERN_ISOLATED]", raw_text) if had_inj else raw_text
    cid = "CHK-" + sha256_text(f"{origin_cn}|{locator}|{cleaned[:120]}")[:16].upper()
    return AnchoredTextChunk(
        chunk_id=cid,
        origin_cn=origin_cn,
        origin_path=origin_path,
        locator=locator,
        text_clean=cleaned,
        injection_neutralized=had_inj,
        origin_sha256=origin_sha256,
    )


class PureTabularForensicParsers:
    """Parsers puros deterministcos para SIMBA/CSV, CDR/ERB ANATEL, E-mail e CGNAT."""

    @staticmethod
    def parse_simba_or_financial_csv(
        text: str,
        origin_cn: str,
        origin_sha256: str,
        seen_signatures: set[str],
    ) -> tuple[FinancialLedgerEntryRecord, ...]:
        """Converte lancamentos SIMBA BACEN / CSV em centavos inteiros BIGINT e detecta duplicatas."""
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return ()
        header_low = lines[0].lower()
        if not any(k in header_low for k in ("valor", "amount", "agencia", "conta", "simba", "cpf_cnpj")):
            return ()

        delim = ";" if ";" in lines[0] else ","
        cols = [c.strip().lower() for c in lines[0].split(delim)]
        out: list[FinancialLedgerEntryRecord] = []

        for row_idx, row_line in enumerate(lines[1:], start=2):
            parts = [p.strip() for p in row_line.split(delim)]
            if len(parts) < len(cols):
                continue
            row_map = dict(zip(cols, parts))
            raw_val = row_map.get("valor") or row_map.get("amount") or "0,00"
            cents_vo = parse_money_to_cents(raw_val)
            raw_dt = row_map.get("data_lancamento") or row_map.get("tx_utc") or row_map.get("data") or "2026-01-01T00:00:00Z"
            tx_ts = parse_timestamp_to_utc(raw_dt)
            bank = row_map.get("banco", "001")
            branch = row_map.get("agencia", "0001")
            acct = row_map.get("conta", "00000-0")
            holder = row_map.get("titular_cpf_cnpj") or row_map.get("holder_tax_id") or "EXPLICIT_GAP"
            counter = row_map.get("origem_destino_cpf_cnpj") or row_map.get("counterparty_tax_id") or "EXPLICIT_GAP"
            dc = (row_map.get("natureza") or row_map.get("dc") or "C").upper()

            dup_key = f"{bank}|{branch}|{acct}|{holder}|{counter}|{tx_ts.iso_utc}|{dc}|{cents_vo.cents}"
            is_dup = dup_key in seen_signatures
            seen_signatures.add(dup_key)

            entry_id = "FIN-" + sha256_text(f"{origin_cn}|{row_idx}|{dup_key}")[:14].upper()
            out.append(
                FinancialLedgerEntryRecord(
                    entry_id=entry_id,
                    origin_cn=origin_cn,
                    bank_code=bank,
                    branch=branch,
                    account=acct,
                    holder_tax_id=holder,
                    counterparty_tax_id=counter,
                    tx_utc=tx_ts.iso_utc,
                    debit_credit=dc,
                    amount_cents=cents_vo.cents,
                    raw_amount_text=raw_val,
                    is_inter_file_duplicate=is_dup,
                    locator=f"linha {row_idx}",
                    origin_sha256=origin_sha256,
                )
            )
        return tuple(out)

    @staticmethod
    def parse_cdr_erb_csv(
        text: str,
        origin_cn: str,
        origin_sha256: str,
    ) -> tuple[TelecomCdrRecord, ...]:
        """Normaliza registros CDR/ERB em UTC e micrograus inteiros com detector de salto impossivel."""
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return ()
        header_low = lines[0].lower()
        if not any(k in header_low for k in ("cgi", "erb", "cell_id", "lat_microdeg", "azimute")):
            return ()

        delim = ";" if ";" in lines[0] else ","
        cols = [c.strip().lower() for c in lines[0].split(delim)]
        out: list[TelecomCdrRecord] = []
        prev_by_caller: dict[str, tuple[int, int, int]] = {}

        for row_idx, row_line in enumerate(lines[1:], start=2):
            parts = [p.strip() for p in row_line.split(delim)]
            if len(parts) < len(cols):
                continue
            rm = dict(zip(cols, parts))
            caller = rm.get("caller") or rm.get("interlocutor_a") or "UNKNOWN"
            callee = rm.get("callee") or rm.get("interlocutor_b") or "UNKNOWN"
            imei = rm.get("imei") or "EXPLICIT_GAP"
            start_ts = parse_timestamp_to_utc(rm.get("start_time") or rm.get("inicio") or "2026-01-01T00:00:00Z")
            dur = int(rm.get("duration_sec") or rm.get("duracao") or "0")
            cgi = rm.get("cgi") or rm.get("cell_id") or "724-00-0000-0000"
            lat_micro = _coord_to_microdeg(rm.get("lat_microdeg") or rm.get("latitude") or "0")
            lon_micro = _coord_to_microdeg(rm.get("lon_microdeg") or rm.get("longitude") or "0")
            azimuth = int(rm.get("azimuth_deg") or rm.get("azimute") or "0")

            impossible = False
            if caller in prev_by_caller:
                prev_ep, prev_lat, prev_lon = prev_by_caller[caller]
                dt_sec = abs(start_ts.epoch_seconds - prev_ep)
                d_lat_m = (abs(lat_micro - prev_lat) * 111_139) // 1_000_000
                d_lon_m = (abs(lon_micro - prev_lon) * 100_000) // 1_000_000
                approx_dist_m = d_lat_m + d_lon_m
                if approx_dist_m > 50_000 and (dt_sec == 0 or (approx_dist_m // max(1, dt_sec)) > 340):
                    impossible = True

            prev_by_caller[caller] = (start_ts.epoch_seconds, lat_micro, lon_micro)
            cdr_id = "CDR-" + sha256_text(f"{origin_cn}|{row_idx}|{caller}|{start_ts.iso_utc}")[:14].upper()
            out.append(
                TelecomCdrRecord(
                    cdr_id=cdr_id,
                    origin_cn=origin_cn,
                    caller=caller,
                    callee=callee,
                    imei=imei,
                    start_utc=start_ts.iso_utc,
                    epoch_seconds=start_ts.epoch_seconds,
                    duration_sec=dur,
                    cell_cgi=cgi,
                    lat_microdeg=lat_micro,
                    lon_microdeg=lon_micro,
                    azimuth_deg=azimuth,
                    impossible_speed_flag=impossible,
                    locator=f"linha {row_idx}",
                    origin_sha256=origin_sha256,
                )
            )
        return tuple(out)

    @staticmethod
    def parse_cgnat_logs(
        text: str,
        origin_cn: str,
        origin_sha256: str,
    ) -> tuple[CgnatAuditRecord, ...]:
        """Audita logs IP/CGNAT exigindo porta logica de origem (Decreto 12.975/2026)."""
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(lines) < 2:
            return ()
        header_low = lines[0].lower()
        if "cgnat" not in header_low and "shared_ip" not in header_low and "ip_compartilhado" not in header_low:
            return ()

        delim = ";" if ";" in lines[0] else ","
        cols = [c.strip().lower() for c in lines[0].split(delim)]
        out: list[CgnatAuditRecord] = []

        for row_idx, row_line in enumerate(lines[1:], start=2):
            parts = [p.strip() for p in row_line.split(delim)]
            if len(parts) < len(cols):
                continue
            rm = dict(zip(cols, parts))
            ip_str = rm.get("shared_ip") or rm.get("ip_compartilhado") or "0.0.0.0"
            raw_port = (rm.get("source_port") or rm.get("porta_logica") or "").strip()
            ts_val = parse_timestamp_to_utc(rm.get("ts_utc") or rm.get("timestamp") or "2026-01-01T00:00:00Z")

            port_int: int | None = None
            if raw_port.isdigit():
                cand_p = int(raw_port)
                if 1 <= cand_p <= 65535:
                    port_int = cand_p

            missing_defect = port_int is None
            log_id = "CGN-" + sha256_text(f"{origin_cn}|{row_idx}|{ip_str}|{ts_val.iso_utc}")[:14].upper()
            out.append(
                CgnatAuditRecord(
                    log_id=log_id,
                    origin_cn=origin_cn,
                    shared_ip=ip_str,
                    source_logical_port=port_int,
                    ts_utc=ts_val.iso_utc,
                    missing_logical_port_defect=missing_defect,
                    locator=f"linha {row_idx}",
                    origin_sha256=origin_sha256,
                )
            )
        return tuple(out)


def _coord_to_microdeg(raw: str) -> int:
    cleaned = raw.strip().replace(",", ".")
    if "." in cleaned:
        scaled = (Decimal(cleaned) * Decimal(1_000_000)).to_integral_value()
        return int(scaled)
    return int(cleaned)


def detect_primary_doc_in_unpacked_text(
    rel_path: str,
    origin_cn: str,
    sha256_hex: str,
    text: str,
    captured_at_utc: str,
    source_id: str,
) -> PrimaryDocumentCandidate | None:
    """Identifica pecas processuais primarias descompactadas na Fase 04 (Extrator #11)."""
    upper = text.upper()
    doc_type: PrimaryDocType | None = None
    if "AUTO DE APREENS" in upper:
        doc_type = PrimaryDocType.AUTO_APREENSAO
    elif "FICHA DE ACOMPANHAMENTO DE VEST" in upper or ("FAV" in upper and "LACRE" in upper):
        doc_type = PrimaryDocType.FAV
    elif "MANDADO DE BUSCA" in upper:
        doc_type = PrimaryDocType.MANDADO
    elif "LAUDO PERICIAL" in upper or "LAUDO OFICIAL" in upper:
        doc_type = PrimaryDocType.LAUDO_PERICIAL
    if doc_type is None:
        return None
    first_ln = text.strip().splitlines()[0][:160]
    return PrimaryDocumentCandidate(
        source_id=source_id,
        rel_path=rel_path,
        sha256_hex=sha256_hex,
        doc_type=doc_type,
        extracted_text=text,
        anchor=SourceAnchor(
            origin_control_number=origin_cn,
            origin_path=rel_path,
            locator="p. 1",
            verbatim_excerpt=first_ln,
            captured_at_utc=captured_at_utc,
            origin_sha256=sha256_hex,
        ),
    )


@dataclass(frozen=True, slots=True)
class RegisteredExtractorSpec:
    """Especificacao plugavel no ExtractorRegistry (Principio Open/Closed)."""

    name: str
    predicate: Callable[[InventoryWorkingItem], bool]
    handler: Callable[[InventoryWorkingItem, int | None, set[str], str], ExtractionBatchOutput]


class ExtractorRegistry:
    """Registro extensivel OCP de extratores especializados da Subetapa 4.3."""

    def __init__(self) -> None:
        self._specs: list[RegisteredExtractorSpec] = []

    def register(self, spec: RegisteredExtractorSpec) -> None:
        """Adiciona um extrator especializado ao pipeline sem alterar o caso de uso."""
        self._specs.append(spec)

    @property
    def specs(self) -> tuple[RegisteredExtractorSpec, ...]:
        """Retorna todos os extratores registrados."""
        return tuple(self._specs)
