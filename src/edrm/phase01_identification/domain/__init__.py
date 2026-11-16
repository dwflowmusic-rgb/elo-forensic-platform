"""Dominio puro da Fase 01 — Magic Bytes, Schemas Dinamicos, POP Senasp, Paridade e Cochran."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
import re
from typing import Callable

from edrm.shared_kernel.contracts import (
    CochranSamplePlan,
    CustodianRecord,
    DeclaredEvidenceItem,
    DivergenceRecord,
    DynamicSchemaBlueprint,
    ParityMatrixRow,
    PrimaryDocumentCandidate,
    ProbedFileRecord,
    StateIpedAuditReport,
)
from edrm.shared_kernel.enums import (
    EpistemicStatus,
    MagicSignature,
    ParityState,
    PrimaryDocType,
    ReconciliationTier,
    StateIpedProfileRisk,
)
from edrm.shared_kernel.time_normalizer import parse_timestamp_to_utc
from edrm.shared_kernel.value_objects import ControlNumber, SourceAnchor, sha256_text

_KNOWN_MOBILE_TABLES: frozenset[str] = frozenset(
    {
        "messages",
        "message",
        "chat",
        "jid",
        "zwamessage",
        "zwachatstorage",
        "zwagroupmember",
        "sqlite_sequence",
        "android_metadata",
    }
)

_SAFE_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`\[]?([A-Za-z_][A-Za-z0-9_]*)[\"`\]]?\s*\((.+)\)",
    re.IGNORECASE | re.DOTALL,
)
_PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+previous\s+instructions|system\s+prompt|disregard\s+all\s+rules)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SignatureRule:
    """Regra plugavel de assinatura binaria de 16 bytes (Principio Open/Closed)."""

    name: str
    signature: MagicSignature
    expected_extensions: tuple[str, ...]
    matcher: Callable[[bytes, str], bool]


class SignatureRegistry:
    """Registro extensivel OCP de assinaturas binarias reais e deteccao de camuflagem."""

    def __init__(self) -> None:
        self._rules: list[SignatureRule] = []
        self._register_builtin_signatures()

    def register(self, rule: SignatureRule) -> None:
        """Registra uma nova regra de assinatura binaria sem alterar casos de uso."""
        self._rules.insert(0, rule)

    def _register_builtin_signatures(self) -> None:
        defaults: tuple[SignatureRule, ...] = (
            SignatureRule(
                name="SQLite3Header",
                signature=MagicSignature.SQLITE3,
                expected_extensions=(".db", ".sqlite", ".sqlite3", ".sqlitedb", ".storedata"),
                matcher=lambda b, _: b.startswith(b"SQLite format 3\x00"),
            ),
            SignatureRule(
                name="EnCaseEwfE01",
                signature=MagicSignature.EWF_E01,
                expected_extensions=(".e01", ".ex01", ".s01"),
                matcher=lambda b, _: b.startswith(b"EVF\x09\x0d\x0a\xff\x00"),
            ),
            SignatureRule(
                name="PdfDocument",
                signature=MagicSignature.PDF_DOCUMENT,
                expected_extensions=(".pdf",),
                matcher=lambda b, _: b.startswith(b"%PDF-"),
            ),
            SignatureRule(
                name="CellebriteUfdrContainer",
                signature=MagicSignature.CELLEBRITE_UFDR_UFDX,
                expected_extensions=(".ufdr", ".ufdx"),
                matcher=lambda b, ext: b.startswith(b"PK\x03\x04") and ext in (".ufdr", ".ufdx"),
            ),
            SignatureRule(
                name="ZipContainer",
                signature=MagicSignature.ZIP_CONTAINER,
                expected_extensions=(".zip", ".docx", ".xlsx", ".odt", ".jar", ".apk"),
                matcher=lambda b, ext: b.startswith(b"PK\x03\x04")
                and ext not in (".ufdr", ".ufdx"),
            ),
            SignatureRule(
                name="RarArchive",
                signature=MagicSignature.RAR_V4_V5,
                expected_extensions=(".rar",),
                matcher=lambda b, _: b.startswith(b"Rar!\x1a\x07"),
            ),
            SignatureRule(
                name="SevenZipArchive",
                signature=MagicSignature.SEVEN_ZIP,
                expected_extensions=(".7z",),
                matcher=lambda b, _: b.startswith(b"7z\xbc\xaf\x27\x1c"),
            ),
            SignatureRule(
                name="OutlookPstOst",
                signature=MagicSignature.PST_OST,
                expected_extensions=(".pst", ".ost"),
                matcher=lambda b, _: b.startswith(b"!BDN"),
            ),
            SignatureRule(
                name="GzipArchive",
                signature=MagicSignature.GZIP,
                expected_extensions=(".gz", ".tgz"),
                matcher=lambda b, _: b.startswith(b"\x1f\x8b\x08"),
            ),
            SignatureRule(
                name="LuksVolume",
                signature=MagicSignature.LUKS,
                expected_extensions=(".luks", ".img", ".bin", ".enc"),
                matcher=lambda b, _: b.startswith(b"LUKS\xba\xbe"),
            ),
            SignatureRule(
                name="WhatsAppCrypt",
                signature=MagicSignature.WHATSAPP_CRYPT,
                expected_extensions=(".crypt12", ".crypt14", ".crypt15"),
                matcher=lambda b, ext: ext in (".crypt12", ".crypt14", ".crypt15")
                or b.startswith(b"WACR"),
            ),
            SignatureRule(
                name="WavAudio",
                signature=MagicSignature.WAV_AUDIO,
                expected_extensions=(".wav",),
                matcher=lambda b, _: len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WAVE",
            ),
            SignatureRule(
                name="JpegImage",
                signature=MagicSignature.JPEG_IMAGE,
                expected_extensions=(".jpg", ".jpeg"),
                matcher=lambda b, _: b.startswith(b"\xff\xd8\xff"),
            ),
            SignatureRule(
                name="PngImage",
                signature=MagicSignature.PNG_IMAGE,
                expected_extensions=(".png",),
                matcher=lambda b, _: b.startswith(b"\x89PNG\r\n\x1a\n"),
            ),
            SignatureRule(
                name="Mp4Video",
                signature=MagicSignature.MP4_VIDEO,
                expected_extensions=(".mp4", ".m4a", ".mov"),
                matcher=lambda b, _: len(b) >= 8 and b[4:8] == b"ftyp",
            ),
            SignatureRule(
                name="WindowsLnkShortcut",
                signature=MagicSignature.WINDOWS_LNK_SHORTCUT,
                expected_extensions=(".lnk",),
                matcher=lambda b, _: len(b) >= 8 and b[:8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00",
            ),
            SignatureRule(
                name="XmlDocument",
                signature=MagicSignature.XML_DOCUMENT,
                expected_extensions=(".xml", ".ufd", ".ufdx", ".ofx", ".html"),
                matcher=lambda b, _: b.lstrip().startswith(b"<?xml") or b.lstrip().startswith(b"<"),
            ),
        )
        self._rules = list(defaults)

    def classify(self, header_16b: bytes, filename: str, sample_bytes: bytes = b"") -> tuple[MagicSignature, bool, bool]:
        """Classifica os 16 bytes iniciais e avalia camuflagem de extensao ou cifragem.

        Args:
            header_16b: Primeiros 16 bytes lidos do arquivo.
            filename: Nome logico do arquivo (para extrair extensao nominal).
            sample_bytes: Amostra inicial opcional (ate 4096 bytes) para avaliacao de cifragem.

        Returns:
            Tupla (MagicSignature, extension_spoofed, is_encrypted_or_corrupted).
        """
        lower_name = filename.lower()
        dot_idx = lower_name.rfind(".")
        ext = lower_name[dot_idx:] if dot_idx != -1 else ""

        for rule in self._rules:
            if rule.matcher(header_16b, ext):
                spoofed = bool(ext) and (ext not in rule.expected_extensions)
                is_enc = rule.signature in (
                    MagicSignature.LUKS,
                    MagicSignature.PGP_GPG,
                    MagicSignature.WHATSAPP_CRYPT,
                )
                return rule.signature, spoofed, is_enc

        probe_buf = sample_bytes if sample_bytes else header_16b
        if ext in (".enc", ".gpg", ".pgp", ".aes", ".locked"):
            return MagicSignature.HIGH_ENTROPY_ENCRYPTED, False, True

        if probe_buf and b"\x00" not in probe_buf:
            try:
                probe_buf.decode("utf-8")
                return MagicSignature.UTF8_TEXT_OR_CSV, False, False
            except UnicodeDecodeError:
                distinct_bytes = len(set(probe_buf))
                if len(probe_buf) >= 256 and distinct_bytes >= 200:
                    return MagicSignature.HIGH_ENTROPY_ENCRYPTED, False, True

        if len(probe_buf) >= 256 and len(set(probe_buf)) >= 215:
            return MagicSignature.HIGH_ENTROPY_ENCRYPTED, False, True

        return MagicSignature.UNKNOWN_BINARY, False, False


def sanitize_indirect_prompt_injection(raw_text: str) -> tuple[str, bool]:
    """Neutraliza tentativas de prompt injection indireto sem destruir a prova textual.

    Args:
        raw_text: Texto extraido da evidencia.

    Returns:
        Tupla (texto_sanitizado, houve_neutralizacao).
    """
    if _PROMPT_INJECTION_RE.search(raw_text):
        neutralized = _PROMPT_INJECTION_RE.sub("[INJECTION_PATTERN_ISOLATED]", raw_text)
        return neutralized, True
    return raw_text, False


class SchemaDiscoveryEngine:
    """Descobre esquemas SQLite ineditos no HD e gera DynamicSchemaBlueprint seguro."""

    @staticmethod
    def build_dynamic_blueprints(probed_files: tuple[ProbedFileRecord, ...]) -> tuple[DynamicSchemaBlueprint, ...]:
        """Inspeciona comandos CREATE TABLE extraidos e mapeia tabelas desconhecidas.

        Args:
            probed_files: Arquivos sondados na Etapa 1.A/1.B.

        Returns:
            Tupla de DynamicSchemaBlueprint validados sintaticamente contra SQL injection.
        """
        blueprints: list[DynamicSchemaBlueprint] = []
        for pf in probed_files:
            if pf.magic_signature != MagicSignature.SQLITE3 or not pf.sqlite_schemas:
                continue
            for ddl in pf.sqlite_schemas:
                match = _CREATE_TABLE_RE.search(ddl)
                if not match:
                    continue
                table_name = match.group(1)
                if table_name.lower() in _KNOWN_MOBILE_TABLES:
                    continue
                if not _SAFE_SQL_IDENT_RE.match(table_name):
                    continue

                cols_block = match.group(2)
                col_names: list[str] = []
                for raw_col_def in cols_block.split(","):
                    tokens = raw_col_def.strip().split()
                    if not tokens:
                        continue
                    first_tok = tokens[0].strip("\"`[]")
                    upper_tok = first_tok.upper()
                    if upper_tok in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
                        continue
                    if _SAFE_SQL_IDENT_RE.match(first_tok):
                        col_names.append(first_tok)

                if not col_names:
                    continue

                ts_col = col_names[0]
                actor_col = col_names[0]
                content_col = col_names[-1]
                for c in col_names:
                    cl = c.lower()
                    if any(k in cl for k in ("ts", "time", "date", "created", "sent", "utc")):
                        ts_col = c
                    elif any(k in cl for k in ("sender", "user", "author", "from", "actor", "account")):
                        actor_col = c
                    elif any(k in cl for k in ("body", "text", "msg", "content", "payload", "note", "memo")):
                        content_col = c

                sql_template = (
                    f"SELECT {ts_col}, {actor_col}, {content_col} FROM {table_name}"
                )
                schema_sig = sha256_text(f"{pf.rel_path}|{table_name}|{','.join(col_names)}")
                approved = (
                    _SAFE_SQL_IDENT_RE.match(ts_col) is not None
                    and _SAFE_SQL_IDENT_RE.match(actor_col) is not None
                    and _SAFE_SQL_IDENT_RE.match(content_col) is not None
                )
                blueprints.append(
                    DynamicSchemaBlueprint(
                        schema_hash=schema_sig,
                        origin_rel_path=pf.rel_path,
                        table_name=table_name,
                        columns=tuple(col_names),
                        timestamp_column=ts_col,
                        actor_column=actor_col,
                        content_column=content_col,
                        inferred_domain="CUSTOM_APP_SQLITE_LEDGER_OR_MESSENGER",
                        extraction_sql_template=sql_template,
                        approved_by_verifier=approved,
                    )
                )
        return tuple(blueprints)


class PrimaryDocumentClassifierAndExtractor:
    """Reconhece pecas processuais primarias e extrai fichas atomicas POP Senasp 2024."""

    @staticmethod
    def detect_primary_documents(
        probed_files: tuple[ProbedFileRecord, ...],
        captured_at_utc: str,
    ) -> tuple[PrimaryDocumentCandidate, ...]:
        """Localiza Autos de Apreensao, Mandados, FAVs, Decisoes e Laudos no HD."""
        candidates: list[PrimaryDocumentCandidate] = []
        idx = 1
        for pf in probed_files:
            if not pf.text_preview.strip():
                continue
            upper = pf.text_preview.upper()
            lower_path = pf.rel_path.lower()
            doc_type: PrimaryDocType | None = None
            if "AUTO DE APREENS" in upper or "auto_apreensao" in lower_path:
                doc_type = PrimaryDocType.AUTO_APREENSAO
            elif "FICHA DE ACOMPANHAMENTO DE VEST" in upper or "FAV" in upper and "LACRE" in upper:
                doc_type = PrimaryDocType.FAV
            elif "LAUDO PERICIAL" in upper or "laudo_pericial" in lower_path or "LAUDO OFICIAL" in upper:
                doc_type = PrimaryDocType.LAUDO_PERICIAL
            elif "MANDADO DE BUSCA" in upper or "mandado" in lower_path:
                doc_type = PrimaryDocType.MANDADO
            elif "DECISAO JUDICIAL" in upper or "DECISÃO JUDICIAL" in upper:
                doc_type = PrimaryDocType.DECISAO_JUDICIAL
            elif "DENUNCIA" in upper or "DENÚNCIA" in upper:
                doc_type = PrimaryDocType.DENUNCIA

            if doc_type is not None:
                clean_txt, _ = sanitize_indirect_prompt_injection(pf.text_preview)
                first_line = clean_txt.strip().splitlines()[0][:160]
                anchor = SourceAnchor(
                    origin_control_number=ControlNumber.root(idx).code,
                    origin_path=pf.rel_path,
                    locator="p. 1",
                    verbatim_excerpt=first_line,
                    captured_at_utc=captured_at_utc,
                    origin_sha256=pf.sha256_hex,
                )
                candidates.append(
                    PrimaryDocumentCandidate(
                        source_id=pf.source_id,
                        rel_path=pf.rel_path,
                        sha256_hex=pf.sha256_hex,
                        doc_type=doc_type,
                        extracted_text=clean_txt,
                        anchor=anchor,
                    )
                )
                idx += 1
        return tuple(candidates)

    @staticmethod
    def extract_declarations_and_divergences(
        candidates: tuple[PrimaryDocumentCandidate, ...],
        captured_at_utc: str,
    ) -> tuple[tuple[CustodianRecord, ...], tuple[DeclaredEvidenceItem, ...], tuple[DivergenceRecord, ...]]:
        """Extrai custodiantes, vestigios POP Senasp 2024 (Zero-Silent-Drop) e divergencias."""
        custodians_by_id: dict[str, CustodianRecord] = {}
        declared_items: list[DeclaredEvidenceItem] = []
        items_by_logical_ref: dict[str, list[DeclaredEvidenceItem]] = {}

        for doc in candidates:
            blocks = re.split(r"\n(?=ITEM\s*[:#]|\bVESTIGIO\s*[:#])", doc.extracted_text, flags=re.IGNORECASE)
            cust_match = re.search(r"CUSTODIANTE\s*:\s*([^\n]+)", doc.extracted_text, re.IGNORECASE)
            cpf_match = re.search(r"CPF\s*:\s*([0-9.\-]+)", doc.extracted_text, re.IGNORECASE)
            cust_name = cust_match.group(1).strip() if cust_match else "EXPLICIT_GAP"
            cust_cpf = cpf_match.group(1).strip() if cpf_match else "EXPLICIT_GAP"
            cust_id = "CUST-" + sha256_text(cust_name.upper())[:10].upper()

            if cust_id not in custodians_by_id:
                cust_excerpt = cust_match.group(0).strip() if cust_match else doc.anchor.verbatim_excerpt
                custodians_by_id[cust_id] = CustodianRecord(
                    custodian_id=cust_id,
                    name=cust_name,
                    role="INVESTIGADO" if cust_name != "EXPLICIT_GAP" else "EXPLICIT_GAP",
                    identifiers=(cust_cpf,) if cust_cpf != "EXPLICIT_GAP" else (),
                    epistemic_status=(
                        EpistemicStatus.STATE_ALLEGATION
                        if cust_name != "EXPLICIT_GAP"
                        else EpistemicStatus.EXPLICIT_GAP
                    ),
                    anchor=SourceAnchor(
                        origin_control_number=doc.anchor.origin_control_number,
                        origin_path=doc.rel_path,
                        locator="p. 1",
                        verbatim_excerpt=cust_excerpt,
                        captured_at_utc=captured_at_utc,
                        origin_sha256=doc.sha256_hex,
                    ),
                )

            seizure_global = _extract_kv(doc.extracted_text, r"DATA_HORA_APREENSAO\s*:\s*([^\n]+)")
            seizure_utc_str = "EXPLICIT_GAP"
            if seizure_global != "EXPLICIT_GAP":
                try:
                    seizure_utc_str = parse_timestamp_to_utc(seizure_global).iso_utc
                except Exception:
                    seizure_utc_str = "EXPLICIT_GAP"

            for blk_idx, blk in enumerate(blocks):
                if not re.search(r"(?:ITEM|VESTIGIO)\s*[:#]", blk, re.IGNORECASE):
                    continue
                item_ref = _extract_kv(blk, r"(?:ITEM|VESTIGIO)\s*[:#]\s*([^\n]+)")
                brand = _extract_kv(blk, r"MARCA\s*:\s*([^\n]+)")
                model = _extract_kv(blk, r"MODELO\s*:\s*([^\n]+)")
                serial = _extract_kv(blk, r"SERIE\s*:\s*([^\n]+)")
                imei_ch = _extract_list_kv(blk, r"IMEI_CHASSI\s*:\s*([^\n]+)")
                imei_mem = _extract_list_kv(blk, r"IMEI_MEMORIA\s*:\s*([^\n]+)")
                iccid = _extract_list_kv(blk, r"ICCID\s*:\s*([^\n]+)")
                sec_space = _extract_kv(blk, r"SEGUNDO_ESPACO\s*:\s*([^\n]+)")
                lock_st = _extract_kv(blk, r"ESTADO_BLOQUEIO\s*:\s*([^\n]+)")
                rf_iso = _extract_kv(blk, r"ISOLAMENTO_RF\s*:\s*([^\n]+)")
                seals_in = _extract_list_kv(blk, r"LACRE_ENTRADA\s*:\s*([^\n]+)")
                seals_out = _extract_list_kv(blk, r"LACRE_SAIDA\s*:\s*([^\n]+)")
                work_copy = _extract_kv(blk, r"COPIA_TRABALHO\s*:\s*([^\n]+)")
                st_hash = _extract_kv(blk, r"HASH_ORIGEM\s*:\s*([^\n]+)").lower()
                master_hash = _extract_kv(blk, r"HASH_LISTA_MESTRE\s*:\s*([^\n]+)").lower()
                raw_fmt = _extract_kv(blk, r"FORMATO_BRUTO_ESPERADO\s*:\s*([^\n]+)")
                expert_ok = _extract_kv(blk, r"PERITO_OFICIAL\s*:\s*([^\n]+)")
                coll_method = _extract_kv(blk, r"METODO_COLETA\s*:\s*([^\n]+)")
                via_msg_raw = _extract_kv(blk, r"TRANSITO_MENSAGEIRO\s*:\s*([^\n]+)")
                via_msg = via_msg_raw.upper() in ("SIM", "TRUE", "YES", "WHATSAPP")

                blk_seizure = _extract_kv(blk, r"DATA_HORA_APREENSAO\s*:\s*([^\n]+)")
                final_seizure = seizure_utc_str
                if blk_seizure != "EXPLICIT_GAP":
                    try:
                        final_seizure = parse_timestamp_to_utc(blk_seizure).iso_utc
                    except Exception:
                        final_seizure = "EXPLICIT_GAP"

                first_blk_line = blk.strip().splitlines()[0][:160]
                decl_id = "DECL-" + sha256_text(f"{doc.rel_path}|{item_ref}|{blk_idx}")[:12].upper()
                has_gap = "EXPLICIT_GAP" in (
                    final_seizure,
                    brand,
                    model,
                    rf_iso,
                    st_hash,
                ) or len(seals_in) == 0

                item = DeclaredEvidenceItem(
                    declared_id=decl_id,
                    custodian_id=cust_id,
                    primary_doc_type=doc.doc_type,
                    seizure_utc=final_seizure,
                    brand=brand,
                    model=model,
                    serial_number=serial,
                    imei_chassis=imei_ch,
                    imei_memory=imei_mem,
                    iccid=iccid,
                    has_second_space_checked=sec_space,
                    lock_state=lock_st,
                    rf_isolation=rf_iso,
                    seals_in=seals_in,
                    seals_out=seals_out,
                    working_copy_examined=work_copy,
                    state_sha256=st_hash,
                    master_hashlist_sha256=master_hash,
                    expected_raw_format=raw_fmt,
                    extracted_by_official_expert=expert_ok,
                    collection_method_declared=coll_method,
                    transited_via_messenger=via_msg,
                    epistemic_status=(
                        EpistemicStatus.EXPLICIT_GAP
                        if has_gap
                        else EpistemicStatus.STATE_ALLEGATION
                    ),
                    anchor=SourceAnchor(
                        origin_control_number=doc.anchor.origin_control_number,
                        origin_path=doc.rel_path,
                        locator=f"bloco {blk_idx + 1}",
                        verbatim_excerpt=first_blk_line,
                        captured_at_utc=captured_at_utc,
                        origin_sha256=doc.sha256_hex,
                    ),
                )
                declared_items.append(item)
                items_by_logical_ref.setdefault(item_ref.upper(), []).append(item)

        divergences: list[DivergenceRecord] = []
        for ref_key, group in sorted(items_by_logical_ref.items()):
            if len(group) < 2:
                continue
            first_it = group[0]
            for other_it in group[1:]:
                if first_it.seals_in and other_it.seals_in and first_it.seals_in != other_it.seals_in:
                    div_id = "DIV-" + sha256_text(f"SEAL|{first_it.declared_id}|{other_it.declared_id}")[:10].upper()
                    divergences.append(
                        DivergenceRecord(
                            divergence_id=div_id,
                            field_name=f"seals_in ({ref_key})",
                            left_value=",".join(first_it.seals_in),
                            left_anchor=first_it.anchor,
                            right_value=",".join(other_it.seals_in),
                            right_anchor=other_it.anchor,
                            description=(
                                f"Divergencia material de lacre para {ref_key}: "
                                f"{first_it.seals_in} em {first_it.primary_doc_type} vs "
                                f"{other_it.seals_in} em {other_it.primary_doc_type}."
                            ),
                        )
                    )
                if (
                    first_it.state_sha256 != "explicit_gap"
                    and other_it.state_sha256 != "explicit_gap"
                    and first_it.state_sha256 != other_it.state_sha256
                ):
                    div_id = "DIV-" + sha256_text(f"HASH|{first_it.declared_id}|{other_it.declared_id}")[:10].upper()
                    divergences.append(
                        DivergenceRecord(
                            divergence_id=div_id,
                            field_name=f"state_sha256 ({ref_key})",
                            left_value=first_it.state_sha256,
                            left_anchor=first_it.anchor,
                            right_value=other_it.state_sha256,
                            right_anchor=other_it.anchor,
                            description=f"Conflito de SHA-256 estatal declarado para {ref_key}.",
                        )
                    )

        return tuple(custodians_by_id.values()), tuple(declared_items), tuple(divergences)


def _extract_kv(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return "EXPLICIT_GAP"
    val = match.group(1).strip()
    if not val or val.upper() in ("N/A", "NAO CONSTA", "NÃO CONSTA", "OMISSO", "-"):
        return "EXPLICIT_GAP"
    return val


def _extract_list_kv(text: str, pattern: str) -> tuple[str, ...]:
    raw = _extract_kv(text, pattern)
    if raw == "EXPLICIT_GAP":
        return ()
    parts = [p.strip() for p in re.split(r"[,;/]", raw) if p.strip()]
    return tuple(parts)


class CopyReconciliationEngine:
    """Hierarquia deterministica de reconciliacao de copias na midia (Microfase 1.6)."""

    @staticmethod
    def classify_pair(left: ProbedFileRecord, right: ProbedFileRecord) -> ReconciliationTier:
        """Classifica a relacao entre dois arquivos nos 4 niveis forenses."""
        if left.sha256_hex == right.sha256_hex:
            return ReconciliationTier.EXACT_SHA256
        left_name = left.rel_path.rsplit("/", 1)[-1].lower()
        right_name = right.rel_path.rsplit("/", 1)[-1].lower()
        if left_name == right_name and left.size_bytes == right.size_bytes:
            return ReconciliationTier.FILENAME_AND_EXACT_BYTES
        if left_name == right_name:
            return ReconciliationTier.WEAK_NAME_ONLY_UNCONFIRMED
        return ReconciliationTier.UNRESOLVED_GAP


class ParityMatrixEngine:
    """Motor deterministico Declarado x Entregue nos 7 estados oficiais (Microfase 1.9)."""

    @staticmethod
    def compute(
        declared_items: tuple[DeclaredEvidenceItem, ...],
        probed_files: tuple[ProbedFileRecord, ...],
        primary_doc_paths: set[str],
        captured_at_utc: str,
    ) -> tuple[ParityMatrixRow, ...]:
        """Cruza os vestigios declarados nos autos com os arquivos reais entregues no HD."""
        rows: list[ParityMatrixRow] = []
        matched_paths: set[str] = set()

        if not declared_items and not primary_doc_paths:
            for idx, pf in enumerate(probed_files, start=1):
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-DEF-{idx:04d}",
                        declared_id=None,
                        matched_rel_path=pf.rel_path,
                        matched_sha256=pf.sha256_hex,
                        parity_state=ParityState.DEFERRED_AWAITING_PRIMARY_DOC,
                        legal_tags=("AGUARDANDO_PECA_PRIMARIA",),
                        is_judicial_critical=False,
                        rationale="Midia sondada antes da localizacao de Auto de Apreensao ou FAV.",
                        epistemic_status=EpistemicStatus.EXPLICIT_GAP,
                        anchor=SourceAnchor(
                            origin_control_number=ControlNumber.root(idx).code,
                            origin_path=pf.rel_path,
                            locator="header_16b",
                            verbatim_excerpt=pf.magic_header_hex,
                            captured_at_utc=captured_at_utc,
                            origin_sha256=pf.sha256_hex,
                        ),
                    )
                )
            return tuple(rows)

        by_hash = {pf.sha256_hex.lower(): pf for pf in probed_files}

        for idx, decl in enumerate(declared_items, start=1):
            expected_token = decl.expected_raw_format.strip().lower()
            candidate_pf: ProbedFileRecord | None = None

            if decl.state_sha256 != "explicit_gap" and decl.state_sha256 in by_hash:
                candidate_pf = by_hash[decl.state_sha256]
            elif expected_token and expected_token != "explicit_gap":
                for pf in probed_files:
                    if pf.rel_path in primary_doc_paths:
                        continue
                    if expected_token in pf.rel_path.lower() or (
                        expected_token.startswith(".") and pf.rel_path.lower().endswith(expected_token)
                    ):
                        candidate_pf = pf
                        break

            if candidate_pf is None:
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-{idx:04d}",
                        declared_id=decl.declared_id,
                        matched_rel_path=None,
                        matched_sha256=None,
                        parity_state=ParityState.DECLARED_RAW_NOT_DELIVERED,
                        legal_tags=("STF_TEMA_977", "STJ_EDICAO_281", "CPP_ART_159_P6"),
                        is_judicial_critical=True,
                        rationale=(
                            f"Vestigio declarado ({decl.brand} {decl.model} / formato bruto "
                            f"{decl.expected_raw_format}) omitido na midia entregue a defesa."
                        ),
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=decl.anchor,
                    )
                )
                continue

            matched_paths.add(candidate_pf.rel_path)

            if candidate_pf.is_encrypted_or_corrupted:
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-{idx:04d}",
                        declared_id=decl.declared_id,
                        matched_rel_path=candidate_pf.rel_path,
                        matched_sha256=candidate_pf.sha256_hex,
                        parity_state=ParityState.DELIVERED_ENCRYPTED_OR_CORRUPTED,
                        legal_tags=("STJ_RHC_184003_SP", "CERCEAMENTO_DEFESA"),
                        is_judicial_critical=True,
                        rationale=(
                            f"Arquivo entregue ({candidate_pf.rel_path}) encontra-se cifrado "
                            f"ou corrompido sem chave nos autos."
                        ),
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=decl.anchor,
                    )
                )
            elif decl.state_sha256 == "explicit_gap":
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-{idx:04d}",
                        declared_id=decl.declared_id,
                        matched_rel_path=candidate_pf.rel_path,
                        matched_sha256=candidate_pf.sha256_hex,
                        parity_state=ParityState.MATCHED_WITHOUT_ORIGIN_HASH,
                        legal_tags=("CPP_ART_158_B", "POP_SENASP_2024_5_01"),
                        is_judicial_critical=True,
                        rationale=(
                            f"Arquivo {candidate_pf.rel_path} entregue sem hash SHA-256 lavrado "
                            f"no ato da coleta/apreensao estatal."
                        ),
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=decl.anchor,
                    )
                )
            elif decl.state_sha256.lower() != candidate_pf.sha256_hex.lower():
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-{idx:04d}",
                        declared_id=decl.declared_id,
                        matched_rel_path=candidate_pf.rel_path,
                        matched_sha256=candidate_pf.sha256_hex,
                        parity_state=ParityState.DIVERGENT_HASH_OR_SIZE,
                        legal_tags=("CPP_ART_158_A_MESMIDADE", "QUEBRA_CADEIA_CUSTODIA"),
                        is_judicial_critical=True,
                        rationale=(
                            f"Quebra de mesmidade em {candidate_pf.rel_path}: "
                            f"hash estatal={decl.state_sha256} != hash medido={candidate_pf.sha256_hex}."
                        ),
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=decl.anchor,
                    )
                )
            else:
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-{idx:04d}",
                        declared_id=decl.declared_id,
                        matched_rel_path=candidate_pf.rel_path,
                        matched_sha256=candidate_pf.sha256_hex,
                        parity_state=ParityState.MATCHED_INTACT_HASH,
                        legal_tags=("MESMIDADE_CONFIRMADA_ISO_27037",),
                        is_judicial_critical=False,
                        rationale=f"Hash SHA-256 identico ao declarado ({candidate_pf.sha256_hex}).",
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=decl.anchor,
                    )
                )

        undoc_seq = 1
        for pf in probed_files:
            if pf.rel_path in primary_doc_paths or pf.rel_path in matched_paths:
                continue
            cn = ControlNumber.root(len(rows) + undoc_seq).code
            anchor = SourceAnchor(
                origin_control_number=cn,
                origin_path=pf.rel_path,
                locator="header_16b",
                verbatim_excerpt=pf.magic_header_hex,
                captured_at_utc=captured_at_utc,
                origin_sha256=pf.sha256_hex,
            )
            if pf.is_encrypted_or_corrupted:
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-ENC-{undoc_seq:04d}",
                        declared_id=None,
                        matched_rel_path=pf.rel_path,
                        matched_sha256=pf.sha256_hex,
                        parity_state=ParityState.DELIVERED_ENCRYPTED_OR_CORRUPTED,
                        legal_tags=("STJ_RHC_184003_SP", "CERCEAMENTO_DEFESA"),
                        is_judicial_critical=True,
                        rationale=f"Arquivo cifrado/inacessivel ({pf.rel_path}) sem senha nos autos.",
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=anchor,
                    )
                )
            else:
                rows.append(
                    ParityMatrixRow(
                        finding_id=f"PAR-UNDOC-{undoc_seq:04d}",
                        declared_id=None,
                        matched_rel_path=pf.rel_path,
                        matched_sha256=pf.sha256_hex,
                        parity_state=ParityState.DELIVERED_UNDOCUMENTED_IN_AUTOS,
                        legal_tags=("CPP_ART_158_B_ORIGEM_OMISSA",),
                        is_judicial_critical=pf.extension_spoofed,
                        rationale=(
                            f"Artefato presente no HD ({pf.rel_path}) sem documentacao de origem "
                            f"ou lacre individualizado nos autos."
                        ),
                        epistemic_status=EpistemicStatus.VERIFIED_FACT,
                        anchor=anchor,
                    )
                )
            undoc_seq += 1

        return tuple(rows)


class CochranFiniteSampler:
    """Amostragem finita estratificada de Cochran (Z=1.96, p=0.5, e=0.10) em Decimal exato."""

    Z_SCORE: Decimal = Decimal("1.96")
    PROPORTION: Decimal = Decimal("0.5")
    MARGIN_ERROR: Decimal = Decimal("0.10")

    @classmethod
    def compute_sample_size(cls, population_n: int) -> int:
        """Calcula n finito de Cochran usando aritmetica Decimal exata (zero float).

        Formula:
            n0 = (Z^2 * p * (1 - p)) / e^2 = 96.04
            n = ceil(n0 / (1 + (n0 - 1) / N))

        Args:
            population_n: Tamanho N do estrato finito nao critico.

        Returns:
            Tamanho inteiro exato da amostra (0 se N <= 0).
        """
        if population_n <= 0:
            return 0
        n0 = (cls.Z_SCORE * cls.Z_SCORE * cls.PROPORTION * (Decimal("1") - cls.PROPORTION)) / (
            cls.MARGIN_ERROR * cls.MARGIN_ERROR
        )
        n_dec = Decimal(population_n)
        denom = Decimal("1") + ((n0 - Decimal("1")) / n_dec)
        raw_n = (n0 / denom).to_integral_value(rounding=ROUND_CEILING)
        bounded = min(population_n, int(raw_n))
        return bounded

    @classmethod
    def build_plan(
        cls,
        critical_ids: tuple[str, ...],
        non_critical_ids: tuple[str, ...],
        seed: int = 20260901,
    ) -> CochranSamplePlan:
        """Inclui 100% dos achados criticos e sorteia deterministicamente o estrato Cochran.

        Args:
            critical_ids: IDs de conferencia obrigatoria 100%.
            non_critical_ids: IDs candidatos a amostragem finita.
            seed: Semente inteira deterministica registrada para reprodutibilidade.

        Returns:
            CochranSamplePlan auditavel.
        """
        sample_n = cls.compute_sample_size(len(non_critical_ids))
        ranked = sorted(
            non_critical_ids,
            key=lambda item_id: sha256_text(f"SEED={seed}|ID={item_id}"),
        )
        sampled_non_crit = tuple(ranked[:sample_n])
        combined = tuple(critical_ids) + sampled_non_crit
        return CochranSamplePlan(
            population_total=len(critical_ids) + len(non_critical_ids),
            critical_100pct_count=len(critical_ids),
            non_critical_population=len(non_critical_ids),
            cochran_sample_size=sample_n,
            random_seed=seed,
            sampled_ids=combined,
        )


_STORAGE_SHARD_RE = re.compile(r"(?:^|/)iped/data/storage-([0-9]|1[0-5])\.db$", re.IGNORECASE)
_BOOL_KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*([^\r\n#]+)", re.MULTILINE)


class StateIpedCaseAuditor:
    """Auditor deterministico Clean-Room de casos portateis .iped entregues pela Policia/Pericia (Delta v2.1)."""

    CRITICAL_BOOLEAN_TASKS: tuple[str, ...] = (
        "enableCarving",
        "enableLedCarving",
        "enableSQLiteUndelete",
        "enableOCR",
        "processUnallocatedSpace",
    )

    @classmethod
    def audit(
        cls,
        probed_files: tuple[ProbedFileRecord, ...],
        captured_at_utc: str,
    ) -> StateIpedAuditReport | None:
        """Detecta marcadores de caso portatil .iped e audita perfis omissivos e contaminacao externa.

        Args:
            probed_files: Arquivos sondados em modo Read-Only na Fase 01.
            captured_at_utc: Instante UTC para ancoragem probatoria.

        Returns:
            StateIpedAuditReport imutavel se houver caso .iped na midia, ou None caso contrario.
        """
        marker_entry: tuple[int, ProbedFileRecord] | None = None
        shard_indices: set[int] = set()
        sleuth_present = False
        keywords_file_present = False
        config_texts: list[str] = []
        case_root = ""

        for seq, pf in enumerate(probed_files, start=1):
            low = pf.rel_path.lower()
            base = low.rsplit("/", 1)[-1]
            shard_m = _STORAGE_SHARD_RE.search(low)
            if shard_m:
                shard_indices.add(int(shard_m.group(1)))
                if marker_entry is None:
                    marker_entry = (seq, pf)
            if base == "sleuth.db":
                sleuth_present = True
                if marker_entry is None:
                    marker_entry = (seq, pf)
            if base == "iped-searchapp.exe" or "/iped/conf/" in f"/{low}":
                if marker_entry is None or base == "ipedconfig.txt":
                    marker_entry = (seq, pf)
                idx_iped = low.find("iped/")
                if idx_iped > 0 and not case_root:
                    case_root = pf.rel_path[:idx_iped].rstrip("/")
            if base in ("palavras-chave.txt", "keywords.txt"):
                keywords_file_present = True
            if pf.text_preview and (
                "/iped/" in f"/{low}"
                or base in (
                    "ipedconfig.txt",
                    "localconfig.txt",
                    "taskinstaller.xml",
                    "parserconfig.xml",
                    "palavras-chave.txt",
                    "keywords.txt",
                )
                or (base.startswith("iped") and base.endswith(".log"))
            ):
                config_texts.append(pf.text_preview)

        if marker_entry is None:
            return None

        anchor_seq, anchor_pf = marker_entry
        joined_cfg = "\n".join(config_texts)
        kv_map: dict[str, str] = {}
        for m in _BOOL_KEY_RE.finditer(joined_cfg):
            kv_map[m.group(1).strip().lower()] = m.group(2).strip().lower()

        low_cfg = joined_cfg.lower()
        profile_detected = "forensic"
        profile_risk = StateIpedProfileRisk.FORENSIC_COMPLETE

        for prof_cand in ("fastmode", "triage", "blind", "pedantic", "forensic"):
            if (
                re.search(rf"(?:-profile|--profile|profile\s*=)\s*{prof_cand}\b", low_cfg)
                or f"/{prof_cand}/" in low_cfg
            ):
                profile_detected = prof_cand
                break

        if profile_detected in ("fastmode", "triage"):
            profile_risk = StateIpedProfileRisk.FASTMODE_OR_TRIAGE_OMISSIVE
        elif profile_detected == "blind":
            profile_risk = StateIpedProfileRisk.BLIND_HASH_ONLY

        disabled_tasks: list[str] = []
        for task_key in cls.CRITICAL_BOOLEAN_TASKS:
            val = kv_map.get(task_key.lower(), "")
            if val.startswith("false"):
                disabled_tasks.append(task_key)

        hash_val = kv_map.get("hash", "")
        if hash_val and "sha-256" not in hash_val and "sha256" not in hash_val:
            disabled_tasks.append("hash:sha-256_omitted")

        if disabled_tasks and profile_risk == StateIpedProfileRisk.FORENSIC_COMPLETE:
            profile_risk = StateIpedProfileRisk.FASTMODE_OR_TRIAGE_OMISSIVE

        suppressed = (
            "ignorefilesbypathtask" in low_cfg
            or kv_map.get("excludeknown", "").startswith("true")
            or kv_map.get("ignoreduplicates", "").startswith("true")
        )
        delete_ignored = kv_map.get("deleteignoreditemdata", "").startswith("true")
        internet_contamination = (
            "--downloadinternetdata" in low_cfg
            or "-downloadinternetdata" in low_cfg
            or (
                "linkdownloader" in low_cfg
                and not kv_map.get("enablelinkdownloader", "true").startswith("false")
            )
        )
        kw_warning = keywords_file_present or ("filterkeywords" in low_cfg)

        excerpt = (
            anchor_pf.text_preview.strip().splitlines()[0][:160]
            if anchor_pf.text_preview.strip()
            else anchor_pf.magic_header_hex
        )
        anchor = SourceAnchor(
            origin_control_number=ControlNumber.root(anchor_seq).code,
            origin_path=anchor_pf.rel_path,
            locator="iped_config_audit",
            verbatim_excerpt=excerpt,
            captured_at_utc=captured_at_utc,
            origin_sha256=anchor_pf.sha256_hex,
        )

        return StateIpedAuditReport(
            is_iped_case=True,
            case_root_rel_path=case_root or ".",
            profile_detected=profile_detected,
            profile_risk=profile_risk,
            disabled_critical_tasks=tuple(disabled_tasks),
            suppressed_paths_or_hashdb=suppressed,
            delete_ignored_items_active=delete_ignored,
            internet_download_contamination=internet_contamination,
            keywords_negative_proof_warning=kw_warning,
            storage_shards_found=len(shard_indices),
            sleuth_db_present=sleuth_present,
            anchor=anchor,
        )
