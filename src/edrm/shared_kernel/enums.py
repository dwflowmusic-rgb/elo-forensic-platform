"""Enumeracoes forenses, epistemicas, normativas e de ciclo de vida EDRM 2.0."""

from __future__ import annotations

from enum import Enum, IntEnum


class ForensicEnum(str, Enum):
    """Base de enumeracao textual estrita compativel com serializacao JSON canonica."""

    def __str__(self) -> str:
        """Retorna a representacao textual exata do enumerador.

        Returns:
            Valor literal associado ao membro.
        """
        return str(self.value)


class PhaseCode(ForensicEnum):
    """Codigos canonicos das camadas e fases do ciclo EDRM 2.0."""

    IGRM_00 = "IGRM_00"
    PHASE_01_IDENTIFICATION = "PHASE_01_IDENTIFICATION"
    PHASE_02_PRESERVATION = "PHASE_02_PRESERVATION"
    PHASE_03_COLLECTION = "PHASE_03_COLLECTION"
    PHASE_04_PROCESSING = "PHASE_04_PROCESSING"
    CONTINUOUS_ANALYSIS = "CONTINUOUS_ANALYSIS"
    PHASE_05_REVIEW = "PHASE_05_REVIEW"
    PHASE_06_PRODUCTION = "PHASE_06_PRODUCTION"
    PHASE_07_PRESENTATION = "PHASE_07_PRESENTATION"
    PHASE_08_DISPOSITION = "PHASE_08_DISPOSITION"


class SecrecyLevel(ForensicEnum):
    """Niveis de sigilo processual e soberania de rede — IGRM v4.1 (versao vigente oficial do EDRM) / CNJ 615/2025."""

    JUDICIAL_SECRECY_LOCAL_ONLY = "JUDICIAL_SECRECY_LOCAL_ONLY"
    PUBLIC_RECORD = "PUBLIC_RECORD"


class EpistemicStatus(ForensicEnum):
    """Estatuto epistemico obrigatorio de cada registro pericial (Pilar 7 — Imparcialidade)."""

    VERIFIED_FACT = "VERIFIED_FACT"
    STATE_ALLEGATION = "STATE_ALLEGATION"
    ANALYTICAL_INFERENCE = "ANALYTICAL_INFERENCE"
    EXPLICIT_GAP = "EXPLICIT_GAP"


class EpochKind(ForensicEnum):
    """Epocas temporais de origem suportadas pelo normalizador UTC deterministico."""

    UNIX_1970_S = "UNIX_1970_S"
    UNIX_1970_MS = "UNIX_1970_MS"
    COCOA_2001_S = "COCOA_2001_S"
    COCOA_2001_NS = "COCOA_2001_NS"
    QUICKTIME_1904_S = "QUICKTIME_1904_S"
    ISO8601_OFFSET = "ISO8601_OFFSET"
    LOCAL_ASSUMED = "LOCAL_ASSUMED"


class MagicSignature(ForensicEnum):
    """Assinaturas binarias reais de 16 bytes detectadas pela sonda deterministica."""

    SQLITE3 = "SQLITE3"
    EWF_E01 = "EWF_E01"
    AFF4 = "AFF4"
    ZIP_CONTAINER = "ZIP_CONTAINER"
    CELLEBRITE_UFDR_UFDX = "CELLEBRITE_UFDR_UFDX"
    RAR_V4_V5 = "RAR_V4_V5"
    SEVEN_ZIP = "SEVEN_ZIP"
    PDF_DOCUMENT = "PDF_DOCUMENT"
    PST_OST = "PST_OST"
    GZIP = "GZIP"
    TAR_ARCHIVE = "TAR_ARCHIVE"
    LUKS = "LUKS"
    PGP_GPG = "PGP_GPG"
    WHATSAPP_CRYPT = "WHATSAPP_CRYPT"
    WAV_AUDIO = "WAV_AUDIO"
    JPEG_IMAGE = "JPEG_IMAGE"
    PNG_IMAGE = "PNG_IMAGE"
    MP4_VIDEO = "MP4_VIDEO"
    WINDOWS_LNK_SHORTCUT = "WINDOWS_LNK_SHORTCUT"
    STATE_IPED_PORTABLE_CASE = "STATE_IPED_PORTABLE_CASE"
    XML_DOCUMENT = "XML_DOCUMENT"
    UTF8_TEXT_OR_CSV = "UTF8_TEXT_OR_CSV"
    HIGH_ENTROPY_ENCRYPTED = "HIGH_ENTROPY_ENCRYPTED"
    HEADERLESS_HIGH_ENTROPY_ENCRYPTED = "HEADERLESS_HIGH_ENTROPY_ENCRYPTED"
    UNKNOWN_BINARY = "UNKNOWN_BINARY"


class PrimaryDocType(ForensicEnum):
    """Tipos de pecas processuais primarias reconhecidas na autodescoberta."""

    AUTO_APREENSAO = "AUTO_APREENSAO"
    MANDADO = "MANDADO"
    FAV = "FAV"
    DECISAO_JUDICIAL = "DECISAO_JUDICIAL"
    LAUDO_PERICIAL = "LAUDO_PERICIAL"
    DENUNCIA = "DENUNCIA"
    TERMO_RECEBIMENTO = "TERMO_RECEBIMENTO"


class ReconciliationTier(ForensicEnum):
    """Hierarquia deterministica de reconciliacao de copias na midia (Microfase 1.6)."""

    EXACT_SHA256 = "EXACT_SHA256"
    FILENAME_AND_EXACT_BYTES = "FILENAME_AND_EXACT_BYTES"
    WEAK_NAME_ONLY_UNCONFIRMED = "WEAK_NAME_ONLY_UNCONFIRMED"
    UNRESOLVED_GAP = "UNRESOLVED_GAP"


class ParityState(ForensicEnum):
    """Os 7 estados forenses da Matriz Declarado x Entregue (Microfase 1.9)."""

    MATCHED_INTACT_HASH = "MATCHED_INTACT_HASH"
    MATCHED_WITHOUT_ORIGIN_HASH = "MATCHED_WITHOUT_ORIGIN_HASH"
    DIVERGENT_HASH_OR_SIZE = "DIVERGENT_HASH_OR_SIZE"
    DECLARED_RAW_NOT_DELIVERED = "DECLARED_RAW_NOT_DELIVERED"
    DELIVERED_ENCRYPTED_OR_CORRUPTED = "DELIVERED_ENCRYPTED_OR_CORRUPTED"
    DELIVERED_UNDOCUMENTED_IN_AUTOS = "DELIVERED_UNDOCUMENTED_IN_AUTOS"
    DEFERRED_AWAITING_PRIMARY_DOC = "DEFERRED_AWAITING_PRIMARY_DOC"


class PreservationAxis(ForensicEnum):
    """Os 6 Eixos Obrigatorios da Preservacao Estatal na Origem (Fase 02)."""

    ISOLAMENTO_RADIOELETRICO_E_VOLATILIDADE = "ISOLAMENTO_RADIOELETRICO_E_VOLATILIDADE"
    ESTADO_ENERGETICO_BLOQUEIO_E_RELOGIO = "ESTADO_ENERGETICO_BLOQUEIO_E_RELOGIO"
    CADEIA_DE_LACRES_E_FAV = "CADEIA_DE_LACRES_E_FAV"
    CERTIFICACAO_DE_HASH_NA_ORIGEM = "CERTIFICACAO_DE_HASH_NA_ORIGEM"
    INTEGRIDADE_FISICA_E_LOGICA_DO_VESTIGIO = "INTEGRIDADE_FISICA_E_LOGICA_DO_VESTIGIO"
    ACESSIBILIDADE_E_CIFRAGEM = "ACESSIBILIDADE_E_CIFRAGEM"


class CppCustodyStage(ForensicEnum):
    """As 10 etapas legais da Cadeia de Custodia no art. 158-B do CPP."""

    I_RECONHECIMENTO = "I_RECONHECIMENTO"
    II_ISOLAMENTO = "II_ISOLAMENTO"
    III_FIXACAO = "III_FIXACAO"
    IV_COLETA = "IV_COLETA"
    V_ACONDICIONAMENTO = "V_ACONDICIONAMENTO"
    VI_TRANSPORTE = "VI_TRANSPORTE"
    VII_RECEBIMENTO = "VII_RECEBIMENTO"
    VIII_PROCESSAMENTO = "VIII_PROCESSAMENTO"
    IX_ARMAZENAMENTO = "IX_ARMAZENAMENTO"
    X_DESCARTE = "X_DESCARTE"


class AcquisitionMode(ForensicEnum):
    """Modos de aquisicao defensavel para o cofre do caso (Fase 03)."""

    FULL_VAULT_COPY = "FULL_VAULT_COPY"
    SELECTIVE_CRITICAL_COPY = "SELECTIVE_CRITICAL_COPY"
    IMMUTABLE_REFERENCED_INDEX = "IMMUTABLE_REFERENCED_INDEX"


class StateCollectionMethod(ForensicEnum):
    """Metodos estatais de coleta auditados conforme POP Senasp Vol. 5 (2024)."""

    PHYSICAL_BITSTREAM = "PHYSICAL_BITSTREAM"
    FULL_FILE_SYSTEM = "FULL_FILE_SYSTEM"
    LOGICAL_PARTIAL = "LOGICAL_PARTIAL"
    MANUAL_SCREEN_RECORDING_HIGH_RISK = "MANUAL_SCREEN_RECORDING_HIGH_RISK"
    UNDOCUMENTED_METHOD = "UNDOCUMENTED_METHOD"


class EvidentiaryDefectCategory(ForensicEnum):
    """Classificacao juridica concreta do vicio probatorio (Fase 05)."""

    NO_DEFECT = "NO_DEFECT"
    FORMAL_IRREGULARITY = "FORMAL_IRREGULARITY"
    CUSTODY_BREAK_WEIGHT_REDUCTION = "CUSTODY_BREAK_WEIGHT_REDUCTION"
    DEFENSE_PARITY_VIOLATION_TEMA_977 = "DEFENSE_PARITY_VIOLATION_TEMA_977"
    ABSOLUTE_NULLITY_ILLICIT_EVIDENCE = "ABSOLUTE_NULLITY_ILLICIT_EVIDENCE"


class SanitizationMethod(ForensicEnum):
    """Metodos certificados de sanitizacao segundo NIST SP 800-88 Rev. 2 (set./2025)."""

    CLEAR = "CLEAR"
    PURGE_CRYPTOGRAPHIC_ERASE = "PURGE_CRYPTOGRAPHIC_ERASE"
    DESTROY_VERIFIED = "DESTROY_VERIFIED"


class ProcessingPriorityTier(IntEnum):
    """Os 5 Estagios de Dependencia Referencial da Fase 04 (P0 -> P4, Delta v2.1)."""

    P0_ATOMIC_MEDIA_WAL_UNALLOCATED = 0
    P1_EXPANDABLE_CONTAINERS_IMAGES = 1
    P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS = 2
    P3_PRIMARY_MESSAGING_CHATS = 3
    P4_CROSS_BACKUP_MERGE_TIMELINE = 4


class SqliteRowAllocationState(ForensicEnum):
    """Estado forense de alocacao de registro SQLite (NIST IR 8354, Delta v2.1)."""

    ACTIVE_BTREE_ROW = "ACTIVE_BTREE_ROW"
    WAL_UNCOMMITTED_FRAME = "WAL_UNCOMMITTED_FRAME"
    CARVED_FREELIST_OR_UNALLOCATED = "CARVED_FREELIST_OR_UNALLOCATED"


class StateIpedProfileRisk(ForensicEnum):
    """Classificacao de risco metodologico de casos portateis .iped estatais (Delta v2.1)."""

    FORENSIC_COMPLETE = "FORENSIC_COMPLETE"
    FASTMODE_OR_TRIAGE_OMISSIVE = "FASTMODE_OR_TRIAGE_OMISSIVE"
    BLIND_HASH_ONLY = "BLIND_HASH_ONLY"
    CUSTOM_MODIFIED = "CUSTOM_MODIFIED"
    NOT_IPED_SOURCE = "NOT_IPED_SOURCE"
