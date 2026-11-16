"""Contratos imutaveis de transicao entre todas as camadas e fases do EDRM 2.0 (00 -> 08)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from edrm.shared_kernel.enums import (
    AcquisitionMode,
    EpistemicStatus,
    EvidentiaryDefectCategory,
    MagicSignature,
    ParityState,
    PreservationAxis,
    PrimaryDocType,
    SecrecyLevel,
    SqliteRowAllocationState,
    StateIpedProfileRisk,
)
from edrm.shared_kernel.value_objects import SourceAnchor, canonical_json_sha256


@dataclass(frozen=True, slots=True)
class FileStatEntry:
    """Fotografia fisica passiva de um arquivo na midia --source (os.stat)."""

    source_id: str
    rel_path: str
    size_bytes: int
    mtime_utc_ns: int
    mode_octal: str
    inode_or_file_index: int
    is_os_readonly: bool


@dataclass(frozen=True, slots=True)
class MediaSnapshot:
    """Linha de base matematica imutavel (PreScanSnapshot / PostScanSnapshot)."""

    captured_at_utc: str
    entries: tuple[FileStatEntry, ...]
    snapshot_sha256: str


@dataclass(frozen=True, slots=True)
class CalibrationReceipt:
    """Recibo da bateria de auto-calibracao ISO/IEC 27041 (1 positivo + 2 negativos)."""

    calibrated_at_utc: str
    positive_control_passed: bool
    negative_numeric_mutation_blocked: bool
    negative_phantom_entity_blocked: bool
    calibration_sha256: str


@dataclass(frozen=True, slots=True)
class CaseGovernanceContract:
    """Contrato 00 -> Todas: Governanca IGRM v4.1 (versao vigente oficial do EDRM) e isolamento do workspace."""

    case_id: str
    run_id: str
    workspace_root: str
    vault_dir: str
    staging_dir: str
    catalog_dir: str
    deliverables_dir: str
    audit_dir: str
    catalog_db_path: str
    protected_source_roots: tuple[str, ...]
    secrecy_level: SecrecyLevel
    codebase_sha256: str
    calibration_receipt: CalibrationReceipt

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class ProbedFileRecord:
    """Registro do censo binario deterministico em streaming (Etapa 1.A / 1.B)."""

    source_id: str
    rel_path: str
    abs_path: str
    size_bytes: int
    mtime_utc_ns: int
    is_os_readonly: bool
    sha256_hex: str
    magic_header_hex: str
    magic_signature: MagicSignature
    extension_spoofed: bool
    is_encrypted_or_corrupted: bool
    pdf_eof_count: int
    has_wal_sibling: bool
    has_shm_sibling: bool
    container_entries: tuple[str, ...]
    sqlite_schemas: tuple[str, ...]
    tabular_header: str
    text_preview: str


@dataclass(frozen=True, slots=True)
class DynamicSchemaBlueprint:
    """Mapeamento auditado para extracao de banco SQLite ou planilha inedita do HD."""

    schema_hash: str
    origin_rel_path: str
    table_name: str
    columns: tuple[str, ...]
    timestamp_column: str
    actor_column: str
    content_column: str
    inferred_domain: str
    extraction_sql_template: str
    approved_by_verifier: bool


@dataclass(frozen=True, slots=True)
class PrimaryDocumentCandidate:
    """Candidato a peca processual primaria localizado automaticamente no HD."""

    source_id: str
    rel_path: str
    sha256_hex: str
    doc_type: PrimaryDocType
    extracted_text: str
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class StateIpedAuditReport:
    """Relatorio deterministico de auditoria de caso portatil .iped entregue pelo Estado (Delta v2.1)."""

    is_iped_case: bool
    case_root_rel_path: str
    profile_detected: str
    profile_risk: StateIpedProfileRisk
    disabled_critical_tasks: tuple[str, ...]
    suppressed_paths_or_hashdb: bool
    delete_ignored_items_active: bool
    internet_download_contamination: bool
    keywords_negative_proof_warning: bool
    storage_shards_found: int
    sleuth_db_present: bool
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class MediaAutoDiscoveryBlueprint:
    """Contrato Sonda Deterministica <-> IA Governada na Fase 01."""

    case_id: str
    extension_census: tuple[tuple[str, int], ...]
    signature_census: tuple[tuple[str, int], ...]
    spoofed_files: tuple[str, ...]
    encrypted_or_corrupted_files: tuple[str, ...]
    probed_files: tuple[ProbedFileRecord, ...]
    dynamic_schemas: tuple[DynamicSchemaBlueprint, ...]
    primary_doc_candidates: tuple[PrimaryDocumentCandidate, ...]
    recommended_phase_priority: tuple[str, ...]
    state_iped_audit: StateIpedAuditReport | None = None
    headerless_encrypted_files: tuple[str, ...] = ()

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do blueprint."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class CustodianRecord:
    """Custodiante identificado com ancoragem probatoria e status epistemico."""

    custodian_id: str
    name: str
    role: str
    identifiers: tuple[str, ...]
    epistemic_status: EpistemicStatus
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class DeclaredEvidenceItem:
    """Vestigio declarado em peca oficial com todos os atributos POP Senasp Vol. 5 (2024)."""

    declared_id: str
    custodian_id: str
    primary_doc_type: PrimaryDocType
    seizure_utc: str
    brand: str
    model: str
    serial_number: str
    imei_chassis: tuple[str, ...]
    imei_memory: tuple[str, ...]
    iccid: tuple[str, ...]
    has_second_space_checked: str
    lock_state: str
    rf_isolation: str
    seals_in: tuple[str, ...]
    seals_out: tuple[str, ...]
    working_copy_examined: str
    state_sha256: str
    master_hashlist_sha256: str
    expected_raw_format: str
    extracted_by_official_expert: str
    collection_method_declared: str
    transited_via_messenger: bool
    epistemic_status: EpistemicStatus
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class DivergenceRecord:
    """Conflito material lado a lado entre duas declaracoes oficiais nos autos."""

    divergence_id: str
    field_name: str
    left_value: str
    left_anchor: SourceAnchor
    right_value: str
    right_anchor: SourceAnchor
    description: str


@dataclass(frozen=True, slots=True)
class ParityMatrixRow:
    """Linha da Matriz Deterministica Declarado x Entregue nos 7 estados forenses."""

    finding_id: str
    declared_id: str | None
    matched_rel_path: str | None
    matched_sha256: str | None
    parity_state: ParityState
    legal_tags: tuple[str, ...]
    is_judicial_critical: bool
    rationale: str
    epistemic_status: EpistemicStatus
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class CochranSamplePlan:
    """Plano estatistico estratificado de Cochran (Z=1.96, p=0.5, e=0.10) + 100% criticos."""

    population_total: int
    critical_100pct_count: int
    non_critical_population: int
    cochran_sample_size: int
    random_seed: int
    sampled_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Phase01ToPhase02Contract:
    """Contrato imutavel de transicao Fase 01 -> Fase 02."""

    governance: CaseGovernanceContract
    pre_scan_snapshot: MediaSnapshot
    discovery_blueprint: MediaAutoDiscoveryBlueprint
    custodians: tuple[CustodianRecord, ...]
    declared_items: tuple[DeclaredEvidenceItem, ...]
    divergences: tuple[DivergenceRecord, ...]
    parity_matrix: tuple[ParityMatrixRow, ...]
    cochran_plan: CochranSamplePlan
    phase01_report_path: str
    phase01_report_sha256: str
    revision_number: int = 1
    state_iped_audit: StateIpedAuditReport | None = None
    headerless_encrypted_candidates: tuple[str, ...] = ()

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 01->02."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class StructuralHealthFinding:
    """Diagnostico de integridade estrutural de SQLite (-wal/-shm, quick_check) e pacotes."""

    rel_path: str
    sha256_hex: str
    sqlite_quick_check_ok: bool
    has_unconsolidated_wal_frames: bool
    wal_frame_count: int
    archive_crc_ok: bool
    pdf_incremental_revisions: int
    is_healthy: bool
    detail: str


@dataclass(frozen=True, slots=True)
class PreservationAxisFinding:
    """Avaliacao atomica de um dos 6 Eixos Obrigatorios da Preservacao Estatal."""

    finding_id: str
    declared_id: str
    axis: PreservationAxis
    compliant: bool
    homograph_or_seal_mismatch: bool
    legal_tags: tuple[str, ...]
    summary: str
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class SpofRiskEntry:
    """Avaliacao de Ponto Unico de Falha (SPOF) e redundancia Read-Only."""

    rel_path: str
    sha256_hex: str
    in_vault: bool
    is_os_readonly: bool
    is_spof_critical: bool
    recommended_mode: AcquisitionMode


@dataclass(frozen=True, slots=True)
class Phase02ToPhase03Contract:
    """Contrato imutavel de transicao Fase 02 -> Fase 03."""

    phase01_bundle: Phase01ToPhase02Contract
    structural_findings: tuple[StructuralHealthFinding, ...]
    spof_map: tuple[SpofRiskEntry, ...]
    six_axes_findings: tuple[PreservationAxisFinding, ...]
    legal_hold_id: str
    approved_for_acquisition: tuple[str, ...]
    phase02_report_path: str
    phase02_report_sha256: str

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 02->03."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class VaultAcquiredEntry:
    """Item coletado no cofre com verificacao fria pos-fsync e ControlNumber raiz."""

    control_number: str
    source_id: str
    origin_rel_path: str
    vault_rel_path: str
    vault_abs_path: str
    acquisition_mode: AcquisitionMode
    size_bytes: int
    mtime_utc_ns: int
    source_sha256: str
    vault_cold_sha256: str
    vault_locked_readonly: bool


@dataclass(frozen=True, slots=True)
class StateCollectionFinding:
    """Auditoria do metodo estatal de coleta (CPP arts. 158-C/158-D e POP Senasp 5.02)."""

    declared_id: str
    official_expert_verified: bool
    method_used: str
    examined_on_original_device: bool
    messenger_transit_detected: bool
    high_risk_flag: bool
    legal_tags: tuple[str, ...]
    notes: str
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class Phase03ToPhase04Contract:
    """Contrato imutavel de transicao Fase 03 -> Fase 04."""

    phase02_bundle: Phase02ToPhase03Contract
    vault_entries: tuple[VaultAcquiredEntry, ...]
    state_collection_findings: tuple[StateCollectionFinding, ...]
    icp_manifest_path: str
    icp_manifest_sha256: str
    phase03_report_path: str
    phase03_report_sha256: str

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 03->04."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class IterativeDiscoveryFeedbackPayload:
    """Payload de realimentacao 04/05 -> 01 ao descobrir novas pecas primarias no HD."""

    case_id: str
    discovered_in_phase: str
    new_primary_docs: tuple[PrimaryDocumentCandidate, ...]
    new_custodians: tuple[CustodianRecord, ...]
    new_declared_items: tuple[DeclaredEvidenceItem, ...]


class IterativeDiscoveryFeedbackPort(Protocol):
    """Porta segregada para realimentacao iterativa sem acoplamento entre pacotes."""

    def receive_feedback(
        self,
        current_contract: Phase01ToPhase02Contract,
        feedback: IterativeDiscoveryFeedbackPayload,
    ) -> Phase01ToPhase02Contract:
        """Integra novas pecas primarias descobertas e recalcula a Matriz de Paridade.

        Args:
            current_contract: Contrato atual da Fase 01.
            feedback: Novas pecas e declaracoes descompactadas na Fase 04/05.

        Returns:
            Nova revisao imutavel de Phase01ToPhase02Contract.
        """


@dataclass(frozen=True, slots=True)
class TimelineEventRecord:
    """Evento normalizado em UTC na Linha do Tempo Unificada."""

    event_id: str
    origin_cn: str
    event_type: str
    raw_ts: str
    epoch_kind: str
    tz_declared: str
    ts_utc: str
    epoch_seconds: int
    is_post_seizure: bool
    actor_origin: str
    actor_target: str
    content_verbatim: str
    locator: str
    origin_sha256: str
    sqlite_allocation_state: SqliteRowAllocationState = SqliteRowAllocationState.ACTIVE_BTREE_ROW


@dataclass(frozen=True, slots=True)
class FinancialLedgerEntryRecord:
    """Lancamento financeiro SIMBA/OFX/CSV gravado em centavos inteiros BIGINT."""

    entry_id: str
    origin_cn: str
    bank_code: str
    branch: str
    account: str
    holder_tax_id: str
    counterparty_tax_id: str
    tx_utc: str
    debit_credit: str
    amount_cents: int
    raw_amount_text: str
    is_inter_file_duplicate: bool
    locator: str
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class TelecomCdrRecord:
    """Evento telefonico CDR/ERB normalizado em UTC e micrograus inteiros."""

    cdr_id: str
    origin_cn: str
    caller: str
    callee: str
    imei: str
    start_utc: str
    epoch_seconds: int
    duration_sec: int
    cell_cgi: str
    lat_microdeg: int
    lon_microdeg: int
    azimuth_deg: int
    impossible_speed_flag: bool
    locator: str
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class CgnatAuditRecord:
    """Registro de auditoria de log IP/CGNAT (Decreto n. 12.975/2026)."""

    log_id: str
    origin_cn: str
    shared_ip: str
    source_logical_port: int | None
    ts_utc: str
    missing_logical_port_defect: bool
    locator: str
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class DeadLetterExceptionRecord:
    """Item da fila de excecoes (arquivos cifrados sem senha ou corrompidos)."""

    control_number: str
    rel_path: str
    sha256_hex: str
    reason_code: str
    detail: str


@dataclass(frozen=True, slots=True)
class AnchoredTextChunk:
    """Chunk textual ancorado e sanitizado para o indice hibrido RRF."""

    chunk_id: str
    origin_cn: str
    origin_path: str
    locator: str
    text_clean: str
    injection_neutralized: bool
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class RecoveredSqliteRecord:
    """Registro recuperado de freelist/unallocated ou frame WAL de banco SQLite (NIST IR 8354)."""

    record_id: str
    origin_cn: str
    origin_path: str
    allocation_state: SqliteRowAllocationState
    page_or_frame_locator: str
    recovered_text: str
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class WindowsLinkProvenanceRecord:
    """Artefato de autoria e conexao fisica decodificado de .lnk / USBStor / $UsnJrnl."""

    artifact_id: str
    origin_cn: str
    origin_path: str
    artifact_kind: str
    machine_id: str
    volume_serial_hex: str
    droid_volume_guid: str
    droid_file_guid: str
    droid_birth_mac_address: str
    target_path: str
    origin_sha256: str


@dataclass(frozen=True, slots=True)
class Phase04ToPhase05Contract:
    """Contrato imutavel de transicao Fase 04 -> Fase 05 (EDRM 1.0 a 5.0 como piso funcional)."""

    phase03_bundle: Phase03ToPhase04Contract
    updated_phase01_bundle: Phase01ToPhase02Contract
    total_inventory_items: int
    denisted_parent_count: int
    logical_duplicates_count: int
    post_seizure_events_count: int
    pdf_multi_eof_count: int
    financial_duplicates_count: int
    impossible_erb_jumps_count: int
    cgnat_missing_port_count: int
    dead_letter_items: tuple[DeadLetterExceptionRecord, ...]
    timeline_events: tuple[TimelineEventRecord, ...]
    financial_entries: tuple[FinancialLedgerEntryRecord, ...]
    telecom_records: tuple[TelecomCdrRecord, ...]
    cgnat_records: tuple[CgnatAuditRecord, ...]
    anchored_chunks: tuple[AnchoredTextChunk, ...]
    official_five_reports: tuple[tuple[str, str, str], ...]
    recovered_deleted_sqlite_rows_count: int = 0
    physical_link_tracker_findings_count: int = 0
    recovered_sqlite_records: tuple[RecoveredSqliteRecord, ...] = ()
    link_provenance_records: tuple[WindowsLinkProvenanceRecord, ...] = ()
    tier_execution_order: tuple[tuple[str, int], ...] = ()

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 04->05."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class MaterialContradictionRecord:
    """Confronto material Relatorio Policial/Laudo x Prova Bruta do HD (Fase 05)."""

    contradiction_id: str
    contradiction_type: str
    state_claim_excerpt: str
    state_anchor: SourceAnchor
    raw_truth_excerpt: str
    omitted_neighbor_context: str
    raw_anchor: SourceAnchor
    financial_inflation_cents: int
    legal_impact: str


@dataclass(frozen=True, slots=True)
class ClassifiedNullityRecord:
    """Enquadramento processual penal de cada vicio probatorio detectado."""

    nullity_id: str
    source_finding_id: str
    category: EvidentiaryDefectCategory
    legal_articles: tuple[str, ...]
    description: str
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class QualityControlSummary:
    """Metricas de Cochran, Teste de Elusao e Regra do 3 (3/n) de Hanley & Lippman-Hand."""

    cochran_sample_n: int
    elusion_inspected_n: int
    elusion_errors_found: int
    rule_of_3_upper_bound_pct: str
    qc_passed: bool


@dataclass(frozen=True, slots=True)
class Phase05ToPhase06Contract:
    """Contrato imutavel de transicao Fase 05 -> Fase 06."""

    phase04_bundle: Phase04ToPhase05Contract
    privileged_excluded_cns: tuple[str, ...]
    selected_review_cns: tuple[str, ...]
    material_contradictions: tuple[MaterialContradictionRecord, ...]
    classified_nullities: tuple[ClassifiedNullityRecord, ...]
    qc_summary: QualityControlSummary
    frozen_review_sha256: str
    phase05_report_path: str
    phase05_report_sha256: str

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 05->06."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class Phase06ToPhase07Contract:
    """Contrato imutavel de transicao Fase 06 -> Fase 07."""

    phase05_bundle: Phase05ToPhase06Contract
    expert_opinion_path: str
    expert_opinion_sha256: str
    reproduction_script_path: str
    reproduction_script_sha256: str
    concordance_dat_path: str
    edrm_xml_path: str
    icp_detached_manifest_path: str
    verifier_double_pass_zero_errors: bool

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 06->07."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class CustomQuesitoRecord:
    """Quesito pericial estrategico gerado sob medida com base no POP Senasp 2024."""

    quesito_number: int
    target_anomaly_id: str
    normative_basis: str
    question_text: str
    anchor: SourceAnchor


@dataclass(frozen=True, slots=True)
class Phase07ToPhase08Contract:
    """Contrato imutavel de transicao Fase 07 -> Fase 08."""

    phase06_bundle: Phase06ToPhase07Contract
    quesitos: tuple[CustomQuesitoRecord, ...]
    quesitos_path: str
    quesitos_sha256: str
    tema977_exhibit_path: str
    offline_html_dossier_path: str
    offline_html_dossier_sha256: str
    all_deliverables: tuple[tuple[str, str], ...]
    authorize_staging_purge: bool

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do contrato 07->08."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest


@dataclass(frozen=True, slots=True)
class FinalDispositionReceipt:
    """Recibo final de encerramento da Fase 08 reconectado a base IGRM v4.1 (versao vigente oficial do EDRM)."""

    case_id: str
    staging_purged_files_count: int
    staging_purged_bytes: int
    vault_intact_verified: bool
    source_pre_post_snapshot_identical: bool
    post_scan_snapshot: MediaSnapshot
    manifest_sha256_path: str
    recovery_bundle_path: str
    nist_certificate_path: str | None

    def contract_sha256(self) -> str:
        """Calcula a assinatura SHA-256 canonica do recibo final."""
        _, digest = canonical_json_sha256(asdict(self))
        return digest
