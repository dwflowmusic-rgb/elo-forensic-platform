export interface GateExecutionItem {
  gate: string;
  title: string;
  passed: boolean;
  elapsed_ms: number;
  detail: string;
}

export interface GatesReport {
  all_passed: boolean;
  exit_code: number;
  executed_at_utc: string;
  gates: GateExecutionItem[];
}

export interface SourceAnchor {
  origin_control_number: string;
  origin_path: string;
  locator: string;
  verbatim_excerpt: string;
  captured_at_utc: string;
  origin_sha256: string;
}

export interface DynamicSchemaBlueprint {
  schema_hash: string;
  origin_rel_path: string;
  table_name: string;
  columns: string[];
  timestamp_column: string;
  actor_column: string;
  content_column: string;
  inferred_domain: string;
  extraction_sql_template: string;
  approved_by_verifier: boolean;
}

export interface ParityMatrixRow {
  finding_id: string;
  declared_id: string | null;
  matched_rel_path: string | null;
  matched_sha256?: string | null;
  parity_state: string;
  legal_tags: string[];
  is_judicial_critical?: boolean;
  rationale: string;
}

export interface InterDocumentDivergence {
  divergence_id: string;
  field_name: string;
  left_value: string;
  left_anchor: SourceAnchor;
  right_value: string;
  right_anchor: SourceAnchor;
  description: string;
}

export interface SixAxisFinding {
  finding_id: string;
  declared_id: string;
  axis: string;
  compliant: boolean;
  homograph_or_seal_mismatch: boolean;
  legal_tags: string[];
  summary: string;
  anchor: SourceAnchor;
}

export interface StructuralFinding {
  rel_path: string;
  sha256_hex: string;
  sqlite_quick_check_ok: boolean;
  has_unconsolidated_wal_frames: boolean;
  wal_frame_count: number;
  archive_crc_ok: boolean;
  pdf_incremental_revisions: number;
  is_healthy: boolean;
  detail: string;
}

export interface VaultEntry {
  control_number: string;
  origin_abs_path?: string;
  origin_rel_path: string;
  vault_rel_path: string;
  size_bytes: number;
  source_sha256?: string;
  vault_cold_sha256: string;
  state_declared_sha256?: string | null;
  state_hash_matches?: boolean | null;
  vault_locked_readonly: boolean;
}

export interface TimelineEventRecord {
  event_id: string;
  origin_cn: string;
  event_type: string;
  raw_ts: string;
  epoch_kind: string;
  tz_declared: string;
  ts_utc: string;
  epoch_seconds: number;
  is_post_seizure: boolean;
  actor_origin: string;
  actor_target: string;
  content_verbatim: string;
  locator: string;
  origin_sha256: string;
  sqlite_allocation_state?: string;
}

export interface RecoveredSqliteRecord {
  record_id: string;
  origin_cn: string;
  origin_path: string;
  allocation_state: string;
  page_or_frame_locator: string;
  recovered_text: string;
  origin_sha256: string;
}

export interface WindowsLinkProvenanceRecord {
  artifact_id: string;
  origin_cn: string;
  origin_path: string;
  artifact_kind: string;
  machine_id: string;
  volume_serial_hex: string;
  droid_volume_guid: string;
  droid_file_guid: string;
  droid_birth_mac_address: string;
  target_path: string;
  origin_sha256: string;
}

export interface StateIpedAuditReport {
  is_iped_case: boolean;
  case_root_rel_path: string;
  profile_detected: string;
  profile_risk: string;
  disabled_critical_tasks: string[];
  suppressed_paths_or_hashdb: boolean;
  delete_ignored_items_active: boolean;
  internet_download_contamination: boolean;
  keywords_negative_proof_warning: boolean;
  storage_shards_found: number;
  sleuth_db_present: boolean;
  anchor: SourceAnchor;
}

export interface FinancialLedgerEntryRecord {
  entry_id: string;
  origin_cn: string;
  bank_code: string;
  branch: string;
  account: string;
  holder_tax_id: string;
  counterparty_tax_id: string;
  tx_utc: string;
  debit_credit: string;
  amount_cents: number;
  raw_amount_text: string;
  is_inter_file_duplicate: boolean;
  locator: string;
  origin_sha256: string;
}

export interface TelecomCdrRecord {
  cdr_id: string;
  origin_cn: string;
  caller: string;
  callee: string;
  imei: string;
  start_utc: string;
  epoch_seconds: number;
  duration_sec: number;
  cell_cgi: string;
  lat_microdeg: number;
  lon_microdeg: number;
  azimuth_deg: number;
  impossible_speed_flag: boolean;
  locator: string;
  origin_sha256: string;
}

export interface CgnatAuditRecord {
  log_id: string;
  origin_cn: string;
  shared_ip: string;
  source_logical_port: number | null;
  ts_utc: string;
  missing_logical_port_defect: boolean;
  locator: string;
  origin_sha256: string;
}

export interface MaterialContradictionRecord {
  contradiction_id: string;
  contradiction_type: string;
  state_claim_excerpt: string;
  state_anchor: SourceAnchor;
  raw_truth_excerpt: string;
  omitted_neighbor_context: string;
  raw_anchor: SourceAnchor;
  financial_inflation_cents: number;
  legal_impact: string;
}

export interface ClassifiedNullityRecord {
  nullity_id: string;
  source_finding_id: string;
  category: string;
  legal_articles: string[];
  description: string;
  anchor: SourceAnchor;
}

export interface CustomQuesitoRecord {
  quesito_number: number;
  target_anomaly_id: string;
  normative_basis: string;
  question_text: string;
  anchor: SourceAnchor;
}

export interface HybridSearchHit {
  chunk_id: string;
  origin_cn: string;
  locator: string;
  rrf_score: string;
  lexical_rank: number | null;
  vector_rank: number | null;
  origin_sha256: string;
  text_clean: string;
}

export interface CaseAuditSummary {
  case_id: string;
  run_id: string;
  workspace_root: string;
  codebase_sha256: string;
  calibration_receipt: {
    calibrated_at_utc: string;
    positive_control_passed: boolean;
    negative_numeric_mutation_blocked: boolean;
    negative_phantom_entity_blocked: boolean;
    calibration_sha256: string;
  };
  pre_scan_snapshot_sha256: string;
  post_scan_snapshot_sha256: string;
  zero_source_mutation_confirmed: boolean;
  phase01_initial_revision: number;
  phase01_final_revision: number;
  extension_census: Array<[string, number]>;
  signature_census: Array<[string, number]>;
  spoofed_files: string[];
  encrypted_or_corrupted_files: string[];
  dynamic_schemas: DynamicSchemaBlueprint[];
  divergences: InterDocumentDivergence[];
  parity_matrix: ParityMatrixRow[];
  cochran_plan: {
    population_total: number;
    critical_100pct_count: number;
    non_critical_population: number;
    cochran_sample_size: number;
    random_seed: number;
    sampled_ids: string[];
  };
  state_iped_audit: StateIpedAuditReport | null;
  six_axes_findings: SixAxisFinding[];
  structural_findings: StructuralFinding[];
  vault_entries: VaultEntry[];
  processing_metrics: {
    total_inventory_items: number;
    denisted_parent_count: number;
    logical_duplicates_count: number;
    post_seizure_events_count: number;
    pdf_multi_eof_count: number;
    financial_duplicates_count: number;
    impossible_erb_jumps_count: number;
    cgnat_missing_port_count: number;
    recovered_deleted_sqlite_rows_count: number;
    physical_link_tracker_findings_count: number;
    tier_execution_order: Array<[string, number]>;
    indexed_chunks_count: number;
  };
  timeline_events: TimelineEventRecord[];
  recovered_sqlite_records: RecoveredSqliteRecord[];
  link_provenance_records: WindowsLinkProvenanceRecord[];
  financial_entries: FinancialLedgerEntryRecord[];
  telecom_records: TelecomCdrRecord[];
  cgnat_records: CgnatAuditRecord[];
  material_contradictions: MaterialContradictionRecord[];
  classified_nullities: ClassifiedNullityRecord[];
  qc_summary: {
    cochran_sample_n: number;
    elusion_inspected_n: number;
    elusion_errors_found: number;
    rule_of_3_upper_bound_pct: string;
    qc_passed: boolean;
  };
  expert_opinion_path: string;
  expert_opinion_sha256: string;
  reproduction_script_path: string;
  quesitos: CustomQuesitoRecord[];
  offline_html_dossier_path: string;
  offline_html_dossier_sha256: string;
  all_deliverables: Array<[string, string]>;
  disposition: {
    staging_purged_files_count: number;
    staging_purged_bytes: number;
    vault_intact_verified: boolean;
    manifest_sha256_path: string;
    recovery_bundle_path: string;
    nist_certificate_path: string | null;
  };
}

export interface EnrichedCaseData {
  summary: CaseAuditSummary;
  expertOpinionMarkdown: string;
  reproductionScript: string;
  manifestVerification: {
    verified: boolean;
    checked_files: number;
    mismatches: string[];
  };
}

export interface InstallerMetadata {
  filename: string;
  sizeBytes: number;
  sha256: string;
}

export interface LiveMonitorStep {
  ts_utc: string;
  phase: string;
  step: string;
  status: string;
  source: string;
  detail: string;
}

export interface LiveMonitorAlert {
  ts_utc: string;
  phase: string;
  status: string;
  title: string;
  detail: string;
}

export interface LiveMonitorReport {
  checked_at_utc: string;
  dest_root: string;
  run_status: string;
  current_phase: string;
  case_id: string;
  run_id: string;
  checkpoints: {
    phase01_sha256_count: number;
    phase03_icp_count: number;
    phase04_unpack_count: number;
  };
  zones: Record<string, { exists: boolean; file_count: number; last_modified_utc: string }>;
  organized_db_exists: boolean;
  organized_db_bytes: number;
  catalog_sqlite_tables: string[];
  trace_available: boolean;
  zero_source_mutation_confirmed: boolean | null;
  verifier_double_pass_zero_errors: boolean | null;
  steps: LiveMonitorStep[];
  failures_and_alerts: LiveMonitorAlert[];
  journal_markdown: string;
}

export interface ProtectedZipItem {
  zip_path: string;
  filename: string;
  encrypted_members_count: number;
  sample_members: string[];
  has_lookup_password: boolean;
  operation: string;
  status: 'LOCKED_ALERT' | 'UNLOCKED' | 'IGNORED';
  extracted_dir: string;
  unlocked_at_utc: string;
  extracted_files_count: number;
}

export interface ProtectedZipsReport {
  checked_at_utc: string;
  lookup_file: string;
  total_protected_zips: number;
  locked_count: number;
  unlocked_count: number;
  items: ProtectedZipItem[];
}

export type LaboratoryTabId =
  | 'gates-governance'
  | 'acquisition-01-03'
  | 'processing-search-04'
  | 'review-production-05-06'
  | 'presentation-disposition-07-08';
