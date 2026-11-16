"""Esquema relacional canonico unificado das 12 tabelas nucleares do EDRM 2.0."""

from __future__ import annotations

CANONICAL_CATALOG_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS governance_runs (
        run_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        phase_code TEXT NOT NULL,
        codebase_sha256 TEXT NOT NULL,
        pre_scan_snapshot_sha256 TEXT NOT NULL,
        post_scan_snapshot_sha256 TEXT NOT NULL,
        zero_source_mutation_confirmed INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS discovered_media_sources (
        source_id TEXT PRIMARY KEY,
        mount_path TEXT NOT NULL,
        total_files BIGINT NOT NULL,
        total_bytes BIGINT NOT NULL,
        filesystem_hint TEXT NOT NULL,
        scanned_at_utc TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS custodians (
        custodian_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        identifiers_json TEXT NOT NULL,
        epistemic_status TEXT NOT NULL,
        anchor_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS declared_evidence_items (
        declared_id TEXT PRIMARY KEY,
        custodian_id TEXT NOT NULL,
        primary_doc_type TEXT NOT NULL,
        seizure_utc TEXT NOT NULL,
        brand TEXT NOT NULL,
        model TEXT NOT NULL,
        serial_number TEXT NOT NULL,
        imei_chassis_json TEXT NOT NULL,
        imei_memory_json TEXT NOT NULL,
        iccid_json TEXT NOT NULL,
        lock_state TEXT NOT NULL,
        rf_isolation TEXT NOT NULL,
        seals_in_json TEXT NOT NULL,
        seals_out_json TEXT NOT NULL,
        working_copy_examined TEXT NOT NULL,
        state_sha256 TEXT NOT NULL,
        master_hashlist_sha256 TEXT NOT NULL,
        expected_raw_format TEXT NOT NULL,
        epistemic_status TEXT NOT NULL,
        anchor_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence_inventory_tree (
        control_number TEXT PRIMARY KEY,
        parent_control_number TEXT,
        source_id TEXT NOT NULL,
        origin_rel_path TEXT NOT NULL,
        vault_rel_path TEXT NOT NULL,
        size_bytes BIGINT NOT NULL,
        mtime_utc_ns BIGINT NOT NULL,
        is_os_readonly INTEGER NOT NULL,
        sha256_hex TEXT NOT NULL,
        magic_signature TEXT NOT NULL,
        extension_spoofed INTEGER NOT NULL,
        is_encrypted_or_corrupted INTEGER NOT NULL,
        pdf_eof_count INTEGER NOT NULL,
        has_wal_shm_sibling INTEGER NOT NULL,
        is_denist_logical INTEGER NOT NULL,
        duplicate_of_cn TEXT,
        all_custodians_json TEXT NOT NULL,
        all_source_paths_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dynamic_schema_blueprints (
        schema_hash TEXT PRIMARY KEY,
        container_cn TEXT NOT NULL,
        db_or_table_name TEXT NOT NULL,
        columns_json TEXT NOT NULL,
        inferred_domain TEXT NOT NULL,
        extraction_sql_template TEXT NOT NULL,
        approved_by_verifier INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS custody_and_parity_findings (
        finding_id TEXT PRIMARY KEY,
        declared_id TEXT,
        matched_cn TEXT,
        parity_state TEXT NOT NULL,
        preservation_axis TEXT NOT NULL,
        defect_category TEXT NOT NULL,
        legal_tags_json TEXT NOT NULL,
        is_judicial_critical INTEGER NOT NULL,
        epistemic_status TEXT NOT NULL,
        anchor_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS unified_timeline_events (
        event_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        event_type TEXT NOT NULL,
        raw_ts TEXT NOT NULL,
        epoch_kind TEXT NOT NULL,
        tz_declared TEXT NOT NULL,
        ts_utc TEXT NOT NULL,
        is_post_seizure INTEGER NOT NULL,
        actor_origin TEXT NOT NULL,
        actor_target TEXT NOT NULL,
        content_verbatim TEXT NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS financial_ledger_entries (
        entry_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        bank_code TEXT NOT NULL,
        branch TEXT NOT NULL,
        account TEXT NOT NULL,
        holder_tax_id TEXT NOT NULL,
        counterparty_tax_id TEXT NOT NULL,
        tx_utc TEXT NOT NULL,
        debit_credit TEXT NOT NULL,
        amount_cents BIGINT NOT NULL,
        raw_amount_text TEXT NOT NULL,
        is_inter_file_duplicate INTEGER NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS telecom_cdr_erb_events (
        cdr_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        caller TEXT NOT NULL,
        callee TEXT NOT NULL,
        imei TEXT NOT NULL,
        start_utc TEXT NOT NULL,
        duration_sec BIGINT NOT NULL,
        cell_cgi TEXT NOT NULL,
        lat_microdeg BIGINT NOT NULL,
        lon_microdeg BIGINT NOT NULL,
        azimuth_deg BIGINT NOT NULL,
        impossible_speed_flag INTEGER NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS hybrid_search_chunks (
        chunk_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        locator TEXT NOT NULL,
        text_clean TEXT NOT NULL,
        injection_neutralized INTEGER NOT NULL,
        vector_blob BLOB NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS ai_and_qc_audit_log (
        audit_id TEXT PRIMARY KEY,
        ts_utc TEXT NOT NULL,
        phase_code TEXT NOT NULL,
        model_name TEXT NOT NULL,
        prompt_sha256 TEXT NOT NULL,
        tokens_in BIGINT NOT NULL,
        tokens_out BIGINT NOT NULL,
        verifier_passed INTEGER NOT NULL,
        rejected_claims_count BIGINT NOT NULL,
        sampling_method TEXT NOT NULL,
        stratum_stats_json TEXT NOT NULL
    )
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS hybrid_search_fts USING fts5(
        chunk_id UNINDEXED,
        origin_cn,
        locator,
        text_clean
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audio_transcript_cache (
        audio_sha256 TEXT PRIMARY KEY,
        duration_ms BIGINT NOT NULL,
        model_id TEXT NOT NULL,
        segments_json TEXT NOT NULL,
        cached_at_utc TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS container_expansion_checkpoints (
        parent_cn TEXT PRIMARY KEY,
        parent_sha256 TEXT NOT NULL,
        state TEXT NOT NULL,
        expected_children BIGINT NOT NULL,
        unpacked_children BIGINT NOT NULL,
        completed_all_children INTEGER NOT NULL,
        updated_at_utc TEXT NOT NULL
    )
    """,
)
