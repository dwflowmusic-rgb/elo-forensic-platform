"""Publicador do Banco de Dados Mestre Organizado (`case_master_organized.sqlite`) no HD de Destino (Delta v2.2)."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3

from edrm.bootstrap.container import FullPipelineExecutionResult
from edrm.interfaces.disk_router_wizard import CrossDiskRoutingPlan
from edrm.shared_kernel.value_objects import CentsAmount, SafeOsPath

EXECUTIVE_VIEWS_NAMES: tuple[str, ...] = (
    "vw_01_indice_geral_provas",
    "vw_02_matriz_declarado_vs_entregue",
    "vw_03_alertas_cadeia_custodia_e_pericia",
    "vw_04_comunicacoes_unificadas_utc",
    "vw_05_financeiro_consolidado",
    "vw_06_telecom_erb_deslocamentos",
    "vw_07_transcricoes_audio_ancoradas",
    "vw_08_linha_do_tempo_mestra_utc",
)

ORGANIZED_DDL_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS org_inventory_files (
        control_number TEXT PRIMARY KEY,
        parent_control_number TEXT,
        source_id TEXT NOT NULL,
        origin_rel_path TEXT NOT NULL,
        vault_or_ref_path TEXT NOT NULL,
        sha256_hex TEXT NOT NULL,
        size_bytes BIGINT NOT NULL,
        mtime_utc_ns BIGINT NOT NULL,
        magic_signature TEXT NOT NULL,
        extension_spoofed INTEGER NOT NULL,
        is_encrypted_or_corrupted INTEGER NOT NULL,
        pdf_eof_count INTEGER NOT NULL,
        has_wal_sibling INTEGER NOT NULL,
        custodian_names TEXT NOT NULL,
        is_denist_logical INTEGER NOT NULL,
        duplicate_of_cn TEXT,
        acquisition_strategy TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_parity_matrix (
        finding_id TEXT PRIMARY KEY,
        declared_id TEXT,
        primary_doc_type TEXT NOT NULL,
        brand TEXT NOT NULL,
        model TEXT NOT NULL,
        expected_raw_format TEXT NOT NULL,
        state_sha256 TEXT NOT NULL,
        matched_rel_path TEXT,
        matched_sha256 TEXT,
        parity_state TEXT NOT NULL,
        tema977_sonegado_flag INTEGER NOT NULL,
        is_judicial_critical INTEGER NOT NULL,
        legal_tags TEXT NOT NULL,
        rationale TEXT NOT NULL,
        epistemic_status TEXT NOT NULL,
        origin_path TEXT NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_custody_and_forensic_alerts (
        alert_id TEXT PRIMARY KEY,
        phase_origin TEXT NOT NULL,
        alert_category TEXT NOT NULL,
        target_reference TEXT NOT NULL,
        severity TEXT NOT NULL,
        legal_basis TEXT NOT NULL,
        description TEXT NOT NULL,
        origin_cn TEXT NOT NULL,
        origin_path TEXT NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_communications_utc (
        comm_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        ts_utc TEXT NOT NULL,
        epoch_kind TEXT NOT NULL,
        channel_or_type TEXT NOT NULL,
        actor_origin TEXT NOT NULL,
        actor_target TEXT NOT NULL,
        sqlite_allocation_state TEXT NOT NULL,
        is_deleted_recovered INTEGER NOT NULL,
        is_post_seizure INTEGER NOT NULL,
        content_verbatim TEXT NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_financial_consolidated (
        entry_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        instrument_kind TEXT NOT NULL,
        bank_code TEXT NOT NULL,
        branch TEXT NOT NULL,
        account TEXT NOT NULL,
        holder_tax_id TEXT NOT NULL,
        counterparty_tax_id TEXT NOT NULL,
        tx_utc TEXT NOT NULL,
        debit_credit TEXT NOT NULL,
        amount_cents BIGINT NOT NULL,
        amount_brl_formatted TEXT NOT NULL,
        is_inter_file_duplicate INTEGER NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_telecom_erb_cgnat (
        record_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        record_subtype TEXT NOT NULL,
        caller_or_shared_ip TEXT NOT NULL,
        callee_or_port TEXT NOT NULL,
        imei TEXT NOT NULL,
        event_utc TEXT NOT NULL,
        duration_sec BIGINT NOT NULL,
        cell_cgi TEXT NOT NULL,
        lat_microdeg BIGINT NOT NULL,
        lon_microdeg BIGINT NOT NULL,
        azimuth_deg BIGINT NOT NULL,
        impossible_speed_flag INTEGER NOT NULL,
        cgnat_missing_port_flag INTEGER NOT NULL,
        locator TEXT NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_audio_transcript_segments (
        segment_id TEXT PRIMARY KEY,
        audio_sha256 TEXT NOT NULL,
        origin_cn TEXT NOT NULL,
        origin_path TEXT NOT NULL,
        inicio_ms BIGINT NOT NULL,
        fim_ms BIGINT NOT NULL,
        duration_ms BIGINT NOT NULL,
        model_id TEXT NOT NULL,
        transcript_verbatim TEXT NOT NULL,
        cached_at_utc TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_anchored_chunks (
        chunk_id TEXT PRIMARY KEY,
        origin_cn TEXT NOT NULL,
        origin_path TEXT NOT NULL,
        locator TEXT NOT NULL,
        text_clean TEXT NOT NULL,
        injection_neutralized INTEGER NOT NULL,
        origin_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS org_material_contradictions (
        contradiction_id TEXT PRIMARY KEY,
        contradiction_type TEXT NOT NULL,
        state_claim_excerpt TEXT NOT NULL,
        raw_truth_excerpt TEXT NOT NULL,
        omitted_neighbor_context TEXT NOT NULL,
        financial_inflation_cents BIGINT NOT NULL,
        legal_impact TEXT NOT NULL,
        raw_origin_cn TEXT NOT NULL,
        raw_locator TEXT NOT NULL,
        raw_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS fts_global_evidence_index USING fts5(
        doc_ref UNINDEXED,
        origin_cn,
        source_domain,
        locator,
        origin_sha256 UNINDEXED,
        content_text
    )
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_01_indice_geral_provas AS
    SELECT
        control_number,
        parent_control_number,
        source_id,
        origin_rel_path,
        vault_or_ref_path,
        sha256_hex,
        size_bytes,
        magic_signature,
        extension_spoofed,
        is_encrypted_or_corrupted,
        pdf_eof_count,
        has_wal_sibling,
        custodian_names,
        is_denist_logical,
        duplicate_of_cn,
        acquisition_strategy
    FROM org_inventory_files
    ORDER BY control_number ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_02_matriz_declarado_vs_entregue AS
    SELECT
        finding_id,
        declared_id,
        primary_doc_type,
        brand,
        model,
        expected_raw_format,
        state_sha256,
        matched_rel_path,
        matched_sha256,
        parity_state,
        tema977_sonegado_flag,
        is_judicial_critical,
        legal_tags,
        rationale,
        epistemic_status,
        origin_path,
        locator,
        origin_sha256
    FROM org_parity_matrix
    ORDER BY is_judicial_critical DESC, finding_id ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_03_alertas_cadeia_custodia_e_pericia AS
    SELECT
        alert_id,
        phase_origin,
        alert_category,
        target_reference,
        severity,
        legal_basis,
        description,
        origin_cn,
        origin_path,
        locator,
        origin_sha256
    FROM org_custody_and_forensic_alerts
    ORDER BY severity DESC, alert_id ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_04_comunicacoes_unificadas_utc AS
    SELECT
        comm_id,
        origin_cn,
        ts_utc,
        epoch_kind,
        channel_or_type,
        actor_origin,
        actor_target,
        sqlite_allocation_state,
        is_deleted_recovered,
        is_post_seizure,
        content_verbatim,
        locator,
        origin_sha256
    FROM org_communications_utc
    ORDER BY ts_utc ASC, comm_id ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_05_financeiro_consolidado AS
    SELECT
        entry_id,
        origin_cn,
        instrument_kind,
        bank_code,
        branch,
        account,
        holder_tax_id,
        counterparty_tax_id,
        tx_utc,
        debit_credit,
        amount_cents,
        amount_brl_formatted,
        is_inter_file_duplicate,
        locator,
        origin_sha256
    FROM org_financial_consolidated
    ORDER BY tx_utc ASC, entry_id ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_06_telecom_erb_deslocamentos AS
    SELECT
        record_id,
        origin_cn,
        record_subtype,
        caller_or_shared_ip,
        callee_or_port,
        imei,
        event_utc,
        duration_sec,
        cell_cgi,
        lat_microdeg,
        lon_microdeg,
        azimuth_deg,
        impossible_speed_flag,
        cgnat_missing_port_flag,
        locator,
        origin_sha256
    FROM org_telecom_erb_cgnat
    ORDER BY event_utc ASC, record_id ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_07_transcricoes_audio_ancoradas AS
    SELECT
        segment_id,
        audio_sha256,
        origin_cn,
        origin_path,
        inicio_ms,
        fim_ms,
        duration_ms,
        model_id,
        transcript_verbatim,
        cached_at_utc
    FROM org_audio_transcript_segments
    ORDER BY origin_cn ASC, inicio_ms ASC
    """,
    """
    CREATE VIEW IF NOT EXISTS vw_08_linha_do_tempo_mestra_utc AS
    SELECT
        ts_utc,
        'COMUNICACAO' AS domain_source,
        comm_id AS ref_id,
        origin_cn,
        actor_origin AS actor_primary,
        actor_target AS actor_secondary,
        content_verbatim AS summary_verbatim,
        (CASE WHEN is_post_seizure = 1 OR is_deleted_recovered = 1 THEN 1 ELSE 0 END) AS anomaly_flag,
        locator,
        origin_sha256
    FROM org_communications_utc
    UNION ALL
    SELECT
        tx_utc AS ts_utc,
        'FINANCEIRO' AS domain_source,
        entry_id AS ref_id,
        origin_cn,
        holder_tax_id AS actor_primary,
        counterparty_tax_id AS actor_secondary,
        (instrument_kind || ' ' || debit_credit || ' ' || amount_brl_formatted) AS summary_verbatim,
        is_inter_file_duplicate AS anomaly_flag,
        locator,
        origin_sha256
    FROM org_financial_consolidated
    UNION ALL
    SELECT
        event_utc AS ts_utc,
        'TELECOM_ERB_CGNAT' AS domain_source,
        record_id AS ref_id,
        origin_cn,
        caller_or_shared_ip AS actor_primary,
        callee_or_port AS actor_secondary,
        (record_subtype || ' CGI=' || cell_cgi) AS summary_verbatim,
        (CASE WHEN impossible_speed_flag = 1 OR cgnat_missing_port_flag = 1 THEN 1 ELSE 0 END) AS anomaly_flag,
        locator,
        origin_sha256
    FROM org_telecom_erb_cgnat
    ORDER BY ts_utc ASC, ref_id ASC
    """,
)


class OrganizedDatabasePublisher:
    """Materializa a arvore padronizada 00..03 e o banco `case_master_organized.sqlite` no HD de destino."""

    @classmethod
    def publish(
        cls,
        pipeline_result: FullPipelineExecutionResult,
        routing_plan: CrossDiskRoutingPlan,
    ) -> dict[str, object]:
        """Popula as 4 pastas padronizadas, as 8 SQL Views, o indice FTS5 e a documentacao de esquema."""
        zones = routing_plan.standardized_zones
        dir_00 = Path(zones["00_GOVERNANCA_E_AUDITORIA"])
        dir_01 = Path(zones["01_BANCO_ORGANIZADO"])
        dir_02 = Path(zones["02_COFRE_OU_REFERENCIA"])
        dir_03 = Path(zones["03_RELATORIOS_E_DOSSIE"])

        for folder in (dir_00, dir_01, dir_02, dir_03):
            folder.mkdir(parents=True, exist_ok=True)

        db_path = dir_01 / "case_master_organized.sqlite"
        if db_path.exists():
            os.chmod(str(db_path), 0o600)
            db_path.unlink()

        cls._populate_organized_sqlite(db_path, pipeline_result, routing_plan)
        cls._sync_governance_vault_and_deliverables(
            pipeline_result=pipeline_result,
            routing_plan=routing_plan,
            dir_00=dir_00,
            dir_02=dir_02,
            dir_03=dir_03,
        )

        view_counts = cls._count_all_views_readonly(db_path)
        db_sha256 = hashlib.sha256(db_path.read_bytes()).hexdigest()

        schema_md_path = dir_01 / "SCHEMA_PARA_HUMANO_E_IA.md"
        schema_md_content = cls._build_schema_markdown(
            case_id=pipeline_result.governance.case_id,
            db_sha256=db_sha256,
            view_counts=view_counts,
        )
        cls._write_fsync_text(schema_md_path, schema_md_content)

        p01_final = pipeline_result.phase04.updated_phase01_bundle
        executive_summary = {
            "case_id": pipeline_result.governance.case_id,
            "run_id": pipeline_result.governance.run_id,
            "organized_db_path": str(db_path),
            "organized_db_sha256": db_sha256,
            "schema_markdown_path": str(schema_md_path),
            "acquisition_strategy": routing_plan.acquisition_strategy,
            "zero_source_mutation_confirmed": pipeline_result.phase08.source_pre_post_snapshot_identical,
            "pre_scan_snapshot_sha256": pipeline_result.phase01_initial.pre_scan_snapshot.snapshot_sha256,
            "post_scan_snapshot_sha256": pipeline_result.phase08.post_scan_snapshot.snapshot_sha256,
            "custodians_count": len(p01_final.custodians),
            "material_contradictions_count": len(pipeline_result.phase05.material_contradictions),
            "classified_nullities_count": len(pipeline_result.phase05.classified_nullities),
            "quesitos_count": len(pipeline_result.phase07.quesitos),
            "views_row_counts": view_counts,
        }
        summary_json_path = dir_01 / "RESUMO_EXECUTIVO_BANCO.json"
        cls._write_fsync_text(
            summary_json_path,
            json.dumps(executive_summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        return executive_summary

    @classmethod
    def _populate_organized_sqlite(
        cls,
        db_path: Path,
        res: FullPipelineExecutionResult,
        plan: CrossDiskRoutingPlan,
    ) -> None:
        p01 = res.phase04.updated_phase01_bundle
        p02 = res.phase02
        p03 = res.phase03
        p04 = res.phase04
        p05 = res.phase05
        catalog_src = Path(res.governance.catalog_db_path)

        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute("PRAGMA journal_mode = DELETE;")
            conn.execute("PRAGMA synchronous = FULL;")
            for ddl in ORGANIZED_DDL_STATEMENTS:
                conn.execute(ddl)

            custodian_label = ", ".join(c.name for c in p01.custodians) or "NAO_DECLARADO"
            probed_by_rel = {pf.rel_path: pf for pf in p01.discovery_blueprint.probed_files}

            inv_rows = cls._read_catalog_inventory_rows(catalog_src)
            if inv_rows:
                for row in inv_rows:
                    cn, parent_cn, src_id, orig_rel, v_rel, sz, mtime_ns, sha_hex, mag, spoof, enc, eof_c, wal_c, denist, dup_cn = row
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO org_inventory_files VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            cn,
                            parent_cn,
                            src_id,
                            orig_rel,
                            v_rel if plan.acquisition_strategy == "FULL_VAULT_COPY" else f"REF::{orig_rel}",
                            sha_hex,
                            int(sz),
                            int(mtime_ns),
                            mag,
                            int(spoof),
                            int(enc),
                            int(eof_c),
                            int(wal_c),
                            custodian_label,
                            int(denist),
                            dup_cn,
                            plan.acquisition_strategy,
                        ),
                    )
            else:
                for ve in p03.vault_entries:
                    pf = probed_by_rel.get(ve.origin_rel_path)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO org_inventory_files VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            ve.control_number,
                            None,
                            ve.source_id,
                            ve.origin_rel_path,
                            ve.vault_rel_path,
                            ve.source_sha256,
                            int(ve.size_bytes),
                            int(ve.mtime_utc_ns),
                            str(pf.magic_signature) if pf else "UNKNOWN_BINARY",
                            1 if (pf and pf.extension_spoofed) else 0,
                            1 if (pf and pf.is_encrypted_or_corrupted) else 0,
                            int(pf.pdf_eof_count) if pf else 0,
                            1 if (pf and pf.has_wal_sibling) else 0,
                            custodian_label,
                            0,
                            None,
                            plan.acquisition_strategy,
                        ),
                    )

            decl_by_id = {d.declared_id: d for d in p01.declared_items}
            for pm in p01.parity_matrix:
                decl = decl_by_id.get(pm.declared_id or "")
                tema977_flag = 1 if str(pm.parity_state) in (
                    "DECLARED_RAW_NOT_DELIVERED",
                    "DELIVERED_ENCRYPTED_OR_CORRUPTED",
                ) else 0
                conn.execute(
                    """
                    INSERT OR REPLACE INTO org_parity_matrix VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        pm.finding_id,
                        pm.declared_id,
                        str(decl.primary_doc_type) if decl else "NAO_VINCULADO",
                        decl.brand if decl else "N/A",
                        decl.model if decl else "N/A",
                        decl.expected_raw_format if decl else "N/A",
                        decl.state_sha256 if decl else "EXPLICIT_GAP",
                        pm.matched_rel_path,
                        pm.matched_sha256,
                        str(pm.parity_state),
                        tema977_flag,
                        1 if pm.is_judicial_critical else 0,
                        ", ".join(pm.legal_tags),
                        pm.rationale,
                        str(pm.epistemic_status),
                        pm.anchor.origin_path,
                        pm.anchor.locator,
                        pm.anchor.origin_sha256,
                    ),
                )

            cls._insert_forensic_alerts(conn, p01, p02, p04, p05)
            cls._insert_communications_and_fts(conn, p04)
            cls._insert_financial_and_fts(conn, p04)
            cls._insert_telecom_and_cgnat(conn, p04)
            cls._insert_audio_segments_and_chunks(conn, catalog_src, p01, p04, p05)

            conn.commit()
        finally:
            conn.close()

        with open(db_path, "rb+") as fh:
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def _read_catalog_inventory_rows(catalog_src: Path) -> list[tuple[object, ...]]:
        if not catalog_src.is_file():
            return []
        uri = SafeOsPath(str(catalog_src.resolve())).to_sqlite_immutable_uri()
        c_ro = sqlite3.connect(uri, uri=True)
        try:
            c_ro.execute("PRAGMA query_only = 1;")
            cur = c_ro.execute(
                """
                SELECT control_number, parent_control_number, source_id, origin_rel_path,
                       vault_rel_path, size_bytes, mtime_utc_ns, sha256_hex, magic_signature,
                       extension_spoofed, is_encrypted_or_corrupted, pdf_eof_count,
                       has_wal_shm_sibling, is_denist_logical, duplicate_of_cn
                FROM evidence_inventory_tree
                ORDER BY control_number ASC
                """
            )
            return list(cur.fetchall())
        except sqlite3.Error:
            return []
        finally:
            c_ro.close()

    @staticmethod
    def _insert_forensic_alerts(conn: sqlite3.Connection, p01: object, p02: object, p04: object, p05: object) -> None:
        from edrm.shared_kernel.contracts import (
            Phase01ToPhase02Contract,
            Phase02ToPhase03Contract,
            Phase04ToPhase05Contract,
            Phase05ToPhase06Contract,
        )

        assert isinstance(p01, Phase01ToPhase02Contract)
        assert isinstance(p02, Phase02ToPhase03Contract)
        assert isinstance(p04, Phase04ToPhase05Contract)
        assert isinstance(p05, Phase05ToPhase06Contract)

        for nul in p05.classified_nullities:
            sev = "CRITICO" if "NULLITY" in str(nul.category) or "TEMA_977" in str(nul.category) else "ALTO"
            conn.execute(
                "INSERT OR REPLACE INTO org_custody_and_forensic_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    nul.nullity_id,
                    "PHASE_05_NULLITY",
                    str(nul.category),
                    nul.source_finding_id,
                    sev,
                    "; ".join(nul.legal_articles),
                    nul.description,
                    nul.anchor.origin_control_number,
                    nul.anchor.origin_path,
                    nul.anchor.locator,
                    nul.anchor.origin_sha256,
                ),
            )
            conn.execute(
                "INSERT INTO fts_global_evidence_index VALUES (?, ?, ?, ?, ?, ?)",
                (
                    nul.nullity_id,
                    nul.anchor.origin_control_number,
                    "vw_03_alertas_cadeia_custodia_e_pericia",
                    nul.anchor.locator,
                    nul.anchor.origin_sha256,
                    f"{nul.category} {nul.description}",
                ),
            )

        for sf in p02.structural_findings:
            if sf.pdf_incremental_revisions > 1 or sf.has_unconsolidated_wal_frames or not sf.is_healthy:
                aid = f"ALT-STRUCT-{hashlib.sha256(sf.rel_path.encode('utf-8')).hexdigest()[:10].upper()}"
                conn.execute(
                    "INSERT OR REPLACE INTO org_custody_and_forensic_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        aid,
                        "PHASE_02_STRUCTURAL",
                        "PDF_MULTI_EOF_OR_SQLITE_WAL",
                        sf.rel_path,
                        "ALTO",
                        "ISO/IEC 27037; NIST IR 8354",
                        f"Saude estrutural: {sf.detail} (PDF %%EOF={sf.pdf_incremental_revisions}, WAL frames={sf.wal_frame_count})",
                        "ELO-000001",
                        sf.rel_path,
                        "structural_probe",
                        sf.sha256_hex,
                    ),
                )

        for dl in p04.dead_letter_items:
            aid = f"ALT-DLQ-{dl.control_number}"
            conn.execute(
                "INSERT OR REPLACE INTO org_custody_and_forensic_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    aid,
                    "PHASE_04_DEADLETTER",
                    dl.reason_code,
                    dl.rel_path,
                    "ALTO",
                    "STJ RHC 184.003/SP; POP Senasp Vol. 5",
                    dl.detail,
                    dl.control_number,
                    dl.rel_path,
                    "dead_letter_queue",
                    dl.sha256_hex,
                ),
            )

    @staticmethod
    def _insert_communications_and_fts(conn: sqlite3.Connection, p04: object) -> None:
        from edrm.shared_kernel.contracts import Phase04ToPhase05Contract

        assert isinstance(p04, Phase04ToPhase05Contract)
        for ev in p04.timeline_events:
            alloc_str = str(ev.sqlite_allocation_state)
            is_del = 0 if alloc_str == "ACTIVE_BTREE_ROW" else 1
            conn.execute(
                "INSERT OR REPLACE INTO org_communications_utc VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ev.event_id,
                    ev.origin_cn,
                    ev.ts_utc,
                    ev.epoch_kind,
                    ev.event_type,
                    ev.actor_origin,
                    ev.actor_target,
                    alloc_str,
                    is_del,
                    1 if ev.is_post_seizure else 0,
                    ev.content_verbatim,
                    ev.locator,
                    ev.origin_sha256,
                ),
            )
            conn.execute(
                "INSERT INTO fts_global_evidence_index VALUES (?, ?, ?, ?, ?, ?)",
                (
                    ev.event_id,
                    ev.origin_cn,
                    "vw_04_comunicacoes_unificadas_utc",
                    ev.locator,
                    ev.origin_sha256,
                    f"{ev.actor_origin} {ev.actor_target} {ev.content_verbatim}",
                ),
            )

        for rec in p04.recovered_sqlite_records:
            cid = f"REC-{rec.record_id}"
            conn.execute(
                "INSERT OR REPLACE INTO org_communications_utc VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cid,
                    rec.origin_cn,
                    "1970-01-01T00:00:00Z",
                    "CARVED_UNALLOCATED",
                    "SQLITE_RECOVERED_FRAGMENT",
                    "RECOVERED_SOURCE",
                    "UNKNOWN_TARGET",
                    str(rec.allocation_state),
                    1,
                    0,
                    rec.recovered_text,
                    rec.page_or_frame_locator,
                    rec.origin_sha256,
                ),
            )
            conn.execute(
                "INSERT INTO fts_global_evidence_index VALUES (?, ?, ?, ?, ?, ?)",
                (
                    cid,
                    rec.origin_cn,
                    "vw_04_comunicacoes_unificadas_utc",
                    rec.page_or_frame_locator,
                    rec.origin_sha256,
                    rec.recovered_text,
                ),
            )

    @staticmethod
    def _insert_financial_and_fts(conn: sqlite3.Connection, p04: object) -> None:
        from edrm.shared_kernel.contracts import Phase04ToPhase05Contract

        assert isinstance(p04, Phase04ToPhase05Contract)
        for fe in p04.financial_entries:
            brl_txt = CentsAmount(int(fe.amount_cents)).format_brl()
            conn.execute(
                """
                INSERT OR REPLACE INTO org_financial_consolidated VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    fe.entry_id,
                    fe.origin_cn,
                    "SIMBA_OR_BANK_LEDGER",
                    fe.bank_code,
                    fe.branch,
                    fe.account,
                    fe.holder_tax_id,
                    fe.counterparty_tax_id,
                    fe.tx_utc,
                    fe.debit_credit,
                    int(fe.amount_cents),
                    brl_txt,
                    1 if fe.is_inter_file_duplicate else 0,
                    fe.locator,
                    fe.origin_sha256,
                ),
            )
            conn.execute(
                "INSERT INTO fts_global_evidence_index VALUES (?, ?, ?, ?, ?, ?)",
                (
                    fe.entry_id,
                    fe.origin_cn,
                    "vw_05_financeiro_consolidado",
                    fe.locator,
                    fe.origin_sha256,
                    f"{fe.holder_tax_id} {fe.counterparty_tax_id} {brl_txt} {fe.raw_amount_text}",
                ),
            )

    @staticmethod
    def _insert_telecom_and_cgnat(conn: sqlite3.Connection, p04: object) -> None:
        from edrm.shared_kernel.contracts import Phase04ToPhase05Contract

        assert isinstance(p04, Phase04ToPhase05Contract)
        for tr in p04.telecom_records:
            conn.execute(
                """
                INSERT OR REPLACE INTO org_telecom_erb_cgnat VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    tr.cdr_id,
                    tr.origin_cn,
                    "CDR_ERB",
                    tr.caller,
                    tr.callee,
                    tr.imei,
                    tr.start_utc,
                    int(tr.duration_sec),
                    tr.cell_cgi,
                    int(tr.lat_microdeg),
                    int(tr.lon_microdeg),
                    int(tr.azimuth_deg),
                    1 if tr.impossible_speed_flag else 0,
                    0,
                    tr.locator,
                    tr.origin_sha256,
                ),
            )

        for cg in p04.cgnat_records:
            port_str = str(cg.source_logical_port) if cg.source_logical_port is not None else "PORTA_AUSENTE"
            conn.execute(
                """
                INSERT OR REPLACE INTO org_telecom_erb_cgnat VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    cg.log_id,
                    cg.origin_cn,
                    "CGNAT_IP_LOG",
                    cg.shared_ip,
                    port_str,
                    "N/A",
                    cg.ts_utc,
                    0,
                    "CGNAT",
                    0,
                    0,
                    0,
                    0,
                    1 if cg.missing_logical_port_defect else 0,
                    cg.locator,
                    cg.origin_sha256,
                ),
            )

    @staticmethod
    def _insert_audio_segments_and_chunks(
        conn: sqlite3.Connection,
        catalog_src: Path,
        p01: object,
        p04: object,
        p05: object,
    ) -> None:
        from edrm.shared_kernel.contracts import (
            Phase01ToPhase02Contract,
            Phase04ToPhase05Contract,
            Phase05ToPhase06Contract,
        )

        assert isinstance(p01, Phase01ToPhase02Contract)
        assert isinstance(p04, Phase04ToPhase05Contract)
        assert isinstance(p05, Phase05ToPhase06Contract)

        for chk in p04.anchored_chunks:
            conn.execute(
                "INSERT OR REPLACE INTO org_anchored_chunks VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    chk.chunk_id,
                    chk.origin_cn,
                    chk.origin_path,
                    chk.locator,
                    chk.text_clean,
                    1 if chk.injection_neutralized else 0,
                    chk.origin_sha256,
                ),
            )
            conn.execute(
                "INSERT INTO fts_global_evidence_index VALUES (?, ?, ?, ?, ?, ?)",
                (
                    chk.chunk_id,
                    chk.origin_cn,
                    "org_anchored_chunks",
                    chk.locator,
                    chk.origin_sha256,
                    chk.text_clean,
                ),
            )

        for ctr in p05.material_contradictions:
            conn.execute(
                "INSERT OR REPLACE INTO org_material_contradictions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ctr.contradiction_id,
                    ctr.contradiction_type,
                    ctr.state_claim_excerpt,
                    ctr.raw_truth_excerpt,
                    ctr.omitted_neighbor_context,
                    int(ctr.financial_inflation_cents),
                    ctr.legal_impact,
                    ctr.raw_anchor.origin_control_number,
                    ctr.raw_anchor.locator,
                    ctr.raw_anchor.origin_sha256,
                ),
            )

        if catalog_src.is_file():
            uri = SafeOsPath(str(catalog_src.resolve())).to_sqlite_immutable_uri()
            c_ro = sqlite3.connect(uri, uri=True)
            try:
                c_ro.execute("PRAGMA query_only = 1;")
                rows = c_ro.execute(
                    "SELECT audio_sha256, duration_ms, model_id, segments_json, cached_at_utc FROM audio_transcript_cache"
                ).fetchall()
                for a_sha, dur_ms, mod_id, seg_json, cached_utc in rows:
                    segs = json.loads(str(seg_json))
                    if isinstance(segs, list):
                        for idx, seg in enumerate(segs, start=1):
                            if isinstance(seg, dict):
                                ini = int(seg.get("start_ms", 0))
                                fim = int(seg.get("end_ms", int(dur_ms)))
                                txt = str(seg.get("text", ""))
                                sid = f"AUD-{str(a_sha)[:10].upper()}-{idx:04d}"
                                conn.execute(
                                    "INSERT OR REPLACE INTO org_audio_transcript_segments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    (
                                        sid,
                                        str(a_sha),
                                        "ELO-AUDIO",
                                        f"audio_sha256:{a_sha}",
                                        ini,
                                        fim,
                                        int(dur_ms),
                                        str(mod_id),
                                        txt,
                                        str(cached_utc),
                                    ),
                                )
            except sqlite3.Error:
                rows = []
            finally:
                c_ro.close()

        for seq, pf in enumerate(p01.discovery_blueprint.probed_files, start=1):
            if str(pf.magic_signature) == "WAV_AUDIO":
                sid = f"AUD-WAV-{seq:04d}"
                conn.execute(
                    "INSERT OR IGNORE INTO org_audio_transcript_segments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sid,
                        pf.sha256_hex,
                        f"ELO-{seq:06d}",
                        pf.rel_path,
                        0,
                        1000,
                        1000,
                        "elo_deterministic_wav_indexer",
                        f"Arquivo de audio WAV inventariado ({pf.rel_path}, {pf.size_bytes} bytes).",
                        res_ts_fallback(p01.pre_scan_snapshot.captured_at_utc),
                    ),
                )

    @classmethod
    def _sync_governance_vault_and_deliverables(
        cls,
        pipeline_result: FullPipelineExecutionResult,
        routing_plan: CrossDiskRoutingPlan,
        dir_00: Path,
        dir_02: Path,
        dir_03: Path,
    ) -> None:
        audit_src = Path(pipeline_result.governance.audit_dir)
        if audit_src.is_dir():
            for item in sorted(audit_src.iterdir()):
                if item.is_file():
                    dest_f = dir_00 / item.name
                    if dest_f.exists():
                        os.chmod(str(dest_f), 0o600)
                    shutil.copy2(item, dest_f)

        snapshot_proof = {
            "case_id": pipeline_result.governance.case_id,
            "pre_scan_snapshot_sha256": pipeline_result.phase01_initial.pre_scan_snapshot.snapshot_sha256,
            "post_scan_snapshot_sha256": pipeline_result.phase08.post_scan_snapshot.snapshot_sha256,
            "zero_source_mutation_confirmed": pipeline_result.phase08.source_pre_post_snapshot_identical,
            "calibration_receipt": asdict(pipeline_result.governance.calibration_receipt),
        }
        cls._write_fsync_text(
            dir_00 / "PROVA_IMUTABILIDADE_ORIGEM.json",
            json.dumps(snapshot_proof, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

        ref_entries = [asdict(ve) for ve in pipeline_result.phase03.vault_entries]
        cls._write_fsync_text(
            dir_02 / "MANIFESTO_COFRE_E_REFERENCIAS.json",
            json.dumps(
                {
                    "acquisition_strategy": routing_plan.acquisition_strategy,
                    "vault_entries": ref_entries,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )

        deliv_src = Path(pipeline_result.governance.deliverables_dir)
        if deliv_src.is_dir():
            for item in sorted(deliv_src.iterdir()):
                if item.is_file():
                    dest_f = dir_03 / item.name
                    if dest_f.exists():
                        os.chmod(str(dest_f), 0o600)
                    shutil.copy2(item, dest_f)

    @staticmethod
    def _count_all_views_readonly(db_path: Path) -> dict[str, int]:
        uri = SafeOsPath(str(db_path.resolve())).to_sqlite_immutable_uri()
        conn = sqlite3.connect(uri, uri=True)
        counts: dict[str, int] = {}
        try:
            conn.execute("PRAGMA query_only = 1;")
            for v_name in EXECUTIVE_VIEWS_NAMES:
                row = conn.execute(f"SELECT COUNT(*) FROM {v_name}").fetchone()
                counts[v_name] = int(row[0]) if row else 0
            fts_row = conn.execute("SELECT COUNT(*) FROM fts_global_evidence_index").fetchone()
            counts["fts_global_evidence_index"] = int(fts_row[0]) if fts_row else 0
        finally:
            conn.close()
        return counts

    @staticmethod
    def _build_schema_markdown(case_id: str, db_sha256: str, view_counts: dict[str, int]) -> str:
        lines = [
            f"# Mapa do Banco Mestre Organizado (`case_master_organized.sqlite`) — Caso `{case_id}`",
            "",
            f"- **SHA-256 do Banco Organizado**: `{db_sha256}`",
            "- **Modo Recomendado de Leitura**: `file:case_master_organized.sqlite?mode=ro&immutable=1` + `PRAGMA query_only = 1;`",
            "- **Moeda e Coordenadas**: Valores em centavos inteiros (`BIGINT`) + texto formatado `R$`; coordenadas em micrograus inteiros (`BIGINT`); datas normalizadas em `UTC`.",
            "",
            "## 1. As 8 Visões Executivas Prontas (`SQL Views`)",
            "",
            "| View SQL | Registros | Finalidade Direta para Perito, Advogado e Agente MCP |",
            "| :--- | ---: | :--- |",
            f"| `vw_01_indice_geral_provas` | `{view_counts.get('vw_01_indice_geral_provas', 0)}` | Catálogo completo de arquivos do HD original, `ControlNumber`, `SHA-256`, Magic Bytes, camuflagem e custodiante. |",
            f"| `vw_02_matriz_declarado_vs_entregue` | `{view_counts.get('vw_02_matriz_declarado_vs_entregue', 0)}` | Confronto Autos/FAV/Laudo vs. HD real (destaca provas brutas sonegadas — STF Tema 977). |",
            f"| `vw_03_alertas_cadeia_custodia_e_pericia` | `{view_counts.get('vw_03_alertas_cadeia_custodia_e_pericia', 0)}` | Vícios de cadeia de custódia, lacres, pós-apreensão, PDF `%%EOF > 1`, `.lnk` MAC e casos `.iped` omissivos. |",
            f"| `vw_04_comunicacoes_unificadas_utc` | `{view_counts.get('vw_04_comunicacoes_unificadas_utc', 0)}` | Chats e mensagens em `UTC` separando linhas ativas (`ACTIVE_BTREE_ROW`) de registros apagados recuperados. |",
            f"| `vw_05_financeiro_consolidado` | `{view_counts.get('vw_05_financeiro_consolidado', 0)}` | Lançamentos `SIMBA`/`OFX` em centavos `BIGINT`, valor `R$` formatado e flag `is_inter_file_duplicate`. |",
            f"| `vw_06_telecom_erb_deslocamentos` | `{view_counts.get('vw_06_telecom_erb_deslocamentos', 0)}` | Chamadas `CDR`, antenas `ERB` em micrograus, `CGNAT` sem porta lógica e velocidade humana impossível. |",
            f"| `vw_07_transcricoes_audio_ancoradas` | `{view_counts.get('vw_07_transcricoes_audio_ancoradas', 0)}` | Segmentos de áudio com carimbo `inicio_ms` / `fim_ms` vinculados ao `SHA-256` original. |",
            f"| `vw_08_linha_do_tempo_mestra_utc` | `{view_counts.get('vw_08_linha_do_tempo_mestra_utc', 0)}` | Régua cronológica suprema unindo comunicações, financeiro e telecom segundo a segundo em `UTC`. |",
            "",
            "## 2. Índice Textual Instantâneo (`FTS5 BM25`)",
            "",
            f"- Tabela virtual: `fts_global_evidence_index` (`{view_counts.get('fts_global_evidence_index', 0)}` entradas indexadas).",
            "",
            "## 3. Consultas SQL Prontas para Uso Imediato",
            "",
            "```sql",
            "-- 1. Listar provas brutas declaradas pela policia mas NAO entregues no HD (STF Tema 977)",
            "SELECT finding_id, declared_id, brand, model, parity_state, rationale",
            "FROM vw_02_matriz_declarado_vs_entregue WHERE tema977_sonegado_flag = 1;",
            "",
            "-- 2. Verificar todos os alertas criticos de cadeia de custodia e pericia (.iped, pos-apreensao, lacres)",
            "SELECT alert_id, alert_category, severity, legal_basis, description, origin_sha256",
            "FROM vw_03_alertas_cadeia_custodia_e_pericia;",
            "",
            "-- 3. Auditar duplicidades financeiras inter-arquivos SIMBA (sem erro de ponto flutuante)",
            "SELECT entry_id, tx_utc, holder_tax_id, counterparty_tax_id, amount_cents, amount_brl_formatted",
            "FROM vw_05_financeiro_consolidado WHERE is_inter_file_duplicate = 1;",
            "",
            "-- 4. Busca instantanea BM25 em todo o caso com retorno de ControlNumber e SHA-256",
            "SELECT doc_ref, origin_cn, source_domain, locator, origin_sha256, content_text",
            "FROM fts_global_evidence_index WHERE fts_global_evidence_index MATCH 'aluguel OR contrato' LIMIT 20;",
            "```",
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _write_fsync_text(target: Path, content: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())


def res_ts_fallback(ts_utc: str) -> str:
    """Garante timestamp ISO UTC nao vazio."""
    return ts_utc if ts_utc else "1970-01-01T00:00:00Z"
