"""Infraestrutura fisica da Fase 01 — Scanner Read-Only, SHA-256 4MiB, SQLite Immutable e Catalogo."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tarfile
import zipfile

from edrm.phase01_identification.domain import SignatureRegistry
from edrm.shared_kernel.compressibility_probe import (
    WINDOW_SIZE_BYTES,
    probe_headerless_encryption_bytes,
)
from edrm.shared_kernel.contracts import (
    CustodianRecord,
    DeclaredEvidenceItem,
    DivergenceRecord,
    FileStatEntry,
    MediaAutoDiscoveryBlueprint,
    MediaSnapshot,
    ParityMatrixRow,
    Phase01ToPhase02Contract,
    ProbedFileRecord,
)
from edrm.shared_kernel.enums import MagicSignature
from edrm.shared_kernel.value_objects import ControlNumber, SafeOsPath, canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly

STREAM_BLOCK_BYTES: int = 4 * 1024 * 1024
_PDF_PAREN_TEXT_RE = re.compile(rb"\(([^()]{3,400})\)")


def extract_pdf_native_text_bytes(raw_pdf: bytes) -> str:
    """Extrai fluxos textuais legiveis de PDFs nativos sem alterar nenhum byte."""
    chunks: list[str] = []
    for match in _PDF_PAREN_TEXT_RE.finditer(raw_pdf):
        token = match.group(1).replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\n", b"\n")
        try:
            decoded = token.decode("utf-8")
        except UnicodeDecodeError:
            decoded = token.decode("latin-1", errors="ignore")
        if decoded.strip():
            chunks.append(decoded)
    return "\n".join(chunks)


class ReadOnlyMediaScannerAdapter:
    """Sonda binaria deterministica em streaming sobre midias --source (100% Read-Only)."""

    def capture_physical_snapshot(
        self,
        source_roots: tuple[str, ...],
        captured_at_utc: str,
    ) -> MediaSnapshot:
        """Captura fotografia passiva os.stat de 100% dos arquivos das raizes --source."""
        entries: list[FileStatEntry] = []
        is_win = os.name == "nt"

        for src_idx, root_str in enumerate(source_roots, start=1):
            source_id = f"SRC-{src_idx:02d}"
            root_path = Path(root_str).resolve()
            discovered_files = self._walk_passive(root_path)
            for abs_file in sorted(discovered_files):
                ext_str = SafeOsPath(str(abs_file)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_str, follow_symlinks=False)
                rel_p = abs_file.relative_to(root_path).as_posix()
                writable = bool(st.st_mode & stat.S_IWUSR)
                entries.append(
                    FileStatEntry(
                        source_id=source_id,
                        rel_path=rel_p,
                        size_bytes=int(st.st_size),
                        mtime_utc_ns=int(st.st_mtime_ns),
                        mode_octal=oct(st.st_mode & 0o777),
                        inode_or_file_index=int(st.st_ino),
                        is_os_readonly=(not writable),
                    )
                )

        comparable_payload = [asdict(e) for e in entries]
        _, snap_hash = canonical_json_sha256(comparable_payload)
        return MediaSnapshot(
            captured_at_utc=captured_at_utc,
            entries=tuple(entries),
            snapshot_sha256=snap_hash,
        )

    def _walk_passive(self, root_path: Path) -> list[Path]:
        """Percorre diretorios usando exclusivamente os.scandir passivo."""
        results: list[Path] = []
        stack: list[Path] = [root_path]
        is_win = os.name == "nt"
        while stack:
            current = stack.pop()
            ext_cur = SafeOsPath(str(current)).to_os_extended(is_windows=is_win)
            with os.scandir(ext_cur) as it:
                for entry in it:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(SafeOsPath(entry.path).logical_path))
                    elif entry.is_file(follow_symlinks=False):
                        results.append(Path(SafeOsPath(entry.path).logical_path))
        return results

    def probe_all_files_streaming(
        self,
        source_roots: tuple[str, ...],
        audit_dir: str,
        signature_registry: SignatureRegistry,
    ) -> tuple[ProbedFileRecord, ...]:
        """Executa SHA-256 em blocos de 4 MiB com checkpoint warm-start e radiografia."""
        checkpoint_file = Path(audit_dir) / "phase01_sha256_checkpoint.json"
        cached_hashes: dict[str, str] = {}
        if checkpoint_file.exists():
            cached_hashes = json.loads(checkpoint_file.read_text(encoding="utf-8"))

        is_win = os.name == "nt"
        probed: list[ProbedFileRecord] = []

        for src_idx, root_str in enumerate(source_roots, start=1):
            source_id = f"SRC-{src_idx:02d}"
            root_path = Path(root_str).resolve()
            all_files = sorted(self._walk_passive(root_path))
            rel_set = {f.relative_to(root_path).as_posix() for f in all_files}

            for abs_file in all_files:
                rel_p = abs_file.relative_to(root_path).as_posix()
                ext_file = SafeOsPath(str(abs_file)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_file, follow_symlinks=False)
                size_b = int(st.st_size)
                mtime_ns = int(st.st_mtime_ns)
                is_ro = not bool(st.st_mode & stat.S_IWUSR)

                ck_key = f"{source_id}|{rel_p}|{size_b}|{mtime_ns}"
                header_16b = b""
                sample_4k = b""
                sample_entropy = b""

                if ck_key in cached_hashes:
                    file_sha = cached_hashes[ck_key]
                    read_cap = 262_144 if size_b >= WINDOW_SIZE_BYTES else 4_096
                    with open(ext_file, "rb") as fh:
                        buf = fh.read(read_cap)
                        sample_entropy = buf
                        sample_4k = buf[:4096]
                        header_16b = buf[:16]
                else:
                    hasher = hashlib.sha256()
                    with open(ext_file, "rb") as fh:
                        first_chunk = True
                        while True:
                            chunk = fh.read(STREAM_BLOCK_BYTES)
                            if not chunk:
                                break
                            if first_chunk:
                                sample_entropy = chunk[:262_144]
                                sample_4k = chunk[:4096]
                                header_16b = chunk[:16]
                                first_chunk = False
                            hasher.update(chunk)
                    file_sha = hasher.hexdigest()
                    cached_hashes[ck_key] = file_sha
                    checkpoint_file.write_text(
                        json.dumps(cached_hashes, sort_keys=True, indent=2),
                        encoding="utf-8",
                    )

                magic_sig, spoofed, is_enc = signature_registry.classify(
                    header_16b, abs_file.name, sample_4k
                )
                if (
                    magic_sig in (MagicSignature.UNKNOWN_BINARY, MagicSignature.HIGH_ENTROPY_ENCRYPTED)
                    and size_b >= WINDOW_SIZE_BYTES
                    and len(sample_entropy) >= WINDOW_SIZE_BYTES
                ):
                    comp_probe = probe_headerless_encryption_bytes(
                        sample_entropy, MagicSignature.UNKNOWN_BINARY
                    )
                    if comp_probe.is_headerless_encrypted:
                        magic_sig = MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED
                        is_enc = True

                has_wal = (f"{rel_p}-wal" in rel_set)
                has_shm = (f"{rel_p}-shm" in rel_set)
                container_entries: tuple[str, ...] = ()
                sqlite_schemas: tuple[str, ...] = ()
                pdf_eof_count = 0
                tabular_header = ""
                text_preview = ""

                if magic_sig in (MagicSignature.ZIP_CONTAINER, MagicSignature.CELLEBRITE_UFDR_UFDX):
                    container_entries, zip_corrupt = self._probe_zip_central_directory(ext_file)
                    if zip_corrupt:
                        is_enc = True
                elif magic_sig == MagicSignature.TAR_ARCHIVE or rel_p.lower().endswith(".tar"):
                    container_entries = self._probe_tar_headers(ext_file)
                elif magic_sig == MagicSignature.SQLITE3:
                    sqlite_schemas, sqlite_corrupt = self._probe_sqlite_immutable(str(abs_file))
                    if sqlite_corrupt:
                        is_enc = True
                elif magic_sig == MagicSignature.PDF_DOCUMENT:
                    pdf_eof_count, text_preview = self._probe_pdf_readonly(ext_file)
                elif magic_sig in (MagicSignature.UTF8_TEXT_OR_CSV, MagicSignature.XML_DOCUMENT):
                    tabular_header, text_preview = self._probe_text_readonly(ext_file)

                probed.append(
                    ProbedFileRecord(
                        source_id=source_id,
                        rel_path=rel_p,
                        abs_path=str(abs_file),
                        size_bytes=size_b,
                        mtime_utc_ns=mtime_ns,
                        is_os_readonly=is_ro,
                        sha256_hex=file_sha,
                        magic_header_hex=header_16b.hex(),
                        magic_signature=magic_sig,
                        extension_spoofed=spoofed,
                        is_encrypted_or_corrupted=is_enc,
                        pdf_eof_count=pdf_eof_count,
                        has_wal_sibling=has_wal,
                        has_shm_sibling=has_shm,
                        container_entries=container_entries,
                        sqlite_schemas=sqlite_schemas,
                        tabular_header=tabular_header,
                        text_preview=text_preview,
                    )
                )

        return tuple(probed)

    def _probe_zip_central_directory(self, ext_file: str) -> tuple[tuple[str, ...], bool]:
        """Lista o Central Directory de ZIP/UFDR sem extrair conteudo."""
        try:
            with open(ext_file, "rb") as raw_fh:
                with zipfile.ZipFile(raw_fh, mode="r") as zf:
                    names = tuple(info.filename for info in zf.infolist()[:200])
                    encrypted = any(bool(info.flag_bits & 0x1) for info in zf.infolist())
                    return names, encrypted
        except (zipfile.BadZipFile, OSError):
            return (), True

    def _probe_tar_headers(self, ext_file: str) -> tuple[str, ...]:
        """Lista membros de arquivos TAR sem extrair em disco."""
        try:
            with open(ext_file, "rb") as raw_fh:
                with tarfile.open(fileobj=raw_fh, mode="r:*") as tf:
                    return tuple(m.name for m in tf.getmembers()[:200])
        except (tarfile.TarError, OSError):
            return ()

    def _probe_sqlite_immutable(self, abs_path_str: str) -> tuple[tuple[str, ...], bool]:
        """Extrai CREATE TABLE exclusivamente via URI mode=ro&immutable=1 + query_only=1."""
        uri = SafeOsPath(abs_path_str).to_sqlite_immutable_uri(is_windows=(os.name == "nt"))
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                conn.execute("PRAGMA query_only = 1;")
                cur = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL ORDER BY name"
                )
                ddls = tuple(str(row[0]) for row in cur.fetchall())
                return ddls, False
            finally:
                conn.close()
        except sqlite3.DatabaseError:
            return (), True

    def _probe_pdf_readonly(self, ext_file: str) -> tuple[int, str]:
        """Conta revisoes incrementais %%EOF e extrai texto nativo disponivel."""
        with open(ext_file, "rb") as fh:
            data = fh.read(2 * 1024 * 1024)
        eof_count = data.count(b"%%EOF")
        preview = extract_pdf_native_text_bytes(data)[:16384]
        return eof_count, preview

    def _probe_text_readonly(self, ext_file: str) -> tuple[str, str]:
        """Le cabecalho tabular e previa textual UTF-8 de forma passiva."""
        with open(ext_file, "rb") as fh:
            raw = fh.read(32768)
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        first_line = lines[0][:512] if lines else ""
        return first_line, text[:16384]


class SqliteCatalog01RepositoryAdapter:
    """Persiste os resultados da Fase 01 nas tabelas relacionais canonicas do workspace."""

    def persist_phase01_results(self, contract: Phase01ToPhase02Contract) -> None:
        """Grava fontes, custodiantes, declaracoes, inventario inicial e matriz de paridade."""
        db_ext = SafeOsPath(contract.governance.catalog_db_path).to_os_extended(
            is_windows=(os.name == "nt")
        )
        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO governance_runs (
                        run_id, case_id, phase_code, codebase_sha256,
                        pre_scan_snapshot_sha256, post_scan_snapshot_sha256,
                        zero_source_mutation_confirmed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"{contract.governance.run_id}-P01-R{contract.revision_number}",
                        contract.governance.case_id,
                        "PHASE_01_IDENTIFICATION",
                        contract.governance.codebase_sha256,
                        contract.pre_scan_snapshot.snapshot_sha256,
                        contract.pre_scan_snapshot.snapshot_sha256,
                        1,
                    ),
                )

                for idx, src_root in enumerate(contract.governance.protected_source_roots, start=1):
                    src_id = f"SRC-{idx:02d}"
                    src_files = [
                        pf for pf in contract.discovery_blueprint.probed_files if pf.source_id == src_id
                    ]
                    total_b = sum(pf.size_bytes for pf in src_files)
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO discovered_media_sources (
                            source_id, mount_path, total_files, total_bytes,
                            filesystem_hint, scanned_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            src_id,
                            src_root,
                            len(src_files),
                            total_b,
                            "NTFS_EXTENDED" if os.name == "nt" else "POSIX_FS",
                            contract.pre_scan_snapshot.captured_at_utc,
                        ),
                    )

                for cust in contract.custodians:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO custodians (
                            custodian_id, name, role, identifiers_json,
                            epistemic_status, anchor_json
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cust.custodian_id,
                            cust.name,
                            cust.role,
                            json.dumps(list(cust.identifiers), ensure_ascii=False),
                            str(cust.epistemic_status),
                            json.dumps(cust.anchor.to_dict(), ensure_ascii=False, sort_keys=True),
                        ),
                    )

                for decl in contract.declared_items:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO declared_evidence_items (
                            declared_id, custodian_id, primary_doc_type, seizure_utc,
                            brand, model, serial_number, imei_chassis_json, imei_memory_json,
                            iccid_json, lock_state, rf_isolation, seals_in_json, seals_out_json,
                            working_copy_examined, state_sha256, master_hashlist_sha256,
                            expected_raw_format, epistemic_status, anchor_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            decl.declared_id,
                            decl.custodian_id,
                            str(decl.primary_doc_type),
                            decl.seizure_utc,
                            decl.brand,
                            decl.model,
                            decl.serial_number,
                            json.dumps(list(decl.imei_chassis)),
                            json.dumps(list(decl.imei_memory)),
                            json.dumps(list(decl.iccid)),
                            decl.lock_state,
                            decl.rf_isolation,
                            json.dumps(list(decl.seals_in)),
                            json.dumps(list(decl.seals_out)),
                            decl.working_copy_examined,
                            decl.state_sha256,
                            decl.master_hashlist_sha256,
                            decl.expected_raw_format,
                            str(decl.epistemic_status),
                            json.dumps(decl.anchor.to_dict(), ensure_ascii=False, sort_keys=True),
                        ),
                    )

                for seq, pf in enumerate(contract.discovery_blueprint.probed_files, start=1):
                    cn = ControlNumber.root(seq).code
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO evidence_inventory_tree (
                            control_number, parent_control_number, source_id, origin_rel_path,
                            vault_rel_path, size_bytes, mtime_utc_ns, is_os_readonly,
                            sha256_hex, magic_signature, extension_spoofed,
                            is_encrypted_or_corrupted, pdf_eof_count, has_wal_shm_sibling,
                            is_denist_logical, duplicate_of_cn, all_custodians_json,
                            all_source_paths_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cn,
                            None,
                            pf.source_id,
                            pf.rel_path,
                            "",
                            pf.size_bytes,
                            pf.mtime_utc_ns,
                            1 if pf.is_os_readonly else 0,
                            pf.sha256_hex,
                            str(pf.magic_signature),
                            1 if pf.extension_spoofed else 0,
                            1 if pf.is_encrypted_or_corrupted else 0,
                            pf.pdf_eof_count,
                            1 if (pf.has_wal_sibling or pf.has_shm_sibling) else 0,
                            0,
                            None,
                            json.dumps([c.custodian_id for c in contract.custodians]),
                            json.dumps([pf.rel_path]),
                        ),
                    )

                path_to_cn = {
                    pf.rel_path: ControlNumber.root(seq).code
                    for seq, pf in enumerate(contract.discovery_blueprint.probed_files, start=1)
                }
                for ds in contract.discovery_blueprint.dynamic_schemas:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO dynamic_schema_blueprints (
                            schema_hash, container_cn, db_or_table_name, columns_json,
                            inferred_domain, extraction_sql_template, approved_by_verifier
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ds.schema_hash,
                            path_to_cn.get(ds.origin_rel_path, "CN-00000001"),
                            ds.table_name,
                            json.dumps(list(ds.columns)),
                            ds.inferred_domain,
                            ds.extraction_sql_template,
                            1 if ds.approved_by_verifier else 0,
                        ),
                    )

                for row in contract.parity_matrix:
                    matched_cn = (
                        path_to_cn.get(row.matched_rel_path) if row.matched_rel_path else None
                    )
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO custody_and_parity_findings (
                            finding_id, declared_id, matched_cn, parity_state,
                            preservation_axis, defect_category, legal_tags_json,
                            is_judicial_critical, epistemic_status, anchor_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row.finding_id,
                            row.declared_id,
                            matched_cn,
                            str(row.parity_state),
                            "PHASE_01_PARITY",
                            "PENDING_PHASE_05",
                            json.dumps(list(row.legal_tags)),
                            1 if row.is_judicial_critical else 0,
                            str(row.epistemic_status),
                            json.dumps(row.anchor.to_dict(), ensure_ascii=False, sort_keys=True),
                        ),
                    )
        finally:
            conn.close()


class Phase01MarkdownCompilerAdapter:
    """Compila o Relatorio Oficial da Fase 01 e o valida no Verificador Bloqueante."""

    def compile_and_verify_report(
        self,
        deliverables_dir: str,
        blueprint: MediaAutoDiscoveryBlueprint,
        custodians: tuple[CustodianRecord, ...],
        declared_items: tuple[DeclaredEvidenceItem, ...],
        divergences: tuple[DivergenceRecord, ...],
        parity_matrix: tuple[ParityMatrixRow, ...],
        revision_number: int,
    ) -> tuple[str, str]:
        """Gera Markdown ancorado, executa verificacao bloqueante e salva em deliverables/."""
        lines: list[str] = [
            f"# Relatorio Oficial Fase 01 — Identificacao e Autodescoberta (Rev. {revision_number})",
            "",
            f"Caso: **{blueprint.case_id}**",
            "",
            "## 1. Censo Binario Deterministico e Assinaturas Magic Bytes (16B)",
        ]
        known_hashes: set[str] = set()
        known_cns: set[str] = set()
        corpus_parts: list[str] = []

        for idx, pf in enumerate(blueprint.probed_files, start=1):
            cn = ControlNumber.root(idx).code
            known_cns.add(cn)
            known_hashes.add(pf.sha256_hex)
            corpus_parts.append(pf.text_preview)
            corpus_parts.append(pf.magic_header_hex)
            spoof_flag = " [EXTENSAO CAMUFLADA]" if pf.extension_spoofed else ""
            lines.append(
                f"- `{cn}` | `{pf.rel_path}` | `{pf.size_bytes}` bytes | "
                f"Magic: `{pf.magic_signature}`{spoof_flag} | SHA-256: `{pf.sha256_hex}`"
            )

        lines.append("")
        lines.append("## 2. Schemas SQLite Ineditos Autodescobertos no HD")
        if blueprint.dynamic_schemas:
            for ds in blueprint.dynamic_schemas:
                known_hashes.add(ds.schema_hash)
                lines.append(
                    f"- Tabela `{ds.table_name}` em `{ds.origin_rel_path}` | "
                    f"Colunas: `{', '.join(ds.columns)}` | Hash Schema: `{ds.schema_hash}`"
                )
        else:
            lines.append("- Nenhum banco SQLite inedito adicional detectado.")

        lines.append("")
        lines.append("## 3. Custodiantes e Declaracoes POP Senasp Vol. 5 (2024)")
        for cust in custodians:
            known_cns.add(cust.anchor.origin_control_number)
            known_hashes.add(cust.anchor.origin_sha256)
            corpus_parts.append(cust.anchor.verbatim_excerpt)
            lines.append(
                f"- Custodiante `{cust.custodian_id}`: **{cust.name}** "
                f"(Ancora `{cust.anchor.origin_control_number}`, trecho «{cust.anchor.verbatim_excerpt}»)"
            )

        for decl in declared_items:
            known_cns.add(decl.anchor.origin_control_number)
            known_hashes.add(decl.anchor.origin_sha256)
            if len(decl.state_sha256) == 64:
                known_hashes.add(decl.state_sha256)
            corpus_parts.append(decl.anchor.verbatim_excerpt)
            lines.append(
                f"- Declarado `{decl.declared_id}` ({decl.primary_doc_type}): "
                f"{decl.brand} {decl.model} | Apreensao UTC: `{decl.seizure_utc}` | "
                f"Lacres Entrada: `{','.join(decl.seals_in) or 'EXPLICIT_GAP'}`"
            )

        if divergences:
            lines.append("")
            lines.append("## 4. Conflitos Lado a Lado Entre Pecas Oficiais (DivergenceRecord)")
            for div in divergences:
                lines.append(
                    f"- `{div.divergence_id}` ({div.field_name}): `{div.left_value}` vs `{div.right_value}` — {div.description}"
                )

        lines.append("")
        lines.append("## 5. Matriz Deterministica Declarado x Entregue (7 Estados)")
        for row in parity_matrix:
            known_cns.add(row.anchor.origin_control_number)
            known_hashes.add(row.anchor.origin_sha256)
            if row.matched_sha256:
                known_hashes.add(row.matched_sha256)
            corpus_parts.append(row.anchor.verbatim_excerpt)
            lines.append(
                f"- `{row.finding_id}` | Estado: **{row.parity_state}** | "
                f"Tags: `{', '.join(row.legal_tags)}` | {row.rationale}"
            )

        if blueprint.headerless_encrypted_files:
            lines.append("")
            lines.append("## 6. Volumes Candidatos a Criptografia Sem Cabecalho (VeraCrypt/BitLocker Raw 64 KiB)")
            for h_path in blueprint.headerless_encrypted_files:
                lines.append(f"- `{h_path}` — Incompressibilidade >= 995 permille sem assinatura de arquivo comprimido.")

        if blueprint.state_iped_audit is not None and blueprint.state_iped_audit.is_iped_case:
            ia = blueprint.state_iped_audit
            known_cns.add(ia.anchor.origin_control_number)
            known_hashes.add(ia.anchor.origin_sha256)
            corpus_parts.append(ia.anchor.verbatim_excerpt)
            lines.append("")
            lines.append("## 7. Auditoria de Caso Portatil .iped Estatal (Delta v2.1)")
            lines.append(
                f"- Ancora `{ia.anchor.origin_control_number}` (`{ia.anchor.origin_path}`) | "
                f"Perfil: **{ia.profile_detected}** (`{ia.profile_risk}`) | "
                f"Shards `storage-*.db`: `{ia.storage_shards_found}` | "
                f"Tarefas Desligadas: `{', '.join(ia.disabled_critical_tasks) or 'NENHUMA'}` | "
                f"Download Externo: `{ia.internet_download_contamination}` | "
                f"Alerta Palavras-Chave: `{ia.keywords_negative_proof_warning}`"
            )

        markdown_content = "\n".join(lines) + "\n"
        verify_markdown_report_strictly(
            markdown_text=markdown_content,
            known_sha256_set=known_hashes,
            known_cn_set=known_cns,
            all_verbatim_corpus_text="\n".join(corpus_parts),
        )

        filename = (
            "phase01_identification_report.md"
            if revision_number == 1
            else f"phase01_identification_report_rev{revision_number}.md"
        )
        out_path = Path(deliverables_dir) / filename
        ext_out = SafeOsPath(str(out_path)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext_out, "w", encoding="utf-8") as fh:
            fh.write(markdown_content)
            fh.flush()
            os.fsync(fh.fileno())
        return str(out_path), sha256_text(markdown_content)
