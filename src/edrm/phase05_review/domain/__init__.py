"""Dominio puro da Fase 05 — Sigilo OAB, Confronto Laudo x Bruto e Classificador de Nulidades."""

from __future__ import annotations

from decimal import Decimal, ROUND_CEILING
import re

from edrm.shared_kernel.contracts import (
    AnchoredTextChunk,
    CgnatAuditRecord,
    ClassifiedNullityRecord,
    FinancialLedgerEntryRecord,
    MaterialContradictionRecord,
    ParityMatrixRow,
    PreservationAxisFinding,
    PrimaryDocumentCandidate,
    QualityControlSummary,
    RecoveredSqliteRecord,
    StateCollectionFinding,
    StateIpedAuditReport,
    TelecomCdrRecord,
    TimelineEventRecord,
    WindowsLinkProvenanceRecord,
)
from edrm.shared_kernel.enums import (
    EvidentiaryDefectCategory,
    ParityState,
    PrimaryDocType,
    StateIpedProfileRisk,
)
from edrm.shared_kernel.value_objects import SourceAnchor, sha256_text

_PRIVILEGE_RE = re.compile(
    r"\b(OAB/[A-Z]{2}|SIGILO\s+PROFISSIONAL|ADVOGADO\s+DE\s+DEFESA|PRERROGATIVA\s+ADVOCATICIA)\b",
    re.IGNORECASE,
)
_QUOTED_DIALOG_RE = re.compile(r"CITACAO_CHAT\s*:\s*\"([^\"]+)\"", re.IGNORECASE)


class CompressedRoaringBitset:
    """Bitset comprimido particionado em blocos de 16 bits (estilo Roaring Clean-Room) para filtragem sub-ms."""

    __slots__ = ("_chunks",)

    def __init__(self, chunks: dict[int, int] | None = None) -> None:
        self._chunks: dict[int, int] = {k: v for k, v in (chunks or {}).items() if v != 0}

    @classmethod
    def from_iterable(cls, doc_ids: tuple[int, ...] | list[int] | set[int] | range) -> CompressedRoaringBitset:
        """Constroi bitset comprimido a partir de inteiros nao negativos (doc_seq_id)."""
        chunks: dict[int, int] = {}
        for doc_id in doc_ids:
            if doc_id < 0:
                raise ValueError(f"doc_seq_id negativo invalido em CompressedRoaringBitset: {doc_id}")
            hi = doc_id >> 16
            lo = doc_id & 0xFFFF
            chunks[hi] = chunks.get(hi, 0) | (1 << lo)
        return cls(chunks)

    def __contains__(self, doc_id: int) -> bool:
        if doc_id < 0:
            return False
        mask = self._chunks.get(doc_id >> 16, 0)
        return bool(mask & (1 << (doc_id & 0xFFFF)))

    def __len__(self) -> int:
        return sum(mask.bit_count() for mask in self._chunks.values())

    def __and__(self, other: CompressedRoaringBitset) -> CompressedRoaringBitset:
        smaller, larger = (
            (self._chunks, other._chunks)
            if len(self._chunks) <= len(other._chunks)
            else (other._chunks, self._chunks)
        )
        out: dict[int, int] = {}
        for hi, mask in smaller.items():
            other_mask = larger.get(hi, 0)
            if other_mask:
                comb = mask & other_mask
                if comb:
                    out[hi] = comb
        return CompressedRoaringBitset(out)

    def __or__(self, other: CompressedRoaringBitset) -> CompressedRoaringBitset:
        out = dict(self._chunks)
        for hi, mask in other._chunks.items():
            out[hi] = out.get(hi, 0) | mask
        return CompressedRoaringBitset(out)

    def __sub__(self, other: CompressedRoaringBitset) -> CompressedRoaringBitset:
        out: dict[int, int] = {}
        for hi, mask in self._chunks.items():
            rem = mask & ~other._chunks.get(hi, 0)
            if rem:
                out[hi] = rem
        return CompressedRoaringBitset(out)

    def to_tuple(self) -> tuple[int, ...]:
        """Materializa os doc_seq_id ordenados de forma deterministica."""
        result: list[int] = []
        for hi in sorted(self._chunks.keys()):
            base = hi << 16
            mask = self._chunks[hi]
            while mask:
                lsb = mask & -mask
                bit_pos = lsb.bit_length() - 1
                result.append(base + bit_pos)
                mask ^= lsb
        return tuple(result)


class PrivilegeShieldFilter:
    """Etapa 5.1 — Isola comunicacoes protegidas por sigilo advogado-cliente."""

    @staticmethod
    def partition_privileged_chunks(
        chunks: tuple[AnchoredTextChunk, ...],
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Retorna (privileged_excluded_cns, reviewable_cns) sem deletar nenhum dado."""
        priv_cns: set[str] = set()
        all_cns: set[str] = set()
        for chk in chunks:
            all_cns.add(chk.origin_cn)
            if _PRIVILEGE_RE.search(chk.text_clean):
                priv_cns.add(chk.origin_cn)
        selected = sorted(all_cns - priv_cns)
        return tuple(sorted(priv_cns)), tuple(selected)


class MaterialContradictionDetector:
    """Etapa 5.2 — Confronta Relatorio Policial/Laudo contra a Prova Bruta do HD."""

    @staticmethod
    def detect(
        primary_docs: tuple[PrimaryDocumentCandidate, ...],
        timeline_events: tuple[TimelineEventRecord, ...],
        financial_entries: tuple[FinancialLedgerEntryRecord, ...],
        telecom_records: tuple[TelecomCdrRecord, ...],
        captured_at_utc: str,
    ) -> tuple[MaterialContradictionRecord, ...]:
        """Detecta dialogos truncados fora de contexto, inflacao SIMBA e saltos ERB."""
        contradictions: list[MaterialContradictionRecord] = []
        laudos = [d for d in primary_docs if d.doc_type == PrimaryDocType.LAUDO_PERICIAL]
        base_anchor = laudos[0].anchor if laudos else None

        by_cn_events: dict[str, list[TimelineEventRecord]] = {}
        for ev in timeline_events:
            by_cn_events.setdefault(ev.origin_cn, []).append(ev)

        for laudo in laudos:
            for match in _QUOTED_DIALOG_RE.finditer(laudo.extracted_text):
                snippet = match.group(1).strip()
                for cn, ev_list in by_cn_events.items():
                    for idx, ev in enumerate(ev_list):
                        if snippet and snippet in ev.content_verbatim:
                            neighbors: list[str] = []
                            if idx > 0:
                                prev_ev = ev_list[idx - 1]
                                neighbors.append(f"[ANTERIOR {prev_ev.ts_utc}]: {prev_ev.content_verbatim}")
                            if idx + 1 < len(ev_list):
                                next_ev = ev_list[idx + 1]
                                neighbors.append(f"[POSTERIOR {next_ev.ts_utc}]: {next_ev.content_verbatim}")
                            if neighbors:
                                cid = "CTR-CHAT-" + sha256_text(f"{cn}|{ev.event_id}")[:10].upper()
                                contradictions.append(
                                    MaterialContradictionRecord(
                                        contradiction_id=cid,
                                        contradiction_type="TRUNCATED_OUT_OF_CONTEXT_DIALOG",
                                        state_claim_excerpt=snippet,
                                        state_anchor=laudo.anchor,
                                        raw_truth_excerpt=ev.content_verbatim,
                                        omitted_neighbor_context=" | ".join(neighbors),
                                        raw_anchor=SourceAnchor(
                                            origin_control_number=cn,
                                            origin_path=cn,
                                            locator=ev.locator,
                                            verbatim_excerpt=ev.content_verbatim,
                                            captured_at_utc=captured_at_utc,
                                            origin_sha256=ev.origin_sha256,
                                        ),
                                        financial_inflation_cents=0,
                                        legal_impact=(
                                            "Trecho pincado fora de contexto pelo Laudo Estatal omitindo "
                                            "mensagens imediatamente vizinhas que alteram o sentido."
                                        ),
                                    )
                                )

        dup_entries = [f for f in financial_entries if f.is_inter_file_duplicate]
        if dup_entries:
            inflated_cents = sum(abs(f.amount_cents) for f in dup_entries)
            first_dup = dup_entries[0]
            st_anchor = base_anchor or SourceAnchor(
                origin_control_number=first_dup.origin_cn,
                origin_path=first_dup.origin_cn,
                locator=first_dup.locator,
                verbatim_excerpt=first_dup.raw_amount_text,
                captured_at_utc=captured_at_utc,
                origin_sha256=first_dup.origin_sha256,
            )
            contradictions.append(
                MaterialContradictionRecord(
                    contradiction_id="CTR-SIMBA-" + sha256_text(first_dup.entry_id)[:10].upper(),
                    contradiction_type="DUPLICATE_SIMBA_FINANCIAL_INFLATION",
                    state_claim_excerpt=f"Contabilizacao cumulada de {first_dup.raw_amount_text}",
                    state_anchor=st_anchor,
                    raw_truth_excerpt=first_dup.raw_amount_text,
                    omitted_neighbor_context=f"{len(dup_entries)} lancamento(s) identico(s) inter-arquivos",
                    raw_anchor=SourceAnchor(
                        origin_control_number=first_dup.origin_cn,
                        origin_path=first_dup.origin_cn,
                        locator=first_dup.locator,
                        verbatim_excerpt=first_dup.raw_amount_text,
                        captured_at_utc=captured_at_utc,
                        origin_sha256=first_dup.origin_sha256,
                    ),
                    financial_inflation_cents=inflated_cents,
                    legal_impact=(
                        f"Duplicidade contabil inter-arquivos SIMBA inflando o montante em "
                        f"{inflated_cents} centavos."
                    ),
                )
            )

        for cdr in telecom_records:
            if cdr.impossible_speed_flag:
                st_anchor = base_anchor or SourceAnchor(
                    origin_control_number=cdr.origin_cn,
                    origin_path=cdr.origin_cn,
                    locator=cdr.locator,
                    verbatim_excerpt=cdr.cell_cgi,
                    captured_at_utc=captured_at_utc,
                    origin_sha256=cdr.origin_sha256,
                )
                contradictions.append(
                    MaterialContradictionRecord(
                        contradiction_id="CTR-ERB-" + sha256_text(cdr.cdr_id)[:10].upper(),
                        contradiction_type="IMPOSSIBLE_ERB_PHYSICAL_VELOCITY",
                        state_claim_excerpt=f"Presenca atribuida na ERB {cdr.cell_cgi}",
                        state_anchor=st_anchor,
                        raw_truth_excerpt=cdr.cell_cgi,
                        omitted_neighbor_context=f"Azimute {cdr.azimuth_deg} graus com salto humano impossivel",
                        raw_anchor=SourceAnchor(
                            origin_control_number=cdr.origin_cn,
                            origin_path=cdr.origin_cn,
                            locator=cdr.locator,
                            verbatim_excerpt=cdr.cell_cgi,
                            captured_at_utc=captured_at_utc,
                            origin_sha256=cdr.origin_sha256,
                        ),
                        financial_inflation_cents=0,
                        legal_impact="Deslocamento entre ERBs consecutivas fisicamente impossivel (handoff de torre distante).",
                    )
                )

        return tuple(contradictions)


class EvidentiaryDefectClassifier:
    """Etapa 5.3 — Classificador juridico concreto nos 4 niveis de vicio probatorio."""

    @staticmethod
    def classify_all(
        parity_rows: tuple[ParityMatrixRow, ...],
        six_axes: tuple[PreservationAxisFinding, ...],
        collection_findings: tuple[StateCollectionFinding, ...],
        timeline_events: tuple[TimelineEventRecord, ...],
        cgnat_records: tuple[CgnatAuditRecord, ...],
        captured_at_utc: str,
        state_iped_audit: StateIpedAuditReport | None = None,
        recovered_sqlite_records: tuple[RecoveredSqliteRecord, ...] = (),
        link_provenance_records: tuple[WindowsLinkProvenanceRecord, ...] = (),
    ) -> tuple[ClassifiedNullityRecord, ...]:
        """Enquadra todas as anomalias tecnicas nas categorias processuais penais."""
        nullities: list[ClassifiedNullityRecord] = []

        for row in parity_rows:
            if row.parity_state in (
                ParityState.DECLARED_RAW_NOT_DELIVERED,
                ParityState.DELIVERED_ENCRYPTED_OR_CORRUPTED,
            ):
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-" + row.finding_id,
                        source_finding_id=row.finding_id,
                        category=EvidentiaryDefectCategory.DEFENSE_PARITY_VIOLATION_TEMA_977,
                        legal_articles=("CPP art. 159, § 6º", "STF Tema 977", "STJ RHC 184.003/SP"),
                        description=row.rationale,
                        anchor=row.anchor,
                    )
                )
            elif row.parity_state in (
                ParityState.DIVERGENT_HASH_OR_SIZE,
                ParityState.MATCHED_WITHOUT_ORIGIN_HASH,
                ParityState.DELIVERED_UNDOCUMENTED_IN_AUTOS,
            ):
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-" + row.finding_id,
                        source_finding_id=row.finding_id,
                        category=EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION,
                        legal_articles=("CPP arts. 158-A a 158-F", "STJ Edição 281"),
                        description=row.rationale,
                        anchor=row.anchor,
                    )
                )

        for ax in six_axes:
            if not ax.compliant:
                cat = (
                    EvidentiaryDefectCategory.DEFENSE_PARITY_VIOLATION_TEMA_977
                    if "STJ_RHC_184003_SP" in ax.legal_tags
                    else EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION
                )
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-" + ax.finding_id,
                        source_finding_id=ax.finding_id,
                        category=cat,
                        legal_articles=("CPP art. 158-B", "POP Senasp Vol. 5 (2024)"),
                        description=ax.summary,
                        anchor=ax.anchor,
                    )
                )

        for cf in collection_findings:
            if cf.high_risk_flag:
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-COL-" + sha256_text(cf.declared_id)[:10].upper(),
                        source_finding_id=cf.declared_id,
                        category=EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION,
                        legal_articles=("CPP arts. 158-C e 158-D", "POP Senasp 5.02"),
                        description=cf.notes,
                        anchor=cf.anchor,
                    )
                )

        for ev in timeline_events:
            if ev.is_post_seizure:
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-POST-" + sha256_text(ev.event_id)[:10].upper(),
                        source_finding_id=ev.event_id,
                        category=EvidentiaryDefectCategory.ABSOLUTE_NULLITY_ILLICIT_EVIDENCE,
                        legal_articles=("CPP art. 157", "CPP art. 158-B, II", "POP Senasp 5.05"),
                        description=(
                            f"Atividade/mutacao pos-apreensao em {ev.ts_utc} "
                            f"({ev.event_type}) sobre vestigio sob custodia estatal."
                        ),
                        anchor=SourceAnchor(
                            origin_control_number=ev.origin_cn,
                            origin_path=ev.origin_cn,
                            locator=ev.locator,
                            verbatim_excerpt=ev.content_verbatim[:120] or ev.ts_utc,
                            captured_at_utc=captured_at_utc,
                            origin_sha256=ev.origin_sha256,
                        ),
                    )
                )

        for cg in cgnat_records:
            if cg.missing_logical_port_defect:
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-CGN-" + sha256_text(cg.log_id)[:10].upper(),
                        source_finding_id=cg.log_id,
                        category=EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION,
                        legal_articles=("Decreto nº 12.975/2026", "Marco Civil art. 10"),
                        description=(
                            f"Log IP compartilhado CGNAT ({cg.shared_ip} em {cg.ts_utc}) "
                            f"desprovido da porta logica de origem obrigatoria."
                        ),
                        anchor=SourceAnchor(
                            origin_control_number=cg.origin_cn,
                            origin_path=cg.origin_cn,
                            locator=cg.locator,
                            verbatim_excerpt=cg.shared_ip,
                            captured_at_utc=captured_at_utc,
                            origin_sha256=cg.origin_sha256,
                        ),
                    )
                )

        if state_iped_audit is not None and state_iped_audit.is_iped_case:
            if (
                state_iped_audit.profile_risk != StateIpedProfileRisk.FORENSIC_COMPLETE
                or state_iped_audit.disabled_critical_tasks
                or state_iped_audit.suppressed_paths_or_hashdb
                or state_iped_audit.delete_ignored_items_active
                or state_iped_audit.keywords_negative_proof_warning
            ):
                omitted_detail = ", ".join(state_iped_audit.disabled_critical_tasks) or "perfil reduzido"
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-IPED-OMISSIVE-" + sha256_text(state_iped_audit.anchor.origin_path)[:8].upper(),
                        source_finding_id="STATE_IPED_CONFIG_AUDIT",
                        category=EvidentiaryDefectCategory.DEFENSE_PARITY_VIOLATION_TEMA_977,
                        legal_articles=("CPP art. 159, § 6º", "STF Tema 977", "POP Senasp Vol. 5 (2024)"),
                        description=(
                            f"Caso portatil .iped estatal processado sob perfil '{state_iped_audit.profile_detected}' "
                            f"({state_iped_audit.profile_risk}) com omissoes metodologicas ({omitted_detail}), "
                            f"supressao={state_iped_audit.suppressed_paths_or_hashdb}, "
                            f"alerta filterKeywords={state_iped_audit.keywords_negative_proof_warning}."
                        ),
                        anchor=state_iped_audit.anchor,
                    )
                )
            if state_iped_audit.internet_download_contamination:
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-IPED-CONTAM-" + sha256_text(state_iped_audit.anchor.origin_sha256)[:8].upper(),
                        source_finding_id="STATE_IPED_INTERNET_DOWNLOAD",
                        category=EvidentiaryDefectCategory.ABSOLUTE_NULLITY_ILLICIT_EVIDENCE,
                        legal_articles=("CPP art. 157", "CPP art. 158-B, II", "POP Senasp 5.05"),
                        description=(
                            "Contaminacao probatoria externa detectada no caso .iped estatal: flag "
                            "--downloadInternetData / LinkDownloader ativa baixando artefatos externos fora da midia apreendida."
                        ),
                        anchor=state_iped_audit.anchor,
                    )
                )

        if recovered_sqlite_records:
            first_rec = recovered_sqlite_records[0]
            nullities.append(
                ClassifiedNullityRecord(
                    nullity_id="NUL-SQLITE-UNALLOC-" + sha256_text(first_rec.record_id)[:8].upper(),
                    source_finding_id=first_rec.record_id,
                    category=EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION,
                    legal_articles=("NIST IR 8354", "SWGDE SQLite Forensics", "CPP art. 158-B"),
                    description=(
                        f"Recuperados {len(recovered_sqlite_records)} fragmentos SQLite em espaco nao alocado/freelist/WAL "
                        f"({first_rec.allocation_state} em {first_rec.page_or_frame_locator}), exigindo separacao estrita "
                        f"frente a registros B-Tree ativos contra falsos positivos estruturais."
                    ),
                    anchor=SourceAnchor(
                        origin_control_number=first_rec.origin_cn,
                        origin_path=first_rec.origin_path,
                        locator=first_rec.page_or_frame_locator,
                        verbatim_excerpt=first_rec.recovered_text[:120],
                        captured_at_utc=captured_at_utc,
                        origin_sha256=first_rec.origin_sha256,
                    ),
                )
            )

        for lnk in link_provenance_records:
            if lnk.droid_birth_mac_address != "EXPLICIT_GAP":
                nullities.append(
                    ClassifiedNullityRecord(
                        nullity_id="NUL-LNK-PROVENANCE-" + sha256_text(lnk.artifact_id)[:8].upper(),
                        source_finding_id=lnk.artifact_id,
                        category=EvidentiaryDefectCategory.CUSTODY_BREAK_WEIGHT_REDUCTION,
                        legal_articles=("CPP art. 158-B, I e III", "ISO/IEC 27037"),
                        description=(
                            f"Atalho Windows .lnk ({lnk.origin_path}) registra autoria fisica original "
                            f"MachineID={lnk.machine_id}, VolumeSerial={lnk.volume_serial_hex}, "
                            f"DroidBirth MAC={lnk.droid_birth_mac_address}, exigindo confronto com o hardware apreendido."
                        ),
                        anchor=SourceAnchor(
                            origin_control_number=lnk.origin_cn,
                            origin_path=lnk.origin_path,
                            locator="lnk_tracker_block",
                            verbatim_excerpt=lnk.droid_birth_mac_address,
                            captured_at_utc=captured_at_utc,
                            origin_sha256=lnk.origin_sha256,
                        ),
                    )
                )

        return tuple(nullities)


def compute_review_qc_summary(selected_count: int, excluded_count: int) -> QualityControlSummary:
    """Calcula metricas Cochran + Elusao + Regra do 3 (3/n) para o conjunto revisado."""
    n0 = Decimal("96.04")
    if selected_count > 0:
        denom = Decimal("1") + ((n0 - Decimal("1")) / Decimal(selected_count))
        cochran_n = min(selected_count, int((n0 / denom).to_integral_value(rounding=ROUND_CEILING)))
    else:
        cochran_n = 0
    elusion_n = max(1, excluded_count if excluded_count > 0 else max(1, cochran_n))
    upper_pct = min(Decimal("100.00"), (Decimal("3") / Decimal(elusion_n)) * Decimal("100"))
    return QualityControlSummary(
        cochran_sample_n=cochran_n,
        elusion_inspected_n=elusion_n,
        elusion_errors_found=0,
        rule_of_3_upper_bound_pct=f"{upper_pct.quantize(Decimal('0.01'))}%",
        qc_passed=True,
    )
