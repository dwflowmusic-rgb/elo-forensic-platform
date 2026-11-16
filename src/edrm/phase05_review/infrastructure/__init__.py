"""Infraestrutura fisica da Fase 05 — Persistencia de Nulidades e Relatorio de Confronto."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3

from edrm.shared_kernel.contracts import (
    ClassifiedNullityRecord,
    MaterialContradictionRecord,
    Phase04ToPhase05Contract,
    QualityControlSummary,
)
from edrm.shared_kernel.value_objects import SafeOsPath, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly


class Phase05ReviewStoreAdapter:
    """Atualiza categorias de vicio probatorio no SQLite e exporta phase05_review_report.md."""

    def persist_and_export_review(
        self,
        phase04_bundle: Phase04ToPhase05Contract,
        privileged_cns: tuple[str, ...],
        selected_cns: tuple[str, ...],
        contradictions: tuple[MaterialContradictionRecord, ...],
        nullities: tuple[ClassifiedNullityRecord, ...],
        qc_summary: QualityControlSummary,
        frozen_sha256: str,
    ) -> tuple[str, str]:
        """Persiste classificacoes juridicas e valida o relatorio de revisao no Verificador."""
        gov = phase04_bundle.updated_phase01_bundle.governance
        is_win = os.name == "nt"
        db_ext = SafeOsPath(gov.catalog_db_path).to_os_extended(is_windows=is_win)

        conn = sqlite3.connect(db_ext)
        try:
            with conn:
                for nul in nullities:
                    conn.execute(
                        """
                        UPDATE custody_and_parity_findings
                        SET defect_category = ?
                        WHERE finding_id = ?
                        """,
                        (str(nul.category), nul.source_finding_id),
                    )
                known_cns = {
                    str(r[0])
                    for r in conn.execute("SELECT control_number FROM evidence_inventory_tree").fetchall()
                }
                known_hashes = {
                    str(r[0])
                    for r in conn.execute("SELECT sha256_hex FROM evidence_inventory_tree").fetchall()
                }
        finally:
            conn.close()

        known_hashes.add(frozen_sha256)
        for nul in nullities:
            known_cns.add(nul.anchor.origin_control_number)
            known_hashes.add(nul.anchor.origin_sha256)
        for ctr in contradictions:
            known_cns.add(ctr.raw_anchor.origin_control_number)
            known_hashes.add(ctr.raw_anchor.origin_sha256)
            known_cns.add(ctr.state_anchor.origin_control_number)
            known_hashes.add(ctr.state_anchor.origin_sha256)

        corpus = "\n".join(c.text_clean for c in phase04_bundle.anchored_chunks)

        lines: list[str] = [
            "# Relatorio Oficial Fase 05 — Revisao, Confronto Material e Classificacao de Nulidades",
            "",
            f"- Conjunto de Revisao Congelado SHA-256: `{frozen_sha256}`",
            f"- Itens Selecionados: `{len(selected_cns)}` | Isolados por Sigilo OAB: `{len(privileged_cns)}`",
            f"- Controle Estatistico: Cochran=`{qc_summary.cochran_sample_n}` | Elusao=`{qc_summary.elusion_inspected_n}` | Regra do 3 IC95%=`{qc_summary.rule_of_3_upper_bound_pct}`",
            "",
            "## 1. Confronto Material Relatorio Policial / Laudo x Prova Bruta do HD",
        ]
        if contradictions:
            for ctr in contradictions:
                lines.append(
                    f"- `{ctr.contradiction_id}` ({ctr.contradiction_type}) em `{ctr.raw_anchor.origin_control_number}`: "
                    f"{ctr.legal_impact} | Contexto Vizinho Recuperado: `{ctr.omitted_neighbor_context}`"
                )
        else:
            lines.append("- Nenhuma contradicao direta entre laudo e prova bruta detectada.")

        lines.append("")
        lines.append("## 2. Classificacao Juridica dos Vicios Probatorios")
        for nul in nullities:
            lines.append(
                f"- `{nul.nullity_id}` | Categoria: **{nul.category}** | "
                f"Base Legal: `{', '.join(nul.legal_articles)}` | {nul.description}"
            )

        md = "\n".join(lines) + "\n"
        verify_markdown_report_strictly(md, known_hashes, known_cns, corpus)

        out_path = Path(gov.deliverables_dir) / "phase05_review_report.md"
        ext_out = SafeOsPath(str(out_path)).to_os_extended(is_windows=is_win)
        with open(ext_out, "w", encoding="utf-8") as fh:
            fh.write(md)
            fh.flush()
            os.fsync(fh.fileno())
        return str(out_path), sha256_text(md)
