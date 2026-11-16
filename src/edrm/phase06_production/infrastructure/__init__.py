"""Infraestrutura fisica da Fase 06 — Dupla Passagem no Verificador, Load Files e ICP-Brasil."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3

from edrm.shared_kernel.contracts import Phase05ToPhase06Contract
from edrm.shared_kernel.value_objects import SafeOsPath, canonical_json_sha256, sha256_text
from edrm.shared_kernel.verifier_primitives import verify_markdown_report_strictly


class Phase06DeliverablesWriterAdapter:
    """Executa dupla passagem no Verificador Bloqueante e grava parecer, load files e ICP."""

    def verify_double_pass_and_write(
        self,
        bundle: Phase05ToPhase06Contract,
        opinion_markdown: str,
        repro_script: str,
        concordance_dat: str,
        edrm_xml: str,
        issued_at_utc: str,
    ) -> tuple[str, str, str, str, str, str, str]:
        """Valida antes da escrita e revalida apos releitura fria do disco."""
        p04 = bundle.phase04_bundle
        p01 = p04.updated_phase01_bundle
        gov = p01.governance
        is_win = os.name == "nt"

        db_ext = SafeOsPath(gov.catalog_db_path).to_os_extended(is_windows=is_win)
        conn = sqlite3.connect(db_ext)
        try:
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

        for nul in bundle.classified_nullities:
            known_cns.add(nul.anchor.origin_control_number)
            known_hashes.add(nul.anchor.origin_sha256)
        known_hashes.update(
            {
                gov.codebase_sha256,
                p01.pre_scan_snapshot.snapshot_sha256,
                gov.calibration_receipt.calibration_sha256,
                bundle.frozen_review_sha256,
                p04.phase03_bundle.icp_manifest_sha256,
            }
        )
        corpus_parts = [chk.text_clean for chk in p04.anchored_chunks] + [
            ev.content_verbatim for ev in p04.timeline_events
        ]
        full_corpus = "\n".join(corpus_parts)

        verify_markdown_report_strictly(opinion_markdown, known_hashes, known_cns, full_corpus)

        deliv = Path(gov.deliverables_dir)
        op_path = deliv / "phase06_parecer_tecnico_7_blocos.md"
        repro_path = deliv / "phase06_reproducao_independente.sh"
        dat_path = deliv / "phase06_loadfile_concordance.dat"
        xml_path = deliv / "phase06_loadfile_edrm.xml"
        icp_path = deliv / "phase06_icp_brasil_detached_signature_manifest.json"

        self._write_fsync(op_path, opinion_markdown)
        self._write_fsync(repro_path, repro_script)
        self._write_fsync(dat_path, concordance_dat)
        self._write_fsync(xml_path, edrm_xml)

        cold_opinion = op_path.read_text(encoding="utf-8")
        verify_markdown_report_strictly(cold_opinion, known_hashes, known_cns, full_corpus)

        op_sha = sha256_text(cold_opinion)
        repro_sha = sha256_text(repro_path.read_text(encoding="utf-8"))
        dat_sha = sha256_text(dat_path.read_text(encoding="utf-8"))
        xml_sha = sha256_text(xml_path.read_text(encoding="utf-8"))

        icp_obj = {
            "case_id": gov.case_id,
            "issued_at_utc": issued_at_utc,
            "standard": "ICP-Brasil_CAdES_PAdES_Detached_Ready",
            "artifacts": {
                "parecer_7_blocos_sha256": op_sha,
                "reproducao_sh_sha256": repro_sha,
                "concordance_dat_sha256": dat_sha,
                "edrm_xml_sha256": xml_sha,
            },
        }
        _, icp_sig = canonical_json_sha256(icp_obj)
        icp_obj["manifest_sha256"] = icp_sig
        self._write_fsync(icp_path, json.dumps(icp_obj, ensure_ascii=False, indent=2, sort_keys=True))

        return (
            str(op_path),
            op_sha,
            str(repro_path),
            repro_sha,
            str(dat_path),
            str(xml_path),
            str(icp_path),
        )

    def _write_fsync(self, target: Path, text: str) -> None:
        ext = SafeOsPath(str(target)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
