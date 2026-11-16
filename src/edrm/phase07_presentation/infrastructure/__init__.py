"""Infraestrutura fisica da Fase 07 — Exportacao de Quesitos, Anexo Tema 977 e Dossie HTML5."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from edrm.shared_kernel.contracts import CustomQuesitoRecord
from edrm.shared_kernel.value_objects import SafeOsPath, sha256_text


class Phase07PresenterWriterAdapter:
    """Grava os artefatos finais de apresentacao e enumera os hashes de deliverables/."""

    def write_presentation_deliverables(
        self,
        deliverables_dir: str,
        quesitos: tuple[CustomQuesitoRecord, ...],
        tema977_markdown: str,
        offline_html: str,
    ) -> tuple[str, str, str, str, str, tuple[tuple[str, str], ...]]:
        """Escreve com fsync os arquivos de apresentacao e retorna inventario completo."""
        deliv = Path(deliverables_dir)
        q_lines = ["# QUESITOS PERICIAIS ESTRATEGICOS SOB MEDIDA (POP SENASP VOL. 5 / 2024)", ""]
        for q in quesitos:
            q_lines.append(
                f"{q.quesito_number}. **[{q.normative_basis}]** (Ref. `{q.target_anomaly_id}`): {q.question_text}"
            )
        q_md = "\n".join(q_lines) + "\n"

        q_path = deliv / "phase07_quesitos_estrategicos_pop_senasp.md"
        ex_path = deliv / "phase07_anexo_peticao_stf_tema977.md"
        html_path = deliv / "phase07_dossie_interativo_offline.html"

        self._write_fsync(q_path, q_md)
        self._write_fsync(ex_path, tema977_markdown)
        self._write_fsync(html_path, offline_html)

        all_items: list[tuple[str, str]] = []
        for f in sorted(deliv.iterdir()):
            if f.is_file():
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                all_items.append((f.name, digest))

        return (
            str(q_path),
            sha256_text(q_md),
            str(ex_path),
            str(html_path),
            sha256_text(offline_html),
            tuple(all_items),
        )

    def _write_fsync(self, target: Path, content: str) -> None:
        ext = SafeOsPath(str(target)).to_os_extended(is_windows=(os.name == "nt"))
        with open(ext, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
