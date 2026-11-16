"""Dominio puro da Fase 06 — Parecer Pericial nos 7 Blocos, Protocolo de Reproducao e Load Files."""

from __future__ import annotations

from xml.sax.saxutils import escape as xml_escape

from edrm.shared_kernel.contracts import Phase05ToPhase06Contract
from edrm.shared_kernel.value_objects import CentsAmount

CONCORDANCE_DELIM: str = "\x14"
CONCORDANCE_QUOTE: str = "\xfe"


class SevenBlockExpertOpinionBuilder:
    """Etapa 6.1 — Compilador deterministico do Parecer Tecnico Defensivo nos 7 Blocos Oficiais."""

    @staticmethod
    def compile_opinion_and_repro_script(
        bundle: Phase05ToPhase06Contract,
        issued_at_utc: str,
    ) -> tuple[str, str]:
        """Retorna (parecer_7_blocos_markdown, script_reproducao_independente_sh)."""
        p04 = bundle.phase04_bundle
        p03 = p04.phase03_bundle
        p01 = p04.updated_phase01_bundle
        gov = p01.governance

        repro_lines: list[str] = [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            f"# Protocolo Deterministico de Reproducao Independente (ISO/IEC 27042) — Caso {gov.case_id}",
            f"# Emitido em UTC: {issued_at_utc}",
            "",
            "# 1. Conferencia de Mesmidade SHA-256 em blocos sobre a midia acautelada:",
        ]
        for ve in p03.vault_entries:
            repro_lines.append(
                f"# Esperado {ve.control_number} ({ve.origin_rel_path}): {ve.vault_cold_sha256}"
            )
            repro_lines.append(f'sha256sum "$SOURCE_ROOT/{ve.origin_rel_path}"')

        repro_lines.extend(
            [
                "",
                "# 2. Consulta SQLite Estritamente Imutavel (ISO/IEC 27037):",
                '# sqlite3 "file:$SOURCE_ROOT/<banco.db>?mode=ro&immutable=1" "PRAGMA query_only=1; PRAGMA quick_check;"',
            ]
        )
        for ds in p01.discovery_blueprint.dynamic_schemas:
            repro_lines.append(
                f'# sqlite3 "file:$SOURCE_ROOT/{ds.origin_rel_path}?mode=ro&immutable=1" '
                f'"PRAGMA query_only=1; {ds.extraction_sql_template};"'
            )
        repro_script = "\n".join(repro_lines) + "\n"

        blocks: list[str] = [
            "# PARECER TECNICO PERICIAL DE INFORMÁTICA FORENSE (EDRM 2.0 / CPP ART. 159, §§ 5º E 6º)",
            "",
            "## BLOCO 1 — PREAMBULO, IDENTIFICACAO PROCESSUAL E DELIMITACAO DO ESCOPO",
            f"- Caso Identificador: **{gov.case_id}** | Execucao Auditada: `{gov.run_id}`",
            f"- Nivel de Sigilo: `{gov.secrecy_level}` | Emitido em UTC: `{issued_at_utc}`",
            f"- Codigo-Fonte Auditado SHA-256: `{gov.codebase_sha256}`",
            f"- Linha de Base Fisica PreScanSnapshot SHA-256: `{p01.pre_scan_snapshot.snapshot_sha256}`",
            "",
            "## BLOCO 2 — INVENTARIO CRIPTOGRAFICO DAS MIDIAS RECEBIDAS E CADEIA DE CUSTODIA DEFENSIVA",
        ]
        for ve in p03.vault_entries:
            blocks.append(
                f"- `{ve.control_number}` | Origem: `{ve.origin_rel_path}` | `{ve.size_bytes}` bytes | "
                f"SHA-256 Verificado a Frio: `{ve.vault_cold_sha256}` | Cofre Read-Only: `{ve.vault_locked_readonly}`"
            )

        blocks.extend(
            [
                "",
                "## BLOCO 3 — METODOLOGIA CIENTIFICA, CALIBRACAO ISO/IEC 27041 E FERRAMENTAS AUDITAVEIS",
                "- Fronteira Normativa Estrita: O fluxo de fases adota o modelo publico **EDRM 2.0** (CC BY 4.0 EDRM.net, versao 01/09/2026) reconectado ao **IGRM v4.1 (versao vigente oficial do EDRM)**, tratando as especificacoes EDRM Processing 1.0–5.0 como piso funcional flexivel (*floor, not a ceiling*) expandido pelas filas de dependencia P0->P4; os enquadramentos de cadeia de custodia e paridade de armas constituem engenharia juridico-pericial propria da Plataforma ELO sob o Processo Penal Brasileiro (CPP arts. 158-A a 158-F e art. 159, §§ 5º e 6º; POP Senasp Vol. 5 — 2024; NIST IR 8354; NIST SP 800-218 SSDF v1.1).",
                f"- Recibo de Auto-Calibracao ISO/IEC 27041 SHA-256: `{gov.calibration_receipt.calibration_sha256}`",
                f"- Controle Positivo Aprovado: `{gov.calibration_receipt.positive_control_passed}` | "
                f"Bloqueio Mutacao Numerica: `{gov.calibration_receipt.negative_numeric_mutation_blocked}` | "
                f"Bloqueio Entidade Fantasma: `{gov.calibration_receipt.negative_phantom_entity_blocked}`",
                f"- Controle Estatistico Cochran (95%, ±10%): `{bundle.qc_summary.cochran_sample_n}` | "
                f"Elusao: `{bundle.qc_summary.elusion_inspected_n}` | Limite Regra do 3 (3/n): `{bundle.qc_summary.rule_of_3_upper_bound_pct}`",
                "",
                "## BLOCO 4 — EXAME DE INTEGRALIDADE, MATRIZ DECLARADO X ENTREGUE E EXCECOES TECNICAS",
            ]
        )
        for row in p01.parity_matrix:
            blocks.append(
                f"- `{row.finding_id}` | Estado: **{row.parity_state}** | "
                f"Enquadramento: `{', '.join(row.legal_tags)}` | {row.rationale}"
            )
        if p04.dead_letter_items:
            for dl in p04.dead_letter_items:
                blocks.append(
                    f"- Excecao Tecnica `{dl.control_number}` (`{dl.rel_path}`): `{dl.reason_code}` — {dl.detail}"
                )

        blocks.extend(
            [
                "",
                "## BLOCO 5 — ACHADOS PERICIAIS MEDIDOS, LINHAS DO TEMPO UTC E CONFRONTO COM O LAUDO ESTATAL",
                f"- Eventos Totais em Linha do Tempo UTC: `{len(p04.timeline_events)}`",
                f"- Eventos Detectados APOS o Horario Oficial da Apreensao: `{p04.post_seizure_events_count}`",
                f"- Documentos PDF com Multiplas Revisoes Incrementais (%%EOF > 1): `{p04.pdf_multi_eof_count}`",
                f"- Duplicidades Contabeis SIMBA Inter-Arquivos: `{p04.financial_duplicates_count}`",
                f"- Logs CGNAT Desprovidos de Porta Logica (Decreto 12.975/2026): `{p04.cgnat_missing_port_count}`",
                f"- Fragmentos SQLite Recuperados Fora da B-Tree Ativa (NIST IR 8354): `{p04.recovered_deleted_sqlite_rows_count}`",
                f"- Artefatos Fisicos Windows .lnk Rastreados (DroidBirth MAC): `{p04.physical_link_tracker_findings_count}`",
            ]
        )
        for ev in p04.timeline_events:
            if ev.is_post_seizure:
                blocks.append(
                    f"- [POS-APREENSAO] `{ev.origin_cn}` em `{ev.ts_utc}` ({ev.locator}): "
                    f"trecho literal «{ev.content_verbatim}» (SHA-256: `{ev.origin_sha256}`)"
                )
        for ctr in bundle.material_contradictions:
            infl_txt = (
                f" | Inflacao Medida: {CentsAmount(ctr.financial_inflation_cents).format_brl()}"
                if ctr.financial_inflation_cents > 0
                else ""
            )
            blocks.append(
                f"- [CONTRADICAO `{ctr.contradiction_id}`] `{ctr.contradiction_type}` em "
                f"`{ctr.raw_anchor.origin_control_number}`: {ctr.legal_impact}{infl_txt}"
            )

        blocks.extend(
            [
                "",
                "## BLOCO 6 — PROTOCOLO EXATO DE REPRODUCAO INDEPENDENTE (ISO/IEC 27042)",
                "Qualquer perito oficial ou assistente tecnico obtera exatamente os mesmos hashes e registros executando:",
                "```bash",
                repro_script.strip(),
                "```",
                "",
                "## BLOCO 7 — CONCLUSAO TECNICA, ENQUADRAMENTO DE VICIOS E MANIFESTO ICP-BRASIL",
                f"- Conjunto Congelado de Revisao SHA-256: `{bundle.frozen_review_sha256}`",
                f"- Manifesto Mestre ICP-Brasil Fase 03 SHA-256: `{p03.icp_manifest_sha256}`",
            ]
        )
        for nul in bundle.classified_nullities:
            blocks.append(
                f"- Vicio `{nul.nullity_id}` -> **{nul.category}** ({', '.join(nul.legal_articles)}): {nul.description}"
            )

        return "\n".join(blocks) + "\n", repro_script


class LoadFileBuilder:
    """Etapa 6.2 — Gera Load Files forenses seguros (.DAT Concordance e EDRM XML)."""

    @staticmethod
    def build_concordance_dat_and_edrm_xml(bundle: Phase05ToPhase06Contract) -> tuple[str, str]:
        """Retorna (conteudo_dat, conteudo_edrm_xml) preservando genealogia ControlNumber."""
        vault_entries = bundle.phase04_bundle.phase03_bundle.vault_entries
        q = CONCORDANCE_QUOTE
        d = CONCORDANCE_DELIM
        headers = ("CONTROL_NUMBER", "PARENT_CN", "ORIGIN_REL_PATH", "SIZE_BYTES", "SHA256")
        dat_lines = [d.join(f"{q}{h}{q}" for h in headers)]

        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<Root CaseId="{xml_escape(bundle.phase04_bundle.updated_phase01_bundle.governance.case_id)}" MajorVersion="2" MinorVersion="0">',
            "  <Batch>",
            "    <Documents>",
        ]

        for ve in vault_entries:
            vals = (
                ve.control_number,
                "",
                ve.origin_rel_path,
                str(ve.size_bytes),
                ve.vault_cold_sha256,
            )
            dat_lines.append(d.join(f"{q}{v}{q}" for v in vals))
            xml_lines.extend(
                [
                    f'      <Document DocID="{xml_escape(ve.control_number)}">',
                    "        <Fields>",
                    f'          <Field Name="OriginPath" Value="{xml_escape(ve.origin_rel_path)}" />',
                    f'          <Field Name="SizeBytes" Value="{ve.size_bytes}" />',
                    f'          <Field Name="SHA256" Value="{xml_escape(ve.vault_cold_sha256)}" />',
                    "        </Fields>",
                    "      </Document>",
                ]
            )

        xml_lines.extend(["    </Documents>", "  </Batch>", "</Root>"])
        return "\n".join(dat_lines) + "\n", "\n".join(xml_lines) + "\n"
