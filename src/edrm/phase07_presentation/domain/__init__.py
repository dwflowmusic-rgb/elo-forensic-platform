"""Dominio puro da Fase 07 — Gerador de Quesitos POP Senasp 2024 e Compilador HTML5 Offline."""

from __future__ import annotations

import html
import json

from edrm.shared_kernel.contracts import CustomQuesitoRecord, Phase06ToPhase07Contract
from edrm.shared_kernel.enums import EvidentiaryDefectCategory


class StrategicInterrogatoryBuilder:
    """Etapa 7.1 — Converte cada anomalia real do HD em quesitos ancorados no POP Senasp 2024."""

    @staticmethod
    def generate_quesitos(bundle: Phase06ToPhase07Contract) -> tuple[CustomQuesitoRecord, ...]:
        """Gera quesitos objetivos fundamentados nos arts. 158-A a 158-F do CPP e POP Vol. 5."""
        p05 = bundle.phase05_bundle
        quesitos: list[CustomQuesitoRecord] = []
        q_num = 1

        for nul in p05.classified_nullities:
            if nul.nullity_id.startswith("NUL-IPED-OMISSIVE-"):
                text = (
                    f"Queira o Sr. Perito Oficial apresentar os arquivos integrais IPEDConfig.txt, "
                    f"LocalConfig.txt e logs de processamento do caso .iped entregue ({nul.description}), "
                    f"esclarecendo por que foram suprimidas etapas forenses essenciais (carving, espaco "
                    f"nao alocado, undelete SQLite ou OCR) e se a lista palavras-chave.txt sofreu filtragem "
                    f"por Manager.filterKeywords() ocultando termos com zero ocorrencias (prova negativa)."
                )
            elif nul.nullity_id.startswith("NUL-IPED-CONTAM-"):
                text = (
                    f"Queira o Sr. Perito Oficial esclarecer a ativacao do parametro externo "
                    f"--downloadInternetData / LinkDownloader ({nul.description}), discriminando quais "
                    f"arquivos foram baixados da internet durante o exame pericial e nao integravam "
                    f"originalmente a midia apreendida sob lacre (CPP arts. 157 e 158-B, II)."
                )
            elif nul.nullity_id.startswith("NUL-SQLITE-UNALLOC-"):
                text = (
                    f"Queira o Sr. Perito Oficial informar se os registros citados oriundos de bancos SQLite "
                    f"foram extraidos da arvore B-Tree ativa ou recuperados de paginas freelist/espaco nao "
                    f"alocado/frames WAL ({nul.description}), discriminando seu estado de alocacao conforme "
                    f"exigem o NIST IR 8354 e as diretrizes SWGDE para prevenir falsos positivos estruturais."
                )
            elif nul.nullity_id.startswith("NUL-LNK-PROVENANCE-"):
                text = (
                    f"Queira o Sr. Perito Oficial confrontar os identificadores fisicos gravados no bloco "
                    f"DistributedLinkTracker do atalho Windows .lnk ({nul.description}) — em especial "
                    f"MachineID, VolumeSerial e endereco MAC DroidBirth — com as interfaces fisicas da "
                    f"maquina efetivamente apreendida nos autos (CPP art. 158-B, I e III)."
                )
            elif nul.category == EvidentiaryDefectCategory.DEFENSE_PARITY_VIOLATION_TEMA_977:
                text = (
                    f"Queira o Sr. Perito Oficial informar se o arquivo bruto integral "
                    f"correspondente a ({nul.description}) foi devidamente acautelado com hash "
                    f"SHA-256 e por qual razao tecnica nao foi disponibilizado de forma acessivel "
                    f"e desencriptada a Defesa (CPP art. 159, § 6º, STF Tema 977 e STJ RHC 184.003/SP)."
                )
            elif nul.category == EvidentiaryDefectCategory.ABSOLUTE_NULLITY_ILLICIT_EVIDENCE:
                text = (
                    f"Queira o Sr. Perito Oficial esclarecer a origem tecnica do evento/mutacao "
                    f"registrado APOS o horario oficial da apreensao ({nul.description}), indicando "
                    f"se o dispositivo estava isolado em bolsa de Faraday/bloqueador de escrita "
                    f"conforme exige o POP Senasp Vol. 5 (2024), itens 5.02 e 5.05."
                )
            else:
                text = (
                    f"Queira o Sr. Perito Oficial justificar tecnicamente a divergencia ou omissao "
                    f"documental verificada em ({nul.description}), confrontando-a com os requisitos "
                    f"dos arts. 158-A a 158-F do CPP e do POP Senasp Vol. 5 (2024)."
                )

            quesitos.append(
                CustomQuesitoRecord(
                    quesito_number=q_num,
                    target_anomaly_id=nul.nullity_id,
                    normative_basis="; ".join(nul.legal_articles),
                    question_text=text,
                    anchor=nul.anchor,
                )
            )
            q_num += 1

        return tuple(quesitos)

    @staticmethod
    def build_tema977_motion_exhibit(bundle: Phase06ToPhase07Contract) -> str:
        """Etapa 7.2 — Gera Quadro Probatorio Sintetico para Peticoes e Sustentacao Oral."""
        p05 = bundle.phase05_bundle
        p01 = p05.phase04_bundle.updated_phase01_bundle
        lines = [
            "# QUADRO TECNICO ANEXO PARA PETICAO E SUSTENTACAO ORAL (STF TEMA 977 / STJ EDICAO 281)",
            "",
            f"Caso: **{p01.governance.case_id}** | Fluxo Estrutural: EDRM 2.0 (CC BY 4.0 EDRM.net) / IGRM v4.1 | Regencia Juridica: CPP arts. 158-A a 158-F e POP Senasp Vol. 5 (2024)",
            "",
            "## 1. Sintese de Omissoes de Prova Bruta e Inacessibilidade",
        ]
        for row in p01.parity_matrix:
            if row.is_judicial_critical:
                lines.append(
                    f"- `{row.finding_id}` | **{row.parity_state}** | `{', '.join(row.legal_tags)}` | {row.rationale}"
                )
        lines.append("")
        lines.append("## 2. Contradicoes Materiais Medias Entre Relatorio Acusatorio e Prova Bruta")
        for ctr in p05.material_contradictions:
            lines.append(
                f"- `{ctr.contradiction_id}` (`{ctr.contradiction_type}`): {ctr.legal_impact}"
            )
        return "\n".join(lines) + "\n"


class OfflineHtmlDossierCompiler:
    """Etapa 7.3 — Compila Dossie Interativo HTML5 em arquivo unico 100% offline/autocontido."""

    @staticmethod
    def compile_single_file_html(
        bundle: Phase06ToPhase07Contract,
        quesitos: tuple[CustomQuesitoRecord, ...],
    ) -> str:
        """Gera HTML5 completo sem nenhuma dependencia externa de rede ou CDN."""
        p05 = bundle.phase05_bundle
        p04 = p05.phase04_bundle
        p03 = p04.phase03_bundle
        p01 = p04.updated_phase01_bundle
        gov = p01.governance

        timeline_json = json.dumps(
            [
                {
                    "ts_utc": ev.ts_utc,
                    "cn": ev.origin_cn,
                    "type": ev.event_type,
                    "actor": ev.actor_origin,
                    "post_seizure": ev.is_post_seizure,
                    "content": ev.content_verbatim,
                    "sha256": ev.origin_sha256,
                }
                for ev in p04.timeline_events
            ],
            ensure_ascii=False,
        )

        contradictions_html = "".join(
            f"""
            <div class="compare-row">
              <div class="col-state">
                <strong>Alegacao Estatal ({html.escape(c.contradiction_type)})</strong>
                <p>{html.escape(c.state_claim_excerpt)}</p>
              </div>
              <div class="col-raw">
                <strong>Prova Bruta Verificada ({html.escape(c.raw_anchor.origin_control_number)})</strong>
                <p>{html.escape(c.raw_truth_excerpt)}</p>
                <small>{html.escape(c.omitted_neighbor_context)} — {html.escape(c.legal_impact)}</small>
              </div>
            </div>
            """
            for c in p05.material_contradictions
        ) or "<p>Nenhuma contradicao material direta listada.</p>"

        vault_cards_html = "".join(
            f"""
            <tr>
              <td><code>{html.escape(v.control_number)}</code></td>
              <td>{html.escape(v.origin_rel_path)}</td>
              <td class="num">{v.size_bytes}</td>
              <td><code>{html.escape(v.vault_cold_sha256)}</code></td>
            </tr>
            """
            for v in p03.vault_entries
        )

        quesitos_html = "".join(
            f"<li><strong>Quesito {q.quesito_number} ({html.escape(q.normative_basis)}):</strong> {html.escape(q.question_text)}</li>"
            for q in quesitos
        )

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Dossie Pericial Offline ELO — {html.escape(gov.case_id)}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --surface: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #475569;
      --accent: #1d4ed8;
      --danger: #b91c1c;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 32px;
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 28px; }}
    h1 {{ margin: 0 0 8px 0; font-size: 26px; }}
    h2 {{ margin-top: 32px; font-size: 19px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
    .meta {{ color: var(--muted); font-size: 13px; }}
    .search-bar {{
      display: flex;
      gap: 12px;
      margin: 16px 0;
    }}
    input[type="search"] {{
      flex: 1;
      padding: 10px 14px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 14px;
    }}
    table {{ width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; }}
    td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    code {{ font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }}
    .compare-row {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      background: var(--surface);
      border: 1px solid var(--border);
      padding: 16px;
      margin-bottom: 12px;
    }}
    .post-flag {{ color: var(--danger); font-weight: 700; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Dossie Pericial Interativo Offline — Caso {html.escape(gov.case_id)}</h1>
      <div class="meta">
        Execucao {html.escape(gov.run_id)} · PreScanSnapshot SHA-256: <code>{html.escape(p01.pre_scan_snapshot.snapshot_sha256)}</code> · Parecer SHA-256: <code>{html.escape(bundle.expert_opinion_sha256)}</code>
      </div>
    </header>

    <section>
      <h2>1. Linha do Tempo Unificada em UTC (Busca Instantanea Local)</h2>
      <div class="search-bar">
        <input id="tlSearch" type="search" placeholder="Filtrar eventos por texto, interlocutor, data UTC ou POS-APREENSAO..." aria-label="Filtrar eventos da linha do tempo" />
      </div>
      <table>
        <thead>
          <tr>
            <th>Instante UTC</th>
            <th>CN</th>
            <th>Tipo</th>
            <th>Origem</th>
            <th>Status</th>
            <th>Conteudo Ancorado</th>
          </tr>
        </thead>
        <tbody id="tlBody"></tbody>
      </table>
    </section>

    <section>
      <h2>2. Comparador Lado a Lado (Relatorio Acusatorio vs. Dado Bruto Original)</h2>
      {contradictions_html}
    </section>

    <section>
      <h2>3. Cartoes de Verificacao SHA-256 do Cofre Forense</h2>
      <table>
        <thead>
          <tr><th>ControlNumber</th><th>Arquivo de Origem</th><th>Bytes</th><th>SHA-256 Verificado a Frio</th></tr>
        </thead>
        <tbody>{vault_cards_html}</tbody>
      </table>
    </section>

    <section>
      <h2>4. Quesitos Periciais Estrategicos (POP Senasp Vol. 5 / 2024)</h2>
      <ol>{quesitos_html}</ol>
    </section>
  </div>

  <script>
    const EVENTS = {timeline_json};
    const tbody = document.getElementById("tlBody");
    const input = document.getElementById("tlSearch");

    function renderRows(query) {{
      const q = (query || "").toLowerCase();
      const filtered = EVENTS.filter(ev => {{
        const hay = (ev.ts_utc + " " + ev.cn + " " + ev.type + " " + ev.actor + " " + ev.content + (ev.post_seizure ? " pos-apreensao" : "")).toLowerCase();
        return hay.includes(q);
      }});
      tbody.innerHTML = filtered.map(ev => `
        <tr>
          <td><code>${{ev.ts_utc}}</code></td>
          <td><code>${{ev.cn}}</code></td>
          <td>${{ev.type}}</td>
          <td>${{ev.actor}}</td>
          <td class="${{ev.post_seizure ? 'post-flag' : ''}}">${{ev.post_seizure ? 'POS-APREENSAO' : 'ANTERIOR'}}</td>
          <td>${{ev.content}}</td>
        </tr>
      `).join("");
    }}
    input.addEventListener("input", e => renderRows(e.target.value));
    renderRows("");
  </script>
</body>
</html>
"""
