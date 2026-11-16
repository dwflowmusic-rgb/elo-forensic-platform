import { useState, type FormEvent } from 'react';
import { Search } from 'lucide-react';
import type { CaseAuditSummary, HybridSearchHit } from '../types/forensic.ts';
import {
  formatCentsToBrl,
  formatMicrodegrees,
  shortenSha256,
  summarizeFinancialLedgerCents,
} from '../utils/forensicModel.ts';

interface ProcessingAndSearchViewProps {
  caseSummary: CaseAuditSummary;
  searchHits: HybridSearchHit[];
  searchQuery: string;
  searching: boolean;
  onExecuteSearch: (query: string) => void;
}

export function ProcessingAndSearchView({
  caseSummary,
  searchHits,
  searchQuery,
  searching,
  onExecuteSearch,
}: ProcessingAndSearchViewProps) {
  const [inputVal, setInputVal] = useState(searchQuery);
  const [onlyPostSeizure, setOnlyPostSeizure] = useState(false);

  const ledgerStats = summarizeFinancialLedgerCents(caseSummary.financial_entries);
  const pm = caseSummary.processing_metrics;

  const visibleTimeline = onlyPostSeizure
    ? caseSummary.timeline_events.filter((ev) => ev.is_post_seizure)
    : caseSummary.timeline_events;

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    onExecuteSearch(inputVal);
  };

  return (
    <div className="space-y-8">
      {/* Hybrid RRF Search Console */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="pb-4 border-b border-slate-200">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
             Camada Transversal · Análise Contínua &amp; Recuperação Híbrida RRF (k = 60)
          </p>
          <h2 className="text-xl font-semibold text-slate-900 mt-1">
            Busca Auditável SQLite FTS5 BM25 + Similaridade Vetorial Determinística
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            Índice unificado com <span className="font-mono font-semibold">{pm.indexed_chunks_count}</span> chunks sanitizados pelo Escudo Anti-Prompt-Injection e ancorados ao SHA-256 de origem.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <label htmlFor="elo-rrf-search-input" className="sr-only">
              Termo de pesquisa probatória RRF
            </label>
            <input
              id="elo-rrf-search-input"
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              placeholder="Ex.: aluguel contrato nota fiscal, pos apreensao, camuflado dll…"
              className="w-full px-3.5 py-2 text-sm border border-slate-300 rounded-md bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
          <button
            type="submit"
            disabled={searching}
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-slate-900 text-white text-sm font-medium hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
          >
            <Search className="w-4 h-4" />
            {searching ? 'Consultando FTS5 + Vetor…' : 'Pesquisar Catálogo RRF'}
          </button>
        </form>

        <div className="flex flex-wrap gap-2 mt-2.5 text-xs text-slate-500">
          <span>Consultas rápidas:</span>
          {['aluguel imovel nota fiscal', 'APOS a apreensao policial', 'camuflado dll', 'R$ 1.540,90'].map(
            (preset) => (
              <button
                key={preset}
                type="button"
                onClick={() => {
                  setInputVal(preset);
                  onExecuteSearch(preset);
                }}
                className="underline hover:text-blue-700 cursor-pointer"
              >
                {preset}
              </button>
            ),
          )}
        </div>

        <div className="mt-5 divide-y divide-slate-100 border border-slate-200 rounded-md">
          {searchHits.length === 0 ? (
            <div className="p-4 text-sm text-slate-500">
              Nenhum chunk retornado para a consulta atual. Experimente uma das consultas rápidas acima.
            </div>
          ) : (
            searchHits.map((hit) => (
              <div key={hit.chunk_id} className="p-4 hover:bg-slate-50/70">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 font-mono">
                  <span className="font-semibold text-slate-900">
                    {hit.origin_cn} · {hit.locator}
                  </span>
                  <span className="tabular-nums">
                    Score RRF: {Number(hit.rrf_score).toFixed(6)} · Rank BM25: {hit.lexical_rank ?? '—'} · Rank Vetor: {hit.vector_rank ?? '—'}
                  </span>
                </div>
                <p className="mt-1.5 text-sm text-slate-800 leading-relaxed">{hit.text_clean}</p>
                <div className="mt-1 font-mono text-[11px] text-slate-400 tabular-nums">
                  SHA-256 Origem: {shortenSha256(hit.origin_sha256, 16, 12)}
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      {/* EDRM 5.0 Metrics Strip */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          Fase 04 · Processamento Forense (Piso Funcional EDRM 1.0 a 5.0 + 5 Filas P0 → P4)
        </p>
        <h2 className="text-xl font-semibold text-slate-900 mt-1">
          Deduplicação Lógica, Barreira Referencial P0 → P4, Undelete SQLite e Ledgers Determinísticos
        </h2>
        <p className="text-xs text-slate-500 mt-1 font-mono">
          Filas P0 → P4 executadas · Registros SQLite recuperados (NIST IR 8354): {pm.recovered_deleted_sqlite_rows_count} · Proveniência física .lnk: {pm.physical_link_tracker_findings_count}
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pt-4 border-t border-slate-200">
          <div>
            <div className="text-xs text-slate-500">Inventário Expandido</div>
            <div className="font-mono text-lg font-semibold text-slate-900 tabular-nums">
              {pm.total_inventory_items} itens
            </div>
            <div className="text-xs text-slate-500">
              Duplicatas exatas SHA-256: {pm.logical_duplicates_count} · De-NIST: {pm.denisted_parent_count}
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Eventos Pós-Apreensão</div>
            <div className="font-mono text-lg font-semibold text-red-700 tabular-nums">
              {pm.post_seizure_events_count} detectado(s)
            </div>
            <div className="text-xs text-slate-500">
              PDFs múltiplos %%EOF: {pm.pdf_multi_eof_count}
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Inflação Financeira SIMBA</div>
            <div className="font-mono text-lg font-semibold text-red-700 tabular-nums">
              {formatCentsToBrl(ledgerStats.duplicateInflationCents)}
            </div>
            <div className="text-xs text-slate-500">
              Líquido auditado: {formatCentsToBrl(ledgerStats.netAuditedTotalCents)}
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Anomalias Telecom &amp; CGNAT</div>
            <div className="font-mono text-lg font-semibold text-red-700 tabular-nums">
              {pm.impossible_erb_jumps_count} salto ERB · {pm.cgnat_missing_port_count} sem porta
            </div>
            <div className="text-xs text-slate-500">Decreto n. 12.975/2026</div>
          </div>
        </div>
      </section>

      {/* Unified UTC Timeline */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-4 border-b border-slate-200">
          <div>
            <h3 className="text-lg font-semibold text-slate-900">
              Linha do Tempo Unificada em UTC (Épocas 1970, 2001 Cocoa, 1904 HFS+)
            </h3>
            <p className="text-xs text-slate-500">
              Confronto automático contra o marco temporal da apreensão estatal (2026-05-10T14:00:00Z).
            </p>
          </div>
          <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
            <input
              type="checkbox"
              checked={onlyPostSeizure}
              onChange={(e) => setOnlyPostSeizure(e.target.checked)}
              className="rounded border-slate-300 text-blue-700 focus:ring-blue-600"
            />
            Exibir apenas eventos pós-apreensão ({pm.post_seizure_events_count})
          </label>
        </div>

        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-2.5 pr-4">Instante UTC</th>
                <th className="py-2.5 px-4">Controle / Fonte</th>
                <th className="py-2.5 px-4">Ator</th>
                <th className="py-2.5 px-4">Conteúdo / Evento</th>
                <th className="py-2.5 pl-4 text-right">Integridade Temporal</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleTimeline.map((ev) => (
                <tr key={ev.event_id} className={ev.is_post_seizure ? 'bg-red-50/50' : ''}>
                  <td className="py-2.5 pr-4 font-mono text-xs text-slate-900 whitespace-nowrap tabular-nums">
                    {ev.ts_utc}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-xs text-slate-600 whitespace-nowrap">
                    {ev.origin_cn} · {ev.locator}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-xs text-slate-800">{ev.actor_origin}</td>
                  <td className="py-2.5 px-4 text-xs text-slate-800">{ev.content_verbatim}</td>
                  <td className="py-2.5 pl-4 text-right whitespace-nowrap">
                    <span
                      className={`text-xs font-semibold ${
                        ev.is_post_seizure ? 'text-red-700' : 'text-slate-600'
                      }`}
                    >
                      {ev.is_post_seizure ? 'PÓS-APREENSÃO (CONTAMINAÇÃO)' : 'PRÉ-APREENSÃO'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Financial SIMBA Ledger + Telecom/CGNAT */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-slate-900">
            Ledger Financeiro SIMBA em Centavos Inteiros (BIGINT)
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Total Bruto: <span className="font-mono">{formatCentsToBrl(ledgerStats.grossTotalCents)}</span> · Duplicidade entre remessas: <span className="font-mono text-red-700">{formatCentsToBrl(ledgerStats.duplicateInflationCents)}</span> · Líquido: <span className="font-mono font-semibold text-emerald-700">{formatCentsToBrl(ledgerStats.netAuditedTotalCents)}</span>
          </p>
          <div className="mt-4 divide-y divide-slate-100">
            {caseSummary.financial_entries.map((fe) => (
              <div key={fe.entry_id} className="py-3 text-xs flex items-center justify-between gap-4">
                <div>
                  <div className="font-mono font-semibold text-slate-900">
                    {fe.tx_utc} · {fe.origin_cn} ({fe.locator})
                  </div>
                  <div className="text-slate-600 mt-0.5">
                    Titular {fe.holder_tax_id} → Contraparte {fe.counterparty_tax_id}
                  </div>
                </div>
                <div className="text-right whitespace-nowrap">
                  <div className="font-mono text-sm font-semibold text-slate-900 tabular-nums">
                    {formatCentsToBrl(fe.amount_cents)}
                  </div>
                  <div
                    className={`text-[11px] font-semibold ${
                      fe.is_inter_file_duplicate ? 'text-red-700' : 'text-emerald-700'
                    }`}
                  >
                    {fe.is_inter_file_duplicate ? 'REMESSA DUPLICADA' : 'LANÇAMENTO ÚNICO'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-slate-900">
            Auditoria Telecom CDR/ERB &amp; Provedores CGNAT
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Geometria Haversine e aferição de porta lógica de origem (Decreto n. 12.975/2026).
          </p>
          <div className="mt-4 space-y-3">
            {caseSummary.telecom_records.map((tr) => (
              <div key={tr.cdr_id} className="p-3 border border-slate-200 rounded-md text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-slate-900">
                    CDR {tr.start_utc} · ERB {tr.cell_cgi}
                  </span>
                  <span
                    className={`font-semibold ${
                      tr.impossible_speed_flag ? 'text-red-700' : 'text-slate-600'
                    }`}
                  >
                    {tr.impossible_speed_flag ? 'VELOCIDADE IMPOSSÍVEL (>1.200 km/h)' : 'DESLOCAMENTO COMPATÍVEL'}
                  </span>
                </div>
                <div className="font-mono text-slate-600 mt-1 tabular-nums">
                  Coord: {formatMicrodegrees(tr.lat_microdeg)}, {formatMicrodegrees(tr.lon_microdeg)} · Azimute {tr.azimuth_deg}°
                </div>
              </div>
            ))}

            {caseSummary.cgnat_records.map((cg) => (
              <div key={cg.log_id} className="p-3 border border-slate-200 rounded-md text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-slate-900">
                    IP Compartilhado {cg.shared_ip} · Porta: {cg.source_logical_port ?? 'OMISSA'}
                  </span>
                  <span
                    className={`font-semibold ${
                      cg.missing_logical_port_defect ? 'text-red-700' : 'text-emerald-700'
                    }`}
                  >
                    {cg.missing_logical_port_defect ? 'IMPRESTABILIDADE CGNAT' : 'PORTA IDENTIFICADA'}
                  </span>
                </div>
                <div className="font-mono text-slate-500 mt-1 tabular-nums">
                  Timestamp UTC: {cg.ts_utc} · {cg.origin_cn} ({cg.locator})
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
