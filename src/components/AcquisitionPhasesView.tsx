import { AlertTriangle, CheckCircle2, Lock } from 'lucide-react';
import type { CaseAuditSummary } from '../types/forensic.ts';
import {
  describeParityState,
  formatByteSize,
  shortenSha256,
} from '../utils/forensicModel.ts';

interface AcquisitionPhasesViewProps {
  caseSummary: CaseAuditSummary;
}

export function AcquisitionPhasesView({ caseSummary }: AcquisitionPhasesViewProps) {
  return (
    <div className="space-y-8">
      {/* Phase 01: Magic Bytes, Spoofing & Dynamic SQLite Blueprints */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="pb-4 border-b border-slate-200">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Fase 01 · Autodescoberta Agnóstica da Mídia (Revisão Final {caseSummary.phase01_final_revision})
          </p>
          <h2 className="text-xl font-semibold text-slate-900 mt-1">
            Censo Magic Bytes (16B), Camuflagem de Extensão e Introspecção SQLite Imutável
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            Amostragem estatística de Cochran recomendada: <span className="font-mono font-semibold">{caseSummary.cochran_plan.cochran_sample_size}</span> itens + <span className="font-mono font-semibold">{caseSummary.cochran_plan.critical_100pct_count}</span> críticos (100%) para população N={caseSummary.cochran_plan.population_total} (95% confiança · ±10% margem).
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-5">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 mb-3">
              Censo Real por Assinatura Binária (Magic Bytes)
            </h3>
            <div className="divide-y divide-slate-100 border border-slate-200 rounded-md">
              {caseSummary.signature_census.map(([sig, count]) => (
                <div key={sig} className="flex items-center justify-between px-3.5 py-2 text-sm">
                  <span className="font-mono text-xs text-slate-800">{sig}</span>
                  <span className="font-mono text-xs font-semibold text-slate-900 tabular-nums">
                    {count} {count === 1 ? 'arquivo' : 'arquivos'}
                  </span>
                </div>
              ))}
            </div>

            {caseSummary.spoofed_files.length > 0 && (
              <div className="mt-4 p-3.5 rounded-md bg-amber-50/70 border border-amber-200">
                <div className="flex items-center gap-2 text-xs font-semibold text-amber-900 uppercase tracking-wider">
                  <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0" />
                  Camuflagem de Extensão Detectada (Magic Bytes != Extensão)
                </div>
                <ul className="mt-2 space-y-1">
                  {caseSummary.spoofed_files.map((sp) => (
                    <li key={sp} className="font-mono text-xs text-amber-950">
                      {sp} → cabeçalho binário real SQLite Format 3
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-slate-900 mb-3">
              Esquemas SQLite Descobertos Dinamicamente (URI mode=ro&amp;immutable=1)
            </h3>
            <div className="divide-y divide-slate-200 border border-slate-200 rounded-md">
              {caseSummary.dynamic_schemas.map((ds) => (
                <div key={ds.schema_hash} className="p-3.5 text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-semibold text-slate-900">
                      {ds.origin_rel_path} · tabela {ds.table_name}
                    </span>
                    <span className="font-mono text-xs text-emerald-700 font-semibold">
                      {ds.approved_by_verifier ? 'APROVADO' : 'PENDENTE'}
                    </span>
                  </div>
                  <div className="mt-1 text-xs text-slate-600">
                    Colunas: <span className="font-mono">{ds.columns.join(', ')}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    Mapeamento inferido: Tempo={ds.timestamp_column} · Ator={ds.actor_column} · Conteúdo={ds.content_column}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Inter-Document Divergences */}
        {caseSummary.divergences.length > 0 && (
          <div className="mt-6 pt-5 border-t border-slate-200">
            <h3 className="text-sm font-semibold text-slate-900 mb-3">
              Divergências Interdocumentais (Auto de Apreensão vs. Laudo / FAV)
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500">
                    <th className="py-2.5 pr-4">ID</th>
                    <th className="py-2.5 px-4">Campo Divergente</th>
                    <th className="py-2.5 px-4">Documento A</th>
                    <th className="py-2.5 px-4">Documento B</th>
                    <th className="py-2.5 pl-4">Impacto Técnico-Jurídico</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {caseSummary.divergences.map((d) => (
                    <tr key={d.divergence_id}>
                      <td className="py-2.5 pr-4 font-mono text-xs text-slate-900">{d.divergence_id}</td>
                      <td className="py-2.5 px-4 font-mono text-xs font-semibold text-red-700">{d.field_name}</td>
                      <td className="py-2.5 px-4 font-mono text-xs text-slate-700">
                        {d.left_value} <span className="text-slate-400">({d.left_anchor.origin_path})</span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-xs text-slate-700">
                        {d.right_value} <span className="text-slate-400">({d.right_anchor.origin_path})</span>
                      </td>
                      <td className="py-2.5 pl-4 text-xs text-slate-700">{d.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      {/* Parity Matrix (7 Canonical States) */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="pb-4 border-b border-slate-200">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Matriz de Paridade Probatória · 7 Estados Canônicos
          </p>
          <h2 className="text-xl font-semibold text-slate-900 mt-1">
            Confronto Declarado nos Autos vs. Efetivamente Entregue na Mídia
          </h2>
        </div>
        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-3 pr-4">Achado</th>
                <th className="py-3 px-4">Estado Canônico</th>
                <th className="py-3 px-4">Item / Arquivo Associado</th>
                <th className="py-3 pl-4">Fundamentação &amp; Enquadramento</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {caseSummary.parity_matrix.map((row) => {
                const desc = describeParityState(row.parity_state);
                return (
                  <tr key={row.finding_id} className="hover:bg-slate-50/70">
                    <td className="py-3 pr-4 font-mono text-xs font-semibold text-slate-900 whitespace-nowrap">
                      {row.finding_id}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`text-xs font-semibold ${
                          desc.isCriticalDefect ? 'text-red-700' : 'text-emerald-700'
                        }`}
                      >
                        {desc.label}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs text-slate-700">
                      {row.matched_rel_path ?? row.declared_id ?? '—'}
                    </td>
                    <td className="py-3 pl-4 text-xs text-slate-700">
                      <div>{row.rationale}</div>
                      {row.legal_tags.length > 0 && (
                        <div className="mt-1 font-mono text-[11px] text-slate-500">
                          {row.legal_tags.join(' · ')}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Phase 02 & Phase 03 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Fase 02 · Preservação &amp; Integridade Estrutural
          </p>
          <h3 className="text-lg font-semibold text-slate-900 mt-1">
            Auditoria dos 6 Eixos (ABNT ISO/IEC 27037 &amp; CPP Art. 158-A..F)
          </h3>
          <div className="mt-4 divide-y divide-slate-100">
            {caseSummary.six_axes_findings.map((ax) => (
              <div key={ax.finding_id} className="py-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-slate-900">
                    {ax.declared_id} · {ax.axis}
                  </span>
                  <span
                    className={`text-xs font-semibold shrink-0 ${
                      ax.compliant ? 'text-emerald-700' : 'text-red-700'
                    }`}
                  >
                    {ax.compliant ? 'CONFORME' : 'NÃO CONFORME'}
                  </span>
                </div>
                <p className="text-xs text-slate-600 mt-1">{ax.summary}</p>
                {ax.legal_tags.length > 0 && (
                  <p className="font-mono text-[11px] text-slate-500 mt-1">
                    {ax.legal_tags.join(' · ')}
                  </p>
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="bg-white border border-slate-200 rounded-lg p-6">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Fase 03 · Cofre Imutável &amp; Releitura Fria (os.fsync)
          </p>
          <h3 className="text-lg font-semibold text-slate-900 mt-1">
            Aquisição Defensiva com Permissão Read-Only (0o444)
          </h3>
          <div className="mt-4 max-h-96 overflow-y-auto divide-y divide-slate-100 pr-1">
            {caseSummary.vault_entries.map((ve) => (
              <div key={ve.control_number} className="py-2.5 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-slate-900">
                    {ve.control_number} · {ve.origin_rel_path}
                  </span>
                  <span className="inline-flex items-center gap-1 text-emerald-700 font-medium">
                    {ve.vault_locked_readonly ? <Lock className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                    {formatByteSize(ve.size_bytes)}
                  </span>
                </div>
                <div className="font-mono text-[11px] text-slate-500 mt-0.5 tabular-nums">
                  Cold SHA-256: {shortenSha256(ve.vault_cold_sha256, 16, 12)}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
