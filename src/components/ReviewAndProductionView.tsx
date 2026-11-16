import { useState } from 'react';
import { FileCheck2, Terminal } from 'lucide-react';
import type { CaseAuditSummary } from '../types/forensic.ts';
import { formatCentsToBrl, shortenSha256 } from '../utils/forensicModel.ts';

interface ReviewAndProductionViewProps {
  caseSummary: CaseAuditSummary;
  expertOpinionMarkdown: string;
  reproductionScript: string;
}

export function ReviewAndProductionView({
  caseSummary,
  expertOpinionMarkdown,
  reproductionScript,
}: ReviewAndProductionViewProps) {
  const [activeArtifact, setActiveArtifact] = useState<'opinion' | 'script'>('opinion');
  const qc = caseSummary.qc_summary;

  return (
    <div className="space-y-8">
      {/* Phase 05: Side-by-Side Material Contradictions */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="pb-4 border-b border-slate-200">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Fase 05 · Revisão Probatória, Contraditório Técnico &amp; Regra do 3 (3/n)
          </p>
          <h2 className="text-xl font-semibold text-slate-900 mt-1">
            Confronto Material Lado a Lado: Alegação Estatal vs. Prova Bruta Auditada
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            Controle estatístico de elusão: <span className="font-mono font-semibold">{qc.elusion_inspected_n}</span> itens inspecionados · <span className="font-mono font-semibold">{qc.elusion_errors_found}</span> erros · Limite superior Hanley &amp; Lippman-Hand (3/n): <span className="font-mono font-semibold">{qc.rule_of_3_upper_bound_pct}%</span>.
          </p>
        </div>

        <div className="mt-5 space-y-5">
          {caseSummary.material_contradictions.map((mc) => (
            <div key={mc.contradiction_id} className="border border-slate-200 rounded-md overflow-hidden">
              <div className="px-4 py-2.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="font-mono font-semibold text-slate-900">
                  {mc.contradiction_id} · {mc.contradiction_type}
                </span>
                {mc.financial_inflation_cents > 0 && (
                  <span className="font-mono font-semibold text-red-700 tabular-nums">
                    Inflação contábil expurgada: {formatCentsToBrl(mc.financial_inflation_cents)}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-slate-200">
                <div className="p-4">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    Versão Estatal (Relatório / Laudo)
                  </div>
                  <p className="mt-2 text-sm text-slate-800">{mc.state_claim_excerpt}</p>
                  <div className="mt-2 font-mono text-[11px] text-slate-500">
                    Âncora: {mc.state_anchor.origin_path} ({mc.state_anchor.locator})
                  </div>
                </div>

                <div className="p-4 bg-slate-50/40">
                  <div className="text-xs font-semibold uppercase tracking-wider text-blue-800">
                    Verdade Material na Mídia Bruta (--source)
                  </div>
                  <p className="mt-2 text-sm text-slate-900 font-medium">{mc.raw_truth_excerpt}</p>
                  {mc.omitted_neighbor_context && (
                    <p className="mt-2 text-xs text-slate-600">
                      Contexto vizinho omitido: {mc.omitted_neighbor_context}
                    </p>
                  )}
                  <div className="mt-2 font-mono text-[11px] text-slate-500">
                    Âncora: {mc.raw_anchor.origin_control_number} · {mc.raw_anchor.origin_path} ({mc.raw_anchor.locator})
                  </div>
                </div>
              </div>

              <div className="px-4 py-2.5 border-t border-slate-200 text-xs text-slate-700">
                <span className="font-semibold text-slate-900">Consequência Processual:</span> {mc.legal_impact}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Classified Evidentiary Nullities */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          Taxonomia de Vícios Probatórios
        </p>
        <h3 className="text-lg font-semibold text-slate-900 mt-1">
          Enquadramento Normativo (CPP Art. 158-A a 158-F, Tema 977/STJ e ABNT ISO 27037)
        </h3>
        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-2.5 pr-4">Código</th>
                <th className="py-2.5 px-4">Categoria Técnica</th>
                <th className="py-2.5 px-4">Dispositivos Violados</th>
                <th className="py-2.5 pl-4">Descrição Ancorada</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {caseSummary.classified_nullities.map((cn) => (
                <tr key={cn.nullity_id}>
                  <td className="py-2.5 pr-4 font-mono text-xs font-semibold text-slate-900 whitespace-nowrap">
                    {cn.nullity_id}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-xs text-red-700 whitespace-nowrap">
                    {cn.category}
                  </td>
                  <td className="py-2.5 px-4 font-mono text-xs text-slate-700">
                    {cn.legal_articles.join(' · ')}
                  </td>
                  <td className="py-2.5 pl-4 text-xs text-slate-700">{cn.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Phase 06: 7-Block Expert Opinion & Reproduction Script */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Fase 06 · Produção Pericial Validada em Dupla Passagem (0 Erros no Verificador)
            </p>
            <h3 className="text-lg font-semibold text-slate-900 mt-1">
              Parecer Técnico-Pericial em 7 Blocos &amp; Script de Reprodutibilidade Independente
            </h3>
            <p className="font-mono text-xs text-slate-500 mt-1 tabular-nums">
              SHA-256 Parecer: {shortenSha256(caseSummary.expert_opinion_sha256, 18, 12)}
            </p>
          </div>

          <div className="inline-flex rounded-md border border-slate-200 p-0.5 bg-slate-100 self-start">
            <button
              type="button"
              onClick={() => setActiveArtifact('opinion')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded cursor-pointer ${
                activeArtifact === 'opinion'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <FileCheck2 className="w-3.5 h-3.5" />
              Parecer 7 Blocos (.md)
            </button>
            <button
              type="button"
              onClick={() => setActiveArtifact('script')}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded cursor-pointer ${
                activeArtifact === 'script'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              Script Reprodutibilidade (.sh)
            </button>
          </div>
        </div>

        <pre className="mt-4 p-4 bg-slate-950 text-slate-100 rounded-md text-xs font-mono overflow-x-auto max-h-[460px] overflow-y-auto leading-relaxed whitespace-pre-wrap">
          {activeArtifact === 'opinion' ? expertOpinionMarkdown : reproductionScript}
        </pre>
      </section>
    </div>
  );
}
