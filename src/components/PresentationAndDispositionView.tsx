import { CheckCircle2, Download, RefreshCw, ShieldCheck } from 'lucide-react';
import type { CaseAuditSummary, InstallerMetadata } from '../types/forensic.ts';
import { formatByteSize, shortenSha256 } from '../utils/forensicModel.ts';

interface PresentationAndDispositionViewProps {
  caseSummary: CaseAuditSummary;
  installerInfo: InstallerMetadata;
  docsInstallerInfo?: InstallerMetadata | null;
  manifestVerification: {
    verified: boolean;
    checked_files: number;
    mismatches: string[];
  };
  verifyingManifest: boolean;
  onVerifyManifest: () => void;
}

export function PresentationAndDispositionView({
  caseSummary,
  installerInfo,
  docsInstallerInfo,
  manifestVerification,
  verifyingManifest,
  onVerifyManifest,
}: PresentationAndDispositionViewProps) {
  const disp = caseSummary.disposition;

  return (
    <div className="space-y-8">
      {/* Phase 07: Custom Quesitos & Offline HTML5 Dossier */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Fase 07 · Apresentação Judicial &amp; Quesitação Estratégica (POP Senasp 2024)
            </p>
            <h2 className="text-xl font-semibold text-slate-900 mt-1">
              Quesitos Periciais Sob Medida e Dossiê Interativo HTML5 100% Offline
            </h2>
            <p className="font-mono text-xs text-slate-500 mt-1 tabular-nums break-all">
              Dossiê HTML5 SHA-256: {shortenSha256(caseSummary.offline_html_dossier_sha256, 18, 12)}
            </p>
          </div>
          <a
            href="/api/download/dossier"
            download="phase07_dossie_interativo_offline.html"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-slate-900 text-white text-sm font-medium hover:bg-slate-800 transition-colors self-start"
          >
            <Download className="w-4 h-4" />
            Baixar Dossiê HTML5 Offline
          </a>
        </div>

        <div className="mt-5 max-h-[360px] overflow-y-auto divide-y divide-slate-200 border border-slate-200 rounded-md">
          {caseSummary.quesitos.map((q) => (
            <div key={q.quesito_number} className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 font-mono">
                <span className="font-semibold text-slate-900">
                  QUESITO {String(q.quesito_number).padStart(2, '0')} · Alvo: {q.target_anomaly_id}
                </span>
                <span>Base Normativa: {q.normative_basis}</span>
              </div>
              <p className="mt-2 text-sm text-slate-800 leading-relaxed">{q.question_text}</p>
              <div className="mt-1.5 font-mono text-[11px] text-slate-400">
                Âncora: {q.anchor.origin_path} ({q.anchor.locator})
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Phase 08: Disposition + Standalone SHA-256 Verified Installer */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <section className="min-w-0 bg-white border border-slate-200 rounded-lg p-6">
          <div className="flex flex-wrap items-start justify-between gap-3 pb-4 border-b border-slate-200">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Fase 08 · Destinação Final &amp; Reconexão IGRM v4.1 (NIST SP 800-88)
              </p>
              <h3 className="text-lg font-semibold text-slate-900 mt-1">
                Expurgo Seletivo de Staging e Conferência Fria do Manifesto
              </h3>
            </div>
            <button
              type="button"
              onClick={onVerifyManifest}
              disabled={verifyingManifest}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 bg-white text-xs font-medium text-slate-800 hover:bg-slate-50 disabled:opacity-60 cursor-pointer shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifyingManifest ? 'animate-spin' : ''}`} />
              Auditar Manifesto
            </button>
          </div>

          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2 py-1.5 border-b border-slate-100">
              <dt className="text-slate-600">Arquivos temporários expurgados (staging/)</dt>
              <dd className="font-mono font-semibold text-slate-900 tabular-nums">
                {disp.staging_purged_files_count} ({formatByteSize(disp.staging_purged_bytes)})
              </dd>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 py-1.5 border-b border-slate-100">
              <dt className="text-slate-600">Cofre imutável (vault/) intacto pós-expurgo</dt>
              <dd className="font-semibold text-emerald-700">
                {disp.vault_intact_verified ? 'VERIFICADO (100%)' : 'FALHA'}
              </dd>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 py-1.5 border-b border-slate-100">
              <dt className="text-slate-600">Conferência MANIFESTO_SHA256.txt a frio</dt>
              <dd className="inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-emerald-700 tabular-nums">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                {manifestVerification.verified
                  ? `${manifestVerification.checked_files} artefatos íntegros (0 divergências)`
                  : 'Divergência detectada'}
              </dd>
            </div>
            <div className="pt-1 text-xs text-slate-500 font-mono break-all">
              Pacote de recuperação: {disp.recovery_bundle_path}
            </div>
          </dl>
        </section>

        <section className="min-w-0 bg-white border border-slate-200 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Portão G9 · Entrega Integral Autocontida
            </p>
            <h3 className="text-lg font-semibold text-slate-900 mt-1">
              Instalador Autocontido Verificado por SHA-256
            </h3>
            <p className="text-sm text-slate-600 mt-2 leading-relaxed">
              Script Python único e autônomo (<code className="font-mono text-xs">materialize_elo_platform.py</code>) contendo 100% dos 71 módulos (EDRM 2.0 Ondas 1–5 + Refatoração Delta v2.1) empacotados deterministicamente com conferência SHA-256 a frio via <code className="font-mono text-xs">os.fsync</code>.
            </p>

            <div className="mt-4 p-3.5 bg-slate-50 border border-slate-200 rounded-md space-y-1.5 text-xs font-mono overflow-x-auto">
              <div className="flex flex-wrap items-center justify-between gap-2 text-slate-700">
                <span>Arquivo: {installerInfo.filename}</span>
                <span className="tabular-nums">{formatByteSize(installerInfo.sizeBytes)}</span>
              </div>
              <div className="text-slate-600 break-all tabular-nums">
                SHA-256: {installerInfo.sha256}
              </div>
              <div className="pt-2 text-slate-800 break-all">
                $ python3 materialize_elo_platform.py --target ./elo_lab --verify
              </div>
              <div className="text-slate-800 break-all">
                $ python3 ./elo_lab/tools/run_forensic_gates.py
              </div>
            </div>
            {docsInstallerInfo && (
              <div className="mt-3 p-3.5 bg-slate-50 border border-slate-200 rounded-md space-y-1.5 text-xs font-mono overflow-x-auto">
                <div className="flex flex-wrap items-center justify-between gap-2 text-slate-700">
                  <span>Suíte Documental (18 artefatos): {docsInstallerInfo.filename}</span>
                  <span className="tabular-nums">{formatByteSize(docsInstallerInfo.sizeBytes)}</span>
                </div>
                <div className="text-slate-600 break-all tabular-nums">
                  SHA-256: {docsInstallerInfo.sha256}
                </div>
                <div className="pt-1 text-slate-800 break-all">
                  $ python3 materialize_docs.py --target ./elo_docs --verify
                </div>
              </div>
            )}
          </div>

          <div className="mt-5 pt-4 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3">
            <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              Homologado G0–G11 (EXIT CODE 0)
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <a
                href="/api/download/docs-installer"
                download="materialize_docs.py"
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md border border-slate-300 bg-white text-slate-800 text-sm font-medium hover:bg-slate-50 transition-colors"
              >
                <Download className="w-4 h-4 shrink-0 text-emerald-700" />
                Baixar Docs SHA-256
              </a>
              <a
                href="/api/download/installer"
                download="materialize_elo_platform.py"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-blue-700 text-white text-sm font-medium hover:bg-blue-800 transition-colors"
              >
                <Download className="w-4 h-4 shrink-0" />
                Baixar Instalador SHA-256
              </a>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
