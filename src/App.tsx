import { useCallback, useEffect, useState } from 'react';
import {
  Download,
  HardDrive,
  Layers,
  RefreshCw,
  Scale,
  Search,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react';
import { AcquisitionPhasesView } from './components/AcquisitionPhasesView.tsx';
import { GatesAndGovernanceView } from './components/GatesAndGovernanceView.tsx';
import { PresentationAndDispositionView } from './components/PresentationAndDispositionView.tsx';
import { ProcessingAndSearchView } from './components/ProcessingAndSearchView.tsx';
import { ReviewAndProductionView } from './components/ReviewAndProductionView.tsx';
import type {
  EnrichedCaseData,
  GatesReport,
  HybridSearchHit,
  InstallerMetadata,
  LaboratoryTabId,
} from './types/forensic.ts';
import { countCriticalParityAnomalies, summarizeGateMetrics } from './utils/forensicModel.ts';

export default function App() {
  const [activeTab, setActiveTab] = useState<LaboratoryTabId>('gates-governance');
  const [gatesReport, setGatesReport] = useState<GatesReport | null>(null);
  const [caseData, setCaseData] = useState<EnrichedCaseData | null>(null);
  const [installerInfo, setInstallerInfo] = useState<InstallerMetadata | null>(null);
  const [docsInstallerInfo, setDocsInstallerInfo] = useState<InstallerMetadata | null>(null);
  const [caseIdInput, setCaseIdInput] = useState('CASO-PENAL-EDRM20');

  const [loadingBootstrap, setLoadingBootstrap] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [runningGates, setRunningGates] = useState(false);
  const [runningPipeline, setRunningPipeline] = useState(false);
  const [verifyingManifest, setVerifyingManifest] = useState(false);

  const [searchQuery, setSearchQuery] = useState('aluguel imovel nota fiscal');
  const [searchHits, setSearchHits] = useState<HybridSearchHit[]>([]);
  const [searching, setSearching] = useState(false);

  const executeSearch = useCallback(async (query: string) => {
    setSearchQuery(query);
    if (!query.trim()) {
      setSearchHits([]);
      return;
    }
    setSearching(true);
    try {
      const resp = await fetch(`/api/cases/search?q=${encodeURIComponent(query)}&topN=10`);
      if (!resp.ok) {
        throw new Error(`Falha na consulta RRF (${resp.status})`);
      }
      const data = (await resp.json()) as { hits: HybridSearchHit[] };
      setSearchHits(data.hits);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setSearching(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoadingBootstrap(true);
        const resp = await fetch('/api/bootstrap');
        if (!resp.ok) {
          const errBody = (await resp.json().catch(() => ({}))) as { error?: string };
          throw new Error(errBody.error ?? `Falha ao inicializar laboratório (${resp.status})`);
        }
        const payload = (await resp.json()) as {
          gatesReport: GatesReport;
          activeCase: EnrichedCaseData;
          installerInfo: InstallerMetadata;
          docsInstallerInfo?: InstallerMetadata;
        };
        if (!cancelled) {
          setGatesReport(payload.gatesReport);
          setCaseData(payload.activeCase);
          setInstallerInfo(payload.installerInfo);
          if (payload.docsInstallerInfo) {
            setDocsInstallerInfo(payload.docsInstallerInfo);
          }
          setCaseIdInput(payload.activeCase.summary.case_id);
          void executeSearch('aluguel imovel nota fiscal');
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setErrorMessage(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (!cancelled) {
          setLoadingBootstrap(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [executeSearch]);

  const handleReRunGates = async () => {
    setRunningGates(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/gates/run', { method: 'POST' });
      if (!resp.ok) {
        throw new Error(`Erro ao executar portões G0–G12 (${resp.status})`);
      }
      const report = (await resp.json()) as GatesReport;
      setGatesReport(report);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setRunningGates(false);
    }
  };

  const handleRunSyntheticPipeline = async () => {
    setRunningPipeline(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/cases/run-synthetic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ caseId: caseIdInput }),
      });
      if (!resp.ok) {
        throw new Error(`Erro ao executar pipeline 00→08 (${resp.status})`);
      }
      const freshCase = (await resp.json()) as EnrichedCaseData;
      setCaseData(freshCase);
      await executeSearch(searchQuery || 'aluguel imovel nota fiscal');
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setRunningPipeline(false);
    }
  };

  const handleVerifyManifest = async () => {
    setVerifyingManifest(true);
    setErrorMessage(null);
    try {
      const resp = await fetch('/api/cases/verify-manifest', { method: 'POST' });
      if (!resp.ok) {
        throw new Error(`Erro ao verificar manifesto (${resp.status})`);
      }
      const ver = (await resp.json()) as {
        verified: boolean;
        checked_files: number;
        mismatches: string[];
      };
      setCaseData((prev) => (prev ? { ...prev, manifestVerification: ver } : prev));
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
    } finally {
      setVerifyingManifest(false);
    }
  };

  if (loadingBootstrap || !gatesReport || !caseData || !installerInfo) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6">
        <div className="max-w-md w-full bg-white border border-slate-200 rounded-lg p-8 text-center">
          <RefreshCw className="w-7 h-7 text-blue-700 animate-spin mx-auto" />
          <h1 className="text-lg font-semibold text-slate-900 mt-4">
            Inicializando Motor Forense ELO (EDRM 2.0)
          </h1>
          <p className="text-sm text-slate-600 mt-2">
            Executando calibração ISO/IEC 27041, Portões G0–G12 e auditoria Plug-and-Analyze na Sandbox Python…
          </p>
          {errorMessage && (
            <p className="mt-4 text-xs text-red-700 font-mono break-all">{errorMessage}</p>
          )}
        </div>
      </div>
    );
  }

  const gateStats = summarizeGateMetrics(gatesReport.gates);
  const s = caseData.summary;
  const criticalParityCount = countCriticalParityAnomalies(s.parity_matrix);

  const navItems: Array<{
    id: LaboratoryTabId;
    label: string;
    metric: string;
    icon: typeof ShieldCheck;
  }> = [
    {
      id: 'gates-governance',
      label: '00 · Governança & Portões G0–G12',
      metric: `${gateStats.passedCount}/${gateStats.totalCount} PASS`,
      icon: ShieldCheck,
    },
    {
      id: 'acquisition-01-03',
      label: '01–03 · Descoberta, Preservação & Coleta',
      metric: `${criticalParityCount} anomalias`,
      icon: HardDrive,
    },
    {
      id: 'processing-search-04',
      label: '04 · Processamento & Busca RRF',
      metric: `${s.processing_metrics.indexed_chunks_count} chunks`,
      icon: Search,
    },
    {
      id: 'review-production-05-06',
      label: '05–06 · Contraditório & Parecer 7 Blocos',
      metric: `${s.material_contradictions.length} contradições`,
      icon: Scale,
    },
    {
      id: 'presentation-disposition-07-08',
      label: '07–08 · Quesitos, Dossiê & Instalador',
      metric: `${s.quesitos.length} quesitos`,
      icon: Layers,
    },
  ];

  return (
    <div className="min-h-screen w-full overflow-x-hidden bg-slate-50 text-slate-900 flex flex-col">
      {/* Top Laboratory Header */}
      <header className="w-full overflow-hidden bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <TerminalSquare className="w-5 h-5 text-blue-700 shrink-0" />
              <h1 className="text-lg sm:text-xl font-bold text-slate-900 tracking-tight">
                ELO — Plataforma Forense Universal EDRM 2.0
              </h1>
            </div>
            <p className="text-xs text-slate-600 mt-1">
              EDRM 2.0 + Delta v2.2 (Cross-Disk · Banco 8 Views · MCP 10 Tools &amp; 6 Skills · IPED Clean-Room) · IGRM v4.1 · Verificador Bloqueante
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-2">
              <label htmlFor="elo-case-id-input" className="text-xs font-medium text-slate-600">
                Caso:
              </label>
              <input
                id="elo-case-id-input"
                type="text"
                value={caseIdInput}
                onChange={(e) => setCaseIdInput(e.target.value)}
                className="px-2.5 py-1.5 text-xs font-mono border border-slate-300 rounded-md bg-white text-slate-900 w-44 focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>

            <button
              type="button"
              onClick={handleRunSyntheticPipeline}
              disabled={runningPipeline}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${runningPipeline ? 'animate-spin' : ''}`} />
              {runningPipeline ? 'Auditando HD 00→08…' : 'Executar HD Sintético (00→08)'}
            </button>

            <a
              href="/api/download/cli-installer"
              download="install_elo.py"
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md border border-slate-300 bg-white text-slate-800 text-xs font-medium hover:bg-slate-50"
            >
              <Download className="w-3.5 h-3.5 text-slate-700" />
              install_elo.py
            </a>

            <a
              href="/api/download/installer"
              download="materialize_elo_platform.py"
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md border border-slate-300 bg-white text-slate-800 text-xs font-medium hover:bg-slate-50"
            >
              <Download className="w-3.5 h-3.5 text-blue-700" />
              materialize_elo_platform.py
            </a>

            <a
              href="/api/download/docs-installer"
              download="materialize_docs.py"
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md border border-slate-300 bg-white text-slate-800 text-xs font-medium hover:bg-slate-50"
            >
              <Download className="w-3.5 h-3.5 text-emerald-700" />
              materialize_docs.py
            </a>
          </div>
        </div>

        {/* Navigation Bar */}
        <nav
          aria-label="Fases EDRM 2.0"
          className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex overflow-x-auto border-t border-slate-100"
        >
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-2 px-4 py-3 text-xs font-medium border-b-2 whitespace-nowrap transition-colors cursor-pointer ${
                  isActive
                    ? 'border-blue-700 text-blue-800 bg-blue-50/40 font-semibold'
                    : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.label}</span>
                <span className="font-mono text-[11px] text-slate-500 tabular-nums">
                  · {item.metric}
                </span>
              </button>
            );
          })}
        </nav>
      </header>

      {/* Error Banner */}
      {errorMessage && (
        <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 mt-4">
          <div className="p-3 rounded-md bg-red-50 border border-red-200 text-xs text-red-800 font-mono">
            {errorMessage}
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 min-w-0 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'gates-governance' && (
          <GatesAndGovernanceView
            gatesReport={gatesReport}
            caseSummary={s}
            runningGates={runningGates}
            onReRunGates={handleReRunGates}
          />
        )}

        {activeTab === 'acquisition-01-03' && <AcquisitionPhasesView caseSummary={s} />}

        {activeTab === 'processing-search-04' && (
          <ProcessingAndSearchView
            caseSummary={s}
            searchHits={searchHits}
            searchQuery={searchQuery}
            searching={searching}
            onExecuteSearch={executeSearch}
          />
        )}

        {activeTab === 'review-production-05-06' && (
          <ReviewAndProductionView
            caseSummary={s}
            expertOpinionMarkdown={caseData.expertOpinionMarkdown}
            reproductionScript={caseData.reproductionScript}
          />
        )}

        {activeTab === 'presentation-disposition-07-08' && (
          <PresentationAndDispositionView
            caseSummary={s}
            installerInfo={installerInfo}
            docsInstallerInfo={docsInstallerInfo}
            manifestVerification={caseData.manifestVerification}
            verifyingManifest={verifyingManifest}
            onVerifyManifest={handleVerifyManifest}
          />
        )}
      </main>
    </div>
  );
}
