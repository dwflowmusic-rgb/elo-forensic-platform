import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  Play,
  RefreshCw,
  ShieldCheck,
  Unlock,
  XCircle,
} from 'lucide-react';
import type {
  CaseAuditSummary,
  GatesReport,
  LiveMonitorReport,
  ProtectedZipsReport,
} from '../types/forensic.ts';
import { shortenSha256, summarizeGateMetrics } from '../utils/forensicModel.ts';

interface GatesAndGovernanceViewProps {
  gatesReport: GatesReport;
  caseSummary: CaseAuditSummary;
  runningGates: boolean;
  onReRunGates: () => void;
}

export function GatesAndGovernanceView({
  gatesReport,
  caseSummary,
  runningGates,
  onReRunGates,
}: GatesAndGovernanceViewProps) {
  const metrics = summarizeGateMetrics(gatesReport.gates);
  const cal = caseSummary.calibration_receipt;

  const [liveMonitor, setLiveMonitor] = useState<LiveMonitorReport | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);
  const [loadingLive, setLoadingLive] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [logFilter, setLogFilter] = useState<'all' | 'failures' | 'checkpoints' | 'auditor'>('all');
  const [protectedZips, setProtectedZips] = useState<ProtectedZipsReport | null>(null);
  const [zipPasswords, setZipPasswords] = useState<Record<string, string>>({});
  const [unlockingPath, setUnlockingPath] = useState<string | null>(null);
  const [unlockFeedback, setUnlockFeedback] = useState<string | null>(null);

  const fetchProtectedZips = useCallback(async () => {
    try {
      const resp = await fetch('/api/cases/protected-zips');
      if (resp.ok) {
        const data = (await resp.json()) as ProtectedZipsReport;
        setProtectedZips(data);
      }
    } catch {
      // Silencioso para nao bloquear painel principal
    }
  }, []);

  const handleUnlockZip = useCallback(
    async (zipPath: string, useLookup: boolean) => {
      setUnlockingPath(zipPath);
      setUnlockFeedback(null);
      try {
        const resp = await fetch('/api/cases/unlock-zip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            zipPath,
            password: useLookup ? '' : (zipPasswords[zipPath] ?? ''),
            useLookup,
          }),
        });
        const data = (await resp.json()) as {
          unlocked?: boolean;
          extracted_files_count?: number;
          extracted_dir?: string;
          error?: string;
        };
        if (!resp.ok || !data.unlocked) {
          throw new Error(data.error ?? 'Falha ao desbloquear ZIP.');
        }
        setUnlockFeedback(
          `Desbloqueado com sucesso (${data.extracted_files_count ?? 0} arquivos) em ${data.extracted_dir ?? ''}`,
        );
        await fetchProtectedZips();
      } catch (err: unknown) {
        setUnlockFeedback(err instanceof Error ? err.message : String(err));
      } finally {
        setUnlockingPath(null);
      }
    },
    [fetchProtectedZips, zipPasswords],
  );

  const fetchLiveMonitor = useCallback(async () => {
    setLoadingLive(true);
    try {
      const resp = await fetch('/api/cases/live-monitor');
      if (!resp.ok) {
        throw new Error(`Falha ao consultar monitor ao vivo (${resp.status})`);
      }
      const data = (await resp.json()) as LiveMonitorReport;
      setLiveMonitor(data);
      setLiveError(null);
    } catch (err: unknown) {
      setLiveError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoadingLive(false);
    }
  }, []);

  useEffect(() => {
    void fetchLiveMonitor();
    void fetchProtectedZips();
  }, [fetchLiveMonitor, fetchProtectedZips]);

  useEffect(() => {
    if (!autoRefresh) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void fetchLiveMonitor();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, fetchLiveMonitor]);

  return (
    <div className="space-y-8">
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Camada 00 · Governança IGRM v4.1 · NIST SSDF v1.1 &amp; Homologação Automatizada
            </p>
            <h2 className="text-xl font-semibold text-slate-900 mt-1">
              Portões Forenses Cumulativos G0 a G12
            </h2>
            <p className="text-sm text-slate-600 mt-1">
              Auditoria AST (Clean/Hexagonal + NIST SSDF), calibração ISO/IEC 27041, LSP, IPED Clean-Room, Cross-Disk 8 Views, MCP JSON-RPC 2.0 e 6 Skills.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-4 shrink-0">
            <div className="sm:text-right">
              <div className="text-xs text-slate-500">Tempo Acumulado</div>
              <div className="font-mono text-sm font-semibold text-slate-900 tabular-nums whitespace-nowrap">
                {metrics.totalElapsedMs} ms · EXIT CODE {gatesReport.exit_code}
              </div>
            </div>
            <button
              type="button"
              onClick={onReRunGates}
              disabled={runningGates}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-blue-700 text-white text-sm font-medium whitespace-nowrap hover:bg-blue-800 disabled:opacity-60 transition-colors cursor-pointer"
            >
              {runningGates ? (
                <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
              ) : (
                <Play className="w-4 h-4 shrink-0" />
              )}
              {runningGates ? 'Executando G0–G12…' : 'Reexecutar Portões G0–G12'}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 py-5 border-b border-slate-200">
          <div>
            <div className="text-xs font-medium text-slate-500">
              Prova de Imutabilidade da Fonte (--source)
            </div>
            <div className="mt-1 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" />
              <span className="text-sm font-semibold text-slate-900">
                {caseSummary.zero_source_mutation_confirmed
                  ? 'PreScanSnapshot == PostScanSnapshot'
                  : 'Violação Detectada'}
              </span>
            </div>
            <div className="mt-1 font-mono text-xs text-slate-600 tabular-nums break-all">
              Pre: {shortenSha256(caseSummary.pre_scan_snapshot_sha256, 16, 10)}
            </div>
            <div className="font-mono text-xs text-slate-600 tabular-nums break-all">
              Post: {shortenSha256(caseSummary.post_scan_snapshot_sha256, 16, 10)}
            </div>
          </div>

          <div>
            <div className="text-xs font-medium text-slate-500">
              Auto-Calibração Prévia ISO/IEC 27041
            </div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              1 Controle Positivo · 2 Controles Negativos Bloqueados
            </div>
            <div className="mt-1 text-xs text-slate-600">
              Mutação numérica rejeitada: {cal.negative_numeric_mutation_blocked ? 'Sim' : 'Não'} ·
              Entidade fantasma rejeitada: {cal.negative_phantom_entity_blocked ? 'Sim' : 'Não'}
            </div>
            <div className="font-mono text-xs text-slate-600 mt-0.5 tabular-nums">
              Recibo SHA-256: {shortenSha256(cal.calibration_sha256, 14, 10)}
            </div>
          </div>

          <div>
            <div className="text-xs font-medium text-slate-500">
              Assinatura Determinística do Motor ELO
            </div>
            <div className="mt-1 text-sm font-semibold text-slate-900">
              Revisão Iterativa Fase 01: Rev. {caseSummary.phase01_initial_revision} → Rev.{' '}
              {caseSummary.phase01_final_revision}
            </div>
            <div className="mt-1 font-mono text-xs text-slate-600 tabular-nums">
              Run ID: {caseSummary.run_id}
            </div>
            <div className="font-mono text-xs text-slate-600 tabular-nums">
              Codebase: {shortenSha256(caseSummary.codebase_sha256, 14, 10)}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold uppercase tracking-wider text-slate-500">
                <th className="py-3 pr-4">Portão</th>
                <th className="py-3 px-4">Escopo de Homologação</th>
                <th className="py-3 px-4">Evidência Empírica</th>
                <th className="py-3 px-4 text-right">Latência</th>
                <th className="py-3 pl-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-sm">
              {gatesReport.gates.map((g) => (
                <tr key={g.gate} className="hover:bg-slate-50/80">
                  <td className="py-3 pr-4 font-mono font-semibold text-slate-900 whitespace-nowrap">
                    {g.gate}
                  </td>
                  <td className="py-3 px-4 font-medium text-slate-900">{g.title}</td>
                  <td className="py-3 px-4 text-slate-600">{g.detail}</td>
                  <td className="py-3 px-4 text-right font-mono text-xs text-slate-600 tabular-nums whitespace-nowrap">
                    {g.elapsed_ms} ms
                  </td>
                  <td className="py-3 pl-4 text-right whitespace-nowrap">
                    {g.passed ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                        <CheckCircle2 className="w-4 h-4" />
                        APROVADO
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700">
                        <XCircle className="w-4 h-4" />
                        REPROVADO
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Monitoramento Passo a Passo · Caso Real Cross-Disk (E:\ → F:\) &amp; Subagente Auditor
            </p>
            <h3 className="text-lg font-semibold text-slate-900 mt-1 flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-700 shrink-0" />
              Acompanhamento de Logs, Checkpoints e Falhas
            </h3>
            <p className="text-xs text-slate-600 mt-1 font-mono">
              {liveMonitor
                ? `Destino: ${liveMonitor.dest_root} · Fase: ${liveMonitor.current_phase} · Status: ${liveMonitor.run_status}`
                : 'Conectando ao observador read-only…'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <label className="inline-flex items-center gap-2 text-xs font-medium text-slate-700 cursor-pointer">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="rounded border-slate-300"
              />
              Auto-atualizar (5s)
            </label>
            <button
              type="button"
              onClick={() => void fetchLiveMonitor()}
              disabled={loadingLive}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 bg-white text-slate-700 text-xs font-medium hover:bg-slate-50 disabled:opacity-60 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingLive ? 'animate-spin' : ''}`} />
              Atualizar Agora
            </button>
          </div>
        </div>

        {liveError && (
          <div className="mt-4 p-3 rounded-md bg-red-50 border border-red-200 text-xs text-red-800 font-mono">
            {liveError}
          </div>
        )}

        {liveMonitor && (
          <div className="space-y-5 mt-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 rounded-md bg-slate-50 border border-slate-200">
                <div className="text-xs text-slate-500">Phase 01 · SHA-256</div>
                <div className="font-mono text-lg font-semibold text-slate-900 tabular-nums">
                  {liveMonitor.checkpoints.phase01_sha256_count}
                </div>
              </div>
              <div className="p-3 rounded-md bg-slate-50 border border-slate-200">
                <div className="text-xs text-slate-500">Phase 03 · ICP / Cofre</div>
                <div className="font-mono text-lg font-semibold text-slate-900 tabular-nums">
                  {liveMonitor.checkpoints.phase03_icp_count}
                </div>
              </div>
              <div className="p-3 rounded-md bg-slate-50 border border-slate-200">
                <div className="text-xs text-slate-500">Phase 04 · Descompactação</div>
                <div className="font-mono text-lg font-semibold text-slate-900 tabular-nums">
                  {liveMonitor.checkpoints.phase04_unpack_count}
                </div>
              </div>
              <div className="p-3 rounded-md bg-slate-50 border border-slate-200">
                <div className="text-xs text-slate-500">Banco Organizado (F:\)</div>
                <div className="font-mono text-sm font-semibold text-slate-900 mt-1">
                  {liveMonitor.organized_db_exists
                    ? `PRONTO (${liveMonitor.organized_db_bytes} B)`
                    : 'Aguardando Fase 08…'}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 border-b border-slate-200 pb-3">
              {(
                [
                  ['all', `Todos os Passos (${liveMonitor.steps.length})`],
                  ['failures', `Falhas & Alertas (${liveMonitor.failures_and_alerts.length})`],
                  ['checkpoints', 'Checkpoints'],
                  ['auditor', 'Diário do Auditor'],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setLogFilter(id)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium cursor-pointer transition-colors ${
                    logFilter === id
                      ? 'bg-slate-900 text-white'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {logFilter === 'auditor' ? (
              <pre className="p-4 rounded-md bg-slate-900 text-slate-100 text-xs font-mono whitespace-pre-wrap max-h-96 overflow-y-auto">
                {liveMonitor.journal_markdown || 'Diário do auditor ainda sem registros.'}
              </pre>
            ) : logFilter === 'failures' ? (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {liveMonitor.failures_and_alerts.map((al, idx) => (
                  <div
                    key={`${al.title}-${idx}`}
                    className={`p-3 rounded-md border text-xs ${
                      al.status === 'FAIL'
                        ? 'bg-red-50 border-red-200 text-red-900'
                        : al.status === 'FIXED'
                          ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                          : 'bg-amber-50 border-amber-200 text-amber-900'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 font-semibold">
                      <span className="inline-flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        [{al.status}] {al.phase} · {al.title}
                      </span>
                      <span className="font-mono opacity-75">{al.ts_utc}</span>
                    </div>
                    <div className="mt-1 font-mono break-all">{al.detail}</div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="overflow-x-auto max-h-96 overflow-y-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-500 uppercase">
                      <th className="py-2 pr-3">UTC</th>
                      <th className="py-2 px-3">Fase</th>
                      <th className="py-2 px-3">Passo / Evento</th>
                      <th className="py-2 px-3">Status</th>
                      <th className="py-2 pl-3">Detalhes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {liveMonitor.steps
                      .filter((st) =>
                        logFilter === 'checkpoints' ? st.step.startsWith('CHECKPOINT:') : true,
                      )
                      .map((st, idx) => (
                        <tr key={`${st.step}-${idx}`} className="hover:bg-slate-50">
                          <td className="py-2 pr-3 whitespace-nowrap text-slate-500">{st.ts_utc}</td>
                          <td className="py-2 px-3 whitespace-nowrap text-slate-800">{st.phase}</td>
                          <td className="py-2 px-3 whitespace-nowrap font-semibold text-slate-900">
                            {st.step}
                          </td>
                          <td className="py-2 px-3 whitespace-nowrap">
                            <span
                              className={
                                st.status === 'FAIL'
                                  ? 'text-red-700 font-semibold'
                                  : 'text-emerald-700 font-semibold'
                              }
                            >
                              {st.status}
                            </span>
                          </td>
                          <td className="py-2 pl-3 text-slate-600 break-all">{st.detail}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>

      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Desbloqueio Não-Bloqueante · Consulta `Senhas.md` &amp; Cofre F:\
            </p>
            <h3 className="text-lg font-semibold text-slate-900 mt-1 flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-amber-600 shrink-0" />
              Arquivos ZIP Protegidos por Senha (`ZIP_PASSWORD_PROTECTED`)
            </h3>
            <p className="text-xs text-slate-600 mt-1">
              O motor principal não para durante o processamento; informe a senha abaixo ou use a referência de{' '}
              <span className="font-mono">Senhas.md</span> para extrair em <span className="font-mono">F:\</span> com SHA-256.
            </p>
          </div>
          <button
            type="button"
            onClick={() => void fetchProtectedZips()}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-300 bg-white text-slate-700 text-xs font-medium hover:bg-slate-50 cursor-pointer shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reescanear ZIPs
          </button>
        </div>

        {unlockFeedback && (
          <div className="mt-4 p-3 rounded-md bg-slate-50 border border-slate-200 text-xs font-mono text-slate-800 break-all">
            {unlockFeedback}
          </div>
        )}

        {protectedZips && (
          <div className="space-y-3 mt-4">
            {protectedZips.items.map((item) => (
              <div
                key={item.zip_path}
                className={`p-4 rounded-md border ${
                  item.status === 'UNLOCKED'
                    ? 'bg-emerald-50/60 border-emerald-200'
                    : 'bg-amber-50/60 border-amber-200'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      {item.status === 'UNLOCKED' ? (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700">
                          <Unlock className="w-3.5 h-3.5" />
                          DESBLOQUEADO ({item.extracted_files_count} arquivos)
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-800">
                          <Lock className="w-3.5 h-3.5" />
                          ALERTA: PROTEGIDO POR SENHA ({item.encrypted_members_count} membros)
                        </span>
                      )}
                      {item.operation && (
                        <span className="text-xs px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700">
                          {item.operation}
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-mono text-slate-900 break-all">{item.zip_path}</div>
                    {item.extracted_dir && (
                      <div className="text-xs font-mono text-emerald-800 break-all">
                        Extraído em: {item.extracted_dir}
                      </div>
                    )}
                  </div>

                  {item.status !== 'UNLOCKED' && (
                    <div className="flex flex-wrap items-center gap-2 shrink-0">
                      <input
                        type="password"
                        placeholder="Informar senha..."
                        value={zipPasswords[item.zip_path] ?? ''}
                        onChange={(e) =>
                          setZipPasswords((prev) => ({ ...prev, [item.zip_path]: e.target.value }))
                        }
                        className="px-2.5 py-1.5 text-xs rounded-md border border-slate-300 bg-white font-mono w-40"
                      />
                      <button
                        type="button"
                        disabled={unlockingPath === item.zip_path}
                        onClick={() => void handleUnlockZip(item.zip_path, false)}
                        className="px-3 py-1.5 rounded-md bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
                      >
                        Desbloquear
                      </button>
                      {item.has_lookup_password && (
                        <button
                          type="button"
                          disabled={unlockingPath === item.zip_path}
                          onClick={() => void handleUnlockZip(item.zip_path, true)}
                          className="px-3 py-1.5 rounded-md bg-amber-600 text-white text-xs font-medium hover:bg-amber-700 disabled:opacity-60 cursor-pointer"
                        >
                          Usar Senhas.md
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
