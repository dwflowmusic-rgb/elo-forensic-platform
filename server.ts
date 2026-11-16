import crypto from 'node:crypto';
import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import express from 'express';
import { createServer as createViteServer } from 'vite';

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO_ROOT = __dirname;
const PYTHON_BIN = process.platform === 'win32' ? 'python' : 'python3';
const PYTHON_PATH_VAL = [path.join(REPO_ROOT, 'src'), REPO_ROOT].join(path.delimiter);
const LAB_BASE_DIR = path.join(os.tmpdir(), 'elo_web_lab');
const DEFAULT_LIVE_DEST = process.env.ELO_ACTIVE_DEST ?? '';
const DEFAULT_JOURNAL_FILE = process.env.ELO_JOURNAL_FILE ?? '';

interface GatesReportPayload {
  all_passed: boolean;
  exit_code: number;
  executed_at_utc: string;
  gates: Array<{
    gate: string;
    title: string;
    passed: boolean;
    elapsed_ms: number;
    detail: string;
  }>;
}

interface EnrichedCasePayload {
  summary: Record<string, unknown>;
  expertOpinionMarkdown: string;
  reproductionScript: string;
  manifestVerification: {
    verified: boolean;
    checked_files: number;
    mismatches: string[];
  };
}

let cachedGatesReport: GatesReportPayload | null = null;
let cachedActiveCase: EnrichedCasePayload | null = null;
let bootstrapPromise: Promise<void> | null = null;

function sanitizeCaseId(raw: string): string {
  const cleaned = raw.trim().replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 48);
  return cleaned.length > 0 ? cleaned : 'CASO-EDRM20-LAB';
}

async function getInstallerInfo(filename = 'materialize_elo_platform.py'): Promise<{
  filename: string;
  sizeBytes: number;
  sha256: string;
}> {
  const installerPath = path.join(REPO_ROOT, filename);
  const buf = await fs.readFile(installerPath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  return {
    filename,
    sizeBytes: buf.byteLength,
    sha256,
  };
}

async function runPythonGates(): Promise<GatesReportPayload> {
  const scriptPath = path.join(REPO_ROOT, 'tools', 'run_forensic_gates.py');
  const { stdout } = await execFileAsync(PYTHON_BIN, [scriptPath, '--json'], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      PYTHONPATH: PYTHON_PATH_VAL,
      PYTHONHASHSEED: '42',
    },
    maxBuffer: 16 * 1024 * 1024,
  });
  const parsed = JSON.parse(stdout.trim()) as Omit<GatesReportPayload, 'executed_at_utc'>;
  const enriched: GatesReportPayload = {
    ...parsed,
    executed_at_utc: new Date().toISOString(),
  };
  cachedGatesReport = enriched;
  return enriched;
}

async function runSyntheticCasePipeline(caseIdInput: string): Promise<EnrichedCasePayload> {
  const caseId = sanitizeCaseId(caseIdInput);
  const runStamp = Date.now().toString(36);
  const caseRoot = path.join(LAB_BASE_DIR, `${caseId}_${runStamp}`);
  const hdPath = path.join(caseRoot, 'unknown_forensic_hd');
  const wsPath = path.join(caseRoot, 'isolated_workspace');

  await fs.mkdir(caseRoot, { recursive: true });

  await execFileAsync(
    PYTHON_BIN,
    [
      '-c',
      'import sys; from pathlib import Path; from tests.e2e_synthetic import materialize_synthetic_unknown_forensic_hd; materialize_synthetic_unknown_forensic_hd(Path(sys.argv[1]))',
      hdPath,
    ],
    {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        PYTHONPATH: PYTHON_PATH_VAL,
      },
    },
  );

  const { stdout: runStdout } = await execFileAsync(
    PYTHON_BIN,
    [
      '-m',
      'edrm.interfaces.cli',
      'plug-and-run-all',
      '--case-id',
      caseId,
      '--source',
      hdPath,
      '--workspace',
      wsPath,
      '--json',
    ],
    {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        PYTHONPATH: PYTHON_PATH_VAL,
        PYTHONHASHSEED: '42',
      },
      maxBuffer: 32 * 1024 * 1024,
    },
  );

  const summary = JSON.parse(runStdout.trim()) as Record<string, unknown>;
  const opinionPath = String(summary.expert_opinion_path ?? '');
  const reproPath = String(summary.reproduction_script_path ?? '');

  const [expertOpinionMarkdown, reproductionScript, verifyRes] = await Promise.all([
    opinionPath ? fs.readFile(opinionPath, 'utf-8') : Promise.resolve(''),
    reproPath ? fs.readFile(reproPath, 'utf-8') : Promise.resolve(''),
    execFileAsync(
      PYTHON_BIN,
      ['-m', 'edrm.interfaces.cli', 'verify', '--workspace', wsPath],
      {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          PYTHONPATH: PYTHON_PATH_VAL,
        },
      },
    ),
  ]);

  const manifestVerification = JSON.parse(verifyRes.stdout.trim()) as {
    verified: boolean;
    checked_files: number;
    mismatches: string[];
  };

  const payload: EnrichedCasePayload = {
    summary,
    expertOpinionMarkdown,
    reproductionScript,
    manifestVerification,
  };
  cachedActiveCase = payload;
  return payload;
}

async function loadRealCaseFromDest(destRoot: string): Promise<EnrichedCasePayload | null> {
  if (!destRoot) {
    return null;
  }
  const dbPath = path.join(destRoot, '01_BANCO_ORGANIZADO', 'case_master_organized.sqlite');
  try {
    await fs.access(dbPath);
  } catch {
    return null;
  }
  const scriptPath = path.join(REPO_ROOT, 'tools', 'load_real_case_for_web.py');
  const { stdout } = await execFileAsync(PYTHON_BIN, [scriptPath, '--dest', destRoot], {
    cwd: REPO_ROOT,
    env: { ...process.env, PYTHONPATH: PYTHON_PATH_VAL },
    maxBuffer: 32 * 1024 * 1024,
  });
  const payload = JSON.parse(stdout.trim()) as EnrichedCasePayload;
  cachedActiveCase = payload;
  return payload;
}

async function ensureBootstrapped(): Promise<void> {
  if (cachedGatesReport && cachedActiveCase) {
    return;
  }
  if (!bootstrapPromise) {
    bootstrapPromise = (async () => {
      try {
        await Promise.all([
          cachedGatesReport ? Promise.resolve(cachedGatesReport) : runPythonGates(),
          cachedActiveCase
            ? Promise.resolve(cachedActiveCase)
            : (async () => {
                const realCase = await loadRealCaseFromDest(DEFAULT_LIVE_DEST);
                if (realCase) {
                  return realCase;
                }
                return runSyntheticCasePipeline('CASO-PENAL-EDRM20');
              })(),
        ]);
      } finally {
        bootstrapPromise = null;
      }
    })();
  }
  await bootstrapPromise;
}

async function startServer(): Promise<void> {
  const app = express();
  const port = 3000;

  app.use(express.json({ limit: '2mb' }));

  // Trigger pre-warm in background on startup so initial UI render is instantaneous
  void ensureBootstrapped().catch((err: unknown) => {
    console.error('Initial forensic pre-warm failed:', err);
  });

  app.get('/api/bootstrap', async (_req, res) => {
    try {
      await ensureBootstrapped();
      const [installerInfo, docsInstallerInfo, cliInstallerInfo] = await Promise.all([
        getInstallerInfo('materialize_elo_platform.py'),
        getInstallerInfo('materialize_docs.py'),
        getInstallerInfo('install_elo.py'),
      ]);
      res.json({
        gatesReport: cachedGatesReport,
        activeCase: cachedActiveCase,
        installerInfo,
        docsInstallerInfo,
        cliInstallerInfo,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/gates/run', async (_req, res) => {
    try {
      const report = await runPythonGates();
      res.json(report);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/cases/run-synthetic', async (req, res) => {
    try {
      const requestedCaseId =
        typeof req.body?.caseId === 'string' ? req.body.caseId : 'CASO-PENAL-EDRM20';
      const payload = await runSyntheticCasePipeline(requestedCaseId);
      res.json(payload);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/cases/verify-manifest', async (_req, res) => {
    try {
      await ensureBootstrapped();
      const wsPath = String(cachedActiveCase?.summary?.workspace_root ?? '');
      if (!wsPath) {
        res.status(400).json({ error: 'Nenhum workspace ativo encontrado.' });
        return;
      }
      const { stdout } = await execFileAsync(
        PYTHON_BIN,
        ['-m', 'edrm.interfaces.cli', 'verify', '--workspace', wsPath],
        {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            PYTHONPATH: PYTHON_PATH_VAL,
          },
        },
      );
      const parsed = JSON.parse(stdout.trim()) as {
        verified: boolean;
        checked_files: number;
        mismatches: string[];
      };
      if (cachedActiveCase) {
        cachedActiveCase.manifestVerification = parsed;
      }
      res.json(parsed);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/cases/search', async (req, res) => {
    try {
      await ensureBootstrapped();
      const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      const topN = Math.min(Math.max(Number(req.query.topN ?? 10) || 10, 1), 25);
      if (!query) {
        res.json({ query: '', hits: [] });
        return;
      }
      const wsPath = String(cachedActiveCase?.summary?.workspace_root ?? '');
      const { stdout } = await execFileAsync(
        PYTHON_BIN,
        [
          '-m',
          'edrm.interfaces.cli',
          'search',
          '--workspace',
          wsPath,
          '--query',
          query,
          '--top-n',
          String(topN),
        ],
        {
          cwd: REPO_ROOT,
          env: {
            ...process.env,
            PYTHONPATH: PYTHON_PATH_VAL,
          },
        },
      );
      const hits = JSON.parse(stdout.trim()) as unknown[];
      res.json({ query, hits });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/cases/live-monitor', async (req, res) => {
    try {
      const destParam =
        typeof req.query.dest === 'string' && req.query.dest.trim().length > 0
          ? req.query.dest.trim()
          : DEFAULT_LIVE_DEST;
      const scriptPath = path.join(REPO_ROOT, 'tools', 'monitor_elo_run.py');
      const args = [scriptPath, '--dest', destParam, '--json'];
      if (DEFAULT_JOURNAL_FILE) {
        args.push('--journal-file', DEFAULT_JOURNAL_FILE);
      }
      const { stdout } = await execFileAsync(PYTHON_BIN, args, {
        cwd: REPO_ROOT,
        env: {
          ...process.env,
          PYTHONPATH: PYTHON_PATH_VAL,
        },
        maxBuffer: 16 * 1024 * 1024,
      });
      res.json(JSON.parse(stdout.trim()));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/cases/protected-zips', async (req, res) => {
    try {
      const destParam =
        typeof req.query.dest === 'string' && req.query.dest.trim().length > 0
          ? req.query.dest.trim()
          : DEFAULT_LIVE_DEST;
      const scriptPath = path.join(REPO_ROOT, 'tools', 'unlock_protected_zip.py');
      const { stdout } = await execFileAsync(
        PYTHON_BIN,
        [scriptPath, '--dest', destParam, '--scan'],
        {
          cwd: REPO_ROOT,
          env: { ...process.env, PYTHONPATH: PYTHON_PATH_VAL },
          maxBuffer: 8 * 1024 * 1024,
        },
      );
      res.json(JSON.parse(stdout.trim()));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.post('/api/cases/unlock-zip', async (req, res) => {
    try {
      const body = (req.body ?? {}) as {
        dest?: unknown;
        zipPath?: unknown;
        password?: unknown;
        useLookup?: unknown;
      };
      const destParam =
        typeof body.dest === 'string' && body.dest.trim().length > 0
          ? body.dest.trim()
          : DEFAULT_LIVE_DEST;
      const zipPath = typeof body.zipPath === 'string' ? body.zipPath.trim() : '';
      if (!zipPath) {
        res.status(400).json({ error: 'zipPath é obrigatório.' });
        return;
      }
      const scriptPath = path.join(REPO_ROOT, 'tools', 'unlock_protected_zip.py');
      const args = [scriptPath, '--dest', destParam, '--zip-path', zipPath];
      if (typeof body.password === 'string' && body.password.length > 0) {
        args.push('--password', body.password);
      }
      if (body.useLookup) {
        args.push('--use-lookup');
      }
      const { stdout } = await execFileAsync(PYTHON_BIN, args, {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONPATH: PYTHON_PATH_VAL },
        maxBuffer: 8 * 1024 * 1024,
      });
      res.json(JSON.parse(stdout.trim()));
    } catch (err: unknown) {
      const execErr = err as { stdout?: string; message?: string };
      if (execErr.stdout) {
        try {
          const parsed = JSON.parse(execErr.stdout.trim()) as Record<string, unknown>;
          res.status(400).json(parsed);
          return;
        } catch {
          // fallback para mensagem bruta
        }
      }
      const message = err instanceof Error ? err.message : String(err);
      res.status(400).json({ unlocked: false, error: message });
    }
  });

  app.post('/api/cases/ignore-zip', async (req, res) => {
    try {
      const body = (req.body ?? {}) as {
        dest?: unknown;
        zipPath?: unknown;
        reason?: unknown;
      };
      const destParam =
        typeof body.dest === 'string' && body.dest.trim().length > 0
          ? body.dest.trim()
          : DEFAULT_LIVE_DEST;
      const zipPath = typeof body.zipPath === 'string' ? body.zipPath.trim() : '';
      if (!zipPath) {
        res.status(400).json({ error: 'zipPath é obrigatório.' });
        return;
      }
      const scriptPath = path.join(REPO_ROOT, 'tools', 'unlock_protected_zip.py');
      const args = [scriptPath, '--dest', destParam, '--zip-path', zipPath, '--ignore'];
      if (typeof body.reason === 'string' && body.reason.trim().length > 0) {
        args.push('--reason', body.reason.trim());
      }
      const { stdout } = await execFileAsync(PYTHON_BIN, args, {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONPATH: PYTHON_PATH_VAL },
        maxBuffer: 4 * 1024 * 1024,
      });
      res.json(JSON.parse(stdout.trim()));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(400).json({ ignored: false, error: message });
    }
  });

  app.post('/api/cases/enrich-unlocked', async (req, res) => {
    try {
      const body = (req.body ?? {}) as { dest?: unknown };
      const destParam =
        typeof body.dest === 'string' && body.dest.trim().length > 0
          ? body.dest.trim()
          : DEFAULT_LIVE_DEST;
      const scriptPath = path.join(REPO_ROOT, 'tools', 'enrich_unlocked_and_ocr.py');
      const { stdout } = await execFileAsync(
        PYTHON_BIN,
        [scriptPath, '--dest', destParam, '--include-vault-ocr'],
        {
        cwd: REPO_ROOT,
        env: { ...process.env, PYTHONPATH: PYTHON_PATH_VAL },
        maxBuffer: 8 * 1024 * 1024,
      });
      await loadRealCaseFromDest(destParam);
      res.json(JSON.parse(stdout.trim()));
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ ok: false, error: message });
    }
  });

  app.get('/api/download/installer', async (_req, res) => {
    try {
      const installerPath = path.join(REPO_ROOT, 'materialize_elo_platform.py');
      res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="materialize_elo_platform.py"',
      );
      const content = await fs.readFile(installerPath);
      res.send(content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/download/docs-installer', async (_req, res) => {
    try {
      const docsInstallerPath = path.join(REPO_ROOT, 'materialize_docs.py');
      res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="materialize_docs.py"',
      );
      const content = await fs.readFile(docsInstallerPath);
      res.send(content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/download/cli-installer', async (_req, res) => {
    try {
      const cliInstallerPath = path.join(REPO_ROOT, 'install_elo.py');
      res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="install_elo.py"',
      );
      const content = await fs.readFile(cliInstallerPath);
      res.send(content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  app.get('/api/download/dossier', async (_req, res) => {
    try {
      await ensureBootstrapped();
      const dossierPath = String(cachedActiveCase?.summary?.offline_html_dossier_path ?? '');
      if (!dossierPath) {
        res.status(404).json({ error: 'Dossiê HTML5 ainda não gerado.' });
        return;
      }
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader(
        'Content-Disposition',
        'attachment; filename="phase07_dossie_interativo_offline.html"',
      );
      const content = await fs.readFile(dossierPath);
      res.send(content);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(REPO_ROOT, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`ELO Forensic Platform Server listening on http://0.0.0.0:${port}`);
  });
}

void startServer();
