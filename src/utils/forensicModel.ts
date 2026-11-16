import type {
  FinancialLedgerEntryRecord,
  GateExecutionItem,
  ParityMatrixRow,
} from '../types/forensic.ts';

/**
 * Formats integer cents (BIGINT) into deterministic BRL string without IEEE-754 float drift.
 */
export function formatCentsToBrl(cents: number): string {
  const isNegative = cents < 0;
  const absCents = Math.abs(Math.trunc(cents));
  const whole = Math.floor(absCents / 100);
  const remainder = absCents % 100;
  const wholeFormatted = whole
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/g, '.');
  const centsFormatted = remainder.toString().padStart(2, '0');
  return `${isNegative ? '-' : ''}R$ ${wholeFormatted},${centsFormatted}`;
}

/**
 * Formats integer microdegrees (lat/lon * 1_000_000) into exact 6-decimal coordinate string.
 */
export function formatMicrodegrees(microdeg: number): string {
  const sign = microdeg < 0 ? '-' : '';
  const absVal = Math.abs(Math.trunc(microdeg));
  const deg = Math.floor(absVal / 1_000_000);
  const frac = (absVal % 1_000_000).toString().padStart(6, '0');
  return `${sign}${deg}.${frac}°`;
}

/**
 * Formats exact integer byte count into human-readable forensic unit while preserving exactness.
 */
export function formatByteSize(bytes: number): string {
  const clean = Math.max(0, Math.trunc(bytes));
  if (clean < 1024) {
    return `${clean} B`;
  }
  if (clean < 1024 * 1024) {
    const kib = (clean / 1024).toFixed(1);
    return `${kib} KiB (${clean.toLocaleString('en-US')} B)`;
  }
  const mib = (clean / (1024 * 1024)).toFixed(2);
  return `${mib} MiB (${clean.toLocaleString('en-US')} B)`;
}

/**
 * Truncates a 64-char SHA-256 hex digest deterministically for compact tabular display.
 */
export function shortenSha256(hex: string, prefixLen = 12, suffixLen = 8): string {
  const trimmed = hex.trim().toLowerCase();
  if (trimmed.length <= prefixLen + suffixLen + 3) {
    return trimmed;
  }
  return `${trimmed.slice(0, prefixLen)}…${trimmed.slice(-suffixLen)}`;
}

/**
 * Computes exact net vs gross financial ledger summary in integer cents, isolating SIMBA duplicates.
 */
export function summarizeFinancialLedgerCents(
  entries: readonly FinancialLedgerEntryRecord[],
): {
  grossTotalCents: number;
  duplicateInflationCents: number;
  netAuditedTotalCents: number;
  duplicateCount: number;
} {
  let grossTotalCents = 0;
  let duplicateInflationCents = 0;
  let duplicateCount = 0;

  for (const entry of entries) {
    const cents = Math.trunc(entry.amount_cents);
    grossTotalCents += cents;
    if (entry.is_inter_file_duplicate) {
      duplicateInflationCents += cents;
      duplicateCount += 1;
    }
  }

  return {
    grossTotalCents,
    duplicateInflationCents,
    netAuditedTotalCents: grossTotalCents - duplicateInflationCents,
    duplicateCount,
  };
}

/**
 * Summarizes gate suite timing and pass ratios.
 */
export function summarizeGateMetrics(gates: readonly GateExecutionItem[]): {
  passedCount: number;
  totalCount: number;
  totalElapsedMs: number;
  allGreen: boolean;
} {
  let passedCount = 0;
  let totalElapsedMs = 0;
  for (const g of gates) {
    if (g.passed) {
      passedCount += 1;
    }
    totalElapsedMs += Math.max(0, Math.trunc(g.elapsed_ms));
  }
  return {
    passedCount,
    totalCount: gates.length,
    totalElapsedMs,
    allGreen: gates.length > 0 && passedCount === gates.length,
  };
}

/**
 * Maps canonical ParityState codes to human-readable forensic labels in Portuguese.
 */
export function describeParityState(stateCode: string): {
  label: string;
  isCriticalDefect: boolean;
} {
  switch (stateCode) {
    case 'MATCHED_INTACT_HASH':
    case 'FULL_PARITY_VERIFIED':
      return { label: 'Paridade Integral Verificada (Hash Exato)', isCriticalDefect: false };
    case 'MATCHED_WITHOUT_ORIGIN_HASH':
    case 'DELIVERED_WITHOUT_STATE_HASH':
      return { label: 'Entregue · Sem Hash Estatal na Origem', isCriticalDefect: true };
    case 'DIVERGENT_HASH_OR_SIZE':
    case 'DELIVERED_HASH_MISMATCH':
      return { label: 'Divergência de Hash Estatal ou Tamanho', isCriticalDefect: true };
    case 'DECLARED_RAW_NOT_DELIVERED':
      return { label: 'Declarado nos Autos · Bruto Omitido', isCriticalDefect: true };
    case 'DELIVERED_ENCRYPTED_OR_CORRUPTED':
      return { label: 'Cifrado sem Chave ou Corrompido', isCriticalDefect: true };
    case 'DELIVERED_UNDOCUMENTED_IN_AUTOS':
    case 'DELIVERED_WITHOUT_FORMAL_ORIGIN':
      return { label: 'Entregue na Mídia · Sem Origem Formal nos Autos', isCriticalDefect: true };
    case 'DEFERRED_AWAITING_PRIMARY_DOC':
      return { label: 'Sobrestado · Aguardando Peça Primária', isCriticalDefect: false };
    default:
      return { label: stateCode, isCriticalDefect: false };
  }
}

/**
 * Counts critical parity anomalies across the 7-state Parity Matrix.
 */
export function countCriticalParityAnomalies(rows: readonly ParityMatrixRow[]): number {
  let count = 0;
  for (const row of rows) {
    if (row.is_judicial_critical || describeParityState(row.parity_state).isCriticalDefect) {
      count += 1;
    }
  }
  return count;
}
