import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  countCriticalParityAnomalies,
  describeParityState,
  formatByteSize,
  formatCentsToBrl,
  formatMicrodegrees,
  shortenSha256,
  summarizeFinancialLedgerCents,
  summarizeGateMetrics,
} from './forensicModel.ts';

describe('forensicModel pure deterministic logic', () => {
  it('formats integer cents into exact BRL strings without float drift', () => {
    assert.equal(formatCentsToBrl(0), 'R$ 0,00');
    assert.equal(formatCentsToBrl(154090), 'R$ 1.540,90');
    assert.equal(formatCentsToBrl(123456789), 'R$ 1.234.567,89');
    assert.equal(formatCentsToBrl(-32005), '-R$ 320,05');
  });

  it('formats integer microdegrees into 6-decimal coordinates', () => {
    assert.equal(formatMicrodegrees(-23550520), '-23.550520°');
    assert.equal(formatMicrodegrees(-46633308), '-46.633308°');
    assert.equal(formatMicrodegrees(500), '0.000500°');
  });

  it('summarizes SIMBA financial ledger separating duplicate batch inflation in integer cents', () => {
    const summary = summarizeFinancialLedgerCents([
      {
        entry_id: 'FIN-1',
        origin_cn: 'ELO-000001',
        bank_code: '001',
        branch: '1234',
        account: '99887-1',
        holder_tax_id: '123.456.789-00',
        counterparty_tax_id: '98.765.432/0001-10',
        tx_utc: '2026-05-08T11:20:00Z',
        debit_credit: 'D',
        amount_cents: 154090,
        raw_amount_text: 'R$ 1.540,90',
        is_inter_file_duplicate: false,
        locator: 'line=2',
        origin_sha256: 'a'.repeat(64),
      },
      {
        entry_id: 'FIN-2',
        origin_cn: 'ELO-000002',
        bank_code: '001',
        branch: '1234',
        account: '99887-1',
        holder_tax_id: '123.456.789-00',
        counterparty_tax_id: '98.765.432/0001-10',
        tx_utc: '2026-05-08T11:20:00Z',
        debit_credit: 'D',
        amount_cents: 154090,
        raw_amount_text: 'R$ 1.540,90',
        is_inter_file_duplicate: true,
        locator: 'line=2',
        origin_sha256: 'b'.repeat(64),
      },
      {
        entry_id: 'FIN-3',
        origin_cn: 'ELO-000002',
        bank_code: '001',
        branch: '1234',
        account: '99887-1',
        holder_tax_id: '123.456.789-00',
        counterparty_tax_id: '11.222.333/0001-81',
        tx_utc: '2026-05-09T09:15:00Z',
        debit_credit: 'D',
        amount_cents: 32000,
        raw_amount_text: 'R$ 320,00',
        is_inter_file_duplicate: false,
        locator: 'line=3',
        origin_sha256: 'b'.repeat(64),
      },
    ]);

    assert.equal(summary.grossTotalCents, 340180);
    assert.equal(summary.duplicateInflationCents, 154090);
    assert.equal(summary.netAuditedTotalCents, 186090);
    assert.equal(summary.duplicateCount, 1);
  });

  it('truncates SHA-256 hashes deterministically and formats byte sizes', () => {
    const sha = '65492f79a467996e1b6f15a2ccd62a2f6248a1abe64c37fa90c5d14fc87188ae';
    assert.equal(shortenSha256(sha, 10, 6), '65492f79a4…7188ae');
    assert.equal(formatByteSize(512), '512 B');
    assert.match(formatByteSize(4096), /4\.0 KiB/);
  });

  it('evaluates gate metrics and parity matrix defect counts accurately', () => {
    const gm = summarizeGateMetrics([
      { gate: 'G0', title: 'AST Hygiene', passed: true, elapsed_ms: 210, detail: 'ok' },
      { gate: 'G1', title: 'Clean Arch', passed: true, elapsed_ms: 190, detail: 'ok' },
    ]);
    assert.equal(gm.allGreen, true);
    assert.equal(gm.passedCount, 2);
    assert.equal(gm.totalElapsedMs, 400);

    assert.equal(describeParityState('MATCHED_INTACT_HASH').isCriticalDefect, false);
    const crit = countCriticalParityAnomalies([
      {
        finding_id: 'P-1',
        declared_id: 'DECL-1',
        matched_rel_path: null,
        parity_state: 'DECLARED_RAW_NOT_DELIVERED',
        legal_tags: ['TEMA_977_STJ'],
        rationale: 'Omitted',
      },
      {
        finding_id: 'P-2',
        declared_id: 'DECL-2',
        matched_rel_path: 'msgstore.db',
        parity_state: 'MATCHED_INTACT_HASH',
        legal_tags: [],
        rationale: 'Verified',
      },
    ]);
    assert.equal(crit, 1);
  });
});
