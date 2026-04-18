/**
 * Unit tests for the scoring engine.
 *
 * Tests cover:
 *   - calculateScore: basic score calculation with various findings
 *   - Diminishing returns behavior
 *   - calculateSummary: aggregation across multiple results
 *   - sortFindings: ordering by severity then line number
 *   - getScoreBand: correct band for score ranges
 *   - renderScoreBar: correct bar rendering
 */

import { describe, it, expect } from 'vitest';
import {
  calculateScore,
  calculateSummary,
  sortFindings,
  getScoreBand,
  renderScoreBar,
} from '../../src/scoring/engine.js';
import type { AuditFinding, AuditResult } from '../../src/types/index.js';

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

function makeFinding(severity: AuditFinding['severity'], id = 'DF-TEST-001'): AuditFinding {
  return {
    id,
    title: `Test finding ${id}`,
    description: 'Test',
    severity,
  };
}

function makeResult(findings: AuditFinding[], score?: number): AuditResult {
  return {
    target: '/test/Dockerfile',
    analyzerType: 'dockerfile',
    findings,
    score: score ?? calculateScore(findings),
    duration: 100,
    timestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// calculateScore
// ---------------------------------------------------------------------------

describe('calculateScore', () => {
  it('returns 100 for no findings', () => {
    expect(calculateScore([])).toBe(100);
  });

  it('returns a lower score for a critical finding', () => {
    const score = calculateScore([makeFinding('critical')]);
    expect(score).toBeLessThan(100);
    expect(score).toBeGreaterThan(0);
  });

  it('critical finding reduces score more than high', () => {
    const criticalScore = calculateScore([makeFinding('critical')]);
    const highScore = calculateScore([makeFinding('high')]);
    expect(criticalScore).toBeLessThan(highScore);
  });

  it('high reduces score more than medium', () => {
    const highScore = calculateScore([makeFinding('high')]);
    const mediumScore = calculateScore([makeFinding('medium')]);
    expect(highScore).toBeLessThan(mediumScore);
  });

  it('multiple critical findings reduce score further', () => {
    const oneScore = calculateScore([makeFinding('critical')]);
    const twoScore = calculateScore([makeFinding('critical'), makeFinding('critical')]);
    expect(twoScore).toBeLessThan(oneScore);
  });

  it('score never goes below 0', () => {
    const manyFindings = Array(20).fill(null).map(() => makeFinding('critical'));
    const score = calculateScore(manyFindings);
    expect(score).toBeGreaterThanOrEqual(0);
  });

  it('score never goes above 100', () => {
    expect(calculateScore([])).toBeLessThanOrEqual(100);
  });

  it('applies diminishing returns — 5th critical finding adds less penalty than 1st', () => {
    const scores = [1, 2, 3, 4, 5].map((n) =>
      calculateScore(Array(n).fill(null).map(() => makeFinding('critical'))),
    );

    // Each additional finding should reduce the score, but by less each time
    const drops = scores.slice(1).map((s, i) => (scores[i] ?? 0) - s);
    // First drop should be larger than last drop
    expect(drops[0]).toBeGreaterThan(drops[drops.length - 1]!);
  });

  it('info findings have minimal impact', () => {
    const manyInfo = Array(10).fill(null).map(() => makeFinding('info'));
    const score = calculateScore(manyInfo);
    expect(score).toBeGreaterThan(80); // 10 info findings shouldn't tank the score
  });
});

// ---------------------------------------------------------------------------
// calculateSummary
// ---------------------------------------------------------------------------

describe('calculateSummary', () => {
  it('returns zeroed summary for empty results', () => {
    const summary = calculateSummary([]);
    expect(summary.totalFindings).toBe(0);
    expect(summary.critical).toBe(0);
    expect(summary.overallScore).toBe(100);
  });

  it('counts findings by severity correctly', () => {
    const result = makeResult([
      makeFinding('critical'),
      makeFinding('critical'),
      makeFinding('high'),
      makeFinding('medium'),
      makeFinding('low'),
      makeFinding('info'),
    ]);
    const summary = calculateSummary([result]);
    expect(summary.critical).toBe(2);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.info).toBe(1);
    expect(summary.totalFindings).toBe(6);
  });

  it('averages scores across multiple results', () => {
    const r1 = makeResult([], 100);
    const r2 = makeResult([], 60);
    const summary = calculateSummary([r1, r2]);
    expect(summary.overallScore).toBe(80);
  });

  it('aggregates findings across multiple results', () => {
    const r1 = makeResult([makeFinding('critical')]);
    const r2 = makeResult([makeFinding('high'), makeFinding('medium')]);
    const summary = calculateSummary([r1, r2]);
    expect(summary.totalFindings).toBe(3);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// sortFindings
// ---------------------------------------------------------------------------

describe('sortFindings', () => {
  it('sorts critical before high before medium', () => {
    const findings = [
      makeFinding('medium'),
      makeFinding('critical'),
      makeFinding('high'),
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0]?.severity).toBe('critical');
    expect(sorted[1]?.severity).toBe('high');
    expect(sorted[2]?.severity).toBe('medium');
  });

  it('sorts by line number within same severity', () => {
    const findings: AuditFinding[] = [
      { ...makeFinding('high'), line: 10 },
      { ...makeFinding('high'), line: 3 },
      { ...makeFinding('high'), line: 7 },
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0]?.line).toBe(3);
    expect(sorted[1]?.line).toBe(7);
    expect(sorted[2]?.line).toBe(10);
  });

  it('places findings without line numbers at the end of their severity group', () => {
    const findings: AuditFinding[] = [
      { ...makeFinding('high'), line: undefined },
      { ...makeFinding('high'), line: 5 },
    ];
    const sorted = sortFindings(findings);
    expect(sorted[0]?.line).toBe(5);
    expect(sorted[1]?.line).toBeUndefined();
  });

  it('does not mutate the original array', () => {
    const findings = [makeFinding('medium'), makeFinding('critical')];
    const original = [...findings];
    sortFindings(findings);
    expect(findings[0]?.severity).toBe(original[0]?.severity);
  });
});

// ---------------------------------------------------------------------------
// getScoreBand
// ---------------------------------------------------------------------------

describe('getScoreBand', () => {
  it('returns EXCELLENT for 90+', () => {
    expect(getScoreBand(100).label).toBe('EXCELLENT');
    expect(getScoreBand(90).label).toBe('EXCELLENT');
  });

  it('returns GOOD for 75-89', () => {
    expect(getScoreBand(75).label).toBe('GOOD');
    expect(getScoreBand(89).label).toBe('GOOD');
  });

  it('returns FAIR for 50-74', () => {
    expect(getScoreBand(50).label).toBe('FAIR');
    expect(getScoreBand(74).label).toBe('FAIR');
  });

  it('returns POOR for 25-49', () => {
    expect(getScoreBand(25).label).toBe('POOR');
    expect(getScoreBand(49).label).toBe('POOR');
  });

  it('returns CRITICAL for below 25', () => {
    expect(getScoreBand(0).label).toBe('CRITICAL');
    expect(getScoreBand(24).label).toBe('CRITICAL');
  });
});

// ---------------------------------------------------------------------------
// renderScoreBar
// ---------------------------------------------------------------------------

describe('renderScoreBar', () => {
  it('renders full bar for score 100', () => {
    const bar = renderScoreBar(100, 10);
    expect(bar).toBe('██████████');
  });

  it('renders empty bar for score 0', () => {
    const bar = renderScoreBar(0, 10);
    expect(bar).toBe('░░░░░░░░░░');
  });

  it('renders half bar for score 50', () => {
    const bar = renderScoreBar(50, 10);
    expect(bar).toBe('█████░░░░░');
  });

  it('respects custom width', () => {
    const bar = renderScoreBar(100, 20);
    expect(bar).toHaveLength(20);
  });

  it('total length equals width parameter', () => {
    for (const score of [0, 25, 50, 75, 100]) {
      const bar = renderScoreBar(score, 15);
      expect(bar).toHaveLength(15);
    }
  });
});
