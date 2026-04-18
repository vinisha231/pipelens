/**
 * HTML report generator for pipelens.
 *
 * Produces a self-contained single-file HTML report with:
 *   - Inline CSS (no external dependencies — works offline)
 *   - Summary dashboard with severity counts
 *   - Per-file finding tables with severity color coding
 *   - Expandable finding details (evidence + fix + AI suggestion)
 *   - Score visualization with CSS progress bars
 *   - Dark-mode-friendly color scheme
 */

import type { AuditReport, AuditResult, AuditFinding, Severity } from '../types/index.js';
import { renderScoreBar } from '../scoring/engine.js';
import { PIPELENS_VERSION } from '../constants/index.js';

// ---------------------------------------------------------------------------
// CSS (inline — no external dependencies)
// ---------------------------------------------------------------------------

const CSS = `
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #22263a;
    --border: #2e3250;
    --text: #e2e8f0;
    --text-dim: #718096;
    --text-code: #a8b5c4;
    --critical: #ff4d4d;
    --high: #ff8c42;
    --medium: #ffd166;
    --low: #4ecdc4;
    --info: #718096;
    --success: #2ecc71;
    --accent: #6eb6ff;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1rem; }
  header { text-align: center; padding: 2.5rem 0 2rem; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
  header h1 { font-size: 2.5rem; color: var(--accent); letter-spacing: 0.15em; font-weight: 900; }
  header .subtitle { color: var(--text-dim); margin-top: 0.5rem; }
  header .version { font-size: 0.8rem; color: var(--text-dim); margin-top: 0.25rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .summary-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .summary-card .count { font-size: 2rem; font-weight: 900; }
  .summary-card .label { font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.25rem; }
  .critical-count { color: var(--critical); }
  .high-count { color: var(--high); }
  .medium-count { color: var(--medium); }
  .low-count { color: var(--low); }
  .info-count { color: var(--info); }
  .score-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }
  .score-card h3 { margin-bottom: 1rem; color: var(--text-dim); text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.1em; }
  .score-value { font-size: 3rem; font-weight: 900; }
  .score-bar-container { background: var(--surface2); border-radius: 99px; height: 12px; margin-top: 0.75rem; overflow: hidden; }
  .score-bar { height: 100%; border-radius: 99px; transition: width 0.8s ease; }
  .score-excellent .score-value, .score-excellent .score-bar { color: #2ecc71; background: #2ecc71; }
  .score-good .score-value, .score-good .score-bar { color: #3498db; background: #3498db; }
  .score-fair .score-value, .score-fair .score-bar { color: var(--medium); background: var(--medium); }
  .score-poor .score-value, .score-poor .score-bar { color: var(--high); background: var(--high); }
  .score-critical-band .score-value, .score-critical-band .score-bar { color: var(--critical); background: var(--critical); }
  .file-section { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .file-header { background: var(--surface2); padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .file-path { font-family: var(--mono); font-size: 0.9rem; color: var(--accent); font-weight: 600; }
  .file-meta { font-size: 0.8rem; color: var(--text-dim); }
  .file-score-badge { font-size: 0.85rem; font-weight: 700; padding: 0.2rem 0.75rem; border-radius: 99px; background: var(--bg); }
  .finding { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border); }
  .finding:last-child { border-bottom: none; }
  .finding-header { display: flex; align-items: flex-start; gap: 0.75rem; margin-bottom: 0.5rem; }
  .severity-badge { font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.6rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.08em; white-space: nowrap; flex-shrink: 0; }
  .sev-critical { background: rgba(255,77,77,0.2); color: var(--critical); border: 1px solid var(--critical); }
  .sev-high { background: rgba(255,140,66,0.2); color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: rgba(255,209,102,0.2); color: var(--medium); border: 1px solid var(--medium); }
  .sev-low { background: rgba(78,205,196,0.2); color: var(--low); border: 1px solid var(--low); }
  .sev-info { background: rgba(113,128,150,0.2); color: var(--info); border: 1px solid var(--info); }
  .finding-title { font-weight: 600; color: var(--text); }
  .finding-id { font-family: var(--mono); font-size: 0.8rem; color: var(--text-dim); margin-left: auto; flex-shrink: 0; }
  .finding-description { color: var(--text-dim); font-size: 0.9rem; margin-top: 0.5rem; line-height: 1.5; }
  details { margin-top: 0.75rem; }
  summary { cursor: pointer; font-size: 0.85rem; color: var(--accent); font-weight: 600; list-style: none; display: flex; align-items: center; gap: 0.4rem; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: '▶'; font-size: 0.7rem; transition: transform 0.2s; }
  details[open] summary::before { transform: rotate(90deg); }
  .detail-content { margin-top: 0.75rem; padding: 0.75rem 1rem; background: var(--bg); border-radius: 6px; border: 1px solid var(--border); }
  .detail-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-dim); margin-bottom: 0.4rem; }
  pre { font-family: var(--mono); font-size: 0.82rem; color: var(--text-code); white-space: pre-wrap; word-break: break-all; }
  .fix-content { color: #2ecc71; }
  .ai-badge { display: inline-flex; align-items: center; gap: 0.3rem; font-size: 0.75rem; font-weight: 700; color: var(--accent); background: rgba(110,182,255,0.1); border: 1px solid var(--accent); border-radius: 4px; padding: 0.15rem 0.5rem; margin-bottom: 0.5rem; }
  .ai-content { color: var(--text); font-size: 0.88rem; }
  .no-findings { padding: 2rem 1.5rem; text-align: center; color: var(--success); font-weight: 600; }
  .ai-narrative { background: var(--surface); border: 1px solid var(--accent); border-radius: 8px; padding: 1.5rem; margin-top: 2rem; }
  .ai-narrative h3 { color: var(--accent); margin-bottom: 1rem; font-size: 1.1rem; }
  .ai-narrative-content { color: var(--text); font-size: 0.9rem; line-height: 1.7; }
  .ai-narrative-content h2, .ai-narrative-content h3 { color: var(--text); margin: 1rem 0 0.5rem; }
  .ai-narrative-content ul, .ai-narrative-content ol { padding-left: 1.5rem; margin: 0.5rem 0; }
  .ai-narrative-content code { font-family: var(--mono); font-size: 0.85em; background: var(--bg); padding: 0.1em 0.3em; border-radius: 3px; }
  .ai-narrative-content pre { padding: 0.75rem; background: var(--bg); border-radius: 6px; overflow-x: auto; }
  footer { text-align: center; padding: 2rem 0; color: var(--text-dim); font-size: 0.8rem; border-top: 1px solid var(--border); margin-top: 3rem; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
`;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/** Escapes HTML special characters to prevent XSS in report content */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Returns the CSS class name for a severity level */
function severityClass(severity: Severity): string {
  return `sev-${severity}`;
}

/** Returns the score band CSS class */
function scoreBandClass(score: number): string {
  if (score >= 90) return 'score-excellent';
  if (score >= 75) return 'score-good';
  if (score >= 50) return 'score-fair';
  if (score >= 25) return 'score-poor';
  return 'score-critical-band';
}

/** Returns the score label */
function scoreLabel(score: number): string {
  if (score >= 90) return 'EXCELLENT';
  if (score >= 75) return 'GOOD';
  if (score >= 50) return 'FAIR';
  if (score >= 25) return 'POOR';
  return 'CRITICAL';
}

// ---------------------------------------------------------------------------
// HTML rendering functions
// ---------------------------------------------------------------------------

function renderFindingHTML(finding: AuditFinding): string {
  const hasDetails = finding.evidence || finding.fix || finding.aiSuggestion;

  return `
    <div class="finding">
      <div class="finding-header">
        <span class="severity-badge ${severityClass(finding.severity)}">${finding.severity}</span>
        <span class="finding-title">${escapeHtml(finding.title)}</span>
        <span class="finding-id">${escapeHtml(finding.id)}${finding.line ? ` · line ${finding.line}` : ''}</span>
      </div>
      <div class="finding-description">${escapeHtml(finding.description)}</div>
      ${hasDetails ? `
      <details>
        <summary>Details & Fix</summary>
        <div class="detail-content">
          ${finding.evidence ? `
            <div class="detail-label">Evidence</div>
            <pre>${escapeHtml(finding.evidence)}</pre>
          ` : ''}
          ${finding.fix ? `
            <div class="detail-label" style="margin-top:0.75rem">Suggested Fix</div>
            <pre class="fix-content">${escapeHtml(finding.fix)}</pre>
          ` : ''}
          ${finding.aiSuggestion ? `
            <div style="margin-top:0.75rem">
              <span class="ai-badge">✦ AI Suggestion</span>
              <div class="ai-content">${escapeHtml(finding.aiSuggestion)}</div>
            </div>
          ` : ''}
          ${finding.references?.length ? `
            <div class="detail-label" style="margin-top:0.75rem">References</div>
            ${finding.references.map(r => `<a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(r)}</a>`).join('<br>')}
          ` : ''}
        </div>
      </details>` : ''}
    </div>`;
}

function renderFileSectionHTML(result: AuditResult): string {
  const relPath = result.target.replace(process.cwd(), '.');
  const bandClass = scoreBandClass(result.score);
  const label = scoreLabel(result.score);

  return `
  <div class="file-section">
    <div class="file-header">
      <span class="file-path">${escapeHtml(relPath)}</span>
      <span class="file-meta">${result.analyzerType} · ${result.findings.length} finding(s) · ${result.duration}ms</span>
      <span class="file-score-badge ${bandClass}" style="font-size:0.85rem">
        ${result.score}/100 ${label}
      </span>
    </div>
    <div class="${bandClass}" style="height:4px">
      <div class="score-bar" style="width:${result.score}%"></div>
    </div>
    ${result.findings.length === 0
      ? '<div class="no-findings">✓ No findings — this file looks clean!</div>'
      : result.findings.map(renderFindingHTML).join('')
    }
  </div>`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generates a complete self-contained HTML report from an AuditReport.
 *
 * @param report  The audit report from the orchestrator
 * @returns       Complete HTML string (single file, no external dependencies)
 */
export function renderHTMLReport(report: AuditReport): string {
  const { summary } = report;
  const generatedAt = new Date().toLocaleString();

  const overallBand = scoreBandClass(summary.overallScore);
  const overallLabel = scoreLabel(summary.overallScore);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>pipelens Security Report</title>
  <style>${CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1>PIPELENS</h1>
    <div class="subtitle">AI-powered Dockerfile &amp; CI/CD Pipeline Security Auditor</div>
    <div class="version">v${PIPELENS_VERSION} · Generated ${escapeHtml(generatedAt)}</div>
  </header>

  <!-- Summary cards -->
  <div class="summary-grid">
    <div class="summary-card">
      <div class="count critical-count">${summary.critical}</div>
      <div class="label">Critical</div>
    </div>
    <div class="summary-card">
      <div class="count high-count">${summary.high}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card">
      <div class="count medium-count">${summary.medium}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card">
      <div class="count low-count">${summary.low}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card">
      <div class="count info-count">${summary.info}</div>
      <div class="label">Info</div>
    </div>
    <div class="summary-card">
      <div class="count">${summary.totalFindings}</div>
      <div class="label">Total</div>
    </div>
  </div>

  <!-- Overall score -->
  <div class="score-card ${overallBand}">
    <h3>Overall Security Score</h3>
    <div style="display:flex;align-items:baseline;gap:0.5rem">
      <span class="score-value">${summary.overallScore}</span>
      <span style="color:var(--text-dim)">/100 &nbsp;${overallLabel}</span>
    </div>
    <div class="score-bar-container">
      <div class="score-bar" style="width:${summary.overallScore}%"></div>
    </div>
  </div>

  <!-- Per-file sections -->
  ${report.results.map(renderFileSectionHTML).join('\n')}

  <!-- AI narrative -->
  ${report.aiNarrative ? `
  <div class="ai-narrative">
    <h3>✦ AI Analysis</h3>
    <div class="ai-narrative-content">${escapeHtml(report.aiNarrative).replace(/\n/g, '<br>')}</div>
  </div>` : ''}

  <footer>
    Generated by <a href="https://github.com/vinisha231/pipelens" target="_blank">pipelens</a> v${PIPELENS_VERSION}
    &nbsp;·&nbsp; ${escapeHtml(generatedAt)}
  </footer>
</div>
</body>
</html>`;
}
