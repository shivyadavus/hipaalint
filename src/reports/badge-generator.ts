import type { ComplianceScore, ScoreBand } from '../engine/types.js';

const BAND_COLORS: Record<ScoreBand, string> = {
  compliant: '00c853', // Green
  needs_improvement: 'ff9800', // Amber
  at_risk: 'ff5722', // Deep Orange
  critical: 'd32f2f', // Red
};

const BAND_LABELS: Record<ScoreBand, string> = {
  compliant: 'compliant',
  needs_improvement: 'needs improvement',
  at_risk: 'at risk',
  critical: 'critical',
};

/**
 * Generate a shield badge URL for the HipaaLint Score.
 * Uses shields.io for badge rendering.
 */
export function generateBadgeUrl(score: ComplianceScore): string {
  const color = BAND_COLORS[score.band];
  const label = 'HipaaLint';
  const message = `${score.overallScore}%2F100 · ${BAND_LABELS[score.band]}`;

  return `https://img.shields.io/badge/${encodeURIComponent(label)}-${message}-${color}?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDFMMyA1djZjMCA1LjU1IDMuODQgMTAuNzQgOSAxMiA1LjE2LTEuMjYgOS02LjQ1IDktMTJWNWwtOS00eiIgZmlsbD0id2hpdGUiLz48L3N2Zz4=`;
}

/**
 * Generate markdown badge snippet.
 */
export function generateBadgeMarkdown(score: ComplianceScore, repoUrl?: string): string {
  const badgeUrl = generateBadgeUrl(score);
  const linkUrl = repoUrl || '#';

  return `[![HipaaLint Score](${badgeUrl})](${linkUrl})`;
}

/**
 * Generate the badge as SVG (for self-hosted use).
 */
export function generateBadgeSvg(score: ComplianceScore): string {
  const color = `#${BAND_COLORS[score.band]}`;
  const label = 'HipaaLint';
  const value = `${score.overallScore}/100`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="28" viewBox="0 0 240 28">
  <defs>
    <linearGradient id="g" x2="0" y2="100%">
      <stop offset="0" stop-color="#fff" stop-opacity=".15"/>
      <stop offset="1" stop-opacity=".15"/>
    </linearGradient>
  </defs>
  <rect rx="4" width="240" height="28" fill="#555"/>
  <rect rx="4" x="140" width="100" height="28" fill="${color}"/>
  <rect rx="4" width="240" height="28" fill="url(#g)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,sans-serif" font-size="11">
    <text x="70" y="19.5" fill="#fff">${label}</text>
    <text x="190" y="19.5" fill="#fff">${value}</text>
  </g>
</svg>`;
}
