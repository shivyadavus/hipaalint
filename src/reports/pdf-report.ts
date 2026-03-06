import PDFDocument from 'pdfkit';
import { createWriteStream } from 'fs';
import { join } from 'path';
import type { ComplianceReport, ComplianceFinding } from '../engine/types.js';
import { validateOutputDirectory } from '../security/index.js';

const COLORS = {
  primary: '#1a1a2e',
  accent: '#0f3460',
  success: '#0cce6b',
  warning: '#ffa500',
  danger: '#ff3860',
  critical: '#cc0000',
  muted: '#6c757d',
  text: '#2d3748',
  lightBg: '#f7fafc',
};

const BAND_COLORS: Record<string, string> = {
  strong: COLORS.success,
  needs_improvement: COLORS.warning,
  at_risk: COLORS.warning,
  critical: COLORS.danger,
};

const SEVERITY_LABELS: Record<string, { label: string; color: string }> = {
  critical: { label: 'CRITICAL', color: COLORS.critical },
  high: { label: 'HIGH', color: COLORS.danger },
  medium: { label: 'MEDIUM', color: COLORS.warning },
  low: { label: 'LOW', color: COLORS.muted },
  info: { label: 'INFO', color: COLORS.accent },
};

/**
 * Generate a PDF compliance report.
 */
export async function generatePdfReport(
  report: ComplianceReport,
  outputDir: string,
): Promise<string> {
  const validatedDir = validateOutputDirectory(outputDir);
  const filename = `hipaalint-report-${report.generatedAt.split('T')[0]}.pdf`;
  const outputPath = join(validatedDir, filename);

  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 60, bottom: 60, left: 50, right: 50 },
      info: {
        Title: `HipaaLint Report — ${report.projectName}`,
        Author: 'HipaaLint AI',
        Subject: `HIPAA Compliance Report`,
        Creator: `HipaaLint AI v${report.version}`,
      },
    });

    const stream = createWriteStream(outputPath);
    doc.pipe(stream);

    // ── Cover Page ──
    renderCoverPage(doc, report);

    // ── Executive Summary ──
    doc.addPage();
    renderExecutiveSummary(doc, report);

    // ── Domain Scores ──
    doc.addPage();
    renderDomainScores(doc, report);

    // ── Findings ──
    if (report.findings.length > 0) {
      doc.addPage();
      renderFindings(doc, report);
    }

    // ── Recommendations ──
    if (report.recommendations.length > 0) {
      doc.addPage();
      renderRecommendations(doc, report);
    }

    // ── Footer on each page ──
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      doc
        .fontSize(8)
        .fillColor(COLORS.muted)
        .text(
          `HipaaLint AI v${report.version} | Generated ${report.generatedAt} | Page ${i + 1} of ${pages.count}`,
          50,
          doc.page.height - 40,
          { align: 'center', width: doc.page.width - 100 },
        );
    }

    doc.end();
    stream.on('finish', () => resolve(outputPath));
    stream.on('error', reject);
  });
}

function renderCoverPage(doc: PDFKit.PDFDocument, report: ComplianceReport) {
  doc.moveDown(6);

  // Title
  doc.fontSize(32).fillColor(COLORS.primary).text('HipaaLint', { align: 'center' });
  doc
    .fontSize(14)
    .fillColor(COLORS.accent)
    .text('AI-Powered Compliance Report', { align: 'center' });

  doc.moveDown(2);

  // Score badge
  const bandColor = BAND_COLORS[report.score.band] || COLORS.muted;
  doc.fontSize(72).fillColor(bandColor).text(`${report.score.overallScore}`, { align: 'center' });
  doc.fontSize(16).fillColor(COLORS.text).text(`/ 100`, { align: 'center' });

  doc.moveDown(1);
  doc
    .fontSize(18)
    .fillColor(bandColor)
    .text(report.score.band.replace(/_/g, ' ').toUpperCase(), { align: 'center' });

  doc.moveDown(3);

  // Project info
  doc.fontSize(12).fillColor(COLORS.text);
  doc.text(`Project: ${report.projectName}`, { align: 'center' });
  doc.text(`Framework: HIPAA Security Rule`, { align: 'center' });
  doc.text(`Generated: ${new Date(report.generatedAt).toLocaleDateString()}`, { align: 'center' });
  doc.text(`Files Scanned: ${report.score.metadata.filesScanned}`, { align: 'center' });
  doc.text(`Total Findings: ${report.summary.totalFindings}`, { align: 'center' });
}

function renderExecutiveSummary(doc: PDFKit.PDFDocument, report: ComplianceReport) {
  doc.fontSize(20).fillColor(COLORS.primary).text('Executive Summary');
  doc.moveDown(0.5);

  // Line separator
  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(50, doc.y)
    .lineTo(doc.page.width - 50, doc.y)
    .stroke();
  doc.moveDown(1);

  doc.fontSize(11).fillColor(COLORS.text);
  doc.text(
    `This report presents the HIPAA compliance analysis for "${report.projectName}". ` +
      `The HipaaLint Score evaluates your project across 6 compliance domains ` +
      `weighted by risk impact.\n\n` +
      `DISCLAIMER: This tool assists in identifying potential PHI exposure but does not ` +
      `guarantee HIPAA compliance. Always consult with a qualified legal or compliance professional.`,
  );
  doc.moveDown(1);

  // Findings summary table
  doc.fontSize(14).fillColor(COLORS.primary).text('Findings by Severity');
  doc.moveDown(0.5);

  const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
  for (const sev of severities) {
    const count = report.summary.bySeverity[sev] || 0;
    const { label, color } = SEVERITY_LABELS[sev]!;
    doc
      .fontSize(11)
      .fillColor(color)
      .text(`${label}: `, { continued: true })
      .fillColor(COLORS.text)
      .text(`${count} finding(s)`);
  }

  doc.moveDown(1);

  doc.fontSize(14).fillColor(COLORS.primary).text('Findings by Category');
  doc.moveDown(0.5);

  const categories = [
    ['PHI Protection', report.summary.byCategory.phi_protection],
    ['Encryption', report.summary.byCategory.encryption],
    ['Access Control', report.summary.byCategory.access_control],
    ['Audit Logging', report.summary.byCategory.audit_logging],
    ['Infrastructure', report.summary.byCategory.infrastructure],
    ['AI Governance', report.summary.byCategory.ai_governance],
  ] as const;

  for (const [label, count] of categories) {
    doc.fontSize(11).fillColor(COLORS.text).text(`${label}: ${count} finding(s)`);
  }
}

function renderDomainScores(doc: PDFKit.PDFDocument, report: ComplianceReport) {
  doc.fontSize(20).fillColor(COLORS.primary).text('Domain Scores');
  doc.moveDown(0.5);

  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(50, doc.y)
    .lineTo(doc.page.width - 50, doc.y)
    .stroke();
  doc.moveDown(1);

  const domains = [
    ['PHI Protection', 'phiProtection'],
    ['Encryption & Transport', 'encryption'],
    ['Access Control', 'accessControl'],
    ['Audit Logging', 'auditLogging'],
    ['Infrastructure', 'infrastructure'],
    ['AI Governance', 'aiGovernance'],
  ] as const;

  for (const [label, key] of domains) {
    const ds = report.score.domainScores[key];
    const scoreColor =
      ds.score >= 90 ? COLORS.success : ds.score >= 70 ? COLORS.warning : COLORS.danger;

    doc.fontSize(13).fillColor(COLORS.primary).text(`${label}`, { continued: true });
    doc.fontSize(13).fillColor(scoreColor).text(` — ${ds.score}/100`, { continued: true });
    doc
      .fontSize(10)
      .fillColor(COLORS.muted)
      .text(` (weight: ${(ds.weight * 100).toFixed(0)}%)`);

    doc.fontSize(10).fillColor(COLORS.text);
    doc.text(
      `  ✅ ${ds.passedCheckpoints} passed | ❌ ${ds.failedCheckpoints} failed | ⚠️ ${ds.warningCheckpoints} warnings`,
    );
    doc.moveDown(0.5);
  }
}

function renderFindings(doc: PDFKit.PDFDocument, report: ComplianceReport) {
  doc.fontSize(20).fillColor(COLORS.primary).text('Detailed Findings');
  doc.moveDown(0.5);

  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(50, doc.y)
    .lineTo(doc.page.width - 50, doc.y)
    .stroke();
  doc.moveDown(1);

  // Group by severity
  const grouped = new Map<string, ComplianceFinding[]>();
  for (const f of report.findings) {
    const existing = grouped.get(f.severity) || [];
    existing.push(f);
    grouped.set(f.severity, existing);
  }

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  for (const severity of severityOrder) {
    const findings = grouped.get(severity);
    if (!findings || findings.length === 0) continue;

    const { label, color } = SEVERITY_LABELS[severity]!;
    doc.fontSize(14).fillColor(color).text(`${label} (${findings.length})`);
    doc.moveDown(0.3);

    for (const f of findings.slice(0, 20)) {
      // Limit per severity to avoid huge PDFs
      if (doc.y > doc.page.height - 120) {
        doc.addPage();
      }

      const relPath = f.filePath.replace(report.projectPath + '/', '');
      doc.fontSize(11).fillColor(COLORS.primary).text(`${f.ruleId}: ${f.title}`);
      doc.fontSize(9).fillColor(COLORS.muted).text(`📍 ${relPath}:${f.lineNumber}`);
      doc.fontSize(9).fillColor(COLORS.text).text(`📋 ${f.citation}`);
      doc.fontSize(9).fillColor(COLORS.accent).text(`💡 ${f.remediation}`);
      doc.moveDown(0.5);
    }

    if (findings.length > 20) {
      doc
        .fontSize(9)
        .fillColor(COLORS.muted)
        .text(`... and ${findings.length - 20} more ${severity} finding(s)`);
    }

    doc.moveDown(0.5);
  }
}

function renderRecommendations(doc: PDFKit.PDFDocument, report: ComplianceReport) {
  doc.fontSize(20).fillColor(COLORS.primary).text('Recommendations');
  doc.moveDown(0.5);

  doc
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .moveTo(50, doc.y)
    .lineTo(doc.page.width - 50, doc.y)
    .stroke();
  doc.moveDown(1);

  for (const rec of report.recommendations.slice(0, 15)) {
    if (doc.y > doc.page.height - 100) {
      doc.addPage();
    }

    doc
      .fontSize(11)
      .fillColor(COLORS.primary)
      .text(`${rec.priority}. `, { continued: true })
      .fillColor(COLORS.text)
      .text(rec.description);
    doc.moveDown(0.3);
  }
}
