import * as vscode from 'vscode';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { dirname, extname, join } from 'path';
import { pathToFileURL } from 'url';
import {
  fixCorsWildcardLine,
  fixHttpLine,
  fixWeakTlsLine,
} from './fixes.js';
import type {
  ComplianceFinding,
  ComplianceScore,
  HipaaLintConfig,
  RuleEvaluator,
  ScanResult,
  ScoreCalculator,
  SensitivityLevel,
} from '@hipaalint/ai';

const SUPPORTED_LANGUAGES = new Set([
  'javascript',
  'javascriptreact',
  'typescript',
  'typescriptreact',
  'python',
]);

interface EngineModule {
  RuleEvaluator: typeof RuleEvaluator;
  ScoreCalculator: typeof ScoreCalculator;
  loadConfig: (startDir: string, explicitConfigPath?: string) => HipaaLintConfig;
  mergeWithFlags: (
    config: HipaaLintConfig,
    flags: {
      sensitivity?: SensitivityLevel;
      framework?: string;
      exclude?: string[];
      maxFiles?: number;
      maxDepth?: number;
      timeout?: number;
    },
  ) => {
    sensitivity: SensitivityLevel;
    framework: string;
    ignore: string[];
    maxFiles: number;
    maxDepth: number;
    timeout: number;
    threshold: number;
  };
  countFindings: (findings: ScanResult['findings']) => {
    bySeverity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>;
  };
}

interface ScanOptions {
  framework: string;
  sensitivity: SensitivityLevel;
  ignore: string[];
  maxFiles: number;
  maxDepth: number;
  timeout: number;
}

interface DashboardState {
  workspaceName: string;
  framework: string;
  score?: ComplianceScore;
  counts?: ReturnType<EngineModule['countFindings']>;
  findings?: ComplianceFinding[];
  error?: string;
}

let enginePromise: Promise<EngineModule> | undefined;

async function loadEngine(context: vscode.ExtensionContext): Promise<EngineModule> {
  if (!enginePromise) {
    enginePromise = (async () => {
      try {
        return (await import('@hipaalint/ai')) as EngineModule;
      } catch {
        const packagedFallback = pathToFileURL(
          join(context.extensionPath, 'vendor', 'hipaalint', 'dist', 'index.js'),
        ).href;

        try {
          return (await import(packagedFallback)) as EngineModule;
        } catch {
          const devFallback = pathToFileURL(join(context.extensionPath, '..', 'dist', 'index.js')).href;
          return (await import(devFallback)) as EngineModule;
        }
      }
    })();
  }
  return enginePromise;
}

function isSupportedDocument(document: vscode.TextDocument): boolean {
  return document.uri.scheme === 'file' && SUPPORTED_LANGUAGES.has(document.languageId);
}

function severityToDiagnostic(severity: ComplianceFinding['severity']): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

async function resolveScanOptions(
  context: vscode.ExtensionContext,
  target: vscode.Uri,
): Promise<ScanOptions> {
  const engine = await loadEngine(context);
  const settings = vscode.workspace.getConfiguration('hipaalint', target);
  const folder = vscode.workspace.getWorkspaceFolder(target);
  const startDir = folder?.uri.fsPath ?? dirname(target.fsPath);
  const explicitConfigPath = settings.get<string>('configPath') || undefined;
  const config = engine.loadConfig(startDir, explicitConfigPath);

  return engine.mergeWithFlags(config, {
    sensitivity: settings.get<SensitivityLevel>('sensitivity', 'balanced'),
    framework: settings.get<string>('framework', 'hipaa'),
  });
}

function createTemporaryFile(document: vscode.TextDocument): { tempPath: string; cleanup: () => void } {
  const tempDir = mkdtempSync(join(tmpdir(), 'hipaalint-vscode-'));
  const tempPath = join(tempDir, `document${extname(document.uri.fsPath) || '.ts'}`);
  writeFileSync(tempPath, document.getText(), 'utf-8');
  return {
    tempPath,
    cleanup: () => rmSync(tempDir, { recursive: true, force: true }),
  };
}

class DashboardProvider implements vscode.WebviewViewProvider {
  static readonly viewType = 'hipaalint.dashboard';

  private view?: vscode.WebviewView;
  private state: DashboardState = {
    workspaceName: 'No workspace',
    framework: 'hipaa',
  };

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    this.render();
  }

  update(state: DashboardState): void {
    this.state = state;
    this.render();
  }

  private render(): void {
    if (!this.view) return;

    const score = this.state.score;
    const counts = this.state.counts;
    const findings = (this.state.findings ?? []).slice(0, 5);

    this.view.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<style>
  :root {
    color-scheme: light dark;
    --bg: #f7f4ed;
    --card: rgba(255,255,255,0.82);
    --ink: #18222d;
    --muted: #556270;
    --border: rgba(24,34,45,0.14);
    --accent: #0a6c74;
    --danger: #b03a2e;
    --warn: #b36b00;
  }
  body {
    margin: 0;
    padding: 16px;
    font-family: Georgia, 'Iowan Old Style', serif;
    background: radial-gradient(circle at top, rgba(10,108,116,0.18), transparent 46%), var(--bg);
    color: var(--ink);
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 14px;
    margin-bottom: 12px;
    box-shadow: 0 10px 30px rgba(24,34,45,0.08);
  }
  h1, h2, p { margin: 0; }
  h1 { font-size: 18px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); margin-bottom: 8px; }
  .score {
    font-size: 40px;
    line-height: 1;
    color: var(--accent);
  }
  .band { margin-top: 8px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.12em; color: var(--muted); }
  .counts { display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px; margin-top: 12px; }
  .count { padding: 8px; border-radius: 12px; background: rgba(255,255,255,0.55); border: 1px solid var(--border); }
  .finding { padding: 10px 0; border-top: 1px solid var(--border); }
  .finding:first-child { border-top: none; padding-top: 0; }
  .rule { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
  button {
    border: none;
    border-radius: 999px;
    padding: 10px 14px;
    background: var(--accent);
    color: white;
    font-weight: 600;
    cursor: pointer;
  }
  .error { color: var(--danger); }
</style>
</head>
<body>
  <div class="card">
    <h2>Workspace</h2>
    <h1>${this.state.workspaceName}</h1>
    <p>${this.state.framework.toUpperCase()}</p>
    <div style="margin-top: 12px;"><button onclick="acquireVsCodeApi().postMessage({ command: 'refresh' })">Refresh</button></div>
  </div>
  <div class="card">
    <h2>Score</h2>
    ${score ? `<div class="score">${score.overallScore.toFixed(1)}</div><div class="band">${score.band.replace(/_/g, ' ')}</div>` : '<p>No scan yet.</p>'}
    ${counts ? `<div class="counts">
      <div class="count">Critical: ${counts.bySeverity.critical}</div>
      <div class="count">High: ${counts.bySeverity.high}</div>
      <div class="count">Medium: ${counts.bySeverity.medium}</div>
      <div class="count">Low: ${counts.bySeverity.low}</div>
    </div>` : ''}
    ${this.state.error ? `<p class="error" style="margin-top: 12px;">${this.state.error}</p>` : ''}
  </div>
  <div class="card">
    <h2>Top Findings</h2>
    ${findings.length > 0 ? findings
      .map(
        (finding) => `<div class="finding"><div class="rule">${finding.ruleId}</div><strong>${finding.title}</strong><p>${finding.remediation}</p></div>`,
      )
      .join('') : '<p>No findings.</p>'}
  </div>
  <script>
    window.addEventListener('message', () => {});
    const vscode = acquireVsCodeApi();
    acquireVsCodeApi = () => vscode;
  </script>
</body>
</html>`;

    this.view.webview.onDidReceiveMessage((message) => {
      if (message.command === 'refresh') {
        void vscode.commands.executeCommand('hipaalint.refreshDashboard');
      }
    });
  }
}

class HipaaLintCodeActions implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    const lineText = document.lineAt(range.start.line).text;

    for (const diagnostic of context.diagnostics) {
      const ruleId = typeof diagnostic.code === 'string' ? diagnostic.code : undefined;
      if (!ruleId) continue;

      const title = this.titleForRule(ruleId);
      if (!title) continue;

      const fixedLine = this.fixedLineForRule(ruleId, lineText);
      if (!fixedLine || fixedLine === lineText) continue;

      const action = new vscode.CodeAction(title, vscode.CodeActionKind.QuickFix);
      action.diagnostics = [diagnostic];
      action.isPreferred = true;
      const edit = new vscode.WorkspaceEdit();
      edit.replace(document.uri, document.lineAt(range.start.line).range, fixedLine);
      action.edit = edit;
      actions.push(action);
    }

    return actions;
  }

  private titleForRule(ruleId: string): string | undefined {
    switch (ruleId) {
      case 'HIPAA-ENC-001':
      case 'HITRUST-01.V-01':
      case 'SOC2-CC6.1-001':
        return 'Upgrade to HTTPS';
      case 'HIPAA-ENC-005':
        return 'Upgrade weak TLS version';
      case 'HIPAA-INF-001':
      case 'HITRUST-10.C-01':
        return 'Restrict CORS origins';
      default:
        return undefined;
    }
  }

  private fixedLineForRule(ruleId: string, lineText: string): string | null {
    switch (ruleId) {
      case 'HIPAA-ENC-001':
      case 'HITRUST-01.V-01':
      case 'SOC2-CC6.1-001':
        return fixHttpLine(lineText);
      case 'HIPAA-ENC-005':
        return fixWeakTlsLine(lineText);
      case 'HIPAA-INF-001':
      case 'HITRUST-10.C-01':
        return fixCorsWildcardLine(lineText);
      default:
        return null;
    }
  }
}

class HipaaLintController {
  private readonly diagnostics = vscode.languages.createDiagnosticCollection('hipaalint');
  private readonly dashboard = new DashboardProvider();
  private readonly statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  private readonly debounceTimers = new Map<string, NodeJS.Timeout>();

  constructor(private readonly context: vscode.ExtensionContext) {
    this.statusBar.command = 'hipaalint.refreshDashboard';
    this.statusBar.tooltip = 'Refresh HipaaLint workspace dashboard';
    this.statusBar.text = '$(shield) HipaaLint';
    this.statusBar.show();
  }

  register(): void {
    this.context.subscriptions.push(
      this.diagnostics,
      this.statusBar,
      vscode.window.registerWebviewViewProvider(DashboardProvider.viewType, this.dashboard),
      vscode.languages.registerCodeActionsProvider(
        [{ scheme: 'file', language: 'javascript' }, { scheme: 'file', language: 'javascriptreact' }, { scheme: 'file', language: 'typescript' }, { scheme: 'file', language: 'typescriptreact' }, { scheme: 'file', language: 'python' }],
        new HipaaLintCodeActions(),
        { providedCodeActionKinds: HipaaLintCodeActions.providedCodeActionKinds },
      ),
      vscode.commands.registerCommand('hipaalint.scan', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || !isSupportedDocument(editor.document)) return;
        await this.scanDocument(editor.document, true);
      }),
      vscode.commands.registerCommand('hipaalint.refreshDashboard', async () => {
        await this.refreshWorkspaceDashboard(vscode.window.activeTextEditor?.document.uri ?? vscode.workspace.workspaceFolders?.[0]?.uri);
      }),
      vscode.commands.registerCommand('hipaalint.openConfig', async () => {
        await this.openConfig();
      }),
      vscode.workspace.onDidOpenTextDocument((document) => {
        if (isSupportedDocument(document)) {
          this.scheduleDocumentScan(document);
        }
      }),
      vscode.workspace.onDidSaveTextDocument((document) => {
        if (isSupportedDocument(document)) {
          this.scheduleDocumentScan(document);
          void this.refreshWorkspaceDashboard(document.uri);
        }
      }),
      vscode.workspace.onDidChangeTextDocument((event) => {
        if (isSupportedDocument(event.document)) {
          this.scheduleDocumentScan(event.document);
        }
      }),
      vscode.workspace.onDidCloseTextDocument((document) => {
        this.diagnostics.delete(document.uri);
      }),
      vscode.window.onDidChangeActiveTextEditor((editor) => {
        if (editor && isSupportedDocument(editor.document)) {
          this.scheduleDocumentScan(editor.document);
          void this.refreshWorkspaceDashboard(editor.document.uri);
        }
      }),
    );

    const active = vscode.window.activeTextEditor?.document;
    if (active && isSupportedDocument(active)) {
      this.scheduleDocumentScan(active);
      void this.refreshWorkspaceDashboard(active.uri);
    } else {
      void this.refreshWorkspaceDashboard(vscode.workspace.workspaceFolders?.[0]?.uri);
    }
  }

  private scheduleDocumentScan(document: vscode.TextDocument): void {
    const settings = vscode.workspace.getConfiguration('hipaalint', document.uri);
    if (!settings.get<boolean>('autoScan', true)) return;

    const key = document.uri.toString();
    const existing = this.debounceTimers.get(key);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(() => {
      void this.scanDocument(document, false);
      this.debounceTimers.delete(key);
    }, settings.get<number>('debounceMs', 500));
    this.debounceTimers.set(key, timer);
  }

  private async scanDocument(document: vscode.TextDocument, manual: boolean): Promise<void> {
    if (!isSupportedDocument(document)) return;

    const engine = await loadEngine(this.context);
    const options = await resolveScanOptions(this.context, document.uri);
    const targetPath = document.isDirty ? createTemporaryFile(document) : undefined;

    const evaluator = new engine.RuleEvaluator({ sensitivity: options.sensitivity });
    try {
      const result = evaluator.evaluate([targetPath?.tempPath ?? document.uri.fsPath], options.framework, {
        ignore: options.ignore,
        maxFiles: options.maxFiles,
        maxDepth: options.maxDepth,
        timeoutMs: options.timeout,
      });
      const findings = result.findings;
      this.diagnostics.set(document.uri, findings.map((finding) => this.toDiagnostic(document, finding)));
      if (manual) {
        vscode.window.setStatusBarMessage(`HipaaLint: ${findings.length} finding(s)`, 3500);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      vscode.window.showErrorMessage(`HipaaLint scan failed: ${message}`);
    } finally {
      evaluator.close();
      targetPath?.cleanup();
    }
  }

  private toDiagnostic(document: vscode.TextDocument, finding: ComplianceFinding): vscode.Diagnostic {
    const line = Math.max(0, finding.lineNumber - 1);
    const startCharacter = Math.max(0, finding.columnNumber - 1);
    const lineLength = document.lineAt(Math.min(line, document.lineCount - 1)).text.length;
    const range = new vscode.Range(
      new vscode.Position(line, Math.min(startCharacter, lineLength)),
      new vscode.Position(line, Math.min(lineLength, startCharacter + Math.max(1, finding.codeSnippet.length))),
    );
    const diagnostic = new vscode.Diagnostic(range, `${finding.title}: ${finding.remediation}`, severityToDiagnostic(finding.severity));
    diagnostic.code = finding.ruleId;
    diagnostic.source = 'HipaaLint';
    return diagnostic;
  }

  private async refreshWorkspaceDashboard(target?: vscode.Uri): Promise<void> {
    const folder = target ? vscode.workspace.getWorkspaceFolder(target) : vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      this.dashboard.update({ workspaceName: 'No workspace', framework: 'hipaa', error: 'Open a workspace folder to calculate a compliance score.' });
      this.statusBar.text = '$(shield) HipaaLint';
      return;
    }

    const engine = await loadEngine(this.context);
    const options = await resolveScanOptions(this.context, folder.uri);
    const evaluator = new engine.RuleEvaluator({ sensitivity: options.sensitivity });
    try {
      const scanResult = evaluator.evaluate([folder.uri.fsPath], options.framework, {
        ignore: options.ignore,
        maxFiles: options.maxFiles,
        maxDepth: options.maxDepth,
        timeoutMs: options.timeout,
      });
      const scoreCalculator = new engine.ScoreCalculator();
      const score = scoreCalculator.calculateScore(scanResult, options.framework, options.sensitivity);
      const counts = engine.countFindings(scanResult.findings);
      this.dashboard.update({
        workspaceName: folder.name,
        framework: options.framework,
        score,
        counts,
        findings: scanResult.findings,
      });
      this.statusBar.text = `$(shield) ${score.overallScore.toFixed(0)} ${score.band.replace(/_/g, ' ')}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.dashboard.update({ workspaceName: folder.name, framework: options.framework, error: message });
      this.statusBar.text = '$(shield) HipaaLint';
    } finally {
      evaluator.close();
    }
  }

  private async openConfig(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    const target = editor?.document.uri ?? vscode.workspace.workspaceFolders?.[0]?.uri;
    if (!target) return;

    const settings = vscode.workspace.getConfiguration('hipaalint', target);
    const explicitPath = settings.get<string>('configPath');
    if (explicitPath && existsSync(explicitPath)) {
      const document = await vscode.workspace.openTextDocument(explicitPath);
      await vscode.window.showTextDocument(document);
      return;
    }

    const folder = vscode.workspace.getWorkspaceFolder(target);
    if (!folder) return;

    const candidates = ['.hipaalintrc', '.hipaalintrc.json', 'hipaalint.config.json'];
    for (const candidate of candidates) {
      const candidatePath = join(folder.uri.fsPath, candidate);
      if (existsSync(candidatePath)) {
        const document = await vscode.workspace.openTextDocument(candidatePath);
        await vscode.window.showTextDocument(document);
        return;
      }
    }

    const newFile = await vscode.workspace.openTextDocument({
      language: 'json',
      content: JSON.stringify(
        {
          frameworks: ['hipaa'],
          sensitivity: 'balanced',
          threshold: 70,
        },
        null,
        2,
      ),
    });
    await vscode.window.showTextDocument(newFile);
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const controller = new HipaaLintController(context);
  controller.register();
}

export function deactivate(): void {
  // VS Code disposables handle teardown.
}
