// ──────────────────────────────────────────────────
// Initial Vulnerable Code Sample
// ──────────────────────────────────────────────────
const DEFAULT_CODE = `import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import https from 'https';

const app = express();

/**
 * ⚠️ VULNERABILITY 1: CORS Wildcard
 * Allows any origin to access the API.
 */
app.use(cors({ origin: '*' }));

/**
 * ⚠️ VULNERABILITY 2: Unencrypted Transport
 * Serving sensitive data over HTTP instead of HTTPS.
 */
const API_URL = "http://api.patientportal.com/v1";

app.post('/api/patients', (req, res) => {
    const data = req.body;
    
    // ⚠️ VULNERABILITY 3: Direct PHI Variable Assignment
    const patientSSN = data.socialSecurityNumber;
    const mrn = data.medicalRecordNumber;
    const dob = data.dateOfBirth;
    
    // ⚠️ VULNERABILITY 4: PHI Exposure in Logs
    console.log(\`[POST] Creating new patient record for \${patientSSN}\`);
    console.log(\`Patient medical tracking active: DOB \${dob}, MRN \${mrn}\`);

    // ⚠️ VULNERABILITY 5: Weak TLS Cipher configuration
    const legacyAgent = new https.Agent({
        secureProtocol: "TLSv1_method"
    });

    // Simulated API call sending PHI over legacy TLS
    https.get(\`\${API_URL}/register?ssn=\${patientSSN}\`, { agent: legacyAgent }, (response) => {
        res.json({ success: true, ssn: patientSSN, mrn: mrn });
    });
});

app.listen(8080, () => console.log('Medical API running on port 8080'));
`;

// ──────────────────────────────────────────────────
// Monaco Editor Initialization
// ──────────────────────────────────────────────────
let editor;
let decorations = [];

require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs' } });
require(['vs/editor/editor.main'], function () {
    editor = monaco.editor.create(document.getElementById('editor-container'), {
        value: DEFAULT_CODE,
        language: 'typescript',
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: { enabled: false },
        fontSize: 14,
        fontFamily: "'JetBrains Mono', monospace",
        padding: { top: 16, bottom: 16 },
        scrollBeyondLastLine: false,
        smoothScrolling: true,
        cursorBlinking: "smooth",
        cursorSmoothCaretAnimation: true
    });

    // Initialize Lucide icons
    lucide.createIcons();

    // Ensure editor resizes dynamically
    window.addEventListener('resize', () => {
        editor.layout();
    });
});

// ──────────────────────────────────────────────────
// API Interaction & DOM Updates
// ──────────────────────────────────────────────────

const analyzeBtn = document.getElementById('analyze-btn');
const emptyState = document.getElementById('empty-state');
const loadingState = document.getElementById('loading-state');
const scoreCard = document.getElementById('score-card');
const findingsCard = document.getElementById('findings-card');

const scoreRing = document.getElementById('score-ring');
const scoreNumber = document.getElementById('score-number');
const scoreBand = document.getElementById('score-band');
const domainsContainer = document.getElementById('domains-container');
const findingsList = document.getElementById('findings-list');
const findingsCount = document.getElementById('findings-count');

analyzeBtn.addEventListener('click', async () => {
    const code = editor.getValue();

    // UI Loading State
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `<i data-lucide="loader-2" class="spin"></i> Analyzing...`;
    lucide.createIcons();

    emptyState.classList.add('hidden');
    scoreCard.classList.add('hidden');
    findingsCard.classList.add('hidden');
    loadingState.classList.remove('hidden');

    try {
        // We call /api/scan for full compliance scoring/AST rules
        const resScan = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });

        // We call /api/phi for basic regex/variable PHI detection
        const resPhi = await fetch('/api/phi', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });

        const scanData = await resScan.json();
        const phiData = await resPhi.json();

        const allFindings = [...scanData.findings, ...(phiData.findings || [])];

        renderResults(scanData.score, allFindings);
        highlightEditor(allFindings);

    } catch (err) {
        console.error(err);
        alert('Failed to analyze code. Ensure the backend is running.');
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = `<i data-lucide="zap"></i> Analyze Code`;
        loadingState.classList.add('hidden');
        scoreCard.classList.remove('hidden');
        findingsCard.classList.remove('hidden');
        lucide.createIcons();
    }
});

// ──────────────────────────────────────────────────
// Rendering rendering
// ──────────────────────────────────────────────────

function renderResults(scoreObj, findings) {
    // Animate Score Ring
    const score = scoreObj.overallScore;
    const circumference = 314; // 2 * pi * 50
    const offset = circumference - (score / 100) * circumference;

    // Set color based on score band
    let color = 'var(--success)';
    if (score < 90) color = 'var(--warning)';
    if (score < 70) color = 'var(--danger)';

    scoreRing.style.strokeDashoffset = offset;
    scoreRing.style.stroke = color;

    // Animate Number count up
    animateValue(scoreNumber, 0, score, 1000);

    scoreBand.textContent = scoreObj.band.replace(/_/g, ' ').toUpperCase();
    scoreBand.style.color = color;
    scoreBand.style.borderColor = color;

    // Render Domains
    domainsContainer.innerHTML = '';

    const friendlyNames = {
        phiProtection: "PHI Protection",
        encryption: "Encryption & Transit",
        accessControl: "Access Control",
        auditLogging: "Audit Logging",
        infrastructure: "Infrastructure",
        aiGovernance: "AI Governance"
    };

    for (const [key, ds] of Object.entries(scoreObj.domainScores)) {
        let barColor = 'var(--success)';
        if (ds.score < 90) barColor = 'var(--warning)';
        if (ds.score < 70) barColor = 'var(--danger)';

        const div = document.createElement('div');
        div.className = 'domain-item';
        div.innerHTML = `
            <div class="domain-info">
                <span>${friendlyNames[key] || key}</span>
                <span class="domain-score-val">${ds.score}/100</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: 0%; background: ${barColor}"></div>
            </div>
        `;
        domainsContainer.appendChild(div);

        // Trigger animation after append
        setTimeout(() => {
            div.querySelector('.progress-fill').style.width = `${ds.score}%`;
        }, 100);
    }

    // Render Findings
    findingsCount.textContent = findings.length;
    findingsList.innerHTML = '';
    if (findings.length === 0) {
        findingsList.innerHTML = `
            <div class="empty-state">
                <i data-lucide="shield-check" style="color: var(--success); width: 48px; height: 48px; margin-bottom: 1rem;"></i>
                <p>No vulnerabilities detected!</p>
            </div>
        `;
        return;
    }

    findings.forEach(f => {
        const isPhi = f.identifierType !== undefined;
        const icon = isPhi ? 'eye' : 'alert-circle';
        let severityColor = 'var(--danger)';
        if (f.severity === 'medium' || f.confidence === 'medium') severityColor = 'var(--warning)';
        if (f.severity === 'low' || f.confidence === 'low') severityColor = 'var(--text-muted)';

        const div = document.createElement('div');
        div.className = 'finding-item';
        div.innerHTML = `
            <div class="finding-top">
                <div class="finding-title" style="color: ${severityColor}">
                    <i data-lucide="${icon}"></i> ${isPhi ? 'PHI Exposure: ' + f.identifierType : f.ruleId}
                </div>
                <div class="finding-line">Line ${f.lineNumber}</div>
            </div>
            <div class="finding-desc">${isPhi ? 'Found potential PHI: <code>' + f.matchedText + '</code>' : f.title}</div>
            <div class="finding-remediation">
                <i data-lucide="lightbulb"></i>
                <span>${isPhi ? f.citation : f.remediation}</span>
            </div>
        `;
        findingsList.appendChild(div);
    });
}

function highlightEditor(findings) {
    if (!editor) return;

    // Clear old decorations
    decorations = editor.deltaDecorations(decorations, []);

    const newDecos = findings.map(f => {
        const isPhi = f.identifierType !== undefined;
        let className = isPhi ? 'monaco-phi-highlight' : 'monaco-critical-highlight';

        // Find rough column indices if not provided (for AST rules)
        let startCol = f.columnNumber || 1;
        let endCol = startCol + (f.matchedText ? f.matchedText.length : 100); // 100 is hacky fill for whole line

        return {
            range: new monaco.Range(f.lineNumber, startCol, f.lineNumber, endCol),
            options: {
                isWholeLine: !f.matchedText,
                className: className,
                hoverMessage: { value: `**${isPhi ? 'PHI Detected' : f.ruleId}**\n\n${isPhi ? f.citation : f.remediation}` }
            }
        };
    });

    decorations = editor.deltaDecorations([], newDecos);
}

// Number rolling animation utility
function animateValue(obj, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        // Easing out cubic
        const easeProgress = 1 - Math.pow(1 - progress, 3);
        obj.innerHTML = Math.floor(easeProgress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}
