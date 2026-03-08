import express from 'express';
import cors from 'cors';
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';

// Import HipaaLint engines
import { RuleEvaluator } from '../dist/engine/rule-evaluator.js';
import { PHIDetector } from '../dist/engine/phi-detector.js';
import { ScoreCalculator } from '../dist/engine/score-calculator.js';
import { mergeWithFlags } from '../dist/engine/config-loader.js';

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

const TMP_DIR = join(process.cwd(), '.demo_tmp');
if (!existsSync(TMP_DIR)) {
    mkdirSync(TMP_DIR, { recursive: true });
}

// ──────────────────────────────────────────────────
// API: /api/scan
// ──────────────────────────────────────────────────
app.post('/api/scan', (req, res) => {
    const { code } = req.body;

    if (!code) {
        return res.status(400).json({ error: 'Code is required' });
    }

    // Create a temporary isolation folder for this scan
    const scanId = randomUUID();
    const scanDir = join(TMP_DIR, scanId);
    mkdirSync(scanDir);
    const targetFile = join(scanDir, 'index.ts');

    try {
        writeFileSync(targetFile, code);

        const demoConfig = mergeWithFlags({}, { sensitivity: 'balanced' });

        const evaluator = new RuleEvaluator(demoConfig);
        const result = evaluator.evaluate([scanDir], 'hipaa');

        // For the UI, we just need the findings adjusted to fake line numbers
        // Since we wrote to 'index.ts', the line numbers are accurate.
        const findings = result.findings.map(f => ({
            ...f,
            filePath: 'index.ts'
        }));

        const calculator = new ScoreCalculator();
        const score = calculator.calculateScore({ ...result, findings }, 'hipaa', demoConfig);

        evaluator.close();

        res.json({
            score,
            findings,
        });
    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({ error: 'Internal server error during scan' });
    } finally {
        // Cleanup
        try {
            rmSync(scanDir, { recursive: true, force: true });
        } catch {}
    }
});

// ──────────────────────────────────────────────────
// API: /api/phi
// ──────────────────────────────────────────────────
app.post('/api/phi', (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    try {
        const demoConfig = mergeWithFlags({}, { sensitivity: 'balanced' });

        const detector = new PHIDetector(demoConfig);
        const findings = detector.detect(code, 'index.ts');

        res.json({ findings });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error during PHI detection' });
    }
});

app.listen(port, () => {
    console.log(`HipaaLint Interactive Playground running at http://localhost:${port}`);
});
