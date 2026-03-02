import { describe, it, expect, beforeEach } from 'vitest';
import { PHIDetector } from '../../src/engine/phi-detector.js';

describe('PHIDetector', () => {
    let detector: PHIDetector;

    beforeEach(() => {
        detector = new PHIDetector({ sensitivity: 'balanced' });
    });

    describe('SSN Detection', () => {
        it('should detect SSN patterns', () => {
            const code = 'const ssn = "123-45-6789";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'ssn')).toBe(true);
        });

        it('should not flag non-SSN patterns', () => {
            const code = 'const version = "1.2.3";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.filter((f) => f.identifierType === 'ssn')).toHaveLength(0);
        });
    });

    describe('Email Detection', () => {
        it('should detect email addresses', () => {
            const code = 'const email = "patient@hospital.com";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'email')).toBe(true);
        });

        it('should exclude test emails', () => {
            const code = 'const email = "test@example.com";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.filter((f) => f.identifierType === 'email')).toHaveLength(0);
        });
    });

    describe('Phone Detection', () => {
        it('should detect phone numbers', () => {
            const code = 'const phone = "(555) 123-4567";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'phone')).toBe(true);
        });
    });

    describe('IP Address Detection', () => {
        it('should detect IP addresses', () => {
            const code = 'const server = "192.168.1.100";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'ip_address')).toBe(true);
        });

        it('should exclude localhost', () => {
            const code = 'const server = "127.0.0.1";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.filter((f) => f.identifierType === 'ip_address')).toHaveLength(0);
        });
    });

    describe('PHI Variables', () => {
        it('should detect patientName variables', () => {
            const code = 'const patientName = "John Doe";';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'name')).toBe(true);
        });

        it('should detect SSN variable names', () => {
            const code = 'const patientSSN = env.SSN;';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'ssn')).toBe(true);
        });

        it('should detect dateOfBirth variables', () => {
            const code = 'const dateOfBirth = patient.dob;';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'date_of_birth')).toBe(true);
        });

        it('should detect medicalRecordNumber variables', () => {
            const code = 'const medicalRecordNumber = getMRN();';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.identifierType === 'medical_record_number')).toBe(true);
        });

        it('should skip encrypted PHI variables', () => {
            const code = 'const encrypted patientName = encrypt("John");';
            const findings = detector.detect(code, 'test.ts');
            const nameFindings = findings.filter((f) => f.identifierType === 'name');
            expect(nameFindings).toHaveLength(0);
        });
    });

    describe('Context Detection', () => {
        it('should detect PHI in log statements', () => {
            const code = 'console.log(`Patient: ${patientName}`);';
            const findings = detector.detect(code, 'test.ts');
            const logFindings = findings.filter((f) => f.context === 'log_statement');
            expect(logFindings.length).toBeGreaterThan(0);
        });

        it('should detect PHI in error handlers', () => {
            const code = 'catch (e) { const ssn = "123-45-6789"; }';
            const findings = detector.detect(code, 'test.ts');
            expect(findings.some((f) => f.context === 'error_handler')).toBe(true);
        });
    });

    describe('Sensitivity Levels', () => {
        it('strict mode should detect more findings', () => {
            const code = `
        // Patient SSN: 123-45-6789
        const data = "some data";
      `;
            const strictDetector = new PHIDetector({ sensitivity: 'strict' });
            const relaxedDetector = new PHIDetector({ sensitivity: 'relaxed' });

            const strictFindings = strictDetector.detect(code, 'test.ts');
            const relaxedFindings = relaxedDetector.detect(code, 'test.ts');

            expect(strictFindings.length).toBeGreaterThanOrEqual(relaxedFindings.length);
        });
    });

    describe('Deduplication', () => {
        it('should not report duplicate findings', () => {
            const code = 'const patientName = patientName;';
            const findings = detector.detect(code, 'test.ts');
            const nameFindings = findings.filter(
                (f) => f.identifierType === 'name' && f.lineNumber === 1,
            );
            // Should only count unique column positions
            const uniqueColumns = new Set(nameFindings.map((f) => f.columnNumber));
            expect(nameFindings.length).toBe(uniqueColumns.size);
        });
    });

    describe('containsPHI', () => {
        it('should return true for text with SSN', () => {
            expect(detector.containsPHI('SSN: 123-45-6789')).toBe(true);
        });

        it('should return false for clean text', () => {
            expect(detector.containsPHI('const x = 42;')).toBe(false);
        });
    });
});
