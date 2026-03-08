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

    it('should exclude infrastructure emails like noreply@', () => {
      const code = 'const sender = "noreply@company.com";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'email')).toHaveLength(0);
    });

    it('should exclude admin@ and support@ emails', () => {
      const code = 'const contact = "admin@hospital.com"; const help = "support@hospital.com";';
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
    it('should detect public IP addresses', () => {
      const code = 'const server = "8.8.8.8";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.some((f) => f.identifierType === 'ip_address')).toBe(true);
    });

    it('should exclude localhost', () => {
      const code = 'const server = "127.0.0.1";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'ip_address')).toHaveLength(0);
    });

    it('should exclude 10.x.x.x private range', () => {
      const code = 'const server = "10.0.0.1";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'ip_address')).toHaveLength(0);
    });

    it('should exclude 172.16.x.x private range', () => {
      const code = 'const server = "172.16.0.1";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'ip_address')).toHaveLength(0);
    });

    it('should exclude 192.168.x.x private range', () => {
      const code = 'const server = "192.168.1.1";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'ip_address')).toHaveLength(0);
    });
  });

  describe('Date False Positive Reduction', () => {
    it('should not flag dates on lines with release/version keywords', () => {
      const code = 'const releaseDate = "01/15/2025"; // release version date';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'date_of_birth')).toHaveLength(0);
    });

    it('should not flag dates on lines with copyright keyword', () => {
      const code = '// Copyright 01/15/2024 - All rights reserved';
      const strictDetector = new PHIDetector({ sensitivity: 'strict' });
      const findings = strictDetector.detect(code, 'test.ts');
      expect(findings.filter((f) => f.identifierType === 'date_of_birth')).toHaveLength(0);
    });
  });

  describe('Type Definition Skipping', () => {
    it('should not flag PHI variable names inside interface definitions', () => {
      const code = 'interface PatientRecord {\n  patientName: string;\n}';
      const findings = detector.detect(code, 'test.ts');
      // "interface PatientRecord {" should be skipped for variable detection
      // but the field definition "patientName: string" on the next line is not an interface line
      // so it may still be detected — the key test is the interface line itself
      const interfaceLineFindings = findings.filter((f) => f.lineNumber === 1);
      expect(
        interfaceLineFindings.filter(
          (f) => f.identifierType === 'name' || f.identifierType === 'medical_record_number',
        ),
      ).toHaveLength(0);
    });

    it('should not flag PHI variable names inside type definitions', () => {
      const code = 'type PatientData = { patientName: string; ssn: string; }';
      const findings = detector.detect(code, 'test.ts');
      // The "type" line should be skipped for variable name patterns
      const varFindings = findings.filter(
        (f) => f.identifierType === 'name' || f.identifierType === 'ssn',
      );
      expect(varFindings).toHaveLength(0);
    });

    it('should still flag PHI variable names in const assignments', () => {
      const code = 'const patientName = "John Doe";';
      const findings = detector.detect(code, 'test.ts');
      expect(findings.some((f) => f.identifierType === 'name')).toBe(true);
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

  describe('Base64 PHI Detection', () => {
    it('should detect base64-encoded SSN', () => {
      // "123-45-6789" in base64
      const encoded = Buffer.from('123-45-6789').toString('base64');
      const code = `const data = "${encoded}";`;
      const findings = detector.detect(code, 'test.ts');
      expect(findings.some((f) => f.identifierType === 'ssn')).toBe(true);
      expect(findings.some((f) => f.matchedText.includes('[base64]'))).toBe(true);
    });

    it('should detect base64-encoded email', () => {
      const encoded = Buffer.from('patient@hospital.com').toString('base64');
      const code = `const payload = "${encoded}";`;
      const findings = detector.detect(code, 'test.ts');
      expect(findings.some((f) => f.identifierType === 'email')).toBe(true);
    });

    it('should detect base64-encoded MRN', () => {
      const encoded = Buffer.from('MRN123456').toString('base64');
      const code = `const record = "${encoded}";`;
      const findings = detector.detect(code, 'test.ts');
      expect(findings.some((f) => f.identifierType === 'medical_record_number')).toBe(true);
    });

    it('should not flag non-PHI base64 strings', () => {
      const encoded = Buffer.from('Hello World, this is a test').toString('base64');
      const code = `const msg = "${encoded}";`;
      const findings = detector.detect(code, 'test.ts');
      const base64Findings = findings.filter((f) => f.matchedText.includes('[base64]'));
      expect(base64Findings).toHaveLength(0);
    });

    it('should not flag short base64 strings', () => {
      // Too short to be meaningful base64
      const code = 'const x = "SGVsbA==";';
      const findings = detector.detect(code, 'test.ts');
      const base64Findings = findings.filter((f) => f.matchedText.includes('[base64]'));
      expect(base64Findings).toHaveLength(0);
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
