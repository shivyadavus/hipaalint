---
name: hipaa-compliance
description: >
  HIPAA compliance directives for AI-assisted development. Enforces PHI protection,
  encryption, access control, audit logging, and AI governance standards when generating
  or reviewing healthcare code.
user-invocable: true
argument-hint: "[path]"
allowed-tools: Read, Grep, Glob, Bash
---

# HIPAA Compliance Directives for AI-Assisted Development

You are a coding assistant that helps identify potential HIPAA compliance issues. When generating or reviewing code that handles Protected Health Information (PHI), you MUST follow these directives. Note: this tool assists with compliance best practices but does not guarantee HIPAA compliance or constitute legal advice.

## PHI — The 18 HIPAA Identifiers

NEVER expose the following in logs, error messages, API responses, or unencrypted storage:

1. **Names** — Patient full names, partial names
2. **Dates** — Birth dates, admission/discharge dates, death dates (ages 90+ are PHI)
3. **Phone numbers** — All telephone/fax numbers
4. **Email addresses** — All electronic mail addresses
5. **SSN** — Social Security Numbers
6. **Medical record numbers** — MRN, chart numbers
7. **Health plan beneficiary numbers** — Insurance IDs
8. **Account numbers** — Financial account identifiers
9. **Certificate/license numbers** — Professional licenses
10. **Vehicle identifiers** — VIN, license plates
11. **Device identifiers** — Serial numbers, UDIs
12. **URLs** — Web addresses tied to individuals
13. **IP addresses** — Network addresses
14. **Biometric identifiers** — Fingerprints, retinal scans, voiceprints
15. **Full-face photos** — Photographic images
16. **Geographic data** — Street addresses, ZIP codes (3-digit OK if population >20K)
17. **Fax numbers** — All fax numbers
18. **Any other unique identifier** — Any code that could identify an individual

## Encryption Requirements

- **At rest**: AES-256 for all PHI data storage
- **In transit**: TLS 1.2+ (prefer TLS 1.3) for all data transmission
- **Passwords**: Hash with Argon2id (preferred) or bcrypt (minimum 10 rounds)
- **Keys**: Never hardcode. Use environment variables or secrets managers (AWS Secrets Manager, HashiCorp Vault)
- **Key rotation**: Implement automated key rotation (90-day maximum)

## Access Control Patterns

- Implement RBAC (Role-Based Access Control) for all PHI access
- Require MFA for all users accessing PHI
- Session timeout: 15-30 minutes of inactivity
- Account lockout after 5 failed attempts
- Principle of least privilege — grant minimum necessary access

## Audit Logging Requirements

- Log ALL PHI access events (read, create, update, delete)
- Log MUST include: who, what, when, where, outcome
- NEVER log actual PHI values — log only identifiers and event types
- Retention: minimum 6 years (45 CFR §164.530(j))
- Tamper-proof storage — use append-only, HMAC-chained logs

## PHI Scrubbing Patterns

```
// BAD — PHI in logs
console.log(`Patient ${patientName} SSN: ${ssn} admitted`);
logger.info({ patient: patientData });

// GOOD — Tokenized logging
console.log(`Patient [ID:${patientId}] admitted`);
logger.info({ patientId, event: 'admission', timestamp: new Date() });
```

```
// BAD — PHI in error messages
throw new Error(`Failed to process patient ${name}, SSN: ${ssn}`);

// GOOD — Generic error with reference
throw new Error(`Failed to process patient [ID:${patientId}]. See audit log.`);
```

```
// BAD — PHI in API response without authorization
app.get('/patient/:id', (req, res) => {
  res.json(patient); // Returns all fields including PHI
});

// GOOD — DTO pattern with authorization
app.get('/patient/:id', authenticate, authorize('read:patient'), (req, res) => {
  res.json(toPatientDTO(patient)); // Returns only authorized fields
});
```

## Database Schema Patterns

```sql
-- Encrypted PHI columns
CREATE TABLE patients (
  id UUID PRIMARY KEY,
  patient_id VARCHAR(50) NOT NULL, -- Internal reference, not PHI
  name_encrypted BYTEA NOT NULL,   -- AES-256 encrypted
  ssn_encrypted BYTEA NOT NULL,    -- AES-256 encrypted
  dob_encrypted BYTEA NOT NULL,    -- AES-256 encrypted
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

## AI-Specific Guardrails

- NEVER send PHI to AI/LLM APIs (OpenAI, Anthropic, etc.) without de-identification
- Strip all 18 identifiers before including in AI prompts
- Do not store AI conversation logs containing PHI
- Implement prompt injection protection for healthcare contexts
- Model training data MUST exclude PHI

## Code Review Checklist

Before approving any code that touches PHI:
- [ ] No PHI in log statements
- [ ] No PHI in error messages
- [ ] API responses filtered through DTOs
- [ ] Encryption at rest (AES-256) verified
- [ ] TLS 1.2+ for all endpoints
- [ ] RBAC middleware on PHI routes
- [ ] Audit logging for all PHI operations
- [ ] Session timeout configured (15-30 min)
- [ ] No hardcoded secrets or keys

---

> **Disclaimer:** These directives reflect HIPAA security rule best practices but do not constitute legal advice or guarantee regulatory compliance. Always consult qualified legal and compliance professionals for your specific requirements.
