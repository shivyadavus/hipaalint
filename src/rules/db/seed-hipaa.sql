-- ComplianceShield AI — HIPAA Rule Seed Data
-- Covers all 6 scoring domains per PRD Section 6.1

-- ─────────────────────────────────────────────────
-- Framework
-- ─────────────────────────────────────────────────
INSERT OR IGNORE INTO frameworks (name, version, description, source_url)
VALUES ('hipaa', '2025.1', 'Health Insurance Portability and Accountability Act — Security Rule (2025 Update)', 'https://www.hhs.gov/hipaa/for-professionals/security/index.html');

-- ─────────────────────────────────────────────────
-- DOMAIN 1: PHI Protection (25% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-PHI-001', 'PHI in Log Statements', 'Detects potential PHI (names, SSN, DOB, medical records) in log/print statements.', 'critical', 'phi_protection', '45 CFR §164.502(a) — Minimum Necessary', 'Remove PHI from all log statements. Use tokenized identifiers instead of real patient data.', 'ast_pattern', '{"nodeTypes":["call_expression"],"functionNames":["console.log","console.error","console.warn","console.info","console.debug","logger.info","logger.warn","logger.error","logger.debug","print","logging.info","logging.warning","logging.error","logging.debug"],"checkArguments":true}', 1),

(1, 'HIPAA-PHI-002', 'SSN Pattern in Source Code', 'Detects Social Security Number patterns (XXX-XX-XXXX) in source code.', 'critical', 'phi_protection', '45 CFR §164.514(a) — De-identification', 'Never hardcode SSNs. Use environment variables or secure vault references.', 'code_pattern', '{"regex":"\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b","exclude":["*.test.*","*.spec.*"]}', 1),

(1, 'HIPAA-PHI-003', 'Email Pattern in Code', 'Detects hardcoded email addresses that may represent patient PII.', 'high', 'phi_protection', '45 CFR §164.514(b)(2)(i)(C) — Electronic mail addresses', 'Use tokenized references. Store emails only in encrypted database fields.', 'code_pattern', '{"regex":"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}","contextCheck":true,"excludePatterns":["@example\\\\.com","@test\\\\.com","@localhost"]}', 1),

(1, 'HIPAA-PHI-004', 'Phone Number Pattern', 'Detects US phone number patterns that may represent patient PII.', 'high', 'phi_protection', '45 CFR §164.514(b)(2)(i)(D) — Telephone numbers', 'Remove hardcoded phone numbers. Use references to encrypted storage.', 'code_pattern', '{"regex":"\\\\(?\\\\d{3}\\\\)?[-.\\\\s]?\\\\d{3}[-.\\\\s]?\\\\d{4}","contextCheck":true}', 1),

(1, 'HIPAA-PHI-005', 'IP Address in Logs', 'Detects IP addresses being logged, which HIPAA considers a unique identifier.', 'high', 'phi_protection', '45 CFR §164.514(b)(2)(i)(O) — Internet Protocol address numbers', 'Hash or mask IP addresses before logging. Use anonymized identifiers.', 'code_pattern', '{"regex":"\\\\b(?:\\\\d{1,3}\\\\.){3}\\\\d{1,3}\\\\b","contextRequired":["log","print","console","logger"]}', 1),

(1, 'HIPAA-PHI-006', 'Date of Birth Pattern', 'Detects date of birth fields and patterns that could expose patient age.', 'high', 'phi_protection', '45 CFR §164.514(b)(2)(i)(B) — Dates related to individual', 'Use age ranges instead of exact dates. Store DOB only in encrypted fields.', 'code_pattern', '{"variableNames":["dob","dateOfBirth","date_of_birth","birthDate","birth_date","patientDOB","patient_dob"],"caseSensitive":false}', 1),

(1, 'HIPAA-PHI-007', 'Patient Name in Variables', 'Detects variable names suggesting patient name storage without proper protection.', 'medium', 'phi_protection', '45 CFR §164.514(b)(2)(i)(A) — Names', 'Use patient IDs instead of names in variable references. Encrypt name fields.', 'code_pattern', '{"variableNames":["patientName","patient_name","patientFirstName","patient_first_name","patientLastName","patient_last_name","firstName","lastName"],"contextCheck":true}', 1),

(1, 'HIPAA-PHI-008', 'Medical Record Number Exposure', 'Detects medical record numbers in code or logs.', 'critical', 'phi_protection', '45 CFR §164.514(b)(2)(i)(F) — Medical record numbers', 'Never log or expose MRN. Use encrypted references.', 'code_pattern', '{"variableNames":["mrn","medicalRecordNumber","medical_record_number","medicalRecordNum","medical_record_num"],"caseSensitive":false}', 1),

(1, 'HIPAA-PHI-009', 'PHI in API Response', 'Detects potential PHI being returned in API responses without proper authorization checks.', 'critical', 'phi_protection', '45 CFR §164.312(a)(1) — Access Control', 'Implement response filtering. Only return PHI with proper authorization. Use DTOs to control response shape.', 'ast_pattern', '{"nodeTypes":["return_statement","object"],"checkForPHIFields":true,"apiContext":true}', 1),

(1, 'HIPAA-PHI-010', 'PHI in Error Messages', 'Detects potential PHI exposure through error messages and exception handlers.', 'high', 'phi_protection', '45 CFR §164.502(a) — Minimum Necessary', 'Scrub all PHI from error messages. Use generic error codes.', 'ast_pattern', '{"nodeTypes":["catch_clause","except_clause"],"checkThrowContent":true}', 1);

-- ─────────────────────────────────────────────────
-- DOMAIN 2: Encryption & Transport (20% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-ENC-001', 'Unencrypted HTTP Usage', 'Detects use of http:// (unencrypted) for API calls or data transmission.', 'critical', 'encryption', '45 CFR §164.312(e)(1) — Transmission Security', 'Use https:// for all data transmission. Configure TLS 1.2+ minimum.', 'negative_pattern', '{"regex":"http://(?!localhost|127\\\\.0\\\\.0\\\\.1|0\\\\.0\\\\.0\\\\.0)","exclude":["*.test.*","*.md"]}', 1),

(1, 'HIPAA-ENC-002', 'Weak Hashing Algorithm', 'Detects use of MD5 or SHA1 for hashing sensitive data.', 'high', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Use SHA-256+ or Argon2id/bcrypt for password hashing. AES-256 for data encryption.', 'code_pattern', '{"functionNames":["md5","MD5","sha1","SHA1","createHash"],"argPatterns":["md5","sha1"]}', 1),

(1, 'HIPAA-ENC-003', 'Missing Encryption at Rest', 'Checks for database connections or file storage without encryption configuration.', 'critical', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Enable encryption at rest for all databases and file storage containing PHI.', 'config_pattern', '{"checkFiles":["*.env","*.config.*","database.*"],"requiredSettings":["ENCRYPTION","encrypt","ssl"]}', 1),

(1, 'HIPAA-ENC-004', 'Hardcoded Encryption Key', 'Detects hardcoded encryption keys or secrets in source code.', 'critical', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).', 'code_pattern', '{"variableNames":["secretKey","secret_key","encryptionKey","encryption_key","apiKey","api_key","privateKey","private_key","password","passwd"],"checkAssignment":true,"excludeEnvAccess":true}', 1),

(1, 'HIPAA-ENC-005', 'TLS Version Check', 'Ensures TLS 1.2 or higher is enforced for all secure connections.', 'high', 'encryption', '45 CFR §164.312(e)(2)(ii) — Encryption', 'Set minimum TLS version to 1.2. Prefer TLS 1.3. Disable SSLv3, TLS 1.0, TLS 1.1.', 'code_pattern', '{"patterns":["TLSv1_0","TLSv1_1","SSLv3","ssl3","tls1_0","tls1_1"],"isNegative":true}', 1),

(1, 'HIPAA-ENC-006', 'Plain Text Password Storage', 'Detects password storage without hashing or encryption.', 'critical', 'encryption', '45 CFR §164.312(d) — Person or Entity Authentication', 'Hash passwords with Argon2id or bcrypt with minimum 10 rounds. Never store plaintext.', 'code_pattern', '{"patterns":["password\\\\s*=\\\\s*[\\'\\'\\\"\\\\`]","password\\\\s*:\\\\s*[\\'\\'\\\"\\\\`]"],"excludePatterns":["hash","encrypt","bcrypt","argon","scrypt"]}', 1);

-- ─────────────────────────────────────────────────
-- DOMAIN 3: Access Control (20% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-AC-001', 'Missing Authentication Middleware', 'Checks that API routes handling PHI have authentication middleware.', 'critical', 'access_control', '45 CFR §164.312(d) — Person or Entity Authentication', 'Add authentication middleware to all routes that access PHI. Use JWT or session-based auth.', 'ast_pattern', '{"routePatterns":["app.get","app.post","app.put","app.delete","router.get","router.post"],"requireMiddleware":["auth","authenticate","requireAuth","isAuthenticated","verifyToken"]}', 1),

(1, 'HIPAA-AC-002', 'Missing Authorization Check', 'Detects PHI access without role-based authorization verification.', 'high', 'access_control', '45 CFR §164.312(a)(1) — Access Control', 'Implement RBAC. Check user roles before granting PHI access.', 'code_pattern', '{"patterns":["patient","medical","health","diagnosis","prescription"],"requireNearby":["authorize","checkRole","hasPermission","canAccess","rbac"]}', 1),

(1, 'HIPAA-AC-003', 'Session Timeout Configuration', 'Checks for proper session timeout configuration (15-30 minutes per HIPAA).', 'medium', 'access_control', '45 CFR §164.312(a)(2)(iii) — Automatic Logoff', 'Set session timeout to 15-30 minutes. Implement idle timeout and absolute timeout.', 'config_pattern', '{"checkFiles":["*.env","*.config.*","session.*"],"patterns":["SESSION_TIMEOUT","sessionTimeout","maxAge","cookie.maxAge"],"maxValueMs":1800000}', 1),

(1, 'HIPAA-AC-004', 'Missing MFA Implementation', 'Checks for multi-factor authentication implementation for PHI access.', 'high', 'access_control', '45 CFR §164.312(d) — Person or Entity Authentication', 'Implement MFA for all users accessing PHI. Use TOTP, WebAuthn, or SMS as second factor.', 'import_pattern', '{"requiredImports":["totp","mfa","two-factor","otplib","speakeasy","webauthn"],"context":"authentication"}', 1);

-- ─────────────────────────────────────────────────
-- DOMAIN 4: Audit & Logging (15% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-AL-001', 'Missing Audit Log Implementation', 'Checks that PHI access events are being logged for audit purposes.', 'high', 'audit_logging', '45 CFR §164.312(b) — Audit Controls', 'Implement audit logging for all PHI access, modification, and deletion events.', 'import_pattern', '{"requiredImports":["audit","audit-log","winston","pino","bunyan","log4js"],"context":"logging"}', 1),

(1, 'HIPAA-AL-002', 'PHI in Audit Logs', 'Ensures audit logs do not contain actual PHI values.', 'critical', 'audit_logging', '45 CFR §164.502(a) — Minimum Necessary', 'Log only identifiers and event types. Never log actual PHI values in audit trails.', 'code_pattern', '{"auditContextPatterns":["audit.log","auditLog","audit_log","createAuditEntry"],"checkForPHI":true}', 1),

(1, 'HIPAA-AL-003', 'Log Retention Configuration', 'Checks for log retention configuration meeting HIPAA 6-year requirement.', 'medium', 'audit_logging', '45 CFR §164.530(j) — Retention Period (6 years)', 'Configure log retention for minimum 6 years. Use tamper-proof storage.', 'config_pattern', '{"checkFiles":["*.env","*.config.*","logging.*"],"patterns":["LOG_RETENTION","logRetention","retentionDays","retentionPeriod"]}', 1);

-- ─────────────────────────────────────────────────
-- DOMAIN 5: Infrastructure & Network (10% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-INF-001', 'CORS Misconfiguration', 'Detects overly permissive CORS configuration allowing any origin.', 'high', 'infrastructure', '45 CFR §164.312(e)(1) — Transmission Security', 'Restrict CORS to specific trusted origins. Never use origin: * in production.', 'code_pattern', '{"patterns":["origin:\\\\s*[\\'\\'\\\"\\\\`]\\\\*[\\'\\'\\\"\\\\`]","Access-Control-Allow-Origin.*\\\\*","cors\\\\(\\\\)"],"exclude":["*.test.*"]}', 1),

(1, 'HIPAA-INF-002', 'Missing Rate Limiting', 'Checks that API endpoints have rate limiting to prevent abuse.', 'medium', 'infrastructure', '45 CFR §164.312(a)(1) — Access Control', 'Implement rate limiting on all API endpoints. Use token bucket or sliding window algorithm.', 'import_pattern', '{"requiredImports":["rate-limit","express-rate-limit","ratelimit","throttle","bottleneck"],"context":"api"}', 1),

(1, 'HIPAA-INF-003', 'Missing Security Headers', 'Checks for essential security headers (HSTS, CSP, X-Frame-Options).', 'medium', 'infrastructure', '45 CFR §164.312(e)(2)(ii) — Encryption', 'Use helmet.js or manually set security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options.', 'import_pattern', '{"requiredImports":["helmet","csp","hsts"],"context":"security"}', 1);

-- ─────────────────────────────────────────────────
-- DOMAIN 6: AI & Data Governance (10% weight)
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
(1, 'HIPAA-AI-001', 'PHI in AI/LLM Prompts', 'Detects potential PHI being sent to AI/LLM APIs without guardrails.', 'critical', 'ai_governance', '45 CFR §164.502(a) — Minimum Necessary', 'Implement prompt sanitization. Strip all PHI before sending to AI APIs. Use de-identified data only.', 'code_pattern', '{"functionNames":["openai.chat","anthropic.messages","completion","generate","createChatCompletion","chat.completions.create"],"checkArguments":true,"phiPatterns":true}', 1),

(1, 'HIPAA-AI-002', 'Missing AI Data Governance', 'Checks for AI/ML model training data exclusion policies.', 'high', 'ai_governance', '45 CFR §164.502(a) — Minimum Necessary', 'Ensure PHI is excluded from model training data. Document data governance policies.', 'config_pattern', '{"checkFiles":["*.env","*.config.*","ai.*","ml.*"],"patterns":["training_data_exclusion","data_governance","phi_exclusion"]}', 1),

(1, 'HIPAA-AI-003', 'AI Conversation Logging', 'Detects AI conversation logging that might capture PHI.', 'high', 'ai_governance', '45 CFR §164.502(a) — Minimum Necessary', 'Sanitize AI conversation logs. Remove PHI before storing conversation history.', 'code_pattern', '{"patterns":["conversation.log","chat.log","prompt.log","saveConversation","logPrompt","logConversation"],"checkForPHI":true}', 1);
