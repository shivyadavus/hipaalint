-- HipaaLint AI — HITRUST CSF Framework Stub
-- Maps common controls to HIPAA-equivalent rules with HITRUST citations

INSERT OR IGNORE INTO frameworks (name, version, description, source_url)
VALUES ('hitrust', '11.0', 'HITRUST Common Security Framework v11 — Healthcare Security Controls', 'https://hitrustalliance.net/csf/');

-- Get the framework ID for hitrust
-- Note: framework_id will be auto-assigned; we use a subquery

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-09.L-01', 'PHI in Log Statements', 'Detects potential PHI in log/print statements per HITRUST audit logging controls.', 'critical', 'phi_protection', 'HITRUST CSF v11 — 09.L Monitoring System Use', 'Remove PHI from all log statements. Use tokenized identifiers.', 'semantic_pattern', '{"nodeTypes":["call_expression"],"functionNames":["console.log","console.error","console.warn","console.info","logger.info","logger.warn","logger.error","print","logging.info","logging.warning","logging.error"],"checkArguments":true}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-01.V-01', 'Unencrypted Data Transmission', 'Detects use of http:// for data transmission per HITRUST encryption controls.', 'critical', 'encryption', 'HITRUST CSF v11 — 01.v Information Exchange Policies', 'Use https:// for all data transmission. Configure TLS 1.2+ minimum.', 'negative_pattern', '{"regex":"http://(?!localhost|127\\\\.0\\\\.0\\\\.1|0\\\\.0\\\\.0\\\\.0)","exclude":["*.test.*","*.md"]}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-06.D-01', 'Hardcoded Secrets', 'Detects hardcoded encryption keys or secrets per HITRUST key management controls.', 'critical', 'encryption', 'HITRUST CSF v11 — 06.d Protection of Keys', 'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).', 'code_pattern', '{"variableNames":["secretKey","secret_key","encryptionKey","encryption_key","apiKey","api_key","privateKey","private_key","password","passwd"],"checkAssignment":true,"excludeEnvAccess":true}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-01.C-01', 'Missing Access Control', 'Checks for authentication middleware on routes per HITRUST access management controls.', 'critical', 'access_control', 'HITRUST CSF v11 — 01.c Privilege Management', 'Add authentication middleware to all routes that access sensitive data.', 'semantic_pattern', '{"routePatterns":["app.get","app.post","app.put","app.delete","router.get","router.post"],"requireMiddleware":["auth","authenticate","requireAuth","isAuthenticated","verifyToken"]}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-01.Q-01', 'Missing MFA', 'Checks for MFA implementation per HITRUST authentication requirements.', 'high', 'access_control', 'HITRUST CSF v11 — 01.q User Identification and Authentication', 'Implement MFA for all users accessing protected data.', 'import_pattern', '{"requiredImports":["totp","mfa","two-factor","otplib","speakeasy","webauthn","@auth0","amazon-cognito","passport","next-auth","@clerk"],"context":"authentication"}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-09.AA-01', 'Missing Audit Logging', 'Checks for audit log implementation per HITRUST monitoring controls.', 'high', 'audit_logging', 'HITRUST CSF v11 — 09.aa Audit Logging', 'Implement audit logging for all access and modification events.', 'import_pattern', '{"requiredImports":["audit","audit-log","winston","pino","bunyan","log4js","@sentry","datadog","morgan"],"context":"logging"}', 1),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-10.B-01', 'Missing Input Validation', 'Checks for proper input validation libraries per HITRUST data integrity controls.', 'high', 'infrastructure', 'HITRUST CSF v11 — 10.b Input Data Validation', 'Use input validation libraries (zod, joi, yup, class-validator) on all user inputs.', 'import_pattern', '{"requiredImports":["zod","joi","yup","class-validator","express-validator","validator","ajv"],"context":"validation"}', 0),

((SELECT id FROM frameworks WHERE name = 'hitrust'), 'HITRUST-09.M-01', 'Missing Security Headers', 'Checks for essential security headers per HITRUST network security controls.', 'medium', 'infrastructure', 'HITRUST CSF v11 — 09.m Network Controls', 'Use helmet.js or set HSTS, CSP, X-Frame-Options headers.', 'import_pattern', '{"requiredImports":["helmet","csp","hsts"],"context":"security"}', 1);
