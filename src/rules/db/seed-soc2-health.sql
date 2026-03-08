-- HipaaLint AI — SOC2 Health Framework Stub
-- Maps common Trust Services Criteria to compliance rules for healthcare

INSERT OR IGNORE INTO frameworks (name, version, description, source_url)
VALUES ('soc2-health', '2024.1', 'SOC2 Trust Services Criteria — Healthcare Supplement', 'https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2');

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC6.1-001', 'Unencrypted Data Transmission', 'Detects unencrypted HTTP usage per SOC2 logical access controls.', 'critical', 'encryption', 'SOC2 CC6.1 — Logical and Physical Access Controls', 'Use HTTPS for all data transmission. Enforce TLS 1.2+.', 'negative_pattern', '{"regex":"http://(?!localhost|127\\\\.0\\\\.0\\\\.1|0\\\\.0\\\\.0\\\\.0)","exclude":["*.test.*","*.md"]}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC6.1-002', 'Hardcoded Credentials', 'Detects hardcoded secrets per SOC2 encryption and key management criteria.', 'critical', 'encryption', 'SOC2 CC6.1 — Logical and Physical Access Controls', 'Use environment variables or a secrets manager for all credentials.', 'code_pattern', '{"variableNames":["secretKey","secret_key","encryptionKey","encryption_key","apiKey","api_key","privateKey","private_key","password","passwd"],"checkAssignment":true,"excludeEnvAccess":true}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC6.6-001', 'Missing Authentication', 'Checks API routes for authentication middleware per SOC2 system boundary controls.', 'critical', 'access_control', 'SOC2 CC6.6 — System Boundaries', 'Add authentication middleware to all public-facing routes.', 'semantic_pattern', '{"routePatterns":["app.get","app.post","app.put","app.delete","router.get","router.post"],"requireMiddleware":["auth","authenticate","requireAuth","isAuthenticated","verifyToken"]}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC6.3-001', 'Missing MFA', 'Checks for multi-factor authentication per SOC2 role-based access criteria.', 'high', 'access_control', 'SOC2 CC6.3 — Role-Based Access', 'Implement MFA for administrative and PHI access.', 'import_pattern', '{"requiredImports":["totp","mfa","two-factor","otplib","speakeasy","webauthn","@auth0","passport","next-auth","@clerk"],"context":"authentication"}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC7.2-001', 'Missing Monitoring', 'Checks for security monitoring and audit logging per SOC2 monitoring criteria.', 'high', 'audit_logging', 'SOC2 CC7.2 — System Monitoring', 'Implement centralized logging and monitoring with alerting capabilities.', 'import_pattern', '{"requiredImports":["audit","audit-log","winston","pino","bunyan","log4js","@sentry","datadog","morgan"],"context":"logging"}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC7.2-002', 'PHI in Logs', 'Detects PHI in log statements per SOC2 monitoring criteria for healthcare.', 'critical', 'phi_protection', 'SOC2 CC7.2 — System Monitoring (Healthcare)', 'Remove PHI from log statements. Use tokenized identifiers.', 'semantic_pattern', '{"nodeTypes":["call_expression"],"functionNames":["console.log","console.error","console.warn","logger.info","logger.warn","logger.error","print","logging.info","logging.error"],"checkArguments":true}', 1),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC8.1-001', 'Missing Vulnerability Scanning', 'Checks for vulnerability scanning in the development pipeline per SOC2 change management.', 'medium', 'infrastructure', 'SOC2 CC8.1 — Change Management', 'Integrate vulnerability scanning (Snyk, Dependabot, Trivy) into CI/CD.', 'config_pattern', '{"checkFiles":["*.yml","*.yaml",".snyk","package.json",".github/**"],"patterns":["snyk","dependabot","trivy","npm audit","safety check"]}', 0),

((SELECT id FROM frameworks WHERE name = 'soc2-health'), 'SOC2-CC6.7-001', 'Missing Rate Limiting', 'Checks for rate limiting on API endpoints per SOC2 data flow controls.', 'medium', 'infrastructure', 'SOC2 CC6.7 — Data Flow Restrictions', 'Implement rate limiting on all public API endpoints.', 'import_pattern', '{"requiredImports":["rate-limit","express-rate-limit","ratelimit","throttle","bottleneck"],"context":"api"}', 1);
