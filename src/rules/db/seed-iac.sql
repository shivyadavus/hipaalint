-- HipaaLint AI — IaC / Terraform / CloudFormation Rules
-- Detects HIPAA compliance issues in infrastructure-as-code files

-- ─────────────────────────────────────────────────
-- Framework (reuse HIPAA framework_id = 1)
-- These rules extend the HIPAA framework with IaC-specific checks
-- ─────────────────────────────────────────────────

INSERT INTO rules (framework_id, rule_id, title, description, severity, category, citation, remediation, pattern_type, pattern_config, is_required)
VALUES
-- S3 Encryption
(1, 'HIPAA-IAC-001', 'Unencrypted S3 Bucket', 'Detects S3 buckets without server-side encryption configuration in Terraform/CloudFormation.', 'critical', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Add server_side_encryption_configuration block with AES-256 or aws:kms algorithm.', 'config_pattern', '{"checkFiles":["*.tf","*.hcl","*.yaml","*.yml","*.json"],"patterns":["aws_s3_bucket"],"requiredNearby":["server_side_encryption","sse_algorithm","SSEAlgorithm","ServerSideEncryptionConfiguration"]}', 1),

-- RDS Encryption
(1, 'HIPAA-IAC-002', 'Unencrypted RDS Instance', 'Detects RDS database instances without encryption at rest.', 'critical', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Set storage_encrypted = true and specify a KMS key for RDS instances containing PHI.', 'code_pattern', '{"patterns":["storage_encrypted\\s*=\\s*false","StorageEncrypted.*false"],"exclude":["*.test.*"]}', 1),

-- EBS Encryption
(1, 'HIPAA-IAC-003', 'Unencrypted EBS Volume', 'Detects EBS volumes without encryption enabled.', 'high', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Set encrypted = true on all aws_ebs_volume resources. Enable default EBS encryption for the account.', 'code_pattern', '{"patterns":["aws_ebs_volume[^}]*encrypted\\s*=\\s*false"],"exclude":["*.test.*"]}', 0),

-- Public S3 Bucket
(1, 'HIPAA-IAC-004', 'Public S3 Bucket Policy', 'Detects S3 bucket policies or ACLs that allow public access.', 'critical', 'access_control', '45 CFR §164.312(a)(1) — Access Control', 'Remove public-read, public-read-write ACLs. Use block_public_access with all settings enabled.', 'code_pattern', '{"patterns":["acl\\s*=\\s*\"public","public-read","block_public_acls\\s*=\\s*false","block_public_policy\\s*=\\s*false","ignore_public_acls\\s*=\\s*false","restrict_public_buckets\\s*=\\s*false","PublicAccessBlockConfiguration"],"exclude":["*.test.*"]}', 1),

-- Missing CloudTrail
(1, 'HIPAA-IAC-005', 'Missing CloudTrail Logging', 'Checks that AWS CloudTrail is configured for audit logging of PHI access.', 'high', 'audit_logging', '45 CFR §164.312(b) — Audit Controls', 'Enable CloudTrail with multi-region logging and log file validation. Send logs to a dedicated S3 bucket.', 'config_pattern', '{"checkFiles":["*.tf","*.hcl","*.yaml","*.yml"],"patterns":["aws_cloudtrail","AWS::CloudTrail","cloudtrail"]}', 0),

-- Missing VPC Flow Logs
(1, 'HIPAA-IAC-006', 'Missing VPC Flow Logs', 'Detects VPCs without flow logs enabled for network monitoring.', 'medium', 'audit_logging', '45 CFR §164.312(b) — Audit Controls', 'Enable VPC flow logs and send to CloudWatch Logs or S3 for analysis and retention.', 'config_pattern', '{"checkFiles":["*.tf","*.hcl","*.yaml","*.yml"],"patterns":["aws_flow_log","FlowLog","flow_log"]}', 0),

-- Unencrypted DynamoDB
(1, 'HIPAA-IAC-007', 'Unencrypted DynamoDB Table', 'Detects DynamoDB tables without server-side encryption.', 'high', 'encryption', '45 CFR §164.312(a)(2)(iv) — Encryption and Decryption', 'Set server_side_encryption { enabled = true } with a KMS key on all DynamoDB tables containing PHI.', 'code_pattern', '{"patterns":["aws_dynamodb_table[^}]*server_side_encryption\\s*\\{[^}]*enabled\\s*=\\s*false"],"exclude":["*.test.*"]}', 0),

-- Open Security Group
(1, 'HIPAA-IAC-008', 'Overly Permissive Security Group', 'Detects security groups with unrestricted ingress (0.0.0.0/0) on sensitive ports.', 'critical', 'infrastructure', '45 CFR §164.312(e)(1) — Transmission Security', 'Restrict ingress rules to specific IP ranges. Never allow 0.0.0.0/0 on database or internal service ports.', 'code_pattern', '{"patterns":["cidr_blocks.*0\\.0\\.0\\.0/0","CidrIp.*0\\.0\\.0\\.0/0","ingress.*0\\.0\\.0\\.0/0"],"exclude":["*.test.*"]}', 1),

-- Missing WAF
(1, 'HIPAA-IAC-009', 'Missing Web Application Firewall', 'Checks for WAF configuration on public-facing load balancers and API gateways.', 'medium', 'infrastructure', '45 CFR §164.312(e)(1) — Transmission Security', 'Attach AWS WAF to ALB/API Gateway. Configure rate-based rules and managed rule groups.', 'config_pattern', '{"checkFiles":["*.tf","*.hcl","*.yaml","*.yml"],"patterns":["aws_wafv2","aws_waf","WAFv2","WebACL"]}', 0),

-- Missing Backup Config
(1, 'HIPAA-IAC-010', 'Missing Automated Backup', 'Detects database and storage resources without automated backup configuration.', 'high', 'infrastructure', '45 CFR §164.308(a)(7)(ii)(A) — Data Backup Plan', 'Enable automated backups with appropriate retention periods. Use AWS Backup for centralized management.', 'code_pattern', '{"patterns":["backup_retention_period\\s*=\\s*0","skip_final_snapshot\\s*=\\s*true","deletion_protection\\s*=\\s*false"],"exclude":["*.test.*"]}', 0);
