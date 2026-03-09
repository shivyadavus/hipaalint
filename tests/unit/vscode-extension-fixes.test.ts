import { describe, expect, it } from 'vitest';
import {
  fixCorsWildcardLine,
  fixHttpLine,
  fixWeakTlsLine,
} from '../../vscode-extension/src/fixes.js';

describe('VS Code extension quick fixes', () => {
  it('upgrades insecure http URLs', () => {
    expect(fixHttpLine('const url = "http://api.example.com";')).toBe(
      'const url = "https://api.example.com";',
    );
  });

  it('upgrades weak TLS markers', () => {
    expect(fixWeakTlsLine('minVersion: "TLSv1_1"')).toBe('minVersion: "TLSv1_2"');
  });

  it('rewrites wildcard cors configuration', () => {
    expect(fixCorsWildcardLine('app.use(cors());')).toBe(
      'app.use(cors({ origin: process.env.CORS_ORIGIN }));',
    );
  });
});
