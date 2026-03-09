export function fixHttpLine(line: string): string | null {
  const nextLine = line.replace(/http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g, 'https://');
  return nextLine === line ? null : nextLine;
}

export function fixWeakTlsLine(line: string): string | null {
  const nextLine = line.replace(/\b(TLSv1_0|TLSv1_1|SSLv3|ssl3|tls1_0|tls1_1)\b/g, (match) => {
    return /^[A-Z]/.test(match) ? 'TLSv1_2' : 'tls1_2';
  });
  return nextLine === line ? null : nextLine;
}

export function fixCorsWildcardLine(line: string): string | null {
  if (/origin:\s*["'`]\*["'`]/.test(line)) {
    return line.replace(/origin:\s*["'`]\*["'`]/g, 'origin: process.env.CORS_ORIGIN');
  }
  if (/Access-Control-Allow-Origin[^\n]*["'`]\*["'`]/.test(line)) {
    return line.replace(/["'`]\*["'`]/g, 'process.env.CORS_ORIGIN');
  }
  if (/\bcors\(\s*\)/.test(line)) {
    return line.replace(/\bcors\(\s*\)/g, 'cors({ origin: process.env.CORS_ORIGIN })');
  }
  return null;
}
