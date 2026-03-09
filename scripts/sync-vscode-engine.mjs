import { cpSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';

const root = process.cwd();
const sourceDir = join(root, 'dist');
const targetDir = join(root, 'vscode-extension', 'vendor', 'hipaalint');

rmSync(targetDir, { recursive: true, force: true });
mkdirSync(targetDir, { recursive: true });
cpSync(sourceDir, join(targetDir, 'dist'), { recursive: true });
writeFileSync(
  join(targetDir, 'package.json'),
  JSON.stringify(
    {
      name: '@hipaalint/embedded',
      private: true,
      type: 'module',
      main: './dist/index.js',
    },
    null,
    2,
  ),
);

console.log('Synced dist/ into vscode-extension/vendor/hipaalint');
