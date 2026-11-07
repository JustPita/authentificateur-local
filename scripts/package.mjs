// Construit dist/authentificateur-local-<version>.zip avec uniquement les fichiers de l'extension.
// Usage : node scripts/package.mjs   (nécessite `tar` avec -a, présent sur Windows 10+, macOS, Linux récents)
import { readFileSync, mkdirSync, rmSync, cpSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const manifest = JSON.parse(readFileSync('manifest.json', 'utf8'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
if (manifest.version !== pkg.version) {
  console.error(`Versions différentes : manifest ${manifest.version} / package ${pkg.version}`);
  process.exit(1);
}

const FILES = [
  'manifest.json', 'popup.html', 'popup.css', 'popup.js', 'cam.html', 'cam.css', 'cam.js',
  'lib.js', 'vault.js', 'jsQR.js', 'icons', 'LICENSE', 'LICENSE-jsQR', 'THIRD_PARTY.md',
];
const stage = join('dist', 'stage');
rmSync('dist', { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
for (const f of FILES) {
  if (!existsSync(f)) { console.error('Fichier manquant : ' + f); process.exit(1); }
  cpSync(f, join(stage, f), { recursive: true });
}
const out = `authentificateur-local-${manifest.version}.zip`;
// bsdtar (Windows, macOS) sait écrire du zip ; le tar GNU de Linux non, on utilise alors `zip`.
if (process.platform === 'linux') execFileSync('zip', ['-r', '-q', join('..', out), '.'], { cwd: stage, stdio: 'inherit' });
else execFileSync('tar', ['-a', '-c', '-f', join('..', out), '.'], { cwd: stage, stdio: 'inherit' });
rmSync(stage, { recursive: true, force: true });
console.log('Créé : dist/' + out);
