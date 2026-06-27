#!/usr/bin/env node
// ============================================================
// D3 — Extension packaging script
// ============================================================
// Produces a production zip of the extension/ directory for Chrome Web Store
// upload, into dist/nxlv-shield-extension-v<version>.zip. The version is read
// from extension/manifest.json.
//
// Zipping is delegated to a built-in archiver so no npm dependency is added:
//   • Windows  → PowerShell Compress-Archive
//   • POSIX    → the `zip` command
// If neither is available the script prints the file list and a clear error.
//
// .DS_Store and *.map files are excluded; everything else under extension/ is
// shippable.
// ============================================================

import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  existsSync,
  rmSync,
} from 'node:fs';
import { dirname, join, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { platform } from 'node:os';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const extDir = join(repoRoot, 'extension');
const distDir = join(repoRoot, 'dist');

const EXCLUDE_NAMES = new Set(['.DS_Store', 'Thumbs.db']);
const EXCLUDE_EXT = ['.map'];

function isExcluded(name) {
  if (EXCLUDE_NAMES.has(name)) return true;
  return EXCLUDE_EXT.some((ext) => name.endsWith(ext));
}

/** Recursively collect shippable files (relative to extDir). */
function collectFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (isExcluded(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFiles(full));
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
  return out;
}

function readVersion() {
  const manifest = JSON.parse(readFileSync(join(extDir, 'manifest.json'), 'utf8'));
  if (!manifest.version) {
    throw new Error('extension/manifest.json has no "version" field.');
  }
  return manifest.version;
}

function humanSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function hasCommand(cmd, args) {
  try {
    execFileSync(cmd, args, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** Zip on Windows via PowerShell Compress-Archive. */
function zipWindows(files, outPath) {
  // Compress-Archive preserves relative paths when given items inside a dir,
  // so zip the contents of extension/ (the manifest must sit at the zip root).
  const items = readdirSync(extDir)
    .filter((n) => !isExcluded(n))
    .map((n) => join(extDir, n));
  const quoted = items.map((p) => `'${p.replace(/'/g, "''")}'`).join(', ');
  const ps =
    `$ErrorActionPreference='Stop'; ` +
    `Compress-Archive -Force -DestinationPath '${outPath.replace(/'/g, "''")}' -Path ${quoted}`;
  execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], {
    stdio: 'ignore',
  });
}

/** Zip on POSIX via the `zip` command (run from inside extension/). */
function zipPosix(files, outPath) {
  const rel = files.map((f) => relative(extDir, f));
  // -X strips extra file attributes; -@ reads the file list from stdin.
  execFileSync('zip', ['-X', '-q', outPath, ...rel], {
    cwd: extDir,
    stdio: 'ignore',
  });
}

function main() {
  if (!existsSync(extDir)) {
    console.error('✖ extension/ directory not found.');
    process.exit(1);
  }

  const version = readVersion();
  const files = collectFiles(extDir);
  if (files.length === 0) {
    console.error('✖ No shippable files found under extension/.');
    process.exit(1);
  }

  mkdirSync(distDir, { recursive: true });
  const outPath = join(distDir, `nxlv-shield-extension-v${version}.zip`);

  // Remove a stale archive so the new one is clean.
  if (existsSync(outPath)) rmSync(outPath);

  const isWindows = platform() === 'win32';
  let zipped = false;

  if (isWindows && hasCommand('powershell', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major'])) {
    zipWindows(files, outPath);
    zipped = true;
  } else if (hasCommand('zip', ['-v'])) {
    zipPosix(files, outPath);
    zipped = true;
  }

  if (!zipped) {
    console.error('✖ No built-in archiver available (need PowerShell Compress-Archive on Windows, or `zip` on POSIX).');
    console.error('  Files that would have been packaged:');
    for (const f of files) console.error('    ' + relative(repoRoot, f));
    process.exit(1);
  }

  const size = statSync(outPath).size;
  console.log('✓ Extension packaged.');
  console.log(`  version: ${version}`);
  console.log(`  files:   ${files.length}`);
  console.log(`  output:  ${relative(repoRoot, outPath)}`);
  console.log(`  size:    ${humanSize(size)}`);
  process.exit(0);
}

main();
