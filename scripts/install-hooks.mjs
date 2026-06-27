#!/usr/bin/env node
// ============================================================
// P19 — Git hook installer (no npm dependency, no husky)
// ============================================================
// Wires up a tracked .githooks/ directory via `git config core.hooksPath`
// so the pre-commit token scan runs on every commit. This survives clone
// (the hook is tracked) and needs no node_modules.
//
// Idempotent and cross-platform (pure Node). Degrades gracefully (exit 0)
// when there is no .git directory — e.g. CI tarball installs — so it is
// safe to run from the package.json "prepare" script.
// ============================================================

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');
const hooksDir = join(repoRoot, '.githooks');
const preCommitPath = join(hooksDir, 'pre-commit');

// POSIX sh shim. Git for Windows runs hooks under its bundled bash, so a
// shell script works on Windows and POSIX alike. It just execs node.
const HOOK_SHIM = `#!/bin/sh
# Installed by scripts/install-hooks.mjs — do not edit by hand.
# Blocks commits that add token-shaped secrets or token-logging.
exec node scripts/pre-commit-token-scan.mjs
`;

function inGitRepo() {
  // A plain .git dir, or a worktree/.git file pointer.
  if (existsSync(join(repoRoot, '.git'))) return true;
  try {
    execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd: repoRoot,
      stdio: 'ignore',
    });
    return true;
  } catch {
    return false;
  }
}

function main() {
  if (!inGitRepo()) {
    // No git context (CI install, tarball, etc.) — nothing to wire up.
    console.log('• install-hooks: no .git directory found, skipping (this is fine).');
    process.exit(0);
  }

  // 1. Ensure the tracked hooks dir + shim exist with current content.
  mkdirSync(hooksDir, { recursive: true });
  const desired = HOOK_SHIM;
  const current = existsSync(preCommitPath) ? readFileSync(preCommitPath, 'utf8') : null;
  if (current !== desired) {
    writeFileSync(preCommitPath, desired, 'utf8');
  }
  // Best-effort executable bit (no-op / harmless on Windows).
  try {
    chmodSync(preCommitPath, 0o755);
  } catch {
    /* ignore — not all filesystems support chmod */
  }

  // 2. Point git at the tracked hooks dir (idempotent).
  try {
    execFileSync('git', ['config', 'core.hooksPath', '.githooks'], {
      cwd: repoRoot,
      stdio: 'ignore',
    });
  } catch (err) {
    console.error('✖ install-hooks: could not set core.hooksPath: ' + err.message);
    // Don't fail npm install over this.
    process.exit(0);
  }

  console.log('✓ install-hooks: pre-commit token scan installed (.githooks via core.hooksPath).');
  process.exit(0);
}

main();
