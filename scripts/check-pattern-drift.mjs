#!/usr/bin/env node
// ============================================================
// A5 / H3 — Pattern drift-check (standalone CI entry)
// ============================================================
// Usage: npm run check:drift   (builds the CLI first so dist exists)
//
// Exits 1 if the extension and CLI pattern catalogs have drifted apart on a
// mapped pattern's severity or regex shape.
// ============================================================

import { compareCatalogs } from './pattern-drift-core.mjs';
import { FALLBACK_BUILTIN } from '../extension/lib/skills/pattern-catalog.js';

async function main() {
  let cli;
  try {
    cli = await import('../packages/cli/dist/engines/patterns.js');
  } catch (err) {
    console.error('✖ Could not load CLI patterns from dist. Run `npm run build:cli` first.');
    console.error('  ' + err.message);
    process.exit(2);
  }

  const cliPatterns = [...cli.SECRET_PATTERNS, ...cli.PII_PATTERNS];
  const { errors, warnings } = compareCatalogs(cliPatterns, FALLBACK_BUILTIN);

  for (const w of warnings) console.warn('⚠ ' + w);

  if (errors.length) {
    console.error(`\n✖ Pattern drift detected (${errors.length}):\n`);
    for (const e of errors) console.error('  • ' + e);
    console.error('\nFix: align the diverging pattern in both extension/lib/skills/pattern-catalog.js and packages/cli/src/engines/patterns.ts.');
    process.exit(1);
  }

  console.log('✓ Pattern catalogs in sync (no drift on mapped patterns).');
  process.exit(0);
}

main();
