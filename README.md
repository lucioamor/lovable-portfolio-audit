# NXLV Lovable Portfolio Audit — Lovable Portfolio Audit

> The self-audit security toolkit for Lovable builders — by [**Lucio Amorim**](https://linkedin.com/in/lucioamorim), **Lovable Ambassador**.

A self-service audit tool for Lovable.dev users to review their own projects for exposed credentials, misconfigured Supabase RLS policies, and sensitive data left in source code or chat history.

Run it against your own account. Get a clear report. Fix what needs fixing.

Built and maintained by [**Lucio Amorim**](https://linkedin.com/in/lucioamorim) — Lovable Ambassador — the same hands behind the [Lovable Skills catalog](https://github.com/lucioamor/lovable-skills) (`/wireframe`, `/debate`, `/unbot`). This project is part of a wider toolkit for builders who don't just ship Lovable apps — they verify, harden, and stand behind them.

[![Author: Lucio Amorim](https://img.shields.io/badge/By-Lucio%20Amorim-6c63ff?style=flat-square)](https://linkedin.com/in/lucioamorim) [![Role: Lovable Ambassador](https://img.shields.io/badge/Lovable-Ambassador-8b5cf6?style=flat-square)](https://linkedin.com/in/lucioamorim) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-2ed573?style=flat-square)](./LICENSE)

## Why this exists

As low-code and AI-assisted development tools gain adoption, credential leakage, data exposure, and access-control gaps have become a common class of risk across the whole ecosystem. When developers move fast, it's easy to leave API keys hardcoded, skip RLS configuration, or forget that chat history may be readable beyond its intended scope. These are general security pitfalls that apply to any platform, not faults specific to one.

This tool doesn't place blame — it places the solution in your hands. Instead of waiting for a platform to alert you, you audit yourself, find what's exposed, and fix it. That's it.

## What it does

### 🔍 Detection Engine

| Component | What it catches |
|---|---|
| 🔑 **Secret Patterns** | Supabase `service_role`, OpenAI `sk-*`, Anthropic `sk-ant-*`, Stripe `sk_live_*`, AWS `AKIA*`, GitHub `ghp_*`/`gho_*`/`ghs_*`, Firebase/Google `AIza*`, SendGrid `SG.*`, Slack `xox*`, Twilio, Resend, Postgres connection strings, JWT/PEM private keys, and more |
| 👤 **PII Patterns** | Email addresses, LinkedIn profiles, CPF/CNPJ (Brazilian tax IDs), credit card numbers (Luhn-shaped), phone numbers, US SSN, Stripe customer IDs (`cus_*`) |
| 🛡️ **BOLA/IDOR Test** | Probes file and chat endpoints to verify whether your project returns `200 OK` without ownership validation — a baseline access-control check aligned with the OWASP API Security Top 10 (BOLA). The CLI supports an optional dual-probe mode (`--audit-token`) that confirms cross-account exposure instead of inferring it from a single request |
| 🗄️ **Supabase RLS Audit** | Non-invasive check against common table names using only the `anon` key, plus a copy-paste deep-RLS SQL checklist whose pasted result the CLI classifies into `DB-003`/`DB-004`/`DB-005`/`DB-008`/`DB-009` findings — no automated SQL is ever run against an external Supabase |
| 📦 **Bundle / Source-map Scan** | The CLI fetches a target URL's HTML and JS chunks (read-only, bounded), flags exposed source maps and missing Subresource Integrity, and extracts a hardcoded Supabase URL + anon key to correlate with an RLS gap into a `compound_risk` finding |

The exact pattern set differs slightly between the two channels because they evolved against different rule catalogs:

- **Chrome Extension** (`extension/lib/data-patterns.js`): **24 secret patterns + 7 PII patterns**.
- **CLI** (`packages/cli/src/engines/patterns.ts`): **27 secret patterns + 8 PII patterns**.

### 📊 Analysis & Reporting

| Component | What it does |
|---|---|
| 🎯 **Risk Scoring (0–100)** | Weighted formula combining BOLA exposure, secret/PII counts, RLS status, source-map exposure, and project recency — auto-classifies as **Catastrophic** / **Critical** / **High** / **Medium** / **Low** / **Clean** |
| 🧾 **Reproducible Rationale** | Every score ships with a `rationale` breakdown (which signals contributed how many points) so the number is auditable, not a black box |
| 🖥️ **Extension Dashboard** | Dark side-panel UI with risk rings, severity badges, scan history, and per-finding remediation guidance |
| 🔁 **Baseline & Drift** | Both channels persist a fingerprinted baseline (CLI: `.nxlv-baseline.json`) and report `new` / `unchanged` / `resolved` findings between runs |
| 📦 **Demo Mode** | The extension can explore the full interface with realistic sample data — no token needed |

### 🚀 Output & Actions

| Component | What you get |
|---|---|
| 📥 **JSON / SARIF / Markdown / HTML** | The CLI emits structured JSON, GitHub-ready SARIF 2.1.0, a Markdown report, or a single self-contained HTML file (`--format json\|sarif\|markdown\|html\|all`) |
| 🔐 **Signed Evidence Pack** | The extension exports an HMAC-SHA256 signed report for tamper-proof forensic documentation (see [verification](#verifying-an-evidence-pack) below) |
| 🌐 **Trilingual UI** | 🇺🇸 English (default) · 🇧🇷 Português · 🇪🇸 Español — switch instantly, no reload |

## Two ways to run it

### 🧩 Chrome Extension (recommended)

Runs in your browser, reads your own `lovable.dev` session — no manual token handling required.

1. Open Chrome → `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked** and select the `extension/` directory from this repo
4. Pin the icon to your toolbar, open the side panel, and run a scan

### 🖥️ CLI (`@nxlv-ai/lovable-audit`)

A standalone Node CLI (Node ≥ 18) for terminal and CI use. It needs your Lovable Bearer token, which it reads from `--token` or the `LOVABLE_TOKEN` environment variable.

```bash
# Scan your account (interactive / local)
npx @nxlv-ai/lovable-audit scan --token <bearer>

# Or via env var
LOVABLE_TOKEN=<bearer> npx @nxlv-ai/lovable-audit scan

# Machine-readable / shareable output
npx @nxlv-ai/lovable-audit scan --token <bearer> --format json   --output results.json
npx @nxlv-ai/lovable-audit scan --token <bearer> --format sarif   --output results.sarif
npx @nxlv-ai/lovable-audit scan --token <bearer> --format markdown --output report.md
npx @nxlv-ai/lovable-audit scan --token <bearer> --format html    --output report.html

# Scan a deployed URL's headers, source maps, and bundle
npx @nxlv-ai/lovable-audit scan --token <bearer> --url https://myapp.lovable.app

# Confirm token validity only
npx @nxlv-ai/lovable-audit verify --token <bearer>
```

**Getting your token:** open `lovable.dev` while logged in, open DevTools (F12) → Network, filter for `api.lovable.dev`, and copy the `Authorization: Bearer <token>` value.

**Useful flags:** `--deep` (download and scan file contents locally, behind a consent prompt), `--audit-token` (dual-probe BOLA confirmation), `--baseline` / `--update-baseline` (drift tracking), `--rls-checklist` (print the copy-paste deep-RLS SQL), `--rls-result <file>` (classify a pasted RLS result), `--no-chat` / `--no-files` / `--no-rls` / `--no-headers` (scope the scan).

#### CI mode

The `ci` subcommand is optimized for pipelines: it writes SARIF and exits non-zero when critical or catastrophic findings are present.

```bash
LOVABLE_TOKEN=<bearer> npx @nxlv-ai/lovable-audit ci --output nxlv-audit.sarif
```

A ready-to-use GitHub Action workflow lives in `.github/workflows/nxlv-audit.yml`, and the published privacy policy is in `PRIVACY.md`.

#### More commands

```bash
# Regenerate a report from a saved JSON result — no re-scan
npx @nxlv-ai/lovable-audit report results.json --format html --output report.html

# Extract the copy-paste AI fix prompts from a saved result
npx @nxlv-ai/lovable-audit fix-prompt results.json --output prompts.md

# Verify the HMAC signature of an exported evidence pack
npx @nxlv-ai/lovable-audit verify-evidence pack.json --passphrase <device-key>

# Track drift vs a baseline and POST a summary to a webhook
# (payload carries only counts + finding identifiers — no tokens, no raw bodies)
npx @nxlv-ai/lovable-audit scan --token <bearer> --baseline --webhook https://example.com/hook
```

### Developer tooling

- **Pre-commit token guard** — `npm run hooks:install` wires a dependency-free git hook (`.githooks/pre-commit`) that blocks committing token-shaped strings or code that logs secrets. Bypass with `NXLV_SKIP_TOKEN_SCAN=1` when needed.
- **Package the extension** — `npm run package:ext` produces a Chrome Web Store zip under `dist/`.
- **Pattern drift gate** — `npm run check:drift` fails if the extension and CLI rule catalogs diverge.

### Verifying an Evidence Pack

The **Signed Evidence Pack** export (`lpa-evidence-*.json`) includes an `hmac_sha256` signature. This allows third parties to verify that the report was generated by this tool and has not been tampered with.

To verify using Node.js:

```js
const { webcrypto } = require('crypto');
const fs = require('fs');

async function verify() {
  const file = JSON.parse(fs.readFileSync('./lpa-evidence-123.json', 'utf-8'));
  const payloadStr = JSON.stringify(file.payload, null, 2);
  const passphrase = 'your-passphrase-or-device-key';

  const enc = new TextEncoder();
  const base = await webcrypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('lpa-evidence-v1'), iterations: 100000, hash: 'SHA-256' },
    base, { name: 'HMAC', hash: 'SHA-256' }, true, ['verify']
  );

  const sigBytes = new Uint8Array(file.hmac_sha256.match(/.{2}/g).map(h => parseInt(h, 16)));
  const isValid = await webcrypto.subtle.verify('HMAC', key, sigBytes, enc.encode(payloadStr));

  console.log('Signature Valid:', isValid);
}
verify();
```

The CLI can also verify packs programmatically; the Node snippet above remains the portable, dependency-free reference.

## Architecture

The project is a Chrome Extension (Manifest V3, plain JS) plus a standalone TypeScript CLI. There is no longer a web app — that earlier Vite demo has been removed.

```
├── extension/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json              # Permissions + service worker config
│   ├── background.js              # Service worker — audit orchestrator + message bus
│   ├── content.js                 # Page collectors (state / route / DOM-sink scans)
│   ├── interceptor.js             # Passive fetch/XHR hook (masked extraction in page context)
│   ├── popup.html                 # Quick-view popup
│   ├── sidepanel.html/js/css      # Full dashboard in the side panel
│   ├── devtools.html/js           # DevTools bridge
│   ├── devtools-panel.html/js     # Live findings / endpoints / routes panel
│   ├── icons/                     # Extension icons
│   └── lib/                       # Core modules (plain JS)
│       ├── api-client.js          # Lovable API + chrome.cookies auth
│       ├── audit-engine.js        # Inspection orchestrator
│       ├── data-patterns.js       # 24 secret + 7 PII patterns
│       ├── masking.js             # Secret masking + line numbers
│       ├── health-scorer.js       # Scoring algorithms
│       ├── evidence-pack.js       # HMAC-signed evidence export
│       ├── logger.js              # Logging helper
│       ├── passive-endpoints.js   # Endpoint normalization (5th-endpoint candidate detection)
│       ├── i18n.js                # Trilingual translations
│       └── skills/                # Security "skills" modules
│           ├── token-vault.js     # AES-GCM + PBKDF2 token vault (lock/unlock)
│           ├── consent-gate.js    # L0/L1/L2 consent + legal first-run
│           ├── secret-hasher.js   # SubtleCrypto SHA-256 hashing + dedupe
│           ├── structured-logger.js  # JSON logger with secret redaction
│           ├── rationale-logger.js   # Frozen signal weights + verifiable score rationale
│           ├── dual-probe.js      # owner×audit BOLA signature matrix
│           ├── scan-history.js    # Run history + delta comparison
│           ├── rls-checklist.js   # Deep-RLS copy-paste checklist classifier
│           └── pattern-catalog.js # Dynamic rule catalog (remote fetch + toggle + TTL cache)
│
├── packages/cli/                  # Standalone CLI (@nxlv-ai/lovable-audit, TypeScript)
│   └── src/
│       ├── index.ts               # CLI entry — scan / verify / ci commands
│       ├── commands/scan.ts       # Scan orchestrator
│       ├── engines/
│       │   ├── patterns.ts        # 27 secret + 8 PII patterns
│       │   ├── lovable-client.ts  # Lovable API client + response-signature classifier
│       │   ├── supabase-engine.ts # RLS probe + security headers
│       │   ├── rls-checklist.ts   # Deep-RLS SQL + pasted-result classifier
│       │   ├── bundle-scan.ts     # Remote bundle / source-map / SRI scan
│       │   ├── scorer.ts          # Weighted risk score + rationale
│       │   └── baseline.ts        # Fingerprinted baseline + drift
│       ├── reporters/index.ts     # console / json / sarif / markdown output
│       └── util/logger.ts         # Redacting structured logger
│
└── package.json                   # Root scripts: test (vitest), build:cli, check:drift
```

## Principles

1. **Tokens never leave your browser** — never transmitted to external servers
2. **Response bodies stay local** — only metadata and masked findings are retained in the report
3. **Read-only** — only GET requests against `api.lovable.dev`, never POST/PUT/DELETE
4. **Rate limited** — sustained request throttling to avoid overloading the API
5. **Identified** — requests include an `X-Client` identifier

## Scope

This tool is for auditing your own account. The Chrome Extension operates only on projects belonging to the authenticated user's session, and the CLI only on the account behind the token you provide. It is not designed for, and cannot be used for, inspecting projects belonging to other accounts.

## About the author

Created and maintained by [**Lucio Amorim**](https://linkedin.com/in/lucioamorim) — **Lovable Ambassador**.

Lucio builds practical infrastructure for people who take Lovable seriously: not just to generate apps, but to review them, secure them, move context between tools, and ship with confidence. NXLV Lovable Portfolio Audit is the security half of that toolkit; the [Lovable Skills catalog](https://github.com/lucioamor/lovable-skills) — `/wireframe`, `/debate`, `/unbot` — is the other half.

If this tool saved you from shipping an exposed `service_role` key, that's the whole point. Connect on [LinkedIn](https://linkedin.com/in/lucioamorim) and tell me what it caught.

- 🔗 LinkedIn: [linkedin.com/in/lucioamorim](https://linkedin.com/in/lucioamorim)
- 🧰 Lovable Skills: [github.com/lucioamor/lovable-skills](https://github.com/lucioamor/lovable-skills)

## License

Licensed under [**Apache 2.0**](./LICENSE).

In plain terms: **use it freely** — including commercially — but if you reproduce it, redistribute it, or fold any part of it into a product of your own, you **must credit [Lucio Amorim](https://linkedin.com/in/lucioamorim) as a contributor**, link back to his LinkedIn, and link to the license.

Suggested attribution line:

> Includes work by Lucio Amorim (Lovable Ambassador) — https://linkedin.com/in/lucioamorim — licensed under Apache 2.0.
