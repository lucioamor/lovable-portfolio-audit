# 🛡️ NXLV Audit — The Lovable Production-Readiness Standard

[![npm version](https://img.shields.io/npm/v/@nxlv/audit.svg?style=flat-square)](https://www.npmjs.com/package/@nxlv/audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Security: Read-Only](https://img.shields.io/badge/Security-Read--Only-green.svg?style=flat-square)](#security-invariants)

> **The independent security audit layer for Lovable apps.**
> Lovable's built-in scanner checks your code. NXLV Audit checks if it actually *works in production*.

---

## ⚡ Quickstart

```bash
# Scan your Lovable projects (requires your session token)
npx @nxlv/audit scan --token <your-lovable-bearer-token>

# Scan with Supabase RLS probing
npx @nxlv/audit scan --token <token> --supabase-url https://xyz.supabase.co --supabase-key eyJ...

# Scan a deployed app URL (headers + source maps)
npx @nxlv/audit scan --token <token> --url https://myapp.lovable.app

# CI/CD pipeline (exit code 1 on critical findings, SARIF output)
npx @nxlv/audit ci --output nxlv-audit.sarif
```

### How to get your Lovable token:
1. Open [lovable.dev](https://lovable.dev) and log in
2. Open DevTools (F12) → Network tab  
3. Filter requests for `api.lovable.dev`
4. Copy the `Authorization: Bearer <token>` value from any request header

---

## 🚨 What is BOLA? Why Does This Matter?

**Broken Object Level Authorization (BOLA / IDOR)** is the class of bug where a backend returns an object without checking that the caller owns it. Lovable projects created before November 2025 are the population most at risk of having their project files and AI chat history readable without an ownership check — which can expose hardcoded API keys, database schemas, and credentials shared during development.

**NXLV Audit's BOLA check** (`LOV-001`) probes — read-only, against your own account:
- `GET /projects/{id}/git/files` → reveals if your file tree is exposed
- `GET /projects/{id}/messages` → reveals if your AI chat history is exposed

```
🔴 VULNERABLE:   HTTP 200 — files/chat accessible without ownership check
✅ PROTECTED:    HTTP 403 — proper authorization enforced
```

---

## 🔍 What We Scan

Read-only checks across four areas. Every finding carries a stable rule id, a masked evidence sample, a severity, and a reproducible score rationale.

| Area | What it covers |
|---|---|
| **Secrets & PII** | 27 secret patterns + 8 PII patterns over project file trees and AI chat history |
| **BOLA / IDOR** | `LOV-001` probes the project files and chat endpoints for a missing ownership check — single-probe, or `--audit-token` dual-probe to confirm cross-account exposure |
| **Supabase / RLS** | `anon`-key table probe + storage-bucket probe, plus a copy-paste deep-RLS SQL checklist whose pasted result is classified into `DB-003`/`DB-004`/`DB-005`/`DB-008`/`DB-009`. No SQL is ever run against an external Supabase. |
| **Bundle / runtime** | Bounded remote fetch of a target URL's HTML + JS chunks: exposed source maps, missing Subresource Integrity, security headers, and a hardcoded Supabase URL + anon key correlated with an RLS gap into a `compound_risk` finding |

### Secret detection (27 patterns)

Supabase `service_role` / `anon` keys and project URLs · OpenAI · Anthropic · AWS access & secret keys · Stripe live/test/publishable · GitHub PATs & OAuth · Slack · SendGrid · Twilio · Resend · Firebase / Google API keys · PostgreSQL connection strings · JWT secrets · PEM private keys · generic API-key and password assignments.

### PII detection (8 patterns)

Email addresses · Brazilian CPF · credit-card numbers (Luhn-shaped) · US SSN · and more.

Each finding is tagged with a required **Lovable level** (`L0`/`L1`/`L2`) derived from its severity, so you can triage by how strict the fix needs to be.

---

## 📋 Output Formats

```bash
# Default: colorized console output
npx @nxlv/shield scan --token <token>

# JSON (includes AI fix prompts, remediation SQL, full evidence)
npx @nxlv/shield scan --token <token> --format json --output report.json

# SARIF (upload to GitHub Security tab)
npx @nxlv/shield scan --token <token> --format sarif --output results.sarif

# Markdown (shareable report)
npx @nxlv/shield scan --token <token> --format markdown --output report.md

# HTML (single self-contained file — inline CSS/JS, no network)
npx @nxlv/shield scan --token <token> --format html --output report.html

# All formats at once
npx @nxlv/shield scan --token <token> --format all --output audit
```

The HTML report is a single file with no external or CDN dependencies: it renders
the severity summary, per-project findings (ruleId, severity badge, title, masked
evidence, recommendation), and the reproducible score rationale. All interpolated
values are HTML-escaped.

### Example Console Output

```
🔴 My Production App
   Score: 100/100 | CATASTROPHIC | BOLA-files: vulnerable | BOLA-chat: vulnerable
   ⚠️  Pre-Nov 2025: potentially in BOLA vulnerability window
   [LOV-001] BOLA: Project Files Endpoint Exposed
           Evidence: GET /projects/abc-123/git/files → HTTP 200
   [LOV-001] BOLA: Chat History Endpoint Exposed
           Evidence: GET /projects/abc-123/messages → HTTP 200
   [SUP-001] Supabase Service Role Key (CATASTROPHIC)
           Evidence: eyJh••••••••••••••••••••••••••••••Kz (src/lib/supabase.ts:3)

═══════════════════════════════════════════════
  🛡️  NXLV Shield — Scan Complete
═══════════════════════════════════════════════

  Projects scanned:    47/47
  Duration:            94.2s

  💀 Catastrophic:     3
  🔴 Critical:         8
  🟠 High:             12
  🟡 Medium:           19
  🔵 Low:              5
  🟢 Clean:            0

  Pre-Nov-2025 (BOLA): 43 projects
  BOLA Vulnerable:     7 projects
```

---

## 🧰 Commands

### `scan`
Audit your Lovable projects (see flags above). Additional flags:

```bash
# Compare against a baseline and POST a drift summary to a webhook.
# The payload carries only counts and new/resolved finding identifiers
# (ruleId, title, severity, project) — no tokens, no raw bodies, no evidence.
# A non-2xx response or network error warns and does not fail the scan.
npx @nxlv/shield scan --token <token> --baseline --webhook https://example.com/hook
```

### `report <results.json>`
Regenerate a report from a previously saved JSON report (`scan --format json`)
without re-scanning. The saved `scanTimestamp` is reused so output is stable.

```bash
# Regenerate as HTML (default), Markdown, JSON, or SARIF
npx @nxlv/shield report report.json --format html --output report.html
npx @nxlv/shield report report.json --format markdown   # → stdout
```

### `fix-prompt <results.json>`
Extract the copy-pasteable AI fix prompts from a saved JSON report, grouped by
project and finding, so they can be pasted into the Lovable AI chat. Findings
without a prompt are skipped.

```bash
npx @nxlv/shield fix-prompt report.json                  # → stdout
npx @nxlv/shield fix-prompt report.json --output prompts.md
```

### `verify-evidence <pack.json>`
Verify the HMAC-SHA256 signature of an exported evidence pack. Prints `VALID` /
`INVALID` and exits 0 (valid) or 1 (invalid/error). The passphrase comes from
`--passphrase` or the `NXLV_EVIDENCE_PASSPHRASE` environment variable. Both the
side-panel export (`_signature` + `pack`) and the portable recipe
(`hmac_sha256` + `payload`) shapes are accepted.

```bash
npx @nxlv/shield verify-evidence pack.json --passphrase <device-key-or-passphrase>
NXLV_EVIDENCE_PASSPHRASE=<key> npx @nxlv/shield verify-evidence pack.json
```

### `verify` / `ci`
`verify` checks a Lovable token is valid. `ci` runs a scan optimized for
pipelines (SARIF output, exit code 1 on critical/catastrophic findings).

## 🤖 AI Fix Prompts

Every finding generates a copy-paste prompt optimized for the Lovable AI chat:

```
[SUP-001] Supabase Service Role Key in Frontend

🤖 AI Fix Prompt:
URGENT: In your Supabase dashboard, go to Settings > API and regenerate your 
service_role key. In Lovable, ask the AI to refactor all database operations 
to use the anon key with proper RLS policies instead of service_role.
```

---

## 🔒 Security Invariants

This tool is designed with **defense-in-depth privacy principles**:

| Invariant | Implementation |
|---|---|
| **Read-only** | Only GET requests. Never modifies any data. |
| **No persistence** | File/chat content never written to disk. Only SHA-256 hashes retained. |
| **Masked output** | Secrets always displayed as `sk_l••••9Kz` — raw values never in output. |
| **Rate limited** | 500ms between API requests (configurable). |
| **Consent gate** | `--deep` mode requires explicit flag for file content scanning. |
| **Safe by default** | `safeMode: true` — no active exploitation, no payload injection. |
| **DAST safety** | Supabase probing uses read-only SELECT with `Prefer: count=exact`. |

---

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: NXLV Shield Security Audit
on: [push, pull_request]
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run NXLV Shield
        run: npx @nxlv/shield ci --output nxlv-shield.sarif
        env:
          LOVABLE_TOKEN: ${{ secrets.LOVABLE_TOKEN }}
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nxlv-shield.sarif
```

This repository also ships a ready-to-use workflow at
`.github/workflows/nxlv-shield.yml`. It builds the CLI, runs the `ci` scan to
SARIF, and uploads it to the Security tab. It runs on a schedule and on manual
dispatch, and is guarded on a `LOVABLE_TOKEN` repository secret being present.

---

## 🆚 vs. Lovable Built-in Scanner

| Lovable Built-in | NXLV Shield |
|---|---|
| Runs during development | Runs against deployed production |
| Checks code before publish | Probes endpoints as an attacker would |
| Static analysis of generated code | DAST: tests if RLS *actually works* |
| Integrated in Lovable platform | Independent — works on any Lovable app |
| Trusted (internal) | **Independent audit** — the external auditor |

> *"Lovable tells you your code looks secure. NXLV Shield tests if it actually is."*

---

## 📄 License

MIT — use freely, contribute patterns, cite in your security reports.

---

**Built by the Lovable community for the Lovable community.**  
Positioned as the standard for "Lovable Production-Readiness."

*Found a vulnerability pattern we're missing? Open an issue or PR.*
