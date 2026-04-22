# 🛡️ NXLV Shield — The Lovable Production-Readiness Standard

[![npm version](https://img.shields.io/npm/v/@nxlv/shield.svg?style=flat-square)](https://www.npmjs.com/package/@nxlv/shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Security: Read-Only](https://img.shields.io/badge/Security-Read--Only-green.svg?style=flat-square)](#security-invariants)

> **The independent security audit layer for Lovable apps.**
> Lovable's built-in scanner checks your code. NXLV Shield checks if it actually *works in production*.

---

## ⚡ Quickstart

```bash
# Scan your Lovable projects (requires your session token)
npx @nxlv/shield scan --token <your-lovable-bearer-token>

# Scan with Supabase RLS probing
npx @nxlv/shield scan --token <token> --supabase-url https://xyz.supabase.co --supabase-key eyJ...

# Scan a deployed app URL (headers + source maps)
npx @nxlv/shield scan --token <token> --url https://myapp.lovable.app

# CI/CD pipeline (exit code 1 on critical findings, SARIF output)
npx @nxlv/shield ci --output nxlv-shield.sarif
```

### How to get your Lovable token:
1. Open [lovable.dev](https://lovable.dev) and log in
2. Open DevTools (F12) → Network tab  
3. Filter requests for `api.lovable.dev`
4. Copy the `Authorization: Bearer <token>` value from any request header

---

## 🚨 What is BOLA? Why Does This Matter?

In April 2026, a **Broken Object Level Authorization (BOLA)** vulnerability was disclosed affecting Lovable projects created before November 2025 (CVE-2025-48757).

**What it means:** Any authenticated Lovable user could access another user's project files and AI chat history — including hardcoded API keys, database schemas, and credentials shared during development.

**NXLV Shield's BOLA check** (`LOV-001`) probes:
- `GET /projects/{id}/git/files` → reveals if your file tree is exposed
- `GET /projects/{id}/messages` → reveals if your AI chat history is exposed

```
🔴 VULNERABLE:   HTTP 200 — files/chat accessible without ownership check
✅ PROTECTED:    HTTP 403 — proper authorization enforced
```

---

## 🔍 What We Scan

### 70+ Security Checks Across 4 Layers

| Layer | Checks | Examples |
|---|---|---|
| **DB / Supabase** | 15 | RLS disabled, `USING(true)` policies, service_role key, storage buckets |
| **Application Code** | 17 | 150+ secret patterns, XSS sinks, SQL injection, security headers |
| **AI / Agêntico** | 10 | MCP tool poisoning, prompt injection in `.cursorrules`, Claude hooks |
| **Lovable-Specific** | 8+ | BOLA probe, pre-Nov 2025 age flag, CVE-2025-48757, DB proxy tokens |

### Secret Detection (150+ patterns)

Supabase service_role keys · OpenAI keys · Anthropic keys · AWS credentials · Stripe live/test keys · GitHub PATs · Slack tokens · SendGrid · Twilio · Resend · PostgreSQL connection strings · PEM private keys · Firebase service accounts · Generic JWTs

### Lovable Security Levels

| Level | Meaning | Required for |
|---|---|---|
| **L0** | Baseline — any app | All Lovable projects |
| **L1** | Standard — apps with auth/user data | SaaS, e-commerce |
| **L2** | Strict — sensitive data | Fintech, health, legal |

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

# All formats at once
npx @nxlv/shield scan --token <token> --format all --output audit
```

### Example Console Output

```
🔴 My Production App
   Score: 145/100 | CATASTROPHIC | BOLA-files: vulnerable | BOLA-chat: vulnerable
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

## 🤖 AI Fix Prompts

Every finding generates a copy-paste prompt optimized for the Lovable AI chat:

```
[DB-012] Supabase Service Role Key in Frontend

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

---

## 📊 Tiers

| Feature | Community (Free) | Pro ($9/mo) |
|---|---|---|
| BOLA Check (LOV-001) | ✅ | ✅ |
| 25 security checks | ✅ | — |
| 70+ security checks | — | ✅ |
| Supabase RLS probing | Limited | ✅ Full |
| AI Fix Prompts | — | ✅ |
| SARIF output | ✅ | ✅ |
| Chrome Extension | — | ✅ |
| Project history | — | ✅ |
| Remediation SQL | — | ✅ |

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
