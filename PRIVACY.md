# Privacy Policy — NXLV Lovable Portfolio Audit (Lovable Portfolio Audit)

**Last updated:** 2026-06-28
**Author:** [Lucio Amorim](https://linkedin.com/in/lucioamorim) — Lovable Ambassador
**Applies to:** the "NXLV Lovable Portfolio Audit — Lovable Portfolio Audit" Chrome extension and the `@nxlv-ai/lovable-audit` CLI in this repository.

NXLV Lovable Portfolio Audit is a **self-audit security tool**. You run it against **your own** Lovable.dev account to find security exposure (access-control issues, exposed secrets, Supabase RLS gaps) in projects you own. This policy describes exactly what the tool does and does not do with your data.

The short version: **your data stays on your device.** There is no NXLV server that receives your tokens, your project contents, or any analytics.

---

## 1. Your session token never leaves the browser

To read your own project list and files, the extension needs your Lovable session credential. It obtains this in two ways:

- **From your browser's Lovable cookie** (`__lovable_session`), read via the `cookies` permission. This cookie is `HttpOnly`, so page JavaScript cannot read it — the extension's privileged context is the only way to retrieve it for authenticated requests.
- **From your own page traffic.** When you are logged into lovable.dev, the extension reads the `Authorization` header off requests the Lovable site itself already makes, as a supplementary/fallback source.

In both cases:

- The token is used **only** to authenticate requests to `api.lovable.dev` on your behalf.
- The token is **never transmitted to any NXLV server or any third party.** There is no NXLV backend in this product.
- When stored at rest, the token is held in an **encrypted vault** in local browser storage (`chrome.storage.local`), protected with **AES-GCM (256-bit)** using a key derived from your passphrase via **PBKDF2-SHA256 (600,000 iterations)**. The encryption key lives **only in memory** and is never persisted.

## 2. Raw response bodies are never persisted, logged, or sent

When the extension inspects responses for exposed secrets and PII, the matching and masking happen **in the page context**, before anything crosses into the extension. The raw response body **never** leaves that context.

For each finding, the tool retains only:

- a **masked sample** of the matched value (e.g. `sk-a••••••••••3f9c` — first/last characters only), and
- a **`sha256[:16]` hash** (the first 16 hex characters of a SHA-256 digest) used to de-duplicate findings.

Raw secrets, raw response bodies, and full credential values are **never** persisted to storage, written to logs, or included in any output sent off-device.

## 3. The tool is read-only against Lovable

All requests the tool makes to Lovable are **`GET` only**. The tool reads — it does not create, modify, or delete anything in your Lovable account.

## 4. It operates only on your own account

The tool authenticates as **you**, using **your** session, and scans **your** projects. It does not scan other users' accounts and provides no mechanism to do so.

## 5. No automatic SQL execution against third-party databases

The Supabase Row-Level-Security (RLS) audit uses a **copy-paste model**. The tool generates **read-only** introspection SQL for you to run in your own Supabase SQL editor; you paste the JSON result back in for classification. The extension **never connects to, queries, or enumerates** any `*.supabase.co` database directly, and never executes SQL against any third-party database. (Accordingly, the extension requests **no** `supabase.co` host permission.)

## 6. Telemetry: there is none

The tool collects **no analytics and no telemetry**. There is no usage tracking, no crash reporting SDK, no `sendBeacon`, and no third-party analytics provider. The only network requests the tool makes are:

| Destination | Purpose | Sends your data? |
|---|---|---|
| `https://api.lovable.dev/*` | Authenticated read-only audit of **your own** projects | Sends your token to Lovable (your own provider) only |
| `https://*.lovableproject.com` | Fetches your own project's published preview bundle to scan for exposed secrets | No credentials sent |
| `https://audit.nxlv.ai/patterns.json` | Downloads the public secret-detection pattern catalog (no credentials, `credentials: 'omit'`) | No — request carries no cookies, token, or personal data |

The pattern-catalog request is a one-way download of a public JSON file; it transmits none of your data.

## 7. What is stored locally, and that it stays local

The following are stored **only** in your browser's local extension storage (`chrome.storage.local`) and **never leave your device**:

- the **encrypted token vault** (Section 1);
- **scan history and results** (severity scores, finding metadata, masked samples and `sha256[:16]` hashes — never raw secrets);
- **observed-endpoint metadata** from the optional passive sensor (request path, method, status code — never bodies);
- your **settings and consent records**.

You can clear all of this at any time from the extension UI ("Clear results" / vault reset), or by removing the extension.

## 8. Consent and safe defaults

- **Safe mode is on by default.** The deeper passive sensor is **off by default** and relays nothing until you enable it.
- **Deep inspection** (fetching and scanning file contents) requires your **explicit, per-scan consent**.
- Legal acceptance is recorded locally and gates persistence of passive findings.

## 9. Data sharing

We do not sell, rent, or share your data with anyone, because the tool does not collect your data off your device in the first place. There is no operator-side dataset to share.

## 10. Contact

This is an open-source project by [Lucio Amorim](https://linkedin.com/in/lucioamorim) (Lovable Ambassador). Source code, issues, and contact:
**https://github.com/lucioamor/lovable-portfolio-audit**

---

*This policy describes the current behavior of the published tool. It contains no statements about planned or future functionality. Licensed under Apache 2.0 — see `LICENSE`.*
