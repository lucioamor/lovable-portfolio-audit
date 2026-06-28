# Chrome Web Store Listing — NXLV Lovable Portfolio Audit (Lovable Portfolio Audit)

By [**Lucio Amorim**](https://linkedin.com/in/lucioamorim) — **Lovable Ambassador**.

Everything needed to submit the extension. A human must create the Chrome Web Store **developer account (one-time US$5 fee)** and perform the upload; this document provides the copy, the permission justifications, the packaging command, and the submission checklist.

---

## 1. Permission justification table (from D1)

Every entry below is justified by a concrete code path. Permissions and hosts that had **no** corresponding code were **removed** from `manifest.json`.

### Permissions kept

| Permission | Why it's needed (reviewer-facing) | Evidence |
|---|---|---|
| `cookies` | Read the user's **own** `__lovable_session` cookie to authenticate read-only audit requests as that user. The cookie is `HttpOnly`, so page JS cannot read it — `chrome.cookies` is the only path. | `extension/lib/api-client.js` `getSessionToken()` → `chrome.cookies.get({ name: '__lovable_session' })` |
| `storage` | Store the encrypted token vault, scan results/history, settings, and consent records locally on-device. | `chrome.storage.local` used throughout `background.js`, `token-vault.js`, `consent-gate.js`, `pattern-catalog.js`, `scan-history.js` |
| `sidePanel` | The dashboard UI is a Chrome side panel; the extension sets panel behavior and opens it. | `background.js` `chrome.sidePanel.setPanelBehavior(...)`; `popup.html` `chrome.sidePanel.open(...)`; `side_panel` key in manifest |
| `alarms` | Schedule two background maintenance tasks: daily refresh of the secret-pattern catalog and weekly pruning of old scan history. | `background.js` `chrome.alarms.create('refresh-patterns'|'prune-history')` + `chrome.alarms.onAlarm` |
| `tabs` | lovable.dev is a single-page app, so the content script is not re-injected on in-app navigation. The extension reads the **tab URL** on `chrome.tabs.onUpdated` to track which Lovable workspace is active. It reads only the URL of `lovable.dev` tabs and never injects or executes code. | `background.js` `chrome.tabs.onUpdated.addListener(...)` → matches `lovable.dev/workspaces/:id` |

### Host permissions kept

| Host | Why it's needed (reviewer-facing) | Evidence |
|---|---|---|
| `https://lovable.dev/*` | Inject the content script on the user's logged-in Lovable session and read the session cookie for that origin. | `content_scripts` match + `chrome.cookies.get({ url: 'https://lovable.dev' })` |
| `https://api.lovable.dev/*` | Perform the actual read-only (`GET`) audit: list the user's projects, probe endpoints for BOLA/IDOR, and fetch file/chat content the user owns. | `extension/lib/api-client.js` (`API_BASE = 'https://api.lovable.dev'`), `dual-probe.js`, `audit-engine.js` |
| `https://audit.nxlv.ai/*` | Download the **public** secret-detection pattern catalog (`patterns.json`). The request carries no credentials (`credentials: 'omit'`) and sends no user data; it falls back to a built-in catalog if offline. | `extension/lib/skills/pattern-catalog.js` `DEFAULT_REMOTE_URL` |

### Removed (proven unused — would have drawn reviewer questions)

| Removed | Evidence it was dead | Action taken |
|---|---|---|
| `activeTab` permission | No `chrome.tabs`, `chrome.scripting`, or `executeScript` anywhere in the extension. The only `activeTab` references are an unrelated UI state variable (`state.activeTab` in `sidepanel.js`). The extension reaches pages via **declarative** `content_scripts` + host permissions, which do not need `activeTab`. | Removed from `manifest.json`. No code change needed (nothing consumed it). |
| `https://*.supabase.co/*` host | **No** `fetch`/XHR to any `supabase.co` URL anywhere in the extension. The RLS audit is a copy-paste SQL model (`rls-checklist.js`): the tool generates introspection SQL and the user runs it themselves; the extension never connects to a Supabase database. The only `supabase.co` strings in code are a regex used to *detect* a URL inside fetched file content and a hardcoded demo value. | Removed from `manifest.json`. This was a pure dead grant — no corresponding code path existed to remove. |

> Net result: 5 permissions + 3 host permissions, each tied to a verifiable code path. Nothing unused remains.

---

## 2. Privacy policy URL (required)

The store listing **must** link a publicly hosted privacy policy. Use the rendered `PRIVACY.md` from this repo. Suggested public URL once published:

```
https://github.com/lucioamor/lovable-portfolio-audit/blob/master/PRIVACY.md
```

(If a custom domain is preferred, publish the same content at e.g. `https://nxlv.ai/privacy` and use that URL instead — the content must match the published extension's behavior.)

---

## 3. Store metadata

- **Category:** Developer Tools
- **Suggested name:** NXLV Lovable Portfolio Audit — Lovable Portfolio Audit
- **Developer / author:** Lucio Amorim — Lovable Ambassador ([linkedin.com/in/lucioamorim](https://linkedin.com/in/lucioamorim))
- **Visibility on first submission:** **Unlisted / private** (see Section 8) — do **not** publish publicly until tested.

### Short summary (≤132 chars)

> Self-audit your Lovable.dev projects for access-control issues, exposed secrets, and Supabase RLS gaps. Local-first, read-only, private. (NXLV Lovable Portfolio Audit)

---

## 4. Store description — trilingual (matches the extension's EN/PT/ES UI)

### English

> **NXLV Lovable Portfolio Audit audits your own Lovable.dev projects for security exposure — entirely on your device.**
>
> Log into Lovable, open the side panel, and scan the projects **you own** for:
> - **Access-control exposure** — endpoints that may serve your project files or chat history to other accounts.
> - **Exposed secrets & API keys** — Supabase service-role keys, OpenAI/Anthropic keys, Stripe live keys, database URLs, and more, with masked evidence.
> - **Supabase RLS gaps** — a copy-paste, read-only SQL checklist you run yourself; paste the result back for instant classification (disabled RLS, tautological policies, over-broad grants).
>
> **Privacy by design.** Your session token never leaves the browser and is stored in an AES-GCM encrypted vault. Raw response bodies are never persisted or sent — only masked samples and a short hash are kept. Every Lovable request is read-only (GET). There is no telemetry and no NXLV server. Safe mode is on by default.
>
> Built for Lovable builders who want to verify their own security posture before shipping using NXLV Lovable Portfolio Audit.
>
> Created by Lucio Amorim — Lovable Ambassador. https://linkedin.com/in/lucioamorim

### Português

> **O NXLV Lovable Portfolio Audit audita os seus próprios projetos do Lovable.dev em busca de exposição de segurança — inteiramente no seu dispositivo.**
>
> Faça login no Lovable, abra o painel lateral e analise os projetos que **você possui** em busca de:
> - **Exposição de controle de acesso** — endpoints que podem servir os arquivos ou o histórico de chat do seu projeto a outras contas.
> - **Segredos e chaves de API expostos** — chaves service-role do Supabase, chaves OpenAI/Anthropic, chaves Stripe live, URLs de banco de dados e mais, com evidência mascarada.
> - **Falhas de RLS no Supabase** — um checklist de SQL somente-leitura para copiar e colar, que você executa; cole o resultado de volta para classificação instantânea (RLS desabilitado, políticas tautológicas, grants amplos demais).
>
> **Privacidade por design.** Seu token de sessão nunca sai do navegador e fica num cofre criptografado com AES-GCM. Corpos de resposta brutos nunca são persistidos ou enviados — apenas amostras mascaradas e um hash curto são guardados. Toda requisição ao Lovable é somente-leitura (GET). Não há telemetria nem servidor NXLV. O modo seguro vem ativado por padrão.
>
> Feito para builders do Lovable que querem verificar a própria postura de segurança antes de publicar.
>
> Criado por Lucio Amorim — Lovable Ambassador. https://linkedin.com/in/lucioamorim

### Español

> **NXLV Lovable Portfolio Audit audita tus propios proyectos de Lovable.dev en busca de exposición de seguridad — completamente en tu dispositivo.**
>
> Inicia sesión en Lovable, abre el panel lateral y analiza los proyectos que **te pertenecen** en busca de:
> - **Exposición de control de acceso** — endpoints que podrían servir los archivos o el historial de chat de tu proyecto a otras cuentas.
> - **Secretos y claves de API expuestos** — claves service-role de Supabase, claves de OpenAI/Anthropic, claves live de Stripe, URLs de base de datos y más, con evidencia enmascarada.
> - **Brechas de RLS en Supabase** — una lista de verificación SQL de solo lectura para copiar y pegar, que tú mismo ejecutas; pega el resultado para una clasificación instantánea (RLS deshabilitado, políticas tautológicas, permisos demasiado amplios).
>
> **Privacidad por diseño.** Tu token de sesión nunca sale del navegador y se guarda en una bóveda cifrada con AES-GCM. Los cuerpos de respuesta sin procesar nunca se almacenan ni se envían — solo se conservan muestras enmascaradas y un hash corto. Cada solicitud a Lovable es de solo lectura (GET). No hay telemetría ni servidor NXLV. El modo seguro está activado por defecto.
>
> Hecho para builders de Lovable que quieren verificar su propia postura de seguridad antes de publicar.
>
> Creado por Lucio Amorim — Lovable Ambassador. https://linkedin.com/in/lucioamorim

---

## 5. Screenshot checklist

Chrome Web Store requires at least one 1280×800 (or 640×400) screenshot; provide these three:

- [ ] **Dashboard / scan summary** — the side-panel overview with severity counts (Critical/High/Medium/Clean). Use **Load Demo** to populate realistic data without exposing real projects.
- [ ] **Side panel — scan in progress / settings** — show the safe-mode toggle and consent UI, to visually reinforce the read-only, consent-gated story.
- [ ] **Scan results detail** — a finding expanded to show masked evidence (e.g. masked secret + severity + remediation prompt), demonstrating that raw secrets are never shown in full.

Tip: capture all screenshots in **demo mode** so no real account data is published in the listing.

---

## 6. Icon checklist

All required sizes already exist in `extension/icons/` (verified):

- [x] `extension/icons/icon16.png` (16×16)
- [x] `extension/icons/icon48.png` (48×48)
- [x] `extension/icons/icon128.png` (128×128) — also the store listing tile icon

---

## 7. Production packaging command

The Chrome Web Store expects a ZIP whose root contains `manifest.json` (not a parent folder). Run from the repo root.

**PowerShell (Windows):**

```powershell
# Produces dist/nxlv-shield-2.0.0.zip with manifest.json at the archive root
New-Item -ItemType Directory -Force dist | Out-Null
Compress-Archive -Path extension/* -DestinationPath dist/nxlv-shield-2.0.0.zip -Force
```

**bash / zip (macOS/Linux):**

```bash
mkdir -p dist
( cd extension && zip -r ../dist/nxlv-shield-2.0.0.zip . -x '*.DS_Store' )
```

Before zipping, confirm `extension/` contains no stray dev/test artifacts — only the files the extension actually loads. The version string in the filename should match `version` in `extension/manifest.json` (currently `2.0.0`).

---

## 8. Submission checklist

- [ ] Create the Chrome Web Store **developer account** (one-time **US$5** fee). *(Human task — not automatable.)*
- [ ] Confirm `extension/manifest.json` is valid and version is correct (`2.0.0`).
- [ ] Build the production ZIP (Section 7).
- [ ] Upload the ZIP.
- [ ] Paste the short summary (Section 3) and the trilingual description (Section 4).
- [ ] Set category to **Developer Tools** (Section 3).
- [ ] Add the **privacy policy URL** (Section 2) — required because the extension handles user data.
- [ ] Upload the three screenshots (Section 5) and confirm icons (Section 6).
- [ ] Complete the store's data-handling / permissions-justification form using the table in Section 1.
- [ ] **Submit as Unlisted / private first** for self-testing. Verify install, auth, scan, and clear-data flows on a clean profile.
- [ ] Only after testing, flip visibility to **Public**.

> **Note:** Producing these assets does **not** submit the extension. The actual submission requires the paid developer account and a human to upload — this document prepares the copy and checklist only.
