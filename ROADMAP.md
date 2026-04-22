# Lovable Portfolio Audit — ROADMAP

> **Quem vai ler isso:** outra LLM ou desenvolvedor que precisa entender o projeto antes de qualquer implementação.
> Este documento descreve o que é o produto, por que existe, o que já foi feito e para onde vai.

---

## 1. O que é este projeto

**Lovable Portfolio Audit** é uma ferramenta de auto-auditoria de segurança para usuários que possuem múltiplos projetos no [Lovable.dev](https://lovable.dev).

Ela responde uma pergunta simples: **"dos meus 100+ projetos Lovable, quais estão expostos — e o que eu faço para consertar?"**

O produto tem duas formas de execução:
- **Chrome Extension (MV3)** — instalada no browser, captura o cookie de sessão automaticamente, roda o scan localmente, exibe resultados no side panel. É a forma recomendada.
- **Web App (Vite + TypeScript)** — interface de demonstração e desenvolvimento. Precisa de token manual por causa de CORS.

**Tudo é local.** Nenhum dado é enviado a servidores externos. Nenhum body de resposta é persistido — só metadata (status codes, hashes SHA-256, valores mascarados).

---

## 2. Por que existe — as duas falhas endereçadas

### Falha A — BOLA/IDOR ativo na API da Lovable (abril/2026)

Qualquer conta Lovable autenticada consegue ler dados de projetos de **outros** usuários via endpoints em `https://api.lovable.dev`. O fix foi aplicado apenas a projetos criados após novembro/2025. Projetos anteriores permanecem expostos mesmo se ativamente editados.

HackerOne report em 3 de março de 2026 — triaged, sem remediação 48 dias depois.

Endpoints confirmados vulneráveis:

| Endpoint | O que vaza | Impacto |
|---|---|---|
| `GetProject` | Metadata do projeto | Médio — estrutura do workspace |
| `GetProjectMessagesOutputBody` | Chat completo com a IA | Alto — secrets compartilhados, schemas discutidos |
| `GitFilesResponse` | Árvore de arquivos | Crítico — revela `.env`, `client.ts` |
| `GetProjectFile` | Conteúdo bruto de qualquer arquivo | Crítico — service_role keys, connection strings |

**Assinatura detectável:**
- Vulnerável → `HTTP 200` + JSON estruturado
- Corrigido → `HTTP 403` + `{"type":"forbidden",...}`

### Falha B — CVE-2025-48757 (RLS ausente em Supabase)

Projetos Lovable conectados a Supabase frequentemente foram gerados sem RLS nas tabelas, ou com policies `USING(true)` que não restringem nada. Afetou 170+ projetos, 303 endpoints confirmados.

O scanner oficial da Lovable só verifica **existência** de policy, não efetividade.

### Compounding — quando as duas falhas se somam

Cenário catastrófico:
1. Atacante usa Falha A para baixar `client.ts` de um projeto alvo
2. Extrai `SUPABASE_SERVICE_ROLE_KEY` do código
3. Usa a service_role key para bypassar **toda** RLS e ler o banco inteiro

O scanner detecta e sinaliza esse cenário composto.

---

## 3. Princípios não-negociáveis

| Princípio | Implementação |
|---|---|
| **Tokens nunca saem do browser** | Nunca transmitidos a servidores externos |
| **Bodies não são persistidos** | Apenas status codes, content-length e SHA-256 hash |
| **Read-only** | Apenas GET. POST/PUT/DELETE proibidos |
| **Rate limit** | 500ms entre requests (padrão) — ajustável |
| **Consent explícito** | Safe mode ON por default; file scan requer toggle explícito |
| **Masking antes de qualquer exibição** | `sk_live_xxxx` → `sk_l••••••9Kz` — raw value nunca aparece na UI |
| **Allowlist estrita** | Opera apenas sobre projetos do próprio usuário autenticado |

---

## 4. O que está implementado hoje (estado atual)

### 4.1 Módulos do core (em `extension/lib/` e `src/lib/`)

| Módulo | Responsabilidade |
|---|---|
| `lovable-api-client` | Autenticação, throttle, listagem de projetos, download de arquivos, probe de endpoints |
| `data-patterns` | 17 patterns de secrets + 7 patterns de PII + paths sensíveis; `maskSecret()` + `scanForSecrets()` + `scanForPII()` |
| `health-scorer` | `calculateRiskScore()` + `getSeverityFromScore()` com pesos idênticos ao roadmap de segurança do projectcontrolhub |
| `supabase-inspector` | Extração de credenciais do source code + `testRLS()` com anon key |
| `audit-engine` | Orquestrador: lista projetos → probe (files + chat) → scan de secrets/PII → RLS check → deduplica → pontua |
| `i18n` | Internacionalização PT-BR / EN / ES (strings completas) |

### 4.2 Vetores de scan ativos

| Vetor | O que detecta |
|---|---|
| `bola_files` | GitFilesResponse retorna 200 (arquivos acessíveis) |
| `bola_chat` | GetProjectMessagesOutputBody retorna 200 (chat acessível) |
| `hardcoded_secret` | 17 patterns: Stripe live/test, AWS, GitHub PAT/OAuth, OpenAI, Anthropic, PEM, Supabase service role, Google API, Slack, JWT, DB connection string, Firebase, SendGrid, Twilio, Resend, senha genérica |
| `pii_in_code` | 7 patterns: email, LinkedIn URL, date of birth field, CPF/CNPJ/SSN, telefone, Stripe customer ID, cartão de crédito |
| `pii_in_chat` | Mesmos patterns aplicados ao histórico de chat |
| `rls_missing` | Tabela Supabase acessível com anon key sem autenticação |
| `sensitive_file` | Arquivos como `.env`, `client.ts`, `supabase/config.toml` na árvore |

### 4.3 Scoring

Pesos implementados (idênticos ao SECURITY-ROADMAP.md do projectcontrolhub):

| Sinal | Pontos |
|---|---|
| Files endpoint retorna 200 | +60 |
| Chat endpoint retorna 200 | +60 |
| Secret crítico encontrado | +30 |
| Secret high / PII | +20 |
| Projeto editado nos últimos 30 dias | +10 |
| RLS ausente | +30 |

Bandas: `critical ≥ 80` · `high ≥ 50` · `medium ≥ 20` · `low > 0` · `clean = 0`

### 4.4 Chrome Extension

- MV3, side panel + popup
- Service worker com keep-alive (ping a cada 25s para scans longos)
- Modo demo com 5 projetos fictícios para onboarding
- Storage incremental de resultados em `chrome.storage.local`
- Badge na toolbar com contador de criticals

---

## 5. Gaps identificados — o que falta

> Comparação sistemática contra o `SECURITY-ROADMAP.md` do projectcontrolhub (documento de referência de segurança).

### 🔴 Alta prioridade

| Gap | Por que importa |
|---|---|
| **SHA-256 hash dos matches** | Dedup por hash sem expor valor bruto; invariante de privacidade |
| **Probe dual-account (owner + audit token)** | Sem segundo token, não é possível calcular `response_signature = vulnerable/patched`; hoje só sabe que owner tem acesso, não que audit também tem |
| **`response_signature` por endpoint** | Substitui booleano `isVulnerable` pela matriz precisa do roadmap |
| **Token armazenado em plaintext** | `chrome.storage.local` não é criptografado; deve usar AES-GCM via SubtleCrypto |
| **Consent gate para deep-inspect** | Scan de conteúdo de arquivo deve requerer toggle explícito do usuário |
| **Modal de aceite legal no first-run** | Invariante ético E8 — documentado como obrigatório |

### 🟠 Média prioridade

| Gap | Por que importa |
|---|---|
| **`rationale` JSON por projeto** | Score precisa ser reprodutível e auditável por componente |
| **Safe mode toggle persistido** | Existe na spec; não implementado na extensão |
| **Logger estruturado com strip de secrets** | Impede `console.log(token)` acidental |
| **Histórico de runs** | Habilita delta de KPIs (projeto piorou vs run anterior?) |
| **Export evidence pack HMAC-SHA256** | Descrito no README mas não implementado no flow da extensão |
| **Detecção de `USING(true)` em policies** | RLS existe mas é ineficaz — falha clássica |
| **Catalog dinâmico de patterns** | Hoje hardcoded; deveria ter TTL cache com toggle por pattern |

### 🟡 Baixa prioridade

| Gap | Por que importa |
|---|---|
| Retry automático em `signature='error'` | Resiliência |
| Testes de determinismo do scorer (vitest) | CI guard |
| Drift check entre `extension/lib/*.js` e `src/lib/*.ts` | Evitar divergência entre versões |
| `security_version` por projeto (skip patched) | Evitar re-probe desnecessário |

---

## 6. Skill Files planejados

O projeto usa uma convenção de "skill files" — módulos independentes e coesos, um por responsabilidade:

| # | Arquivo | Responsabilidade |
|---|---|---|
| SKILL-01 | `secret-hasher.js` | `hashSecret()` via SubtleCrypto, `maskSecret()` padronizado |
| SKILL-02 | `dual-probe.js` | Probe com owner + audit token → `response_signature` |
| SKILL-03 | `scan-history.js` | Run history em `chrome.storage`, delta de KPIs |
| SKILL-04 | `token-vault.js` | AES-GCM token storage via SubtleCrypto |
| SKILL-05 | `consent-gate.js` | Safe mode + aceite legal + consent de deep-inspect |
| SKILL-06 | `rationale-logger.js` | Score breakdown reprodutível por projeto |
| SKILL-07 | `structured-logger.js` | Logger com strip automático de keys sensíveis |
| SKILL-08 | `evidence-pack.js` | Export JSON com assinatura HMAC-SHA256 |
| SKILL-09 | `pattern-catalog.js` | Cache com TTL de patterns + toggle por pattern |
| SKILL-10 | `scorer-test.ts` | Suite vitest de determinismo do scorer |

---

## 7. Roadmap de fases

### Fase 1 — MVP local ✅ (concluída)
Chrome Extension instalável, scan dos 4 endpoints confirmados, detecção de 24 patterns (secrets + PII), scoring, masking, side panel com resultados, demo mode, trilingual.

### Fase 2 — Robustez e privacidade 🔨 (em andamento)
Implementar SKILL-01 a SKILL-07: hashing, dual probe, run history, token vault, consent gate, rationale, logger seguro.

### Fase 3 — Completude de detecção
SKILL-08 a SKILL-10: evidence pack exportável, catalog dinâmico, testes CI.

### Fase 4 — Monitor contínuo
`chrome.alarms` para re-scan periódico, alerta em regressão de severity, bulk actions.

### Fase 5 — Saída pública
`audit.nxlv.ai` multi-tenant (mesmo modelo do projectcontrolhub — Supabase backend, Edge Functions, RLS por usuário), integração com APIs de providers para revogação automática de chaves.

---

## 8. Estrutura de arquivos atual

```
lovable-portfolio-audit/
├── extension/                     # Chrome Extension (Manifest V3)
│   ├── manifest.json              # MV3, sidePanel + cookies + storage
│   ├── background.js              # Service worker — orquestrador
│   ├── popup.html                 # Quick-view popup
│   ├── sidepanel.html/js/css      # Dashboard completo no side panel
│   └── lib/                       # Módulos runtime (plain JS)
│       ├── api-client.js          # Lovable API + chrome.cookies auth
│       ├── audit-engine.js        # Orquestrador de scan
│       ├── data-patterns.js       # 17 secrets + 7 PII + masking
│       ├── health-scorer.js       # Scoring + labels + severity
│       └── i18n.js                # PT-BR / EN / ES
│
├── src/                           # Web App (Vite + TypeScript)
│   ├── main.ts                    # App: state, rendering, eventos
│   ├── style.css                  # Dark theme design system
│   └── lib/                       # Módulos fonte (TypeScript — espelham extension/lib)
│       ├── types.ts               # Interfaces TypeScript
│       ├── data-patterns.ts
│       ├── health-scorer.ts
│       ├── lovable-api-client.ts
│       ├── supabase-inspector.ts  # RLS checker (anon key)
│       ├── audit-engine.ts
│       └── i18n.ts
│
├── ROADMAP.md                     # Este arquivo
├── README.md                      # Instruções de instalação
└── package.json
```

> **Nota para LLMs:** `extension/lib/*.js` são os arquivos que rodam na extensão em produção. `src/lib/*.ts` são as fontes TypeScript equivalentes. Qualquer mudança em lógica de negócio deve ser aplicada nos dois lugares.

---

## 9. Convenções do projeto

- **Masking invariante:** valor bruto de qualquer secret/PII nunca aparece fora de `secret-hasher.js`. Qualquer outro módulo recebe apenas `masked` e `hash`.
- **Read-only:** nenhum módulo faz POST/PUT/DELETE.
- **Throttle:** toda request a `api.lovable.dev` passa pelo método `throttle()` do API client.
- **Erro silencioso:** falha em um projeto não aborta o scan do próximo — erros são acumulados e reportados no final.
- **Módulo = uma responsabilidade:** arquivos que misturam fetch + regex + scoring são sinais de rejeição em code review (mesma regra do SECURITY-ROADMAP.md).

---

## 10. Referências

- `SECURITY-ROADMAP.md` — documento de arquitetura do projectcontrolhub (sistema multi-tenant de referência, Supabase + Edge Functions)
- `nxlv_scanner_briefing_v2.md` — briefing original de produto com data model, UI spec e edge functions detalhadas
- `security-gap-analysis.md` — comparação item-a-item entre o que está implementado e o roadmap, com specs dos skill files
