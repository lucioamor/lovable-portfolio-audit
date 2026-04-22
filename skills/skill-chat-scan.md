# Skill: Independent Chat Regex Scanning

> **Roadmap refs:** P10  
> **Complexity:** Small  
> **Files affected:** `extension/lib/audit-engine.js`

---

## Problem

Currently, `audit-engine.js` only scans chat history for secrets and PII *if* the `testBOLA()` check returns `vulnerable` for chat. This means the user's *own* protected chat history isn't scanned for accidental secrets, even though they have the access to read it. The roadmap decouples content inspection from BOLA status.

---

## Implementation

### 1. Decouple in `audit-engine.js`

```js
// BEFORE
if (config.includeChat && bola.chatStatus === 'vulnerable') {

// AFTER
if (config.includeChat) {
  // If explicitly opted in via consent gate, scan the chat history
  // using the owner's session (which will succeed regardless of BOLA status)
  try {
    const messages = await getProjectMessages(project.id);
    if (messages && Array.isArray(messages)) {
      for (const msg of messages.slice(0, 100)) {
        const content = msg.content || msg.text || msg.body || '';
        if (content.length > 10) {
          const findings = await scanContent(content, `chat:${msg.id || 'message'}`);
          result.findings.push(...findings);
        }
        result.chatMessagesScanned++;
      }
    }
  } catch { /* continue */ }
}
```

---

## Acceptance Criteria

- [ ] Chat history is scanned when `includeChat` is true, even if `bolaChatStatus` is `patched`
- [ ] Uses the authenticated owner's session to retrieve the messages
- [ ] `scanContent` correctly processes the messages and creates findings
