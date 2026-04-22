# Skill: CSP & SRI Scanner

> **Roadmap refs:** P8  
> **Complexity:** Medium  
> **Files affected:** `extension/lib/audit-engine.js`

---

## Problem

Lovable projects hosted on the public preview URL might lack fundamental frontend security headers like Content Security Policy (CSP) and Subresource Integrity (SRI) attributes on external scripts.

---

## Implementation

### 1. Fetch headers and HTML

```js
export async function checkFrontendSecurity(projectId) {
  const previewUrl = `https://${projectId}.lovableproject.com`;
  try {
    const res = await fetch(previewUrl);
    const html = await res.text();
    
    const cspHeader = res.headers.get('Content-Security-Policy');
    const hasCspMeta = html.includes('http-equiv="Content-Security-Policy"');
    
    // Check for external scripts missing integrity
    const scriptTags = Array.from(html.matchAll(/<script[^>]+src="([^"]+)"[^>]*>/g));
    const missingSri = scriptTags.some(match => {
      const src = match[1];
      const tag = match[0];
      const isExternal = src.startsWith('http') && !src.includes(previewUrl);
      const hasIntegrity = tag.includes('integrity="');
      return isExternal && !hasIntegrity;
    });

    return {
      hasCsp: !!cspHeader || hasCspMeta,
      missingSri
    };
  } catch (e) {
    return null;
  }
}
```

### 2. Create findings

```js
const frontendSec = await checkFrontendSecurity(project.id);
if (frontendSec) {
  if (!frontendSec.hasCsp) {
    result.findings.push({
      id: crypto.randomUUID(),
      ruleId: 'missing_csp',
      severity: 'low',
      title: 'Missing Content Security Policy',
      vector: 'frontend_security',
      source: 'preview_url',
      description: 'The project preview does not define a CSP header or meta tag.',
      evidence: 'Missing CSP',
      recommendation: 'Add a Content-Security-Policy to mitigate XSS attacks.',
      file: 'index.html',
    });
  }
  if (frontendSec.missingSri) {
    // Add missing SRI finding...
  }
}
```

---

## Acceptance Criteria

- [ ] Checks `Content-Security-Policy` header and meta tag
- [ ] Scans external `<script>` tags for the `integrity` attribute
- [ ] Emits `low` or `medium` severity findings for missing controls
