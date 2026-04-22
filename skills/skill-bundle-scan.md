# Skill: Supabase URL + Anon Key Bundle Scan

> **Roadmap refs:** P9  
> **Complexity:** Medium  
> **Files affected:** `extension/lib/api-client.js`, `extension/lib/audit-engine.js`

---

## Problem

Developers often hardcode their Supabase URL and anon key directly into the compiled frontend JavaScript bundle (`index-xxxx.js`), which gets exposed on the public preview URL even if the source code endpoint is protected.

---

## Implementation

### 1. Fetch the index HTML and extract JS bundle URL

```js
// extension/lib/api-client.js
export async function getPreviewUrl(projectId) {
  // Lovable preview URLs follow a predictable pattern, or can be queried
  return `https://${projectId}.lovableproject.com`;
}

export async function fetchBundleContent(projectId) {
  try {
    const previewUrl = await getPreviewUrl(projectId);
    const htmlRes = await fetch(previewUrl);
    const html = await htmlRes.text();
    
    // Find the main JS bundle: <script type="module" crossorigin src="/assets/index-xxxx.js"></script>
    const scriptMatch = html.match(/src="(\/assets\/index-[^"]+\.js)"/);
    if (!scriptMatch) return null;
    
    const bundleUrl = new URL(scriptMatch[1], previewUrl).href;
    const bundleRes = await fetch(bundleUrl);
    return await bundleRes.text();
  } catch (e) {
    return null;
  }
}
```

### 2. Scan the bundle in `audit-engine.js`

```js
if (config.includeFiles) { // or a new config.includeBundle
  const bundleContent = await fetchBundleContent(project.id);
  if (bundleContent) {
    const bundleFindings = await scanContent(bundleContent, 'compiled_bundle.js');
    result.findings.push(...bundleFindings);
    
    // Explicitly check for Supabase init pattern if not caught by general regex
    const sbMatch = bundleContent.match(/https:\/\/([a-z]{20})\.supabase\.co/);
    if (sbMatch) {
      result.supabaseDetected = true;
      result.supabaseUrl = sbMatch[0];
    }
  }
}
```

---

## Acceptance Criteria

- [ ] Extrapolates or retrieves the correct preview URL for a project
- [ ] Parses the `index.html` to find the minified JS bundle
- [ ] Fetches the bundle and passes it through `scanContent`
- [ ] Does not crash if the preview URL is down or password-protected
