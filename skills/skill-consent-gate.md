# Skill: Safe Mode Default + Consent Gate for Deep Inspection

> **Roadmap refs:** E7, E8, E9, §7.1  
> **Complexity:** Small  
> **Files affected:** `extension/sidepanel.js`, `extension/popup.html`, `extension/lib/audit-engine.js`

---

## Problem

The extension currently lets users start a full deep scan (including file
content reading and chat scanning) without any explicit opt-in beyond clicking
"Start Scan". The roadmap requires:

- **Safe Mode ON by default** — deep inspection (file content + chat regex)
  disabled until user explicitly enables it.
- **Legal accept modal** before the first scan is ever run.
- **Consent gate** — file content scanning and chat scanning each require their
  own explicit toggle; defaults are OFF.

---

## Implementation

### 1. Default preferences in `chrome.storage.local`

```js
// In background.js onInstalled handler
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get('lpa_prefs', (data) => {
    if (!data.lpa_prefs) {
      chrome.storage.local.set({
        lpa_prefs: {
          safe_mode: true,           // deep inspect OFF by default
          includeFiles: false,       // explicit consent required
          includeChat: false,        // explicit consent required
          legal_accepted: false,     // must accept before first scan
          legal_version: 1,
        }
      });
    }
  });
});
```

### 2. Legal accept modal in `sidepanel.html`

```html
<div id="legal-modal" class="modal" hidden>
  <div class="modal-box">
    <h2>Before you scan</h2>
    <p>
      This tool sends GET requests to <code>api.lovable.dev</code> using your
      own browser session. It reads your own projects only. No data is sent to
      external servers. Results are stored locally in this browser.
    </p>
    <p>By clicking <strong>I understand, proceed</strong> you confirm that:</p>
    <ul>
      <li>You own or have explicit permission to audit the scanned projects.</li>
      <li>You accept responsibility for acting on findings appropriately.</li>
    </ul>
    <button id="legal-accept-btn">I understand, proceed</button>
    <button id="legal-reject-btn">Cancel</button>
  </div>
</div>
```

In `sidepanel.js`:
```js
async function checkLegalAccept() {
  const { lpa_prefs } = await chrome.storage.local.get('lpa_prefs');
  if (!lpa_prefs?.legal_accepted) {
    document.getElementById('legal-modal').hidden = false;
    await new Promise(resolve => {
      document.getElementById('legal-accept-btn').onclick = () => {
        chrome.storage.local.set({
          lpa_prefs: { ...lpa_prefs, legal_accepted: true, legal_version: 1 }
        });
        document.getElementById('legal-modal').hidden = true;
        resolve();
      };
      document.getElementById('legal-reject-btn').onclick = () => {
        document.getElementById('legal-modal').hidden = true;
        resolve(new Error('rejected'));
      };
    });
  }
}
```

### 3. Safe mode toggle in scan config UI

```html
<!-- In sidepanel.html scan settings section -->
<label class="toggle-row">
  <span>Safe Mode</span>
  <input type="checkbox" id="safe-mode-toggle" checked />
  <small>When ON, only endpoint status is checked. File contents and chat messages
    are never read. Disable to enable deep secret scanning.</small>
</label>

<div id="deep-scan-options" hidden>
  <label>
    <input type="checkbox" id="include-files" />
    Scan source file contents for secrets (reads files from accessible projects)
  </label>
  <label>
    <input type="checkbox" id="include-chat" />
    Scan chat history for secrets and PII
  </label>
</div>
```

```js
document.getElementById('safe-mode-toggle').addEventListener('change', (e) => {
  const isOn = e.target.checked;
  document.getElementById('deep-scan-options').hidden = isOn;
  if (isOn) {
    document.getElementById('include-files').checked = false;
    document.getElementById('include-chat').checked = false;
  }
});
```

### 4. Enforce consent in `audit-engine.js`

```js
export async function runScan(config, onProgress, onResult) {
  // Consent gate — deep inspect requires explicit opt-in
  if (config.includeFiles && !config.consentGiven) {
    throw new Error('consent_required: set consentGiven=true to enable file scanning');
  }
  if (config.includeChat && !config.consentGiven) {
    throw new Error('consent_required: set consentGiven=true to enable chat scanning');
  }
  // ...
}
```

In `background.js` `START_SCAN` handler:
```js
const prefs = (await chrome.storage.local.get('lpa_prefs')).lpa_prefs || {};
const config = {
  ...msg.config,
  includeFiles: !prefs.safe_mode && msg.config.includeFiles,
  includeChat: !prefs.safe_mode && msg.config.includeChat,
  consentGiven: !prefs.safe_mode,
};
```

---

## Acceptance Criteria

- [ ] First scan triggers legal modal; subsequent scans do not (stored in `lpa_prefs.legal_accepted`)
- [ ] `safe_mode: true` by default — `includeFiles` and `includeChat` are `false`
- [ ] Deep scan options only visible when Safe Mode is toggled OFF
- [ ] `audit-engine.js` throws `consent_required` if `includeFiles/Chat` requested without `consentGiven`
- [ ] Toggling Safe Mode OFF requires user to check each sub-option individually
