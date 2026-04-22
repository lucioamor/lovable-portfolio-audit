# Skill: Diff Alerts (Severity Worsened)

> **Roadmap refs:** P11  
> **Complexity:** Small  
> **Files affected:** `extension/lib/audit-engine.js`

---

## Problem

When a user runs a scan, they don't know if their score worsened compared to the last time they ran it. We need to compare the current scan results with the previous run's stored results.

---

## Implementation

### 1. Load previous results before scan

```js
// In background.js or audit-engine.js initialization
const previousData = await chrome.storage.local.get('lss_results');
const previousResults = previousData.lss_results || [];
const previousMap = new Map(previousResults.map(r => [r.projectId, r]));
```

### 2. Compare in `scanProject`

```js
const previous = previousMap.get(project.id);
result.trend = 'new';
result.scoreDelta = 0;

if (previous) {
  result.scoreDelta = result.riskScore - previous.riskScore;
  
  if (result.scoreDelta > 0) {
    result.trend = 'worsened';
    // Optionally create a synthetic finding or UI alert
  } else if (result.scoreDelta < 0) {
    result.trend = 'improved';
  } else {
    result.trend = 'unchanged';
  }
}
```

### 3. Expose in UI

The UI (e.g. `ProjectDetail` or `SecurityDashboard`) can read the `trend` and `scoreDelta` properties to render green/red arrows.

---

## Acceptance Criteria

- [ ] Calculates score difference between current and previous scan
- [ ] Assigns a `trend` enum (`worsened`, `improved`, `unchanged`, `new`)
- [ ] Persists trend data on the result object
