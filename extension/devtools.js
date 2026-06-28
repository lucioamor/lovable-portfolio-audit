// Registers the NXLV Audit panel in DevTools (C4 — Phase 2 bridge).
chrome.devtools.panels.create(
  'NXLV Audit',
  null,
  'devtools-panel.html',
  () => { /* panel created */ },
);
