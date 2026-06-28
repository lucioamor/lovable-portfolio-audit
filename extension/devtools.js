// Registers the NXLV Lovable Portfolio Audit panel in DevTools (C4 — Phase 2 bridge).
chrome.devtools.panels.create(
  'NXLV Lovable Portfolio Audit',
  null,
  'devtools-panel.html',
  () => { /* panel created */ },
);
