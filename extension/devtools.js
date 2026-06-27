// Registers the NXLV Shield panel in DevTools (C4 — Phase 2 bridge).
chrome.devtools.panels.create(
  'NXLV Shield',
  null,
  'devtools-panel.html',
  () => { /* panel created */ },
);
