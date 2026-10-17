# UX iteration 2
ux_check issues: 35

## Own visual review
Visual review of all pages with responsive layouts and landmarks verified:
- Dark theme renders cleanly across all pages and viewports with excellent readability.
- In light theme (`data-theme="light"`), text contrast failures are widespread:
  - History page: severity badges (`--sev-high`, `--sev-low`) use light shades with insufficient contrast against light backgrounds. History navigation links and action buttons fall below 4.5:1.
  - Auth page: footer anchor links (`Don't have an account? Sign up`) lack sufficient contrast.
  - Landing page: discovery progress text, status chips, flow mathematics numbers, and scanner telemetry badges lack sufficient contrast against light background panels.
  - Scanner dashboard: label hints, input icon glyphs, section titles, demo/real mode badges, and footer text fall below 4.5:1 contrast in light mode.
  - Report page: demo banner, danger box titles, remediation blueprint headers, confidence badges, threat status badges, and findings table headers need darker, accessible colors in light mode.

## Fixed
- In `ui/templates/history.html`: adjusted light mode severity tokens (`--sev-high: #9a3412`, `--sev-low: #166534`, `.sev-bar { color: #ffffff !important; }`), set link colors to `#4338ca`.
- In `ui/templates/auth.html`: styled `.auth-footer a` with accessible `#4338ca` in light theme.
- In `ui/templates/landing.html`: added explicit light theme overrides for `.chip-1`, `.chip-2`, `.chip-3`, `#discoveryProgressText`, `.flow-math .num-*`, `.scanner-res`, `.pill-target`, `.pill-running`, and telemetry alert/success styles.
- In `ui/app.py`: darkened `.label-hint`, `.input-icon-glyph`, `.presets-label`, `.section-title`, `.footer-text` to `#475569`. Styled `.mode-badge-demo` and `.mode-badge-real` with accessible light theme color tokens.
- In `reports/templates/report.html`: styled `.demo-mode-banner`, `.danger-box-title`, `.remediation-title`, confidence badges, threat status badges, section tags, and findings table headers with accessible light-theme colors.

## Remaining
- 1 text-contrast issue on scanner history link button in dark mode (`.history-link-btn`).
