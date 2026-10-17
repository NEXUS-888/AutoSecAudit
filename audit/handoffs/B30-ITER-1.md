# UX iteration 1
ux_check issues: 86

## Own visual review
Visual review of all application pages across desktop (1280x800), tablet (768x1024), and mobile (375x667) in dark and light themes:
- Auth page (`/login`, `/register`): Missing `<main>` landmark. Form structure is clean, but accessibility tree lacks a designated main landmark.
- Scanner page (`/`): Missing `<main>` landmark. Several interactive controls (theme toggle button, scan preset buttons, radio/checkbox inputs) have tap targets smaller than 24x24 px.
- History page (`/history`): Missing `<main>` landmark. Severity indicators lack strong contrast in light theme.
- Landing page (`/landing`): Severe horizontal layout overflow on 375px mobile screens where hero section and attack graph card expand to 472px wide. Preset pills and policy toggles have tap targets under 24px.
- Report page (`/report/<id>`): Missing `<main>` landmark. Demo mode banner and severity badges need structural contrast tuning.

## Fixed
- Added semantic `<main role="main">` landmark elements to `ui/templates/auth.html`, `ui/templates/history.html`, `ui/templates/landing.html`, and `reports/templates/report.html`.
- Expanded tap targets to at least 24x24px via minimum dimensions and padding for `#themeToggle`, `#policyToggleBtn`, `.preset-pill`, `.toggle-pill`, and all checkbox/radio inputs.
- Fixed mobile horizontal overflow in `ui/templates/landing.html` by adding `@media (max-width: 640px)` width and padding constraints on `.hero`, `.navbar`, `.action-box`, `.flow-panel`, `.pipeline-card`, and `.attack-graph-card`.

## Remaining
- 35 text-contrast issues across light theme badges, pills, and headers.
