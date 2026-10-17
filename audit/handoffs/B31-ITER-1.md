# UX iteration 1
ux_check issues: 7

## Own visual review
Visual review of the newly introduced everyday-use features across desktop (1366x768), tablet (768x1024), and mobile (375x667) viewports in both dark and light themes:
- History page (`/history`):
  - Adding the `compare-scans` control and action buttons without flex wrapping caused horizontal layout overflow on 375px mobile screens (content expanded to 401px wide).
  - The per-scan selection checkboxes were rendered at 18x18px, failing the minimum 24x24px tap target guideline.
  - The theme toggle button was squeezed horizontally to 19x36px on mobile viewports due to flex shrink behavior.
- Report page (`/report/<id>`):
  - The "Hide triaged" checkbox control (`#hideTriagedToggle`) was rendered at 18x18px, falling short of the 24x24px target size requirement.
  - The triage note edit button (`.btn-triage-note`) had computed height of 22px (51x22px), below the 24px minimum tap target height.
- Comparison page (`/compare/<older>/<newer>`):
  - Differential analysis cleanly displays New, Fixed, and Unchanged sections, scan metadata, and target mismatch warnings.
- Scanner page (`/scanner`):
  - Progress view properly displays the visible Cancel button (`data-testid="cancel-scan"`) from scan start.

## Fixed
- Implemented AUD-79 finding triage backend: CSRF-protected POST `/report/<report_id>/triage`, sidecar JSON storage in `config.REPORTS_DIR`, and triage state attachment in `view_report`.
- Implemented AUD-80 scan comparison backend: GET `/compare/<older_id>/<newer_id>` utilizing `DeltaAnalyzer.compare_with_dict` with target mismatch warnings and access validation.
- Implemented AUD-81 scan cancellation backend: CSRF-protected POST `/scan/cancel/<scan_id>`, `check_cancelled` integration in background execution thread, and concurrency slot freeing.
- Added compare button and checkboxes in `ui/templates/history.html` and triage controls with hide-triaged toggle in `reports/templates/report.html`.

## Remaining
- Fix 375px mobile horizontal layout overflow on history page.
- Enforce 24x24px minimum tap target size on `#hideTriagedToggle`, `.scan-checkbox`, `.btn-triage-note`, and `#themeToggle`.
