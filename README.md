# SentinelFlow Report Renderer

Browser-side report renderer for the SentinelFlow supervised cybersecurity
triage prototype.

- Reads an approved structured report from the URL fragment.
- Displays evidence, rule references, validation and Supervisor status.
- Creates a downloadable A4 PDF in the browser.
- Provides a local-first `.log` adapter and an explicitly allowlisted URL
  adapter at `?mode=intake`.
- Validates input size, event count, extension, HTTPS origin and response type
  before creating a Flowise-ready TXT file.
- Performs no autonomous remediation.
- Intended for simulated or approved teaching data only.
