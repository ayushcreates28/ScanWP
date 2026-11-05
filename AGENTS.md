# Development rules

The user's attached master prompt is the acceptance specification for the Python audit-engine project.

- Apply RED -> GREEN -> REFACTOR to every new feature and regression fix. Execute new tests and record the expected failure before implementation; do not fabricate historical TDD evidence.
- Record exact commands, exit codes and output in audit-engine/evidence. Report measured coverage and separate mocked tests from real integrations.
- No feature is complete while its required tests fail. Target >=90% line coverage for core logic, including security paths.
- Read-only scanning by default. Only explicitly authorized configured hosts and methods may run. No production scans, connector installation, updates or hosting changes without separately established authorization.
- Use TLS verification, DNS/IP protections, approved redirects, strict timeouts, size limits, throttling and bounded retries. A failure is not a clean scan.
- Store secret references, never secret values, in configuration/database/reports/logs. Preserve provider copyright/license notices.
- Unknown or missing coverage must not produce a pass or a resolved finding. Version matches are not proof of exploitation or malware.
- Treat remote data as untrusted; use structured findings for all counts. Escape HTML and spreadsheet cells. Never execute remote content or suspicious files.
- Do not describe the system as production-ready until every acceptance requirement and required staging/live verification has evidence.
- The existing Sites dashboard uses TypeScript and remains separate from the Python engine until a supported hosted integration is tested. Do not imply that local Python functionality is deployed to Sites.
