# Changes

## 0.2.0 - 2026-11-05 (development, not production release)

- Published source to GitHub after the user completed Git sign-in. Hosted ordinary CI passed all 305 ordinary cases; an added isolated Docker WordPress profile also passed real REST/inventory/token/write-method checks. Preserved the genuine connection-refused RED and corrected WP-CLI bootstrap failure; verified downloaded artifact SHA-256 values.
- Required passing verify/wordpress-integration checks on main, including administrators. Added two test-first regressions and removed CI path filters so documentation-only changes do not leave required checks pending.
- Fixed required report failures leaving completed scan status that could suppress a monthly retry. Individual/consolidated export failures now persist partial status without losing findings; genuine RED and passing regression/full-suite results are retained.
- Added a documented PostgreSQL migration boundary and validation/rollback plan; no PostgreSQL adapter or production migration is claimed.

- Added the Python 3.12 engine, strict multi-site registry and read-only network controls.
- Added authenticated inventory parsing, approved WP-CLI import adapter, restricted WordPress token connector and supplemental PHP admin fixtures.
- Added bounded Wordfence v3 ingestion, range matching, source notices and separate internal priority.
- Added settings/exposure checks, metadata-only integrity baselines, SQLite history, explicit resolution and concurrency/recovery.
- Added JSON/HTML/XLSX/PDF reports and synthetic samples; deterministic summaries with an optional constrained Codex adapter.
- Added CLI, monthly due/missed gates, private GitHub history restoration and disabled scheduled workflow.
- Recorded executed TDD failures and corrections: network exception handling, feed count/time budgets, NAT64 blocking, CSP framing, unknown WP-CLI status, SQLite connection cleanup, timestamp/timezone validation, remote credential echoes and staged report export.
- Initial local dependency audit found pip advisories. Upgraded the isolated environment from pip 25.0.1 to 26.3 and re-audited. See evidence for actual results.
- Existing Sites dashboard/manual collector predate the new TDD prompt. Their earlier development is not retrospectively described as TDD. The earlier collector helper was reused; admin fixtures are supplemental tests added after existing code.
