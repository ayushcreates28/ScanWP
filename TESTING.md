# Executed testing and remaining verification

Status: **partially verified**, not production-ready. Local tests, hosted engine CI and actual isolated Docker WordPress REST integration have passed. No client-site/staging scan, live Wordfence/Codex provider audit or unattended monthly audit is represented by those tests.

## Hosted CI and actual WordPress

[Passing hosted refactor run](https://github.com/ayushcreates28/ScanWP/actions/runs/42003018331), revision `de83145`: ordinary CI ran 303 cases, with **302 passed and 1 intentional Docker-profile skip**; the separate actual WordPress job ran that profile and **1 passed**. Zero failures/errors. Across both jobs, all 303 distinct test cases executed successfully. Python 3.12.15 on the hosted Linux runner; WordPress/WP-CLI/MariaDB/Nginx image digests are pinned in wordpress-test/compose.yml. The earlier local Windows checkpoint uses Python 3.12.14 and retains its one OS symlink skip; the symlink case passed on Linux.

Hosted coverage: **95.65% lines**, **94.16% combined lines/branches** (1628 covered lines + 517 covered branches out of 1702 + 576). Formatting, lint, Mypy, Bandit, dependency audit, PHP fixtures and report smoke generation all passed. CI artifacts were downloaded without forwarding GitHub credentials to signed storage, then verified against GitHub's SHA-256. Latest summaries are in evidence/github-ci-de83145.json and wordpress-real-refactor.json; earlier GREEN evidence is retained too.

Two regression tests first failed because documentation-only changes were excluded by CI's path filters. Removing those filters made both tests pass. CI now runs for every push/PR, preventing required checks from staying pending on documentation updates. Main's required verify/wordpress-integration checks and administrative enforcement were applied and read back through the GitHub API; see CI-VERIFICATION.json. No extra human-review requirement or production scan was introduced.

The actual WordPress test verifies HTTPS, real REST dispatch/collector parsing, active/inactive/must-use components, active theme, core/PHP/settings, missing/wrong tokens, denied POST/PUT/PATCH/DELETE, unchanged inventory after rejected writes, expiry, rotation and revocation. Only the disposable Docker fixture is modified through WP-CLI. It is not a client installation. The initial RED run failed with connection refused before fixture provisioning; a subsequent bootstrap attempt failed because the CLI image needed an explicit wp entrypoint. That was corrected before the GREEN run. Evidence/wordpress-real-red.json and wordpress-bootstrap-attempt.json preserve both actual failures. No production credential was used.

## Measured release results

Read `audit-engine/evidence/release-tests.log`, `release-junit.xml`, `coverage-release.json` and `release-metrics.json` for the latest measured run. At the recorded 299-pass checkpoint: 246 unit-folder tests passed, one unit-folder Windows symlink case skipped; 13 integration-folder tests passed; 40 security-folder tests passed; zero failures/errors. Some unit-folder tests also carry integration/security markers, so folder totals avoid double counting. The mocked two-run end-to-end scenario is included among integration tests.

Python 3.12.14 on Windows. Actual interpreter for these logs: `& '..\..\audit-engine\.venv\Scripts\python.exe'`, with working directory `ScanWP/audit-engine`. Logs abbreviate this interpreter as `python`; all following `-m ...` arguments are recorded. The virtual environment is outside the Git checkout because the new repository was supplied after initial setup. It is not committed. Dependencies are pinned in `requirements.lock`; pip was upgraded to 26.3. Pytest strict markers, branch coverage and a 90% coverage failure threshold are configured in `pyproject.toml`.

Latest coverage: **95.48% line**, **93.94% combined line/branch** across Python engine modules. Exact values are in release-metrics.json. Coverage does not establish correctness or production security. PHP coverage was not measured.

```text
python -m pytest --cov=sentinel_audit --cov-report=term-missing --cov-report=json:evidence/coverage-release.json --cov-report=xml:evidence/coverage-release.xml --junitxml=evidence/release-junit.xml
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m bandit -c pyproject.toml -r src
python -m pip_audit --local --skip-editable --format=json --output=evidence/dependency-audit-release.json
php ../wordpress-connector/tests/contract.php
php ../wordpress-connector/tests/admin.php
python -m sentinel_audit.cli demo --output runtime/demo
```

Ruff formatting/lint, strict Mypy (17 source modules), Bandit and pip-audit passed. Dependency audit reported no known vulnerabilities in the installed environment. It is a point-in-time advisory result. The earlier pip 25.0.1 audit failure is preserved, along with the upgrade and passing audit; do not mistake the old failure for the release environment.

PHP REST fixture checks: valid/missing/wrong/expired/revoked credentials, HTTPS-only, GET-only registration, no refresh/integrity side effects, no token echo and no-store. Supplemental admin fixture checks: capability/superadmin/nonce, hashing, expiry, one-time display and revocation. Those PHP fixtures stub WordPress functions. The separate Docker test supplies actual bootstrapping, REST dispatch, option-backed token behavior, a fixture TLS proxy and real installed inventory; real admin-browser nonce dispatch and multisite/vendor behavior remain unverified.

## TDD evidence by feature

New engine features were tested before implementation. Initial missing-module failures are genuine RED results, followed by implementations, GREEN runs and full-suite refactors. Supplemental branch tests and the reused earlier PHP collector/admin helper are not retrospectively described as test-first development.

| Feature / tests written first | RED evidence and reason | GREEN / refactor evidence |
|---|---|---|
| Registry/URLs/config (`test_config`) | `m01-red.log`: missing module | `m01-green-verified.log` / m01 logs; final suite reruns all configuration tests |
| HTTP pinning/checks/scanner (`test_transport`, `test_checks`, `test_public_scan`) | m02 RED imports; regression RED catches NAT64/CSP | m02 GREEN/regression logs; final transport coverage and suite |
| Inventory/WP-CLI (`test_inventory`), connector contract | m03 import/contract missing; unknown status/malformed record regressions | m03 GREEN logs; PHP release fixture logs; real WordPress not executed |
| Wordfence/version/risk (`test_wordfence`) | m04 import missing; four error/count/time regressions fail | m04 GREEN; m10 provider scope/protocol RED then GREEN; final suite |
| Integrity/environment (`test_integrity`, `test_extended_checks`) | m05 missing modules/checks | m05 GREEN and extension GREEN; real Windows symlink creation unavailable |
| SQLite/history (`test_history`) | m06 missing module; connection leak RED | m06 GREEN; m09 cache RED/GREEN; final history suite |
| Reports (`test_reports`) | m07 missing module; m10 unknown values/partial export RED | m07/m10 GREEN; report-layout tests; final suite |
| Source-bound summary (`test_summary`) | m08 missing module | m08 GREEN, final summary tests; live Codex not executed |
| Scheduler/runner/CLI (`test_scheduler`, `test_runner`, `test_cli`) | m09 imports, CLI missing; secret bundle RED; single-site RED | m09/m10 GREEN; two controlled runs, failure isolation, leases, cancellation and scheduled duplicate gate |
| GitHub history (`test_github_state`) | m09 module missing; m10 artifact digest mismatch accepted (RED) | m09/m10 GREEN; 22 fixture cases; live restore not executed |
| Security regressions (`test_regressions`) | four RED failures: invalid zone/update time, credential echo, missing feed persistence | four GREEN then full-suite rerun |

Find actual filenames in `audit-engine/evidence`; older failed attempts are retained. Some first runs hit sandbox temporary-directory denials and were repeated with permitted temporary fixtures. That environment error is separate from a product failure. One CLI test fixture was corrected to supply the deterministic summary that the real runner returns; no production behavior was weakened to hide that fixture error.

## Report checks

JSON/XLSX/PDF round trips verify counts, site assignment, zero/one/220 finding cases, source notices, pagination, formula injection, escaped HTML and missing information. A failed PDF generator must not leave newly published partial report files. PDF layouts and all six sample workbook sheets produced preview images that were inspected locally. The workbook preview process subsequently exited abnormally (-1073740791), despite producing all images; that renderer run is not reported as passed. Its import also normalizes displayed version strings, while OpenPyXL round-trip tests verify the original stored strings. The portable Poppler renderer emitted missing optional-font warnings; ASCII sample pages rendered legibly. Long cell text can require Excel's cell editor and full JSON as described in REPORTING. Native desktop Excel/Acrobat interaction was not performed. These are remaining visual-verification limitations.

## Required unexecuted checks

- Real admin-browser nonce dispatch, multisite and premium/vendor inventory. Docker was unavailable locally; actual single-site WordPress REST/inventory/token verification subsequently passed in hosted Docker CI.
- Real Wordfence v3 authentication/full feed/schema/licensing workflow using an operator-owned key.
- Real Codex model/API (optional; deterministic summary is tested independently).
- Real verified HTTPS handshake against an approved staging certificate; actual throttling/WAF behavior.
- Monthly dispatch, the application's private history restore end to end, retention and failure notification delivery. Ordinary hosted CI and SHA-verified CI evidence download passed; they are separate from running the monthly audit.
- Approved staging smoke test and two-month operational comparison with independently verified inventory/updates and trusted integrity references.

Do not label these “passed” because mocked adapters passed. See `audit-engine/STATUS.md` for remaining feature limits as well as external prerequisites.
