# Milestone status - 2026-11-05

Overall: **partially verified development build**. This is not a production release and does not satisfy all final acceptance criteria yet. The engine has not scanned a live client site. No connector has been installed on one, and no production scheduler was activated.

| Milestone | Actual implementation / verification | Remaining acceptance |
|---|---|---|
| 1 Foundation | Registry/config, dependencies, TDD logs and CI workflow implemented; local tests/quality pass | Hosted CI and required branch protection need actual GitHub verification |
| 2 Public scanner | Bounded public checks, detection, DNS/IP pinning, request budgets/retries, simulated SNI/Host verified | Real staging TLS/WAF/HTTP behavior; comprehensive cipher/hosting analysis is outside the implemented checks |
| 3 Inventory | Parser, offline WP-CLI adapter and HTTPS token connector implemented; Python + stubbed PHP fixtures pass | Actual isolated WordPress, dispatch/bootstrap, multisite/vendor inventory and approved installation not verified |
| 4 Intelligence | v3 feed adapter, bounded streaming, dates, version ranges, matching, priority and license retention tested with fixtures | Operator account/key/terms and real feed integration; richer exploitation/authentication context beyond implemented schema remains unknown |
| 5 Configuration / integrity | Public/settings checks, approved local SHA-256 metadata, trusted-manifest/previous-baseline comparison implemented | Automatic REST core/package reference acquisition is not implemented. Earlier manual PHP core-checksum helper is separate. Trusted package provenance/approved server capture remain operator tasks. Actual OS symlink fixture skipped on Windows |
| 6 History | Canonical findings, SQLite transactions/backup, comparison, concurrency/leases, interrupted status, feed persistence verified locally | PostgreSQL adapter is not implemented; migration needs a new adapter/import validation. Production backup/recovery still needs operational verification |
| 7 Reports | JSON/HTML/XLSX/PDF, individual/portfolio counts, notices, comparisons, escaping/injection controls, synthetic samples and visual review | Native viewer and staging report verification; PDF non-ASCII uses explicit escapes, very long Excel cells require cell editor/full JSON |
| 8 Summaries | Deterministic source-bound summary plus constrained optional Codex selection adapter; mocked validation passes | Real optional model/API unverified; free-form AI narrative is deliberately not used as factual report data |
| 9 Scheduling | CLI/due/missed/duplicate gates, cancellation, job lease, GitHub private-state restore/digest verification and disabled monthly workflow implemented/tested with fixtures | Repository secrets/private visibility/activation, real history restore and notification delivery not configured or verified |
| 10 Validation | Local full suite / quality tools and dependency audit pass; exact results in release evidence | Real WordPress, hosted CI and approved staging smoke test not executed. Release is not approved for production |

The existing Sites dashboard/manual collector predate this TDD specification. No retroactive RED-phase claim is made. The earlier collector helper is reused; supplemental admin tests were added after that code. Python results are not automatically connected to the existing published dashboard.

The latest metrics and commands are in `evidence/release-metrics.json`, `release-tests.log`, `quality-*.log`, PHP fixture logs and root TESTING.md. Failed attempts and genuine RED runs are preserved. Personal workspace prefixes in shareable evidence are redacted and documented; outcome/count/trace content is otherwise retained.

Selected repository: `https://github.com/ayushcreates28/ScanWP`. Code/workflows are prepared locally; consult handoff status for actual push/hosted CI outcome. Never infer deployment/activation from the existence of workflow files.
