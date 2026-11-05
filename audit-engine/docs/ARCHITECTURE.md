# Planned architecture and acceptance matrix

The user-supplied master prompt is the specification. Existing dashboard features are not evidence that the new Python acceptance criteria have passed.

| Milestone | Modules | Required acceptance / test families | External dependency |
|---|---|---|---|
| 1 Foundation | config, models, registry validation | strict configuration, URL rejection, unique site IDs/hosts, explicit authorization and methods, secret references; CI setup | Python packages |
| 2 Public scanner | transport, detection, checks | DNS/IP pinning, TLS/SNI, redirects, budgets, throttling, WAF/partial/denied results, detection confidence, positive/negative/inconclusive checks | controlled HTTP server; no production target |
| 3 Inventory | connector, inventory, wpcli | restricted auth, expiry/revocation, read-only routes, schema validation, all component states and unusual versions | isolated WordPress; no production credential |
| 4 Intelligence | wordfence, versions, matching | v3 bearer auth, streaming/full-feed bounds, retry/freshness, licenses, multiple ranges and prereleases, four matching outcomes | operator-owned Wordfence v3 API key and terms acceptance for live check |
| 5 Integrity | integrity, environment | trusted hashes, new/changed/deleted/unverified, symlinks and path traversal, limited scans, no execution | trusted reference manifests / approved directories |
| 6 History | database, history | SQLite transactions, deduplication, per-check comparability, no false resolution, interrupted/recovered jobs | persistent private database |
| 7 Reports | reports + templates | canonical JSON/XLSX/HTML/PDF, per-site and consolidated counts, escaping, formula-injection controls, long/empty reports and render inspection | renderer; no third-party report service |
| 8 Summaries | summary | deterministic source-bound counts, optional adapter rejects unsupported narrative claims, prompt-injection fixtures | optional Codex integration credentials; deterministic mode must work without AI |
| 9 Scheduling | scheduler, runner, cli | IST 09:17 first-of-month, due/missed jobs, leases, retries, cancellation, per-site isolation, failure notification outbox | chosen server/CI hosting, authorized registry and secret provisioning |
| 10 Release | CI + e2e fixtures | two simulated monthly runs, real connector environment when available, full tools/coverage/security/dependency checks, setup docs | staging access and optional Docker/live credentials |

Source layout: src/sentinel_audit; tests/unit, integration, security, e2e; examples; templates; evidence; docs. The Python engine cannot run inside the existing Cloudflare Worker runtime; it is a separate process for server cron / GitHub Actions. No hosting migration is performed without authorization.

Evidence lives in timestamped milestone logs and STATUS.md. Each milestone must state executed vs unexecuted integrations. User must supply or configure secrets directly in the runtime; never paste production credentials into source or reports.
