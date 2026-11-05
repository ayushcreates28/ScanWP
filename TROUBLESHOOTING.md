# Troubleshooting

| Symptom | Meaning and next action |
|---|---|
| “A response exceeded the 1 MB audit limit” in the existing dashboard | Its public response reader hit the old safety cap. This is not a vulnerability finding. The new Python engine uses configurable 5 MB per-site limits (10 MB maximum), 4 KB disclosure samples and a separately bounded streaming Wordfence feed. It has not been deployed into that dashboard |
| Unknown installed plugins or activation | Public assets cannot prove the full installed inventory. Install/approve the restricted connector or provide approved offline inventory |
| Connector 403 | Check HTTPS/proxy handling, forwarded Authorization, token reference, expiry, revocation and the correct site. Rotate privately if needed; do not disable TLS |
| Connector endpoint missing | Confirm activation/permalinks and that the site's API route is reachable. A WAF/blocked route is incomplete coverage |
| Unknown updates | WordPress/vendor update cache is missing/stale (>24 hours) or does not support that component. Verify Admin update checks. The scanner does not install updates |
| Potential affected version | Version range matches but component identity is not sufficiently confirmed. Verify exact slug/vendor/package before action |
| Wordfence authentication/terms/rate-limit failure | Configure an operator-owned v3 key, review/accept terms, check account/API access. Retries are bounded; a failure remains incomplete |
| No known advisories | This does not establish complete security. Review feed freshness, inventory, unknown versions/identities and coverage |
| Scope rejection | URL/DNS/redirect left the authorized public scope or resolved privately. Correct the registry/hosting; do not bypass checks |
| Partial every month | Inspect failed/unknown check rows, timestamps and source limitations. Partial results intentionally prevent a completed monthly audit claim |
| Overlap/interrupted | Another process holds the six-hour lease, or an interrupted process has not expired. Do not delete state to bypass it. Preserve history and investigate the runner |
| Missing private history | Artifact expired, workflow never uploaded, permissions/restore validation failed. Restore a private backup. Bootstrap is for the first approved run only |
| Monthly job skipped | Activation variable, private-repository guard, default branch or environment protection is not satisfied. No production execution is enabled automatically |
| Workbook long cell/export failure | Excel has a hard cell-size limit. Review canonical JSON and split/refine data through an approved change; no silent truncation occurs |
| AI summary unavailable | The operator model/key was unavailable or output failed validation. Deterministic facts and summary remain available |

Run demo and the local test suite before investigating a client site. Logs intentionally use error categories rather than raw remote bodies/exception text. Record site ID, scan ID, status, timing and redacted evidence. Keep real credentials out of issues/screenshots.
