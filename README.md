# ScanWP

Read-only WordPress inventory, vulnerability matching, audit history and reports for explicitly authorized sites. The Python engine runs separately from the existing Sites dashboard.

**Current status: verified in local and hosted CI, not a production release.** The connector also passed against actual isolated WordPress in Docker. Live Wordfence/Codex, client staging and operational monthly scans still require verification. See [STATUS](audit-engine/STATUS.md) and [test evidence](TESTING.md). No client website has been scanned or changed by this engine.

The engine inventories installed plugins/themes (including inactive, network-active, must-use, drop-ins and parent themes), versions, activation, update availability and update-cache timestamps. Public checks cover WordPress detection, basic headers/HTTPS, sampled disclosures, directory listings, REST, XML-RPC and public user metadata. Wordfence v3 provides advisory version matching. SQLite tracks explicit new/recurring/resolved/unverified observations. Reports export JSON, XLSX, HTML and PDF for each site and the portfolio.

```powershell
cd audit-engine
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m sentinel_audit.cli demo --output runtime/demo
.\.venv\Scripts\python.exe -m sentinel_audit.cli validate --config examples/sites.json
```

Linux/macOS: use `python3.12`, then `.venv/bin/python` in place of the Windows interpreter. `demo` uses clearly labeled synthetic data and makes no HTTP requests. The example Quadigy registry is disabled. Changing the registry does not install anything on a website.

- [Setup and connector installation](SETUP.md)
- [Registry and secrets](CONFIGURATION.md)
- [GitHub monthly scheduling](SCHEDULING.md)
- [Report interpretation](REPORTING.md)
- [Security boundaries](SECURITY.md)
- [Tests and measured evidence](TESTING.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Changes](CHANGELOG.md)

Live scanning requires both an authorized registry and an explicit `scan --live` invocation. Configure and validate a staging site before production. No updates, exploit execution, logins, password testing, shell execution on websites or automatic remediation are provided.
