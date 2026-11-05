# Setup

## Local verification

Use Python 3.12+, an isolated virtual environment and the installation commands in README. The lock file records the tested development dependencies; CI uses Python 3.12. It includes report and security-check tooling. No paid scanner service is required. OpenAI summarization is optional and may incur provider charges when enabled.

Run `python -m pytest --cov=sentinel_audit`, `python -m ruff check .`, `python -m ruff format --check .`, `python -m mypy`, `python -m bandit -c pyproject.toml -r src`, and `python -m pip_audit --local --skip-editable` from `audit-engine`. Never use production tokens for tests.

## WordPress connector (operator action)

1. Back up and obtain approval for an isolated staging installation first. Use a supported WordPress/PHP runtime.
2. Zip the `wordpress-connector` directory with `scanwp-readonly-connector.php` at the plugin folder root. Install and activate through WordPress Admin, Plugins, Add New, Upload Plugin. A built ZIP is provided under `dist` when packaged.
3. In Tools, ScanWP Connector, create an inventory-only token. Only an administrator can do this; multisite also requires a super administrator. The REST API does not grant administrator access.
4. Save the one-time 64-character token directly in the runtime secret referenced by this site's registry. The WordPress database stores only its SHA-256 hash. Tokens expire after 90 days; set an operator rotation reminder and update GitHub secrets before expiry. Rotation/revocation invalidates the old token immediately.
5. Verify the GET-only `/wp-json/sentinel-audit/v1/inventory` route over HTTPS. Missing, wrong, expired, revoked and HTTP credentials must be denied. No POST/PUT/PATCH/DELETE route is registered.
6. Confirm the complete inventory, plugin/theme activation and pending updates against WordPress Admin. Test premium/vendor plugins, must-use loaders, multisite and custom content paths explicitly. Update information comes from existing WordPress/vendor caches; no update is installed by the API. Stale or absent timestamps stay unknown.

Behind a TLS proxy, configure WordPress's trusted proxy HTTPS handling correctly; the plugin deliberately does not blindly trust client-supplied forwarding headers. Authorization headers must reach PHP. Never disable certificate verification to work around a misconfigured proxy.

## Intelligence and first run

Create your own Wordfence account/integration API key and review the linked provider terms in `audit-engine/docs/INTEGRATIONS.md`. Configure `SENTINEL_WORDFENCE_API_KEY` privately, then set `SENTINEL_WORDFENCE_TERMS_ACCEPTED=yes` only after acceptance. Tests do not create accounts or accept terms.

Copy `audit-engine/examples/sites.json` to a private runtime path. Set approved targets/methods and enable only approved sites. Keep secret values out of the registry. Then:

```text
python -m sentinel_audit.cli validate --config runtime/sites.json
python -m sentinel_audit.cli scan --live --config runtime/sites.json --db runtime/state/history.sqlite --output runtime/output
```

An exit code of 0 means all enabled sites met the execution requirements. Findings can exist in a completed scan. Exit 1 means partial/failed/cancelled/overlapping execution; exit 2 means configuration/input/storage validation failed. Consult reports and `alerts.json`. A technically successful request is not necessarily a completed check.

## Required release verification

Before enabling production: run the actual connector on isolated WordPress, exercise token rotation/revocation, run a real Wordfence download with an operator key, compare installed versions/updates against Admin, validate reports in intended viewers, run two staging audits with a controlled change, verify GitHub artifact restore, cancellation and failure notifications. Obtain explicit live-scan authorization. These checks have not been performed locally; Docker and staging credentials were unavailable.
