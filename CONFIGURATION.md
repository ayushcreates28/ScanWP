# Configuration

The registry is JSON, schema version 1. Add/edit/disable/remove records without changing Python source. Site IDs and production/staging hosts must be unique. Keep a stable ID for one website; use a new ID for a different website to keep histories separate. Removing a registry entry preserves its historical database records. Disabled entries are reported as skipped.

| Field | Meaning |
|---|---|
| id, name | Lowercase stable ID (letters/digits/underscore/hyphen), display name |
| production_url | Absolute HTTP(S) public DNS URL, optionally an installation base path |
| authorized, enabled | Explicit authorization must be true; enabled controls execution |
| staging_url, staging_authorized | Optional separately authorized host; production remains the selected target. Use a staging registry entry to scan staging directly |
| environment | production, staging or development |
| methods | Approved subset: public, inventory, wpcli, integrity |
| connector_token_env | `SENTINEL_...` secret reference; inventory requires HTTPS |
| rate_limit_per_second | Default 0.5, maximum 2; every retry/redirect shares budgets |
| timeout_seconds | Default 15, maximum 30 |
| max_requests | Default 25, maximum 100 per site |
| max_response_bytes | Default 5 MB, maximum 10 MB; disclosure samples use 4 KB |
| criticality | standard, high or critical; publisher CVSS is never changed |
| reporting | formats and IANA timezone; all four exports are currently generated for consistent verification |

IP literals, credentials in URLs, query strings/fragments, unsafe paths, nonstandard ports, reserved/local hostnames and private/mixed DNS destinations are rejected. Redirects may only remain in approved origins. Authenticated requests never follow redirects. The connector path is fixed; arbitrary endpoints and commands cannot be configured.

The global `schedule` accepts day 1-28, hour 0-23, minute 0-59 and an IANA timezone. Defaults: first day, 09:17, Asia/Kolkata. Restricting days to 28 avoids invalid shorter-month schedules. See SCHEDULING for the GitHub tick time.

## Secrets

Local runs: configure each site's referenced environment variable and `SENTINEL_WORDFENCE_API_KEY` in your process environment. Do not paste secrets into chat, code, the registry or reports.

GitHub repository/environment secrets:

- `SENTINEL_REGISTRY_JSON`: private registry JSON, containing references only.
- `SENTINEL_CONNECTOR_TOKENS_JSON`: JSON object of configured token-reference names to 64-character connector tokens. No arbitrary process environment variables are accepted.
- `SENTINEL_WORDFENCE_API_KEY`: operator-owned Wordfence v3 key.

Repository variables: `SENTINEL_ENABLE_SCANS=true` to explicitly activate, `SENTINEL_WORDFENCE_TERMS_ACCEPTED=yes` after acceptance, and `SENTINEL_INITIALIZE_HISTORY=yes` for the first approved bootstrap only. Remove bootstrap permission once private history exists.

Optional local AI variables: `SENTINEL_OPENAI_API_KEY`, `SENTINEL_CODEX_MODEL` (operator-selected supported model). The default workflow does not call AI. `--codex-summary` explicitly enables the optional adapter. No default model or pricing assumption is embedded.

## Approved offline inputs

`wpcli` accepts captured inventory snapshots through `--inventory-dir runtime/inventories`, one `<site-id>.json` per site. Use `inventory.parse_wpcli` to normalize captured `wp core version`, `wp plugin list --format=json` and `wp theme list --format=json` data into the snapshot schema. The engine does not obtain SSH credentials or execute WP-CLI remotely. Slugs from directory hints remain unconfirmed; update caches must have valid recent timestamps to establish currency.

`integrity` accepts `--integrity-dir runtime/manifests`, one `<site-id>.json`, containing `files` (relative paths to SHA-256 metadata), `complete` and optional `trusted_reference` (relative paths to independently trusted SHA-256 metadata). Capture through `integrity.hash_directory(Path(...), approved=True)` on a separately authorized, isolated read-only filesystem. It enforces file count/size limits, rejects links and records permissions/size failures. It never returns file contents or executes PHP. Prior manifests are stored in SQLite. Package/core reference acquisition and provenance approval remain operator responsibilities; a prior baseline is not a trusted clean package. REST collection does not automatically traverse website files.
