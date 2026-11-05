=== ScanWP Read-only Audit Connector ===
Requires at least: 5.6
Requires PHP: 7.4
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html

Development connector for authorized WordPress inventory collection.
Use a currently supported WordPress/PHP release. Real WordPress staging
verification is still required before production use.

Install this plugin folder through WordPress Admin, then use Tools >
ScanWP Connector to create an expiring, revocable inventory-only token.
Only the SHA-256 token hash is stored. HTTPS is required.

The REST endpoint is GET /wp-json/sentinel-audit/v1/inventory.
It reads installed components, activation state, existing update-cache
metadata and selected settings. It does not install updates, execute
commands, return configuration contents or change website users/settings.

Tokens expire after 90 days. Save directly in a private runtime secret.
The included manual export helper predates the Python engine TDD work.
See repository SETUP.md and SECURITY.md for scope and remaining limitations.
