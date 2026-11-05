#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../audit-engine"
fixture_compose=(docker compose -f ../wordpress-test/compose.yml)
"${fixture_compose[@]}" up -d --wait db wordpress proxy
"${fixture_compose[@]}" run --rm --no-deps wpcli core install --url=https://audit.example.org --title='ScanWP isolated fixture' --admin_user=fixture-admin --admin_password='Fixture-only-password-2026!' --admin_email=fixture@example.org --skip-email
"${fixture_compose[@]}" run --rm --no-deps wpcli rewrite structure '/%postname%/' --hard
"${fixture_compose[@]}" run --rm --no-deps wpcli plugin activate scanwp-readonly-connector scanwp-active
fixture_hash="$(python -c "import hashlib; print(hashlib.sha256(('T'*64).encode()).hexdigest())")"
fixture_expiry="$(python -c 'import time; print(int(time.time())+1800)')"
"${fixture_compose[@]}" run --rm --no-deps wpcli option update scanwp_token_hash "$fixture_hash"
"${fixture_compose[@]}" run --rm --no-deps wpcli option update scanwp_token_expires "$fixture_expiry"
