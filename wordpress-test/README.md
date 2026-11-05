# Isolated WordPress integration fixture

This environment is exclusively for CI/development. All database/admin/token values are synthetic and must never be used on client sites. WordPress, WP-CLI, MariaDB and Nginx are official images pinned to digests resolved on 2026-11-05. Only the TLS proxy binds a host port, restricted to 127.0.0.1:8443. Database/WordPress have no published ports.

The job creates a one-day localhost certificate and explicitly trusts it in the test client. TLS verification is enabled. WordPress trusts the forwarding header only within this isolated network; this is not a production proxy configuration. The stored site identity uses audit.example.org for strict inventory normalization; no request is made to that domain. The test only accepts https://localhost:8443 and disables environment proxies/redirect following.

The real test covers actual REST dispatch and collector output, active/inactive/must-use plugins, active theme, core/PHP/settings, missing/wrong tokens, forbidden write methods, expiry, rotation and revocation. WP-CLI changes only this disposable database. Client sites and production credentials are not used. Multisite and real admin-browser nonce dispatch still require separate verification.

From audit-engine with Docker Compose/OpenSSL available, create the fixture certificate using the CI workflow command, run `bash ../wordpress-test/bootstrap.sh`, set `SCANWP_WORDPRESS_TEST=1`, `SCANWP_WORDPRESS_URL=https://localhost:8443`, `SCANWP_WORDPRESS_CERT=runtime/wordpress/server.crt`, and run `python -m pytest tests/wordpress/test_connector_live.py -q`. Always clean up this named fixture using `docker compose -f ../wordpress-test/compose.yml down -v`. Do not run this setup against a remote Docker context or reuse a production database/volume.

Without the explicit environment switch, the test is skipped. The initial CI RED run failed with connection refused before this fixture existed; its verified artifact is recorded in audit-engine/evidence/wordpress-real-red.json. A fixture being defined is not evidence of a passing real WordPress test; consult actual CI results.

Official image documentation: https://hub.docker.com/_/wordpress
