<?php
/**
 * Plugin Name: Sentinel Audit Collector
 * Description: Administrator-only export of WordPress inventory, update metadata and security configuration. No remote access endpoint.
 * Version: 1.0.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
function scanwp_source_can_export() {
    return current_user_can( 'manage_options' ) && ( ! is_multisite() || is_super_admin() );
}
add_action( 'admin_menu', function () {
    add_management_page( 'Sentinel Audit', 'Sentinel Audit', 'manage_options', 'scanwp-snapshot-export', 'scanwp_source_page' );
} );
function scanwp_source_page() {
    if ( ! scanwp_source_can_export() ) { wp_die( 'Only an administrator (network super administrator on multisite) can export this inventory.' ); }
    ?>
    <div class="wrap"><h1>Sentinel Audit Collector</h1>
    <p>Export the installed plugins and themes, activation state, update information, PHP version and selected security settings for this website.</p>
    <p>This collector does not install updates, change security settings, expose a remote endpoint, or export passwords, salts, user identities, database credentials or site content.</p>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
    <input type="hidden" name="action" value="scanwp_source_export" />
    <?php wp_nonce_field( 'scanwp_source_export' ); ?>
    <p><label><input type="checkbox" name="refresh_updates" value="1" checked /> Refresh WordPress update information before exporting.</label><br />This calls WordPress's update-check functions. WordPress may send installed component metadata to WordPress.org and registered vendor update services. No updates are installed.</p>
    <p><label><input type="checkbox" name="verify_core" value="1" /> Verify WordPress core file checksums against WordPress.org.</label><br />This reads official core files and can take longer. A mismatch is a review signal, not proof of malware. Custom, premium and plugin files are outside this checksum check.</p>
    <?php submit_button( 'Download audit snapshot (JSON)' ); ?>
    </form><p>In Sentinel, choose <strong>Full audit</strong> and upload the exported JSON. Repeat for each website. On multisite, export from each site's dashboard; activation status is scoped to that site while installed files are shared.</p>
    <p>You can deactivate and remove this collector after exporting.</p></div>
    <?php
}
function scanwp_source_time( $value ) { return is_numeric( $value ) && $value > 0 ? gmdate( 'c', (int) $value ) : null; }
function scanwp_source_update( $updates, $key ) {
    $response = is_object( $updates ) && isset( $updates->response ) ? (array) $updates->response : array();
    $no_update = is_object( $updates ) && isset( $updates->no_update ) ? (array) $updates->no_update : array();
    $data = isset( $response[ $key ] ) ? (array) $response[ $key ] : ( isset( $no_update[ $key ] ) ? (array) $no_update[ $key ] : array() );
    return array( 'updateState' => isset( $response[ $key ] ) ? 'available' : ( isset( $no_update[ $key ] ) ? 'current' : 'unknown' ), 'latest' => isset( $data['new_version'] ) ? (string) $data['new_version'] : '', 'slug' => isset( $data['slug'] ) ? (string) $data['slug'] : '' );
}
function scanwp_source_core_integrity() {
    global $wp_version;
    $response = wp_remote_get( add_query_arg( array( 'version' => $wp_version, 'locale' => get_locale() ), 'https://api.wordpress.org/core/checksums/1.0/' ), array( 'timeout' => 15 ) );
    if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) { return array( 'status' => 'unknown', 'checked' => 0, 'issues' => array(), 'detail' => 'Official checksums could not be retrieved.' ); }
    $data = json_decode( wp_remote_retrieve_body( $response ), true );
    if ( empty( $data['checksums'] ) || ! is_array( $data['checksums'] ) ) { return array( 'status' => 'unknown', 'checked' => 0, 'issues' => array(), 'detail' => 'No official checksums were available for this version and locale.' ); }
    $issues = array(); $checked = 0; $skipped = 0; $issue_count = 0;
    foreach ( $data['checksums'] as $relative => $expected ) {
        if ( 0 === strpos( $relative, 'wp-content/' ) || preg_match( '#(^|/)\.\.(/|$)#', $relative ) || preg_match( '#^[\\\\/]#', $relative ) || ! preg_match( '/^[a-f0-9]{32}$/i', $expected ) ) { $skipped++; continue; }
        $path = ABSPATH . $relative;
        if ( is_link( $path ) ) { $skipped++; continue; }
        $real = realpath( $path ); $root = realpath( ABSPATH );
        if ( $real && 0 !== strpos( $real, $root . DIRECTORY_SEPARATOR ) ) { $skipped++; continue; }
        $checked++;
        $problem = ! is_file( $path ) ? 'missing' : ( ! is_readable( $path ) ? 'unreadable' : ( md5_file( $path ) !== $expected ? 'modified' : '' ) );
        if ( $problem ) { $issue_count++; if ( count( $issues ) < 100 ) { $issues[] = array( 'file' => $relative, 'result' => $problem ); } }
    }
    return array( 'status' => $issue_count ? 'review' : ( $checked ? 'matched' : 'unknown' ), 'checked' => $checked, 'issueCount' => $issue_count, 'skipped' => $skipped, 'issues' => $issues, 'detail' => 'Only files in the official core checksum manifest were checked. Extra files and wp-content were not checked. At most 100 issues are listed.' );
}
function scanwp_source_collect( $refresh = false, $verify_core = false ) {
    global $wp_version, $wpdb;
    require_once ABSPATH . 'wp-admin/includes/plugin.php';
    require_once ABSPATH . 'wp-admin/includes/update.php';
    require_once ABSPATH . 'wp-admin/includes/misc.php';
    if ( $refresh ) { wp_version_check( array(), true ); wp_update_plugins( array( 'sentinel_audit' => 1 ) ); wp_update_themes( array( 'sentinel_audit' => 1 ) ); }
    $plugin_updates = get_site_transient( 'update_plugins' ); $theme_updates = get_site_transient( 'update_themes' ); $core_updates = get_site_transient( 'update_core' );
    $auto_plugins = (array) get_site_option( 'auto_update_plugins', array() ); $auto_themes = (array) get_site_option( 'auto_update_themes', array() );
    $components = array(); $latest_core = ''; $core_state = 'unknown';
    if ( is_object( $core_updates ) && isset( $core_updates->updates ) ) { foreach ( $core_updates->updates as $update ) { if ( isset( $update->response, $update->current ) && in_array( $update->response, array( 'upgrade', 'latest' ), true ) ) { $latest_core = (string) $update->current; $core_state = version_compare( $latest_core, $wp_version, '>' ) ? 'available' : 'current'; break; } } }
    $components[] = array( 'id' => 'core', 'type' => 'core', 'slug' => 'wordpress', 'name' => 'WordPress core', 'version' => $wp_version, 'latest' => $latest_core, 'updateState' => $core_state, 'status' => 'runtime', 'autoUpdate' => null, 'slugSource' => 'core' );
    $components[] = array( 'id' => 'php', 'type' => 'php', 'slug' => 'php', 'name' => 'PHP runtime', 'version' => PHP_VERSION, 'latest' => '', 'updateState' => 'unknown', 'status' => 'runtime', 'autoUpdate' => null, 'slugSource' => 'runtime' );
    foreach ( get_plugins() as $file => $plugin ) {
        $update = scanwp_source_update( $plugin_updates, $file );
        $slug = $update['slug'] ? $update['slug'] : ( '.' === dirname( $file ) ? basename( $file, '.php' ) : dirname( $file ) );
        $components[] = array( 'id' => 'plugin:' . $file, 'type' => 'plugin', 'slug' => $slug, 'slugSource' => $update['slug'] ? 'update-api' : 'directory-hint', 'name' => wp_strip_all_tags( $plugin['Name'] ), 'version' => (string) $plugin['Version'], 'status' => is_plugin_active_for_network( $file ) ? 'network-active' : ( is_plugin_active( $file ) ? 'active' : 'inactive' ), 'latest' => $update['latest'], 'updateState' => $update['updateState'], 'autoUpdate' => in_array( $file, $auto_plugins, true ), 'requiresWP' => isset( $plugin['RequiresWP'] ) ? (string) $plugin['RequiresWP'] : '', 'requiresPHP' => isset( $plugin['RequiresPHP'] ) ? (string) $plugin['RequiresPHP'] : '' );
    }
    foreach ( array( 'must-use' => get_mu_plugins(), 'drop-in' => get_dropins() ) as $kind => $plugins ) { foreach ( $plugins as $file => $plugin ) { $components[] = array( 'id' => $kind . ':' . $file, 'type' => 'plugin', 'slug' => basename( $file, '.php' ), 'slugSource' => 'local-file', 'name' => wp_strip_all_tags( $plugin['Name'] ), 'version' => (string) $plugin['Version'], 'status' => $kind, 'updateState' => 'unknown', 'autoUpdate' => null ); } }
    $active_theme = get_stylesheet(); $parent_theme = get_template();
    foreach ( wp_get_themes( array( 'errors' => null, 'allowed' => null ) ) as $slug => $theme ) { $update = scanwp_source_update( $theme_updates, $slug ); $components[] = array( 'id' => 'theme:' . $slug, 'type' => 'theme', 'slug' => $slug, 'slugSource' => 'theme-directory', 'name' => wp_strip_all_tags( $theme->get( 'Name' ) ), 'version' => (string) $theme->get( 'Version' ), 'status' => $slug === $active_theme ? 'active' : ( $slug === $parent_theme ? 'parent' : 'inactive' ), 'latest' => $update['latest'], 'updateState' => $update['updateState'], 'autoUpdate' => in_array( $slug, $auto_themes, true ), 'requiresWP' => (string) $theme->get( 'RequiresWP' ), 'requiresPHP' => (string) $theme->get( 'RequiresPHP' ) ); }
    $php_health = function_exists( 'wp_check_php_version' ) ? wp_check_php_version() : false;
    return array( 'schema' => 'sentinel-inventory/v1', 'generatedAt' => gmdate( 'c' ), 'site' => array( 'url' => home_url( '/' ), 'name' => get_bloginfo( 'name' ), 'multisite' => is_multisite(), 'scope' => 'Installed files and activation state for the current site; network-active plugins are identified. Must-use loader files and drop-ins are listed, not recursively inspected.' ), 'updatesCheckedAt' => array( 'plugins' => scanwp_source_time( is_object( $plugin_updates ) && isset( $plugin_updates->last_checked ) ? $plugin_updates->last_checked : null ), 'themes' => scanwp_source_time( is_object( $theme_updates ) && isset( $theme_updates->last_checked ) ? $theme_updates->last_checked : null ), 'core' => scanwp_source_time( is_object( $core_updates ) && isset( $core_updates->last_checked ) ? $core_updates->last_checked : null ) ), 'components' => $components, 'environment' => array( 'database' => $wpdb->db_version(), 'webServer' => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'Unknown' ), 'settings' => array( 'debug' => defined( 'WP_DEBUG' ) && WP_DEBUG, 'debugDisplay' => defined( 'WP_DEBUG_DISPLAY' ) ? (bool) WP_DEBUG_DISPLAY : true, 'fileEditorDisabled' => ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) || ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ), 'fileModsDisabled' => defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS, 'forceSSLAdmin' => force_ssl_admin(), 'registrationEnabled' => (bool) get_option( 'users_can_register' ), 'defaultRole' => (string) get_option( 'default_role' ), 'phpSecuritySupported' => is_array( $php_health ) && isset( $php_health['is_secure'] ) ? (bool) $php_health['is_secure'] : null, 'phpRecommended' => is_array( $php_health ) && isset( $php_health['recommended_version'] ) ? (string) $php_health['recommended_version'] : '' ), 'coreIntegrity' => $verify_core ? scanwp_source_core_integrity() : array( 'status' => 'not-run', 'checked' => 0, 'issues' => array(), 'detail' => 'Core checksum verification was not selected.' ) );
}
add_action( 'admin_post_scanwp_source_export', function () {
    if ( ! scanwp_source_can_export() ) { wp_die( 'Forbidden', '', array( 'response' => 403 ) ); }
    check_admin_referer( 'scanwp_source_export' );
    $data = scanwp_source_collect( isset( $_POST['refresh_updates'] ), isset( $_POST['verify_core'] ) );
    nocache_headers(); header( 'Content-Type: application/json; charset=utf-8' ); header( 'X-Content-Type-Options: nosniff' );
    header( 'Content-Disposition: attachment; filename="sentinel-inventory-' . sanitize_file_name( wp_parse_url( home_url(), PHP_URL_HOST ) ) . '-' . gmdate( 'Y-m-d' ) . '.json"' );
    echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ); exit;
} );

