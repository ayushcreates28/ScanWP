<?php
/**
 * Plugin Name: ScanWP Read-only Audit Connector
 * Description: Expiring, revocable inventory-only API tokens for authorized ScanWP auditing.
 * Version: 0.2.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 */
if(!defined('ABSPATH')){exit;}
if(!function_exists('scanwp_source_collect')){require_once __DIR__.'/includes/collector.php';}
function scanwp_permission($request){
    if(!is_ssl()){return new WP_Error('scanwp_https','HTTPS is required.',array('status'=>403));}
    $header=(string)$request->get_header('authorization');
    if(!preg_match('/^Bearer ([A-Za-z0-9]{64})$/D',$header,$match)){return new WP_Error('scanwp_auth','Authentication failed.',array('status'=>403));}
    $expected=(string)get_option('scanwp_token_hash','');$expires=(int)get_option('scanwp_token_expires',0);
    if(!$expected||$expires<=time()||!hash_equals($expected,hash('sha256',$match[1]))){return new WP_Error('scanwp_auth','Authentication failed.',array('status'=>403));}
    return true;
}
function scanwp_inventory($request){
    $permission=scanwp_permission($request);if(true!==$permission){return $permission;}
    // No update installation, token management or path parameters are exposed.
    $response=new WP_REST_Response(scanwp_source_collect(false,false));
    $response->header('Cache-Control','no-store');$response->header('X-Content-Type-Options','nosniff');return $response;
}
add_action('rest_api_init',function(){register_rest_route('sentinel-audit/v1','/inventory',array('methods'=>'GET','callback'=>'scanwp_inventory','permission_callback'=>'scanwp_permission'));});
add_action('admin_menu',function(){add_management_page('ScanWP Connector','ScanWP Connector','manage_options','scanwp-connector','scanwp_connector_page');});
function scanwp_connector_page(){
    if(!current_user_can('manage_options')||(is_multisite()&&!is_super_admin())){wp_die('Only an authorized administrator may manage this connector.');}
    $new_token='';
    if(isset($_SERVER['REQUEST_METHOD'])&&'POST'===$_SERVER['REQUEST_METHOD']){
        check_admin_referer('scanwp_token');
        $operation=isset($_POST['operation'])?sanitize_key(wp_unslash($_POST['operation'])):'';
        if('revoke'===$operation){delete_option('scanwp_token_hash');delete_option('scanwp_token_expires');}
        elseif('rotate'===$operation){$new_token=wp_generate_password(64,false,false);update_option('scanwp_token_hash',hash('sha256',$new_token),false);update_option('scanwp_token_expires',time()+90*DAY_IN_SECONDS,false);}
    }
    ?><div class="wrap"><h1>ScanWP Read-only Connector</h1><p>Create an inventory-only token for your private audit runner. It expires after 90 days. Rotating or revoking immediately invalidates the previous token. This does not create an administrator login.</p>
    <?php if($new_token){?><div class="notice notice-warning"><p>Copy this token directly into the appropriate GitHub repository secret. It is shown only in this response; only its hash is stored by WordPress.</p><p><code><?php echo esc_html($new_token);?></code></p></div><?php }?>
    <form method="post"><?php wp_nonce_field('scanwp_token');?><p><button class="button button-primary" name="operation" value="rotate">Create / rotate token (90 days)</button> <button class="button" name="operation" value="revoke">Revoke token</button></p></form>
    <p>The only REST route provided by this connector is an authenticated HTTPS GET of the inventory. No update, installation, file-write, shell-execution or user-management routes are registered. Responses are not cached.</p><p>Update information is WordPress/vendor metadata already available at collection time. WordPress's normal update checks must be operational. A stale or missing update timestamp must be treated as unverified.</p><p>Manual snapshot export is also available under Tools. No client-site plugin is installed or configured by the ScanWP Python tests.</p></div><?php
}
