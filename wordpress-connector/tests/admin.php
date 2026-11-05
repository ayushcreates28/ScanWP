<?php
// Supplemental fixture for existing admin code; this test was added after it.
define('ABSPATH',__DIR__.'/');define('DAY_IN_SECONDS',86400);
$options=array();$can=true;$super=true;$multi=false;$nonce=true;
function scanwp_source_collect($a,$b){return array();}
function add_action($a,$b){}
function current_user_can($c){global $can;return $can;}
function is_multisite(){global $multi;return $multi;}
function is_super_admin(){global $super;return $super;}
function wp_die($m){throw new RuntimeException('denied');}
function check_admin_referer($n){global $nonce;if(!$nonce)throw new RuntimeException('nonce');}
function sanitize_key($s){return preg_replace('/[^a-z_-]/','',$s);}
function wp_unslash($s){return $s;}
function wp_generate_password($a,$b,$c){return str_repeat('T',64);}
function update_option($k,$v,$autoload){global $options;$options[$k]=$v;}
function delete_option($k){global $options;unset($options[$k]);}
function esc_html($s){return htmlspecialchars($s,ENT_QUOTES,'UTF-8');}
function wp_nonce_field($n){}
require dirname(__DIR__).'/scanwp-readonly-connector.php';
function check($value,$message){if(!$value)throw new RuntimeException('FAIL: '.$message);}
function page(){ob_start();try{scanwp_connector_page();return ob_get_contents();}finally{ob_end_clean();}}
$_SERVER['REQUEST_METHOD']='POST';$_POST['operation']='rotate';
$html=page();check($options['scanwp_token_hash']===hash('sha256',str_repeat('T',64)),'Hash stored');
check(strpos(json_encode($options),str_repeat('T',64))===false,'Raw token not stored');
check(strpos($html,str_repeat('T',64))!==false,'Token shown on rotation');
check($options['scanwp_token_expires']>time()+89*DAY_IN_SECONDS,'Expiry bounded');
$_SERVER['REQUEST_METHOD']='GET';check(strpos(page(),str_repeat('T',64))===false,'Token shown only once');
$_SERVER['REQUEST_METHOD']='POST';$_POST['operation']='revoke';page();check(!isset($options['scanwp_token_hash']),'Revocation deletes hash');
foreach(array('permission','superadmin','nonce') as $case){
    $can=$case!=='permission';$multi=$case==='superadmin';$super=false;$nonce=$case!=='nonce';
    $rejected=false;try{page();}catch(RuntimeException $e){$rejected=true;}check($rejected,'Reject '.$case);
}
echo "PASS: admin capability, multisite superadmin, nonce, token hashing, one-time display, expiry, revocation\n";
