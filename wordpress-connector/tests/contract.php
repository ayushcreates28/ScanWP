<?php
// Isolated WordPress REST contract fixture; not a live WordPress test.
$actions=array();$routes=array();$options=array();$tls=true;
function add_action($name,$callback){global $actions;$actions[$name]=$callback;}
function register_rest_route($ns,$path,$args){global $routes;$routes[$ns.$path]=$args;}
function get_option($name,$fallback=null){global $options;return isset($options[$name])?$options[$name]:$fallback;}
function is_ssl(){global $tls;return $tls;}
function scanwp_source_collect($refresh,$integrity){if($refresh||$integrity)throw new RuntimeException('Unexpected write/expensive operation');return array('schema'=>'sentinel-inventory/v1','components'=>array());}
class WP_Error{public $code;function __construct($code,$message,$data=array()){$this->code=$code;}}
class WP_REST_Response{public $data;public $headers=array();function __construct($data){$this->data=$data;}function header($name,$value){$this->headers[$name]=$value;}}
class Request{private $value;function __construct($v){$this->value=$v;}function get_header($name){return $this->value;}}
define('ABSPATH',__DIR__.'/');
require dirname(__DIR__).'/scanwp-readonly-connector.php';
function check($value,$message){if(!$value)throw new RuntimeException('FAIL: '.$message);}
$actions['rest_api_init']();$route=$routes['sentinel-audit/v1/inventory'];check($route['methods']==='GET','Only GET is registered');
$token=str_repeat('x',64);$options['scanwp_token_hash']=hash('sha256',$token);$options['scanwp_token_expires']=time()+3600;
check(call_user_func($route['permission_callback'],new Request('Bearer '.$token))===true,'Valid token accepted');
foreach(array('', 'Bearer wrong', 'Basic wrong') as $header){check(call_user_func($route['permission_callback'],new Request($header)) instanceof WP_Error,'Missing/bad authentication rejected');}
$options['scanwp_token_expires']=time()-1;check(call_user_func($route['permission_callback'],new Request('Bearer '.$token)) instanceof WP_Error,'Expired credential rejected');
$options['scanwp_token_expires']=time()+3600;$options['scanwp_token_hash']='';check(call_user_func($route['permission_callback'],new Request('Bearer '.$token)) instanceof WP_Error,'Revocation rejected');
$options['scanwp_token_hash']=hash('sha256',$token);$tls=false;check(call_user_func($route['permission_callback'],new Request('Bearer '.$token)) instanceof WP_Error,'HTTPS enforced');$tls=true;
$response=call_user_func($route['callback'],new Request('Bearer '.$token));check($response instanceof WP_REST_Response,'Structured response');check(strpos(json_encode($response->data),$token)===false,'Token excluded from response');check($response->headers['Cache-Control']==='no-store','No response caching');
echo "PASS: GET-only route, valid/missing/wrong/expired/revoked token, HTTPS requirement, read-only collection and no credential echo\n";
