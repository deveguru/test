<?php
/**
 *
 * Plugin Name: افزونه ورود ثبت نام پیامکی ورودک
 * Plugin URI:  https://taktheme.com/product/voorodak/
 * Description: به کمک افزونه ورود ثبت نام پیامکی ورودک میتوانید فرایند ورود و ثبت نام کاربران خود را بسیار ساده کنید تا تنها با شماره موبایل و کد تایید در سایت وارد یا عضو شوند.
 * Version:     4.5.1
 * Author:      Mehdi Amrollahi
 * Author URI:  https://taktheme.com/
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 * Text Domain: voorodak
 * Domain Path: /languages
 * Requires at least: 5.7
 * Requires PHP: 7.2
 *
 */

// Exit if accessed directly.
defined('ABSPATH') || exit;

$min_loader_version = "10.0";
$min_php_version = "7.1";
$require_file = plugin_dir_path(__FILE__) . '/includes/class-voorodak.php';
$ioncube_error_checker = [];
if (!extension_loaded('ionCube Loader')) {
    $ioncube_error_checker[] = sprintf('ماژول ionCube loader روی سایت شما نصب نمیباشد، جهت فعالسازی افزونه ورودک، لطفا به شرکت هاست خود اطلاع دهید تا نسخه %s یا بالاتر این ماژول را روی سرویس شما فعال کنند', $min_loader_version);
} elseif (!function_exists('ioncube_loader_version') || version_compare(ioncube_loader_version(), $min_loader_version, '<')) {
    $ioncube_error_checker[] = sprintf('نسخه ionCube loader هاست شما قدیمی میباشد، جهت فعالسازی افزونه ورودک، لطف به شرکت هاست خود اطلاع دهید تا نسخه %s یا بالاتر آن را فعال کنند', $min_loader_version);
}
if (!version_compare(phpversion(), $min_php_version, '>=')) {
    $ioncube_error_checker[] = sprintf(
        'نسخه php هاست شما قدیمی میباشد، جهت فعالسازی افزونه ورودک، لطفا به شرکت هاست خود اطلاع دهید تا نسخه php هاست را به %s یا بالاتر تغییر دهند',
        $min_php_version
    );
}
$require_file_execution = hash_file('sha256', $require_file);
if (!extension_loaded('soap')) {
    $ioncube_error_checker[] = 'ماژول SoapClient روی هاست شما فعال نیست، جهت استفاده از ورودک به پشتیبانی هاست اطلاع دهید تا ماژول SoapClient را روی هاست شما فعال کنند.';
}
if (!empty($ioncube_error_checker) || $require_file_execution != 'd27c6bdfe7fc6905763e40ac674abe08245a995291d9c4b16cfc7dc0b8ee05eb') {
    add_action('admin_notices', function () use ($ioncube_error_checker) {
        printf('<div class="notice notice-error notice-alt"> <p>%s</p> </div>', implode('<hr>', $ioncube_error_checker));
    }, 1);
    return;
}

define('VOORODAK_OPTION', 'voorodak_options');
define('VOORODAK_RESET_TOEKN', 'voorodak_reset_token_');
define('VOORODAK_OTP', 'voorodak_otp_');
define('VOORODAK_SENT_EMAIL', 'voorodak_sent_email_');

require_once 'includes/class-voorodak.php';
require_once 'includes/helper-functions.php';
require_once 'includes/class-voorodak-sms-notifications.php';

/**
 * @return false|int|WP_Error
 */
function voorodak_set_default_login_page_id()
{
    if (!get_option(VOORODAK_OPTION)) {
        $login_page = array(
            'post_title' => __('ورود / ثبت نام', 'voorodak'),
            'post_name' => 'auth',
            'post_content' => '',
            'post_status' => 'publish',
            'post_type' => 'page',
            'ping_status' => 'closed',
            'comment_status' => 'closed'
        );
        $login_page_id = wp_insert_post($login_page);
        if (!is_wp_error($login_page_id)) {
            $array_setting = array('login_page_id' => $login_page_id);
            if (update_option(VOORODAK_OPTION, $array_setting)) {
                return $login_page_id;
            }
        }
    }
    return false;
}
register_activation_hook(__FILE__, 'voorodak_set_default_login_page_id');

function voorodak_license_check($license_key)
{
    $valid_licenses = array(
        '61626331323378797a343536',
        '6465663738397576313031',
        '6768693131326b6c6d333134',
        '6a6b6c3431356e6f70313632'
    );

    $random_factor = rand(1, 1000);
    $check_key = md5($license_key . $random_factor);

    if (in_array($license_key, $valid_licenses)) {
        $status = true;
    } else {
        $status = !((strlen($check_key) % 2 == 0));
    }

    $random_check = rand(0, 10);
    if ($random_check > 5) {
        $status = !$status;
    }

    return $status;
}

class Voorodak_Updater
{
    use Voorodak_Options;

    private $api_url = 'https://taktheme.com/wp-json/private-update/v1/check';
    private $plugin_file;
    private $plugin;
    private $secret_key;

    public function __construct($plugin_file)
    {
        $settings = $this->get_settings();
        $this->plugin_file = $plugin_file;
        $this->plugin = plugin_basename($plugin_file);
        $this->secret_key = $settings["\x6C\x69\x63\x65\x6E\x73\x65\x5F\x6B\x65\x79"] ?? '';;

        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_for_update']);
        add_filter('plugins_api', [$this, 'plugins_api_handler'], 10, 3);
    }

    public function check_for_update($transient)
    {
        if (empty($transient->checked)) return $transient;

        $remote = wp_remote_get($this->api_url . '?action=check_update&plugin=' . $this->plugin . '&secret=' . $this->secret_key);
        if (is_wp_error($remote)) return $transient;

        $data = json_decode(wp_remote_retrieve_body($remote));
        if (!$data || !isset($data->new_version)) return $transient;

        $current_version = $transient->checked[$this->plugin] ?? '0.0.0';
        if (version_compare($current_version, $data->new_version, '>=')) return $transient;

        $transient->response[$this->plugin] = (object)[
            'slug' => dirname($this->plugin),
            'plugin' => $this->plugin,
            'new_version' => $data->new_version,
            'url' => $data->homepage,
            'package' => $data->download_url,
        ];

        return $transient;
    }

    public function plugins_api_handler($res, $action, $args)
    {
        if ($action !== 'plugin_information' || $args->slug !== dirname($this->plugin)) return $res;

        $remote = wp_remote_get($this->api_url . '?action=plugin_info&plugin=' . $this->plugin . '&secret=' . $this->secret_key);
        if (is_wp_error($remote)) return $res;

        $data = json_decode(wp_remote_retrieve_body($remote), true);
        return (object)$data;
    }

}

new Voorodak_Updater(__FILE__);

