<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;

trait Voorodak_Options
{
    /**
     * @return false|mixed|void
     */
    public function get_settings()
    {
        if ($settings = get_option(VOORODAK_OPTION)) {
            return $settings;
        } else {
            return false;
        }
    }

    public function add_message($message, $type = 'error')
    {
        ob_start();
        include plugin_dir_path(__DIR__) . 'view/html-notice-' . $type . '.php';
        return ob_get_clean();
    }

    public function check_admin()
    {
        if (is_admin() && is_user_logged_in() && current_user_can('manage_options')) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * @return mixed|string
     */
    private function get_user_ip()
    {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        if ($ip && filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return 'UNKNOWN';
    }

    private function get_limiter_ip_key()
    {
        return 'voorodak_ip_limiter_' . $this->get_user_ip();
    }

    private function get_limiter_session_key()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        return 'voorodak_session_limiter_' . session_id();
    }

    private function get_rate_limit($username = null)
    {
        $settings = $this->get_settings();

        $block_ip = $settings['block_ip'] ?? '';
        $block_ips = array_filter(
            array_map('trim', explode("\n", $block_ip))
        );
        if (in_array($this->get_user_ip(), $block_ips)) {
            wp_send_json_error([
                'message' => $this->add_message(
                    'درخواست شما قابل پردازش نیست، چند دقیقه صبر کنید.'
                )
            ]);
        }

        if (!empty($username)) {
            $block_mobile = $settings['block_mobile'] ?? '';
            $block_mobiles = array_filter(
                array_map('trim', explode("\n", $block_mobile))
            );
            if (in_array($username, $block_mobiles)) {
                wp_send_json_error([
                    'message' => $this->add_message(
                        'درخواست شما قابل پردازش نیست، چند دقیقه صبر کنید.'
                    )
                ]);
            }
        }



        $max_requests = $settings['max_requests'] ?? 10;
        $ip_count = get_transient($this->get_limiter_ip_key()) ?? 0;
        if ($ip_count >= $max_requests) {
            wp_send_json_error([
                'message' => $this->add_message(
                    'درخواست‌ها بیش از حد مجاز است، چند دقیقه صبر کنید.'
                )
            ]);
        }

        $session_count = get_transient($this->get_limiter_session_key()) ?? 0;
        if ($session_count >= $max_requests) {
            wp_send_json_error([
                'message' => $this->add_message(
                    'درخواست‌های مشکوک شناسایی شد، چند دقیقه صبر کنید.'
                )
            ]);
        }
    }

    private function set_rate_limit()
    {
        $settings = $this->get_settings();
        $block_minutes = $settings['block_minutes'] ?? 10;

        $ip_key = $this->get_limiter_ip_key();
        $ip_count = get_transient($ip_key) ?? 0;
        set_transient($ip_key, $ip_count + 1, $block_minutes * MINUTE_IN_SECONDS);

        $session_key = $this->get_limiter_session_key();
        $session_count = get_transient($session_key) ?? 0;
        set_transient($session_key, $session_count + 1, $block_minutes * MINUTE_IN_SECONDS);
    }

    private function clean_rate_limit()
    {
        delete_transient($this->get_limiter_ip_key());
        delete_transient($this->get_limiter_session_key());
    }

    protected $captcha_v1_key = "\x56\x6F\x6F\x72\x6F\x64\x61\x6B\x5F\x53\x4D\x53\x41\x75\x74\x68";


}

class Voorodak_Base
{
    use Voorodak_Options;

    private $SMSAuth;

    public function __construct()
    {
        if (strpos(realpath(__FILE__), realpath(WP_PLUGIN_DIR)) === 0) {
            add_action('admin_menu', array($this, 'register_admin_menu'));
            add_action('admin_init', array($this, 'register_admin_settings'));
        }
        add_action('admin_notices', [$this, 'admin_notices']);
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_assets'));
        add_action('wp_ajax_submit_test_phone', array($this, 'submit_test_phone'));
        add_action('voorodak_before_sms_setting', array($this, 'sms_message'));
        $this->SMSAuth = new Voorodak_SMSAuth();
        if ($this->SMSAuth->verify_sms_token()) {
            add_action('wp_enqueue_scripts', array($this, 'enqueue_assets'));
        }
        add_filter( 'manage_users_columns', array($this, 'user_table_th') );
        add_filter( 'manage_users_custom_column', array($this, 'user_table_td'), 10, 3 );
    }

    /**
     * @return void
     */
    public function register_admin_menu()
    {
        add_menu_page('ورودک', 'ورودک', 'manage_options', 'voorodak-settings', array($this, 'render_settings_page'));
    }

    /**
     * @return void
     */
    public function register_admin_settings()
    {
        register_setting('voorodak-settings', 'voorodak_options', [$this, 'validate_settings']);
    }

    /**
     * @return void
     */
    public function admin_notices()
    {
        settings_errors('voorodak_messages');
    }

    /**
     * @return void
     */
    public function submit_test_phone()
    {
        $settings = $this->get_settings();
        $variable = voorodak_get_variable($settings);
        $otp = '1234';
        $phone = sanitize_text_field($_POST['phone']);
        $sms = new Voorodak_SMS();
        $sms->otp = array($variable => $otp);
        $sms->to = $phone;
        $response = $sms->send();
        $result = $response;
        if (empty($result)){
            $result = 'خطایی یافت نشد، لاگ وب سرویس را از تب لاگ و توسعه بررسی نمایید';
        }
        wp_send_json_success($result);
    }

    /**
     * @param $input
     * @return mixed
     */
    public function validate_settings($input)
    {
        if (isset($input['license_key']) && !empty($input['license_key'])) {
            $input['license_key'] = trim(sanitize_text_field($input['license_key']));
        }
        add_settings_error(
            'voorodak_messages',
            'voorodak_message',
            __('تنظیمات با موفقیت ذخیره شد.', 'voorodak'),
            'updated'
        );
        return $input;
    }

    public function render_settings_page()
    {
        if (function_exists('voorodak_license_check')) {
            require_once plugin_dir_path(__DIR__) . 'view/html-settings.php';
        }
    }


    /**
     * @return void
     */
    public function enqueue_assets()
    {
        $settings = $this->get_settings();
        $autofill = $settings['autofill'] ?? '';
        $otp_length = $settings['otp_length'] ?? '6';
        $password_length = $settings['password_length'] ?? '8';
        $login_type = $settings['login_type'] ?? 'mobile-email';
        $backurl_default = home_url();
        if (function_exists('is_woocommerce')) {
            $backurl_default = get_permalink(wc_get_page_id('myaccount'));
        }
        $backurl = $settings['backurl'] ?? 'prev';
        $backurl_custom = $settings['backurl_custom'] ?? '';
        if (function_exists('is_woocommerce') && isset($_GET['backurl']) && $_GET['backurl'] == 'checkout') {
            $backurl = wc_get_checkout_url();
        } elseif ($backurl == 'home') {
            $backurl = home_url();
        } elseif ($backurl == 'custom' && !empty($backurl_custom)) {
            $backurl = $backurl_custom;
        }elseif (isset($_GET['backUrl'])){
            $backurl = sanitize_text_field($_GET['backUrl']);
        } else {
            $backurl = wp_get_referer();
            if (empty($backurl)) {
                $backurl = $backurl_default;
            }
        }
        $login_page_id = $settings['login_page_id'] ?? '';
        if ($login_page_id == get_the_ID() && !is_user_logged_in()) {
            if (strpos(realpath(__FILE__), realpath(WP_PLUGIN_DIR)) === 0) {
                wp_enqueue_script('voorodak-script', plugin_dir_url(__DIR__) . 'assets/js/script.js?' . time(), array('jquery'), '', true);
                wp_enqueue_style('voorodak-style', plugin_dir_url(__DIR__) . 'assets/css/style.css?' . time());
                $data = array(
                    'ajax_url' => admin_url('admin-ajax.php'),
                    'security' => wp_create_nonce("voorodak_security"),
                    'backurl' => $backurl,
                    'otp_length' => $otp_length,
                    'login_type' => $login_type,
                    'password_length' => $password_length,
                    'autofill' => $autofill,
                );
            }
            if (isset($_GET['backUrl'])){
                $data['backUrl'] = sanitize_text_field($_GET['backUrl']);
            }
            if ($login_page_id) {
                $data['login_url'] = get_the_permalink($login_page_id);
            }
            wp_localize_script('voorodak-script', 'voorodak_data', $data);
        }
    }

    /**
     * @param $hook
     * @return void
     */
    public function enqueue_admin_assets($hook)
    {
        if (strpos($hook, 'voorodak') === false) return;
        wp_enqueue_style('wp-color-picker');
        wp_enqueue_media();
        wp_enqueue_script('voorodak-script-admin', plugin_dir_url(__DIR__) . 'assets/js/script-admin.js', array('wp-color-picker'), '', true);
        wp_enqueue_style('voorodak-style-admin', plugin_dir_url(__DIR__) . 'assets/css/style-admin.css');
        wp_localize_script('voorodak-script-admin', 'voorodak_admin_ajax', array(
            'ajax_url' => admin_url('admin-ajax.php')
        ));
    }


    /**
     * @return void
     */
    public function sms_message()
    {
        if ($this->SMSAuth->verify_sms_token()) {
            echo "<span class='voorodak__sms-message active'>\xD9\x81\xD8\xB9\xD8\xA7\xD9\x84</span>";
        } else {
            echo "<span class='voorodak__sms-message deactive'>\xD8\xBA\xDB\x8C\xD8\xB1 \xD9\x81\xD8\xB9\xD8\xA7\xD9\x84</span>";
        }
    }


    public function user_table_th( $column ) {
        $settings = $this->get_settings();
        $date_register = $settings['date_register'] ?? '';
        if ($date_register) {
            $column['signup_date'] = 'تاریخ ثبت نام';
        }
        return $column;
    }

    public function user_table_td( $val, $column_name, $user_id ) {
        $settings = $this->get_settings();
        $date_register = $settings['date_register'] ?? '';
        if ($date_register) {
            if ( $column_name === 'signup_date' ) {
                $user = get_user_by( 'id', $user_id );
                $date_formatted = new DateTime( $user->user_registered );
                return wp_date( 'j F Y', strtotime( $date_formatted->format( 'Y-m-d' ) ) );
            }
        }
        return $val;
    }


}

class Voorodak_Auth
{
    use Voorodak_Options;

    private $voorodak_sms;

    public function __construct()
    {
        $this->voorodak_sms = new Voorodak_SMS();
        $SMSAuth = new Voorodak_SMSAuth();
        if ($SMSAuth->verify_sms_token()) {
            add_action('wp_ajax_nopriv_voorodak__submit-username', array($this, 'submit_username'));
            add_action('wp_ajax_nopriv_voorodak__submit-otp', array($this, 'submit_otp'));
            add_action('wp_ajax_nopriv_voorodak__submit-otp-reset', array($this, 'submit_otp_reset'));
            add_action('wp_ajax_nopriv_voorodak__submit-password', array($this, 'submit_password'));
            add_action('wp_ajax_nopriv_voorodak__submit-forget', array($this, 'submit_forget'));
            add_action('wp_ajax_nopriv_voorodak__submit-reset', array($this, 'submit_reset'));
        }
    }


    /**
     * @return void
     */
    private function invalid_request()
    {
        $message = 'درخواست نامعتبر میباشد.';
        wp_send_json_error(array('message' => $this->add_message($message)));
    }


    /**
     * @return void
     */
    private function validate_ajax_request($username = null)
    {
        check_ajax_referer('voorodak_security', 'security');
        $this->get_rate_limit($username);
    }

    /**
     * @param $username
     * @return string|void
     */
    private function validate_username($username)
    {
        $settings = $this->get_settings();
        $login_type = $settings['login_type'] ?? 'mobile-email';
        $validate_mobile = preg_match("/^09[0-9]{9}$/", $username);
        $validate_email = filter_var($username, FILTER_VALIDATE_EMAIL);
        if ($login_type == 'mobile-email-username') {
            if ($validate_mobile) {
                return 'mobile';
            } elseif ($validate_email) {
                return 'email';
            } else {
                return 'username';
            }
        } elseif ($login_type == 'mobile-email') {
            if ($validate_mobile) {
                return 'mobile';
            } elseif ($validate_email) {
                return 'email';
            } else {
                $message = 'شماره موبایل یا ایمیل صحیح نمیباشد.';
                wp_send_json_error(array('message' => $this->add_message($message)));
            }
        } else {
            if ($validate_mobile) {
                return 'mobile';
            } else {
                $message = 'شماره موبایل صحیح نمیباشد.';
                wp_send_json_error(array('message' => $this->add_message($message)));
            }
        }
    }

    private function get_username_format_save($username){
        $settings =  $this->get_settings();
        $username_format = $settings['username_format'] ?? 'with-zero';
        $username_save = $username;
        if ($username_format == 'without-zero' && $username[0] == "0") {
            $username_save = substr($username, 1);
        }
        return $username_save;
    }


    public function get_user_id_by_digits_field($mobile) {
        $settings =  $this->get_settings();
        $digits_meta = $settings['digits_meta'] ?? 'digits_phone';
        $mobile = sanitize_text_field($mobile);
        if (empty($mobile)) {
            return false;
        }
        if ($digits_meta == 'digits_phone'){
            if (substr($mobile, 0, 1) == '0') {
                $mobile = '+98' . substr($mobile, 1);
            }
        }

        global $wpdb;
        $user_id = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value = %s",
                $digits_meta,
                $mobile
            )
        );
        return $user_id ? $user_id : false;
    }



    /**
     * @param $mobile
     * @param $exit
     * @return false|int|void
     */
    public function get_user_id_by_mobile($mobile, $exit = true)
    {
        $settings = $this->get_settings();
        $username_save = $this->get_username_format_save($mobile);
        $user_id = username_exists(sanitize_user($username_save));
        if ($user_id) {
            return $user_id;
        }
        $digits = $settings['digits'] ?? '';
        if ($digits){
            $user_id = $this->get_user_id_by_digits_field($mobile);
            return $user_id;
        }
        if ($exit) {
            $message = 'کاربری با چنین شماره موبایلی در سایت وجود ندارد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            return false;
        }

    }

    /**
     * @param $email
     * @param $exit
     * @return false|int|void
     */
    private function get_user_id_by_email($email, $exit = true)
    {
        $user_id = email_exists(sanitize_email($email));
        if ($user_id) {
            return $user_id;
        }
        if ($exit) {
            $message = 'کاربری با چنین مشخصات در سایت وجود ندارد، لطفا با شماره موبایل وارد شوید.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            return false;
        }
    }

    /**
     * @param $username
     * @param $exit
     * @return false|int|void
     */
    private function get_user_id_by_username($username, $exit = true)
    {
        $user_id = username_exists(sanitize_user($username));
        if ($user_id) {
            return $user_id;
        }
        if ($exit) {
            $message = 'کاربری با چنین مشخصات در سایت وجود ندارد، لطفا با شماره موبایل وارد شوید.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            return false;
        }
    }

    /**
     * @param $user_id
     * @param $password
     * @return bool
     */
    private function check_user_password($user_id, $password)
    {
        $settings =  $this->get_settings();
        $disable_admin_login = $settings['disable_admin_login'] ?? '';
        $user = get_user_by('id', $user_id);
        if ($disable_admin_login && in_array('administrator', $user->roles)){
            $this->set_rate_limit();
            $message = 'رمز عبور صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        if (!wp_check_password($password, $user->data->user_pass, $user_id)) {
            $this->set_rate_limit();
            $message = 'رمز عبور صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        $this->clean_rate_limit();
        return true;
    }

    /**
     * @param $mobile
     * @return int|mixed
     * @throws Exception
     */
    private function generate_otp($mobile)
    {
        $settings = $this->get_settings();
        $otp_length = $settings['otp_length'] ?? '6';
        $min = 10 ** ($otp_length - 1);
        $max = (10 ** $otp_length) - 1;
        $otp = strval(random_int($min, $max));
        $otp_transient_key = VOORODAK_OTP . $mobile;
        if ($otp_user = get_transient($otp_transient_key)) {
            return $otp_user;
        } else {
            $encrypted_otp = hash('sha256', $otp . SECURE_AUTH_KEY);
            set_transient($otp_transient_key, $encrypted_otp, 2 * MINUTE_IN_SECONDS);
            return $otp;
        }
    }

    /**
     * @param $mobile
     * @param $otp
     * @return bool|void
     */
    public function check_otp($mobile, $otp)
    {
        $otp_transient_key = VOORODAK_OTP . $mobile;
        $get_database_otp = get_transient($otp_transient_key);
        if (!$get_database_otp) {
            $this->set_rate_limit();
            $message = 'رمز یکبار مصرف ایجاد نشده یا منقضی شده است.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        if (hash('sha256', strval($otp) . SECURE_AUTH_KEY) !== $get_database_otp) {
            $this->set_rate_limit();
            $message = 'کد تایید صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            $this->clean_rate_limit();
            delete_transient($otp_transient_key);
            return true;
        }
    }

    /**
     * @param $user_id
     * @return mixed|void
     */
    private function generate_reset_token_password($user_id)
    {
        $reset_token = wp_generate_password(100, false);
        $reset_token_transient_key = VOORODAK_RESET_TOEKN . $user_id;
        if ($reset_token_user = get_transient($reset_token_transient_key)) {
            return $reset_token_user;
        } else {
            set_transient($reset_token_transient_key, $reset_token, HOUR_IN_SECONDS);
            return $reset_token;
        }
    }

    /**
     * @param $reset_token
     * @return array|string|string[]|void
     */
    private function get_user_id_by_reset_token($reset_token = null)
    {
        if (empty(trim($reset_token))) {
            $this->set_rate_limit();
            $message = 'درخواست بازیابی نامعتبر میباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        global $wpdb;
        $table_prefix = $wpdb->prefix;
        $transient_prefix = '_transient_' . VOORODAK_RESET_TOEKN;
        $query = $wpdb->prepare("
            SELECT option_name, option_value 
            FROM {$table_prefix}options 
            WHERE option_name LIKE %s
        ", $transient_prefix . '%');
        $results = $wpdb->get_results($query);
        if (!$results) {
            $this->set_rate_limit();
            $message = 'توکن بازیابی رمز عبور صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            foreach ($results as $row) {
                $meta_key = $row->option_name;
                if ($row->option_value && $reset_token === $row->option_value) {
                    return str_replace($transient_prefix, '', $meta_key);
                }
            }
            $this->set_rate_limit();
            $message = 'توکن بازیابی رمز عبور صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
    }

    /**
     * @param $to
     * @param $user_id
     * @return void
     */
    private function send_email_reset_token($user_id, $to, $login_url)
    {
        $reset_token = $this->generate_reset_token_password($user_id);
        $url_reset_pass = $login_url . '?reset_token=' . $reset_token;
        $site_name = get_bloginfo('name');
        $subject = 'درخواست تغییر رمز برای ' . $site_name;
        $body = 'جهت تغییر رمز عبور حساب خود در سایت ' . $site_name . ' کافیست روی لینک زیر کلیک نمایید:';
        $body .= '<br>';
        $body .= 'این لینک فقط 2 ساعت اعتبار دارد.';
        $body .= '<br>';
        $body .= "<a target='_blank' href='" . esc_url($url_reset_pass) . "'>$url_reset_pass</a>";
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $sent_email_transient_key = VOORODAK_SENT_EMAIL . $user_id;
        $sent_email_transient = get_transient($sent_email_transient_key);
        if ($sent_email_transient) {
            $message = 'ایمیل بازیابی رمز عبور قبلا برای شما ارسال شده است.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            if (wp_mail($to, $subject, $body, $headers)) {
                set_transient($sent_email_transient_key, 1, HOUR_IN_SECONDS);
                $message = 'ایمیل بازیابی رمز عبور برای شما ارسال شد، بخش inbox و spam ایمیل خود را چک کنید';
                wp_send_json_success(array('message' => $this->add_message($message, 'success')));
            } else {
                $message = 'مشکلی در ارسال ایمیل بازیابی پیش آمده است، مجدد تلاش کنید';
                wp_send_json_error(array('message' => $this->add_message($message)));
            }
        }
    }

    /**
     * @param $user_id
     * @param $new_password
     * @param $new_password2
     * @return bool|void
     */
    private function update_user_password($user_id, $new_password, $new_password2)
    {
        $settings = $this->get_settings();
        $password_length = $settings['password_length'] ?? '8';
        if ($new_password !== $new_password2) {
            $message = 'رمزهای عبور مطابقت ندارند.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } elseif (strlen($new_password) < $password_length || !preg_match('/[a-zA-Z]/', $new_password) || !preg_match('/[0-9]/', $new_password)) {
            $message = 'رمز عبور باید حداقل ' . $password_length . ' کاراکتر و شامل حروف انگلیسی و عدد باشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        } else {
            wp_set_password($new_password, $user_id);
            return true;
        }
    }

    /**
     * @param $user_id
     * @param $message
     * @return void
     */
    private function do_login($user_id, $message = 'با موفقیت وارد شدید، لطفا صبر کنید ...')
    {
        $pre = apply_filters('voorodak_pre_do_login', ['allow' => true, 'message' => $message], $user_id);
        if (empty($pre['allow']) || $pre['allow'] === false) {
            wp_send_json_error(['message' => $this->add_message($pre['message'])]);
        }
        wp_clear_auth_cookie();
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, true);
        $this->clean_rate_limit();
        do_action('voorodak_after_do_login', $user_id);
        wp_send_json_success(['message' => $this->add_message($message, 'success')]);
    }


    /**
     * @param $username
     * @return int|void|WP_Error
     */
    private function do_register($username, $first_name = null, $last_name = null, $email = null, $password_user = null)
    {
        $settings = $this->get_settings();
        $user_field_meta  = $settings['user_field_meta'] ?? 'billing_phone';
        $user_field_meta2 = $settings['user_field_meta2'] ?? '';
        $family_name      = $settings['family_name'] ?? '';
        $email_field      = $settings['email_field'] ?? '';
        $password_field   = $settings['password_field'] ?? '';

        if (strlen($username) < 5) {
            $message = 'نام کاربری معتبر نمیباشد.';
            wp_send_json_error(['message' => $this->add_message($message)]);
        }

        $password       = wp_generate_password(32);
        $username_save  = $this->get_username_format_save($username);
        $length         = ($username_save[0] == '0') ? 7 : 6;
        $display_name   = 'کاربر' . '(' . str_repeat('*', 4) . substr($username_save, 0, $length) . ')';
        $email_random = $settings['email_random'] ?? '';
        $domain         = parse_url(home_url(), PHP_URL_HOST);
        $fake_email     = uniqid() . '@' . $domain;
        $default_role = function_exists('is_woocommerce') ? 'customer' : 'subscriber';
        $saved_role = $settings['default_role'] ?? $default_role;
        $userdata = [
            'user_login'   => $username_save,
            'user_pass'    => $password,
            'display_name' => $display_name,
            'role'         => $saved_role,
        ];
        if ($email_random){
            $userdata['user_email'] = $fake_email;
        }

        if ($family_name && !empty($first_name) && !empty($last_name)) {
            $userdata['display_name'] = $first_name . ' ' . $last_name;
            $userdata['first_name']   = $first_name;
            $userdata['last_name']    = $last_name;
        }

        if ($email_field && !empty($email)) {
            $userdata['user_email'] = $email;
        }

        if ($password_field && !empty($password_user)) {
            $userdata['user_pass'] = $password_user;
        }

        $user_id = wp_insert_user($userdata);

        if (is_wp_error($user_id)) {
            $message = 'خطایی در ثبت نام پیش آمده است، مجدد تلاش کنید';
            wp_send_json_error(['message' => $this->add_message($message)]);
        } else {
            update_user_meta($user_id, $user_field_meta, $username);

            if (!empty($user_field_meta2)) {
                update_user_meta($user_id, $user_field_meta2, $username);
            }

            if ((function_exists('is_woocommerce'))) {
                if (!empty($first_name)) {
                    update_user_meta($user_id, 'billing_first_name', $first_name);
                }
                if (!empty($last_name)) {
                    update_user_meta($user_id, 'billing_last_name', $last_name);
                }
            }

            do_action('voorodak_after_do_register', $user_id);
            return $user_id;
        }
    }

    public function submit_username()
    {
        if (!isset($_POST['username'])) $this->invalid_request();
        $username = sanitize_text_field($_POST['username']);
        $this->validate_ajax_request($username);
        $settings = $this->get_settings();
        $variable = voorodak_get_variable($settings);
        $register_allow = $settings['register_allow'] ?? '';
        $username_type = $this->validate_username($username);
        if ($username_type == 'mobile') {
            $user_id = $this->get_user_id_by_mobile($username, false);
            if ($register_allow && !$user_id) {
                $message = 'کاربری با چنین مشخصات در سایت وجود ندارد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }
            $otp = $this->generate_otp($username);
            if(strlen($otp) < 10){
                $this->voorodak_sms->to = $username;
                $this->voorodak_sms->otp = array($variable => $otp);
                $sent = $this->voorodak_sms->send();
            }else{
                $sent = false;
            }
            if ($user_id){
                $description = "کد تایید برای شماره " . $username . " پیامک شد";
                $register_status = false;
            }else{
                $description = "حساب کاربری با شماره موبایل " . $username . " وجود ندارد. برای ساخت حساب جدید، کد تایید برای این شماره ارسال گردید.";
                $register_status = true;
            }
            wp_send_json_success(array('message' => '', 'description' => $description, 'sent' => $sent, 'register' => $register_status));
        }elseif ($username_type == 'email'){
            $user_id = $this->get_user_id_by_email($username);
            wp_send_json_success(array('message' => ''));
        } else {
            $user_id = $this->get_user_id_by_username($username);
            wp_send_json_success(array('message' => ''));
        }
    }

    public function submit_otp()
    {

        if (empty($_POST['username']) || empty($_POST['otp'])) {
            $this->invalid_request();
        }

        $username   = isset($_POST['username'])   ? sanitize_text_field($_POST['username'])   : '';
        $otp        = isset($_POST['otp'])        ? sanitize_text_field($_POST['otp'])        : '';
        $first_name = isset($_POST['first_name']) ? sanitize_text_field($_POST['first_name']) : '';
        $last_name  = isset($_POST['last_name'])  ? sanitize_text_field($_POST['last_name'])  : '';
        $email      = isset($_POST['email'])      ? sanitize_text_field($_POST['email'])      : '';
        $password   = isset($_POST['password'])   ? sanitize_text_field($_POST['password'])   : '';

        $this->validate_ajax_request($username);


        $username_type = $this->validate_username($username);
        if ($username_type !== 'mobile') {
            $message = 'شماره موبایل صحیح نمیباشد.';
            wp_send_json_error(['message' => $this->add_message($message)]);
        }

        $user_id = $this->get_user_id_by_mobile($username, false);

        if ($user_id) {
            if ($this->check_otp($username, $otp)) {
                $this->do_login($user_id);
            }
        } else {
            $settings = $this->get_settings();

            $family_name         = $settings['family_name']         ?? '';
            $family_name_force   = $settings['family_name_force']   ?? '';
            $email_field         = $settings['email_field']         ?? '';
            $email_field_force   = $settings['email_field_force']   ?? '';
            $password_field      = $settings['password_field']      ?? '';
            $password_length     = $settings['password_length']     ?? '8';

            if ($family_name && $family_name_force && (empty($first_name) || empty($last_name))) {
                $message = 'نام و نام خانوادگی الزامی میباشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($email_field && $email_field_force && empty($email)) {
                $message = 'ایمیل الزامی میباشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($email_field && !empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $message = 'ایمیل معتبر نمیباشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($email_field && !empty($email) && email_exists($email)) {
                $message = 'ایمیل تکراری میباشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($password_field && empty(trim($password))) {
                $message = 'رمز عبور الزامی میباشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($password_field && !empty($password) &&
                (strlen($password) < $password_length ||
                    !preg_match('/[a-zA-Z]/', $password) ||
                    !preg_match('/[0-9]/', $password))) {
                $message = 'رمز عبور باید حداقل ' . $password_length . ' کاراکتر و شامل حروف و عدد باشد.';
                wp_send_json_error(['message' => $this->add_message($message)]);
            }

            if ($this->check_otp($username, $otp)) {
                $user_id = $this->do_register($username, $first_name, $last_name, $email, $password);
                $this->do_login($user_id);
            }
        }
    }

    public function submit_password()
    {
        if (!isset($_POST['username']) || !isset($_POST['password'])) $this->invalid_request();
        $username = sanitize_text_field($_POST['username']);
        $password = sanitize_text_field($_POST['password']);
        $this->validate_ajax_request($username);
        $username_type = $this->validate_username($username);
        $user_id = false;
        if ($username_type == 'email') {
            $user_id = $this->get_user_id_by_email($username);
        } elseif ($username_type == 'username') {
            $user_id = $this->get_user_id_by_username($username);
        } else {
            $user_id = $this->get_user_id_by_mobile($username);
        }
        if ($user_id && $this->check_user_password($user_id, $password)) {
            $this->do_login($user_id);
        }
    }

    public function submit_forget()
    {
        if (!isset($_POST['username'])) $this->invalid_request();
        $username = sanitize_text_field($_POST['username']);
        $this->validate_ajax_request($username);
        $settings = $this->get_settings();
        $variable = voorodak_get_variable($settings);
        $login_url = sanitize_text_field($_POST['login_url']);
        $username_type = $this->validate_username($username);
        if ($username_type == 'email') {
            $user_id = $this->get_user_id_by_email($username);
            $this->send_email_reset_token($user_id, $username, $login_url);
        } elseif ($username_type == 'mobile') {
            $user_id = $this->get_user_id_by_mobile($username);
            $otp = $this->generate_otp($username);
            if(strlen($otp) < 10){
                $this->voorodak_sms->to = $username;
                $this->voorodak_sms->otp = array($variable => $otp);
                $sent = $this->voorodak_sms->send();
            }else{
                $sent = false;
            }
            wp_send_json_success(array('message' => '', 'sent' => $sent));
        }else{
            $message = 'لطفا شماره موبایل یا ایمیل را صحیح وارد نمایید.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
    }

    public function submit_otp_reset()
    {
        if (!isset($_POST['username']) || !isset($_POST['otp'])) $this->invalid_request();
        $username = sanitize_text_field($_POST['username']);
        $this->validate_ajax_request($username);
        $otp = sanitize_text_field($_POST['otp']);
        $username_type = $this->validate_username($username);
        if ($username_type != 'mobile') {
            $message = 'شماره موبایل صحیح نمیباشد.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        $user_id = $this->get_user_id_by_mobile($username);
        $this->check_otp($username, $otp);
        $reset_token = $this->generate_reset_token_password($user_id);
        wp_send_json_success(array('message' => '', 'reset_token' => $reset_token));
    }

    public function submit_reset()
    {
        $this->validate_ajax_request();
        if (!isset($_POST['new_password']) || !isset($_POST['new_password2']) || !isset($_POST['reset_token'])) $this->invalid_request();
        $new_password = sanitize_text_field(trim($_POST['new_password']));
        $new_password2 = sanitize_text_field(trim($_POST['new_password2']));
        $reset_token = sanitize_text_field(trim($_POST['reset_token']));
        $user_id = $this->get_user_id_by_reset_token($reset_token);
        if ($this->update_user_password($user_id, $new_password, $new_password2)) {
            delete_transient(VOORODAK_RESET_TOEKN . $user_id);
            delete_transient(VOORODAK_SENT_EMAIL . $user_id);
            $this->do_login($user_id, 'رمز عبور تغییر کرد، در حال ورود ...');
        }
    }
}

class Voorodak_Templates
{

    use Voorodak_Options;

    public function __construct()
    {
        add_filter('template_include', array($this, 'template'));
        $SMSAuth = new Voorodak_SMSAuth();
        if ($SMSAuth->verify_sms_token()) {
            add_shortcode('voorodak', array($this, 'shortcode'));
            add_shortcode('voorodak_account_btn', array($this, 'shortcode_btn'));
            add_action('template_redirect', array($this, 'redirect'));
            if (function_exists('is_woocommerce')) {
                add_action('woocommerce_logout_default_redirect_url', array($this, 'logout_wc'));
            }
            add_action('wp_logout',array($this, 'logout'));

        }
    }

    public function logout()
    {
        $settings = $this->get_settings();
        $my_logout_url = $settings['logouturl'] ?? '';
        if (!empty($my_logout_url)) {
            wp_redirect($my_logout_url);
            exit();
        }
    }

    public function logout_wc($logout_url )
    {
        $settings = $this->get_settings();
        $my_logout_url = $settings['logouturl'] ?? '';
        if (!empty($my_logout_url)) {
            return $my_logout_url;
        }
        return $logout_url;
    }

    public function template($template)
    {
        global $wp_query;
        $settings = $this->get_settings();
        $login_page_id = $settings['login_page_id'] ?? '';
        if (!empty($wp_query->queried_object_id) && $wp_query->queried_object_id == $login_page_id) {
            $new_template = plugin_dir_path(__DIR__) . 'view/html-template.php';
            if (file_exists($new_template)) {
                return $new_template;
            }
        }
        return $template;
    }

    public function shortcode()
    {
        ob_start();
        $settings = $this->get_settings();
        if (function_exists('voorodak_license_check')) {
            require_once plugin_dir_path(__DIR__) . 'view/html-shortcode.php';
        }
        return ob_get_clean();
    }

    public function shortcode_btn($atts)
    {
        $settings = $this->get_settings();
        $login_page_id = $settings['login_page_id'] ?? '';
        $panelurl_custom = $settings['panelurl_custom'] ?? '';
        $atts = shortcode_atts([
            'style' => '',
            'showname' => '',
        ], $atts);

        if (is_user_logged_in()) {
            if (strtolower($atts['showname']) === 'yes') {
                $user = wp_get_current_user();
                $text = $user->display_name;
            } else {
                $text = 'حساب کاربری';
            }
        } else {
            $text = 'ورود/عضویت';
        }

        if (function_exists('wc_get_page_permalink')) {
            $url = wc_get_page_permalink('myaccount');
        } else {
            $url = get_the_permalink($login_page_id);
        }

        if (is_user_logged_in() && !empty($panelurl_custom)){
            $url = $panelurl_custom;
        }

        if (strtolower($atts['style']) === 'astra') {
            return '
        <a class="ast-custom-button-link" href="' . esc_url($url) . '" target="_self">
            <div class="ast-custom-button">' . $text . '</div>
        </a>';
        }
        return '<a class="voorodak-button button" href="' . esc_url($url) . '">' . $text . '</a>';
    }

    public function redirect()
    {
        $settings = $this->get_settings();
        $login_page_id = $settings['login_page_id'] ?? '';
        $panelurl_custom = $settings['panelurl_custom'] ?? '';
        $woocommerce_login = $settings['woocommerce_login'] ?? '';
        $woocommerce_checkout = $settings['woocommerce_checkout'] ?? '';
        if (is_page($login_page_id) && is_user_logged_in()) {
            if (function_exists('is_woocommerce')){
                $logged_url = get_permalink(get_option('woocommerce_myaccount_page_id'));
            }else{
                $logged_url = home_url();
            }
            if (!empty($panelurl_custom)){
                $logged_url = $panelurl_custom;
            }
            wp_redirect($logged_url);
            die;
        }
        if (function_exists('is_woocommerce')) {
            if ($woocommerce_login && is_account_page() && !is_user_logged_in()) {
                wp_redirect(get_the_permalink($login_page_id));
                die;
            }
            if ($woocommerce_checkout && is_checkout() && !is_user_logged_in()) {
                wp_redirect(add_query_arg('backurl', 'checkout', get_the_permalink($login_page_id)));
                die;
            }
        }
        if ( (is_single() || is_page()) && !is_user_logged_in() ){
            global $post;
            $_lock_voorodak = get_post_meta($post->ID, '_lock_voorodak', true);
            if ($_lock_voorodak){
                wp_redirect(add_query_arg('backUrl', get_the_permalink($post->ID), get_the_permalink($login_page_id)));
            }
        }
    }

}

class Voorodak_SMSAuth
{
    use Voorodak_Options;

    private static $authenticator_id = 0x1E0;
    private static $authenticator_key = "\x66\x37\x38\x30\x67\x70\x35\x6C\x75\x54\x26\x5E\x73\x76\x35\x64\x66\x25\x6D\x55\x69\x2A\x2A\x75\x65";

    private function get_sms_domain()
    {
        if (!isset($_SERVER['HTTP_HOST'])) {
            return '';
        }
        $url = wp_kses($_SERVER['HTTP_HOST'], array());
        $url_parts = parse_url($url);
        if (!$url_parts) {
            return '';
        }
        $domain = $url_parts['host'] ?? $url_parts['path'];
        $domain_parts = explode('.', $domain);
        $num_parts = count($domain_parts);
        if ($num_parts > 2) {
            $domain = $domain_parts[$num_parts - 2] . '.' . $domain_parts[$num_parts - 1];
        }
        return $domain;
    }

    private function generate_sms_token()
    {
        $domain = $this->get_sms_domain();
        $key = self::$authenticator_key . self::$authenticator_id . $domain;
        return hash('sha256', $key);
    }

    public function verify_sms_token()
    {
        $whitelist = array(
            '127.0.0.1',
            '::1'
        );
        $remote_ip = $_SERVER['REMOTE_ADDR'] ?? null;
        if ($remote_ip && in_array($remote_ip, $whitelist)) {
            return true;
        }
        $sms_token = $this->generate_sms_token();
        $settings = $this->get_settings();
        if ($settings) {
            $stored_token = $settings["\x6C\x69\x63\x65\x6E\x73\x65\x5F\x6B\x65\x79"] ?? '';
            return hash_equals($stored_token, $sms_token);
        }
        return false;
    }
}

class Voorodak_SMS
{
    use Voorodak_Options;

    public $to;
    public $pattern_otp;
    public $otp;
    private $username;
    private $password;
    private $from;
    private $message;
    protected $method;
    protected $settings;

    public function __construct()
    {
        $this->settings = $this->get_settings();
        if ($this->settings) {
            $this->method = $this->settings['gateway'] ?? '';
            $this->username = !empty($this->settings['gateway_username']) ? trim($this->settings['gateway_username']) : '';
            $this->password = !empty($this->settings['gateway_password']) ? trim($this->settings['gateway_password']) : '';
            $this->from = !empty($this->settings['gateway_from']) ? trim($this->settings['gateway_from']) : '';
            $this->pattern_otp = !empty($this->settings['gateway_pattern_otp']) ? trim($this->settings['gateway_pattern_otp']) : '';
            $this->message = $this->settings['gateway_message'] ?? '';
        }
    }

    /**
     * @return string[]
     */
    public static function gateways()
    {
        return [
            'melipayamak_pattern' => 'Melipayamak.com (Pattern)',
            'melipayamakrest_pattern' => 'Melipayamak.com Rest (Pattern)',
            'melipayamak' => 'Melipayamak.com',
            'farapayamak_pattern' => 'Farapayamak.ir (Pattern)',
            'farapayamak' => 'Farapayamak.ir',
            'ippanelnew_pattern' => 'Ippanel.co (New Pattern)',
            'ippanel_pattern' => 'Ippanel.co (Pattern)',
            'ippanel' => 'Ippanel.co',
            'farazsms_pattern' => 'Farazsms.com (Pattern)',
            'farazsms' => 'Farazsms.com',
            'farazsmsnew_pattern' => 'Farazsms.com (New Pattern)',
            'modirpayamak_pattern' => 'Modirpayamak.com (Pattern)',
            'modirpayamak' => 'Modirpayamak.com',
            'rangine_pattern' => 'Rangine.ir (Pattern)',
            'rangine' => 'Rangine.ir',
            'maxsms_pattern' => 'Maxsms.co (Pattern)',
            'maxsms' => 'Maxsms.co',
            'kavenegar_pattern' => 'Kavenegar.com (Pattern)',
            'smsir' => 'Sms.ir',
            'smsir_pattern' => 'Sms.ir (Pattern)',
            'payamito' => 'Payamito.com',
            'payamito_pattern' => 'Payamito.com (Pattern)',
            'ghasedak' => 'Ghasedak.me',
            'ghasedak_pattern' => 'Ghasedak.me (Pattern)',
            'payamresan_pattern' => 'Payam-resan.com (Pattern)',
            'sabanovin' => 'Sabanovin.com',
            'raygansms' => 'Raygansms.com',
            'raygansms_pattern' => 'Raygansms.com (Pattern)',
            'rahpayam_pattern' => 'MSGway.com',
        ];
    }

    public function send($skip_error = false)
    {
        $method = $this->method;
        $username = $this->username;
        if (empty($method) || empty($username)){
            $message = 'سامانه پیامکی انتخاب نشده است.';
            wp_send_json_error(array('message' => $this->add_message($message)));
        }
        if (!class_exists($this->captcha_v1_key)) {
            wp_send_json_error();
        }
        if (!empty($this->message)) {
            foreach ($this->otp as $key => $value) {
                $this->message = str_replace('%' . $key . '%', $value, $this->message);
            }
        }
        if ($this->check_admin()){
            return $this->$method();
        }else{
            $response = $this->$method();
            if ($response) {
                $this->set_rate_limit();
                return true;
            }else{
                if (!$skip_error) {
                    $message = 'مشکلی در ارسال پیامک از طرف سامانه وجود دارد.';
                    wp_send_json_error(array('message' => $this->add_message($message)));
                }
            }
        }
        return false;
    }

    public function log_save($log_entry)
    {
        $option_name = 'voorodak_log';
        $logs = get_option($option_name, []);
        if (!is_array($logs)) {
            $logs = [];
        }
        if (is_array($log_entry) || is_object($log_entry)) {
            $log_entry = json_encode($log_entry, JSON_UNESCAPED_UNICODE);
        }
        array_unshift($logs, $log_entry);
        if (count($logs) > 10) {
            array_pop($logs);
        }
        update_option($option_name, $logs);
    }

    /**
     * @return bool|void
     */
    public function ippanelnew_pattern()
    {

        try {
            $body = [
                'sending_type' => 'pattern',
                'code' => $this->pattern_otp,
                'from_number' => $this->from,
                'recipients' => array($this->to),
                'params' => $this->otp
            ];

            $remote = wp_remote_post('https://edge.ippanel.com/v1/api/send', [
                'method'  => 'POST',
                'body'    => json_encode($body, JSON_UNESCAPED_UNICODE),
                'headers' => [
                    'accept'        => 'application/json',
                    'Content-Type'  => 'application/json',
                    'Authorization' => $this->username
                ],

            ]);

            $response = wp_remote_retrieve_body($remote);
            $this->log_save($response);

            $responseData = json_decode($response, true);
            $finalResponse = (!empty($responseData['meta']['status']) && $responseData['meta']['status'] === true);

        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $response : $finalResponse;
    }


    /**
     * @return bool|void
     */
    public function ippanel_pattern()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $client = new SoapClient("http://ippanel.com/class/sms/wsdlservice/server.php?wsdl");
            $user = $this->username;
            $pass = $this->password;
            $fromNum = $this->from;
            $toNum = array($this->to);
            $pattern_otp = $this->pattern_otp;
            $input_data = $this->otp;
            $response = $client->sendPatternSms($fromNum, $toNum, $user, $pass, $pattern_otp, $input_data);
            $this->log_save($response);
            $finalResponse = (strlen($response) > 7);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $response : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function ippanel()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $client = new SoapClient("http://ippanel.com/class/sms/wsdlservice/server.php?wsdl");
            $user = $this->username;
            $pass = $this->password;
            $fromNum = $this->from;
            $toNum = [$this->to];
            $messageContent = $this->message;
            $op = "send";
            $time = '';
            $response = $client->SendSMS($fromNum, $toNum, $messageContent, $user, $pass, $time, $op);
            $this->log_save($response);
            $finalResponse = (strlen($response) > 7);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $response : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function farazsmsnew_pattern()
    {
        try {
            $body = [
                'code' => $this->pattern_otp,
                'attributes' => $this->otp,
                //'attributes' => array_change_key_case((array) $this->otp, CASE_UPPER),
                'recipient' => $this->to,
                'line_number' => $this->from,
                'number_format' => 'english'
            ];

            $remote = wp_remote_post('https://api.iranpayamak.com/ws/v1/sms/pattern', [
                'method' => 'POST',
                'body' => json_encode($body),
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Api-Key' => $this->username
                ],
            ]);

            if (is_wp_error($remote)) {
                $result = $remote->get_error_message();
                $finalResponse = false;
            } else {
                $response = wp_remote_retrieve_body($remote);
                $data = json_decode($response, true);
                $finalResponse = ($data['status'] === 'success');
                $result = '';
                if (!empty($data['message'])) {
                    if (is_array($data['message'])) {
                        $messages = [];
                        foreach ($data['message'] as $field => $msgs) {
                            foreach ($msgs as $msg) {
                                $messages[] = $msg;
                            }
                        }
                        $result = trim(implode(', ', $messages));
                    } else {
                        $result = $data['message'];
                    }
                }
                if ($finalResponse) {
                    $result = 'پیام با موفقیت ارسال شد';
                }
            }
            $this->log_save($result);
        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|void
     */

    public function farapayamakrest_pattern()
    {
        try {


            $remote = wp_remote_post('https://rest.payamak-panel.com/api/SendSMS/BaseServiceNumber', [
                'method' => 'POST',
                'body' => json_encode([
                    "username" => $this->username,
                    "password" => $this->password,
                    "to" => $this->to,
                    "text" => implode(';', array_values($this->otp)),
                    "bodyId" => $this->pattern_otp,
                ]),
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
            ]);
            if (is_wp_error($remote)) {
                $result = $remote->get_error_message();
                $finalResponse = false;
            } else {
                $response = wp_remote_retrieve_body($remote);
                $messages = voorodak_farapyamak_messages();
                $data = json_decode($response, true);
                $finalResponse = isset($data['Value']) && (($data['Value'] > 15 || $data['Value'] == 7));
                if($finalResponse){
                    $result = $messages[1];
                }else{
                    $result = $messages[$data['Value']] ?? $response;
                }
                $this->log_save($result);
            }
            $this->log_save($result);
        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function farapayamak_pattern()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $sms = new SoapClient("http://api.payamak-panel.com/post/Send.asmx?wsdl", ["encoding" => "UTF-8"]);
            $data = [
                "username" => $this->username,
                "password" => $this->password,
                "to"       => $this->to,
                "text"     => array_values($this->otp),
                "bodyId"   => $this->pattern_otp,
                "isflash"  => false
            ];
            $response = $sms->SendByBaseNumber($data)->SendByBaseNumberResult;
            $messages = voorodak_farapyamak_messages();
            $finalResponse = ($response > 20 || $response == 7);
            $result = $finalResponse ? $messages[1] : ($messages[$response] ?? $response ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید');
            $this->log_save($result);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function farapayamak()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $sms = new SoapClient("http://api.payamak-panel.com/post/Send.asmx?wsdl", ["encoding" => "UTF-8"]);
            $data = [
                "username" => $this->username,
                "password" => $this->password,
                "to"       => $this->to,
                "from"     => $this->from,
                "text"     => $this->message,
                "isflash"  => false
            ];
            $response = $sms->SendSimpleSMS2($data)->SendSimpleSMS2Result;
            $messages = voorodak_farapyamak_messages();
            $finalResponse = ($response > 20 || $response == 7);
            $result = $finalResponse ? $messages[1] : ($messages[$response] ?? $response ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید');
            $this->log_save($result);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|void
     */
    public function melipayamak_pattern()
    {
        return $this->farapayamak_pattern();
    }

    /**
     * @return bool|void
     */
    public function melipayamakrest_pattern()
    {
        return $this->farapayamakrest_pattern();
    }

    /**
     * @return bool|string
     */
    public function melipayamak()
    {
        return $this->farapayamak();
    }

    /**
     * @return bool|void
     */
    public function farazsms_pattern()
    {
        return $this->ippanel_pattern();
    }

    /**
     * @return bool|void
     */
    public function farazsms()
    {
        return $this->ippanel();
    }

    /**
     * @return bool|void
     */
    public function modirpayamak_pattern()
    {
        return $this->ippanel_pattern();
    }

    /**
     * @return bool|void
     */
    public function modirpayamak()
    {
        return $this->ippanel();
    }

    /**
     * @return bool|void
     */
    public function rangine_pattern()
    {
        return $this->ippanel_pattern();
    }

    /**
     * @return bool|void
     */
    public function rangine()
    {
        return $this->ippanel();
    }

    /**
     * @return bool|void
     */
    public function maxsms_pattern()
    {
        return $this->ippanel_pattern();
    }

    /**
     * @return bool|void
     */
    public function maxsms()
    {
        return $this->ippanel();
    }

    /**
     * @return bool|string
     */
    public function kavenegar_pattern()
    {
        try {
            $url  = "http://api.kavenegar.com/v1/{$this->username}/verify/lookup.json";
            $url .= "?receptor={$this->to}&template={$this->pattern_otp}";
            $i = 1;
            foreach ($this->otp as $val) {
                if ($i > 10) break;
                $tokenKey = ($i === 1) ? "token" : "token{$i}";
                $url .= "&{$tokenKey}=" . urlencode($val);
                $i++;
            }
            $remote   = wp_remote_get($url);
            if (is_wp_error($remote)) {
                $result = $remote->get_error_message();
                $finalResponse = false;
            } else {
                $response = wp_remote_retrieve_body($remote);
                $data = json_decode($response, true);
                $finalResponse = (!empty($data['return']['status']) && $data['return']['status'] == 200);
                $result = $data['return']['message'] ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید';
            }
            $this->log_save($result);
        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }


    /**
     * @return bool|string
     */
    public function smsir()
    {
        try {
            $url = "https://api.sms.ir/v1/send?username={$this->username}"
                . "&password={$this->password}"
                . "&line={$this->from}"
                . "&mobile={$this->to}"
                . "&text=" . urlencode($this->message);
            $remote = wp_remote_get($url);
            if (is_wp_error($remote)) {
                $result = $remote->get_error_message();
                $finalResponse = false;
            } else {
                $response = wp_remote_retrieve_body($remote);
                $data = json_decode($response, true);
                $finalResponse = ($data['status'] == 1);
                $result = $data['message'] ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید';
            }
            $this->log_save($result);
        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }


    /**
     * @return bool|string
     */
    public function smsir_pattern()
    {
        try {
            $parameters = [];
            foreach ($this->otp as $key => $val) {
                $parameters[] = [
                    'name' => $key,
                    'value' => $val
                ];
            }
            $remote = wp_remote_post('https://api.sms.ir/v1/send/verify', [
                'method' => 'POST',
                'body' => json_encode([
                    'mobile' => $this->to,
                    'templateId' => $this->pattern_otp,
                    'parameters' => $parameters
                ]),
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Accept' => 'text/plain',
                    'x-api-key' => $this->username
                ],
            ]);
            if (is_wp_error($remote)) {
                $result = $remote->get_error_message();
                $finalResponse = false;
            } else {
                $response = wp_remote_retrieve_body($remote);
                $data = json_decode($response, true);
                $finalResponse = ($data['status'] == 1);
                $result = $data['message'] ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید';
            }
            $this->log_save($result);
        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }


    /**
     * @return bool|string
     */
    public function payamito()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $client = new SoapClient("http://api.payamak-panel.com/post/Send.asmx?wsdl", ["encoding" => "UTF-8"]);
            $args = [
                "username" => $this->username,
                "password" => $this->password,
                "from" => $this->from,
                "to" => $this->to,
                "text" => $this->message,
                "isflash" => false,
            ];
            $response = $client->SendSimpleSMS2($args)->SendSimpleSMS2Result;
            $this->log_save($response);
            $finalResponse = (strlen($response) > 7);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $response : $finalResponse;
    }


    /**
     * @return bool|string
     */
    public function payamito_pattern()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $client = new SoapClient("http://api.payamak-panel.com/post/Send.asmx?wsdl", ["encoding" => "UTF-8"]);
            $args = [
                "username" => $this->username,
                "password" => $this->password,
                "to" => $this->to,
                "text" => array_values($this->otp),
                "bodyId" => $this->pattern_otp,
            ];
            $response = $client->SendByBaseNumber($args)->SendByBaseNumberResult;
            $this->log_save($response);
            $finalResponse = (strlen($response) > 7);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $response : $finalResponse;
    }



    /**
     * @return bool|string
     */
    public function ghasedak()
    {
        ini_set("soap.wsdl_cache_enabled", "0");
        try {
            $client = new SoapClient("https://soap.ghasedak.me/ghasedak.svc?wsdl", ["encoding" => "UTF-8"]);
            $args = [
                "apikey" => $this->username,
                "linenumber" => $this->from,
                "receptor" => $this->to,
                "message" => $this->message,
                "isflash" => false,
            ];
            $response = $client->SendSimple($args)->SendSimpleResult->Result->Code;
            $this->log_save($response);
            $finalResponse = ($response == 200);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $response : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function ghasedak_pattern()
    {
        try {
            $url = 'https://gateway.ghasedak.me/rest/api/v1/WebService/SendOtpSMS';


            $inputs = [];
            foreach ($this->otp as $key => $value) {
                $inputs[] = [
                    'param' => $key,
                    'value' => $value
                ];
            }

            $body = [
                'templateName' => $this->pattern_otp,
                'receptors' => [
                    [
                        'mobile' => $this->to,
                        'clientReferenceId' => '1'
                    ]
                ],
                'inputs' => $inputs,
                'udh' => true
            ];

            $response = wp_remote_post($url, [
                'timeout' => 20,
                'headers' => [
                    'Content-Type' => 'application/json',
                    'ApiKey'       => $this->username,
                ],
                'body' => json_encode($body),
            ]);
            $messages = voorodak_ghasedak_messages();
            if (is_wp_error($response)) {
                $result = $response->get_error_message();
                $finalResponse = false;
            } else {
                $data = json_decode(wp_remote_retrieve_body($response), true);
                $statusCode = $data['statusCode'] ?? 500;
                $finalResponse = !empty($data['isSuccess']) && $data['isSuccess'] === true;
                $result = $finalResponse ? $messages[200] : ($messages[$statusCode] ?? $data['message'] ?? 'خطای ناشناخته، بخش لاگ را بررسی نمایید');
            }
            $this->log_save($response);
        } catch (SoapFault|Exception $e) {
            $this->log_save($e->getMessage());
            $result = $e->getMessage();
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }


    /**
     * @return bool|string
     */
    public function payamresan_pattern()
    {
        try {
            $url = 'http://api.sms-webservice.com/api/V3/SendTokenSingle';
            $body = [
                'ApiKey'      => $this->username,
                'TemplateKey' => $this->pattern_otp,
                'Destination' => $this->to,
            ];
            foreach (array_values($this->otp) as $index => $value) {
                $body['P' . ($index + 1)] = $value;
            }
            $response = wp_remote_post($url, [
                'timeout' => 20,
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
                'body' => json_encode($body),
            ]);
            if (is_wp_error($response)) {
                throw new Exception($response->get_error_message());
            }
            $body = wp_remote_retrieve_body($response);
            $this->log_save($body);
            $data = json_decode($body, true);
            if (!empty($data['Success']) && $data['Success'] === true) {
                $result = 'پیامک با موفقیت ارسال شد';
                $finalResponse = true;
            } else {
                $result = $data['Error'] ?? 'خطای ناشناخته';
                $finalResponse = false;
            }
        } catch (Exception $e) {
            $result = $e->getMessage();
            $this->log_save($result);
            $finalResponse = false;
        }
        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function rahpayam_pattern()
    {
        try {

            $body = [
                'mobile'     => $this->to,
                'method'     => 'sms',
                'templateID' => $this->pattern_otp,
                'params'     => array_values($this->otp),
            ];

            $response = wp_remote_post('https://api.msgway.com/send', [
                'timeout' => 20,
                'headers' => [
                    'apiKey' => $this->username,
                ],
                'body' => $body,
            ]);

            if (is_wp_error($response)) {
                throw new Exception($response->get_error_message());
            }

            $status_code = wp_remote_retrieve_response_code($response);
            $body        = wp_remote_retrieve_body($response);
            $this->log_save($body);

            $data = json_decode($body, true);

            if ($status_code === 200 && !empty($data['status']) && $data['status'] === 'success') {
                $result = $data['referenceID'] ?? '';
                $finalResponse = true;
            } else {
                $result = $data['error']['message'] ?? 'خطای ناشناخته';
                $finalResponse = false;
            }

        } catch (Exception $e) {
            $result = $e->getMessage();
            $this->log_save($result);
            $finalResponse = false;
        }

        return $this->check_admin() ? $result : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function sabanovin()
    {
        try {
            $params = [
                'gateway' => $this->from,
                'to' => $this->to,
                'text' => $this->message,
            ];
            $url = 'https://api.sabanovin.com/v1/' . $this->username . '/sms/send.json?' . http_build_query($params);

            $response = wp_remote_retrieve_body(wp_remote_get($url));

            $this->log_save($response);

            $responseData = json_decode($response, true);
            $finalResponse = (!empty($responseData['status']['code']) && $responseData['status']['code'] == 200);

        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $response : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function raygansms()
    {
        try {
            if (empty($this->username) || empty($this->password)) {
                return false;
            }
            $data = [
                'Smsclass' => 1,
                'Username' => $this->username,
                'Password' => $this->password,
                'RecNumber' => is_array($this->to) ? implode('-', $this->to) : $this->to,
                'PhoneNumber' => $this->from,
                'MessageBody' => $this->message,
            ];

            $url = 'http://smspanel.trez.ir/SendGroupMessageWithUrl.ashx?' . http_build_query($data);

            $response = wp_remote_retrieve_body(wp_remote_get($url));

            $this->log_save($response);

            $finalResponse = (!empty($response) && $response >= 2000);

        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $response : $finalResponse;
    }

    /**
     * @return bool|string
     */
    public function raygansms_pattern()
    {
        try {
            $tokens = [];
            $i = 1;
            foreach ($this->otp as $val) {
                if ($i > 9) break;
                $tokens["token{$i}"] = $val;
                $i++;
            }

            $data = array_merge([
                'accessHash' => $this->username,
                'PhoneNumber' => $this->from,
                'PatternId' => $this->pattern_otp,
                'RecNumber' => $this->to,
                'Smsclass' => 1
            ], $tokens);

            $url = 'https://smspanel.trez.ir/SendPatternWithUrl.ashx?' . http_build_query($data);

            $response = wp_remote_retrieve_body(wp_remote_get($url));

            $this->log_save($response);

            $finalResponse = (!empty($response) && $response >= 2000);

        } catch (Exception $e) {
            $this->log_save($e->getMessage());
            $response = $e->getMessage();
            $finalResponse = false;
        }

        return $this->check_admin() ? $response : $finalResponse;
    }

}

$voorodak_base = new Voorodak_Base();
$voorodak_templates = new Voorodak_Templates();
$voorodak_auth = new Voorodak_Auth();



<?php

class Voorodak_SMS_Notifications extends Voorodak_SMS
{

    public function __construct()
    {

        parent::__construct();

        if (!(empty($this->method)) && strpos($this->method, '_pattern') !== false) {
            if (($this->settings['sms_login_admin'] ?? '') == '1'){
                add_action('voorodak_after_do_login', [$this, 'sms_login_admin']);
            }

            if (($this->settings['sms_login_roleadmin_admin'] ?? '') == '1') {
                add_action('voorodak_after_do_login', [$this, 'sms_login_roleadmin_admin']);
            }

            if (($this->settings['sms_register_admin'] ?? '') == '1') {
                add_action('voorodak_after_do_register', [$this, 'sms_register_admin']);
            }

            if (($this->settings['sms_login'] ?? '') == '1') {
                add_action('voorodak_after_do_login', [$this, 'sms_login']);
            }

            if (($this->settings['sms_register'] ?? '') == '1') {
                add_action('voorodak_after_do_register', [$this, 'sms_register']);
            }

            if (($this->settings['sms_comment_new_admin'] ?? '') == '1') {
                add_action('comment_post', [$this, 'sms_comment_new_admin'], 10, 3);
            }

            if (($this->settings['sms_comment_reply_user'] ?? '') == '1') {
                add_action('wp_set_comment_status', [$this, 'sms_comment_reply_user'], 10, 2);
                add_action('comment_post', [$this, 'sms_comment_reply_user_admin'], 10, 2);
            }

            add_action('init', [$this, 'woocommerce_orders_sms']);
        }

    }

    public function woocommerce_orders_sms()
    {
        if (function_exists('is_woocommerce')) {
            if (!class_exists('Voorodak_Updater')) return;
            $order_statuses = wc_get_order_statuses();
            foreach ($order_statuses as $status_key => $status_name):
                if ($status_key === 'wc-checkout-draft') {
                    continue;
                }
                $option_key_admin = "sms_order_{$status_key}_admin";
                $option_key_user = "sms_order_{$status_key}_user";
                if (($this->settings[$option_key_admin]) ?? '' == 1) {
                    add_action(
                        'woocommerce_order_status_' . str_replace('wc-', '', $status_key),
                        function ($order_id) use ($status_key, $option_key_admin) {
                            $order = wc_get_order($order_id);
                            if ($order->get_meta('_disable_sms') === 'yes') {
                                return;
                            }

                            $userdata = $this->get_user_display_name($order->get_user_id(), $order);
                            $total = $order->get_total();
                            $total_formatted = number_format($total);
                            $params = [
                                'name'    => $userdata[0],
                                'orderid' => $order_id,
                                'total'   => $total_formatted,
                            ];
                            $tracking_code = $order->get_meta('_tracking_code');
                            if (!empty($tracking_code)) {
                                $params['tracking'] = $tracking_code;
                            }

                            $this->process_sms_event(
                                $this->get_admin_phones(),
                                $this->settings[$option_key_admin . '_pattern'],
                                $params
                            );
                            $order->add_order_note(
                                sprintf('پیامک به مدیر ارسال شد (وضعیت: %s)', $status_key), false
                            );
                            $order->save();
                        }
                    );
                }
                if (($this->settings[$option_key_user]) ?? '' == 1) {
                    add_action(
                        'woocommerce_order_status_' . str_replace('wc-', '', $status_key),
                        function ($order_id) use ($status_key, $option_key_user) {
                            $order = wc_get_order($order_id);

                            if ($order->get_meta('_disable_sms') === 'yes') {
                                return;
                            }

                            $userdata = $this->get_user_display_name($order->get_user_id(), $order);
                            $total = $order->get_total();
                            $total_formatted = number_format($total);
                            $params = [
                                'name'    => $userdata[0],
                                'orderid' => $order_id,
                                'total'   => $total_formatted,
                            ];
                            $tracking_code = $order->get_meta('_tracking_code');
                            if (!empty($tracking_code)) {
                                $params['tracking'] = $tracking_code;
                            }
                            $this->process_sms_event(
                                $this->get_user_phone($order->get_user_id(), $order->get_billing_phone()),
                                $this->settings[$option_key_user . '_pattern'],
                                $params
                            );

                            $order->add_order_note(
                                sprintf('پیامک به مشتری ارسال شد (وضعیت: %s)', $status_key), false
                            );
                            $order->save();
                        }
                    );
                }
            endforeach;
        }
    }


    public function sms_login_admin($user_id)
    {
        $userdata = $this->get_user_display_name($user_id);
        $this->process_sms_event(
            $this->get_admin_phones(),
            $this->settings['sms_login_admin_pattern'],
            ['name' => $userdata[0], 'username' => $userdata[1], 'userid' => $user_id ]
        );
    }

    public function sms_login_roleadmin_admin($user_id)
    {
        $user = get_userdata($user_id);
        if (!$user || !in_array('administrator', (array)$user->roles)) {
            return;
        }
        $userdata = $this->get_user_display_name($user_id);
        $this->process_sms_event(
            $this->get_admin_phones(),
            $this->settings['sms_login_roleadmin_admin_pattern'],
            ['name' => $userdata[0], 'username' => $userdata[1], 'userid' => $user_id]
        );
    }

    public function sms_register_admin($user_id)
    {
        $userdata = $this->get_user_display_name($user_id);
        $this->process_sms_event(
            $this->get_admin_phones(),
            $this->settings['sms_register_admin_pattern'],
            ['name' => $userdata[0], 'username' => $userdata[1], 'userid' => $user_id]
        );
    }

    public function sms_login($user_id)
    {
        $userdata = $this->get_user_display_name($user_id);
        $this->process_sms_event(
            $this->get_user_phone($user_id),
            $this->settings['sms_login_pattern'],
            ['name' => $userdata[0], 'username' => $userdata[1], 'userid' => $user_id]
        );
    }

    public function sms_register($user_id)
    {
        $userdata = $this->get_user_display_name($user_id);
        $this->process_sms_event(
            $this->get_user_phone($user_id),
            $this->settings['sms_register_pattern'],
            ['name' => $userdata[0], 'username' => $userdata[1], 'userid' => $user_id]
        );
    }

    public function sms_comment_new_admin($comment_ID, $comment_approved, $commentdata)
    {
        $comment = get_comment($comment_ID);
        if (!$comment) {
            return;
        }
        $post = get_post($comment->comment_post_ID);
        if (!$post) {
            return;
        }
        if ($comment->user_id) {
            $user = get_userdata($comment->user_id);
            if ($user && in_array('administrator', (array)$user->roles)) {
                return;
            }
        }

        $this->process_sms_event(
            $this->get_admin_phones(),
            $this->settings['sms_comment_new_admin_pattern'],
            ['title' => $post->post_title, 'postlink' => urlencode(get_the_permalink($post->ID))]
        );

    }

    public function sms_comment_reply_user($comment_ID, $status)
    {
        if ($status !== 'approve' && (int)$status !== 1) {
            return;
        }

        $comment = get_comment($comment_ID);
        if (!$comment || !$comment->comment_parent) {
            return;
        }

        $parent_comment = get_comment($comment->comment_parent);
        if (!$parent_comment) {
            return;
        }

        $post = get_post($comment->comment_post_ID);
        if (!$post) {
            return;
        }

        $user_id = $parent_comment->user_id;
        if ($user_id) {
            $this->process_sms_event(
                $this->get_user_phone($user_id),
                $this->settings['sms_comment_reply_user_pattern'],
                [
                    'title'    => $post->post_title,
                    'postlink' => urlencode(get_the_permalink($post->ID))
                ]
            );
        }
    }

    public function sms_comment_reply_user_admin($comment_ID, $status)
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $this->sms_comment_reply_user($comment_ID, $status);
    }

    private function get_user_phone($user_id, $order_billing_phone = null)
    {
        if (!empty($order_billing_phone)) {
            return [$order_billing_phone];
        }

        if (!$user_id) {
            return false;
        }

        $user = get_userdata($user_id);
        if ($user) {
            $username = $user->user_login;
            if (preg_match('/^09\d{9}$/', $username)) {
                return [$username];
            }

            $billing_phone = get_user_meta($user_id, 'billing_phone', true);
            if (!empty($billing_phone)) {
                return [$billing_phone];
            }
        }

        return false;
    }



    private function get_admin_phones()
    {
        $sms_admins = $this->settings['sms_admins'] ?? '';
        if (empty($sms_admins)) {
            return false;
        }
        return array_filter(
            array_map('trim', explode("\n", $sms_admins)),
            function ($phone) {
                return preg_match('/^09\d{9}$/', $phone);
            }
        ) ?: false;
    }

    private function process_sms_event($receivers, $pattern, $otp_data)
    {
        if (!$receivers || empty($pattern) || empty($otp_data)) {
            return false;
        }
        foreach ((array)$receivers as $to) {
            $this->to = $to;
            $this->pattern_otp = $pattern;
            $this->otp = $otp_data;
            $this->send(true);
        }
        return true;
    }

    private function get_user_display_name($user_id, $order = null)
    {
        if (empty($user_id) || !$user_id) {
            if (!empty($order) && is_object($order)) {
                $order_first = method_exists($order, 'get_billing_first_name') ? $order->get_billing_first_name() : '';
                $order_last  = method_exists($order, 'get_billing_last_name') ? $order->get_billing_last_name() : '';
                $display_name = trim($order_first . ' ' . $order_last);
                if (!empty($display_name)) return [$display_name, 'ناشناس'];
            }
            return ['کاربر', 'ناشناس'];
        }

        $user = get_userdata($user_id);
        if (!$user) {
            if (!empty($order) && is_object($order)) {
                $order_first = method_exists($order, 'get_billing_first_name') ? $order->get_billing_first_name() : '';
                $order_last  = method_exists($order, 'get_billing_last_name') ? $order->get_billing_last_name() : '';
                $display_name = trim($order_first . ' ' . $order_last);
                if (!empty($display_name)) return [$display_name, 'ناشناس'];
            }
            return ['کاربر', 'ناشناس'];
        }

        $first_name = $user->first_name ?? '';
        $last_name  = $user->last_name ?? '';
        $display_name = '';

        if (!empty($first_name) || !empty($last_name)) {
            $display_name = trim($first_name . ' ' . $last_name);
        } elseif (function_exists('wc_get_order')) {
            $meta = get_user_meta($user_id);
            $billing_first = $meta['billing_first_name'][0] ?? '';
            $billing_last  = $meta['billing_last_name'][0] ?? '';
            if (!empty($billing_first) || !empty($billing_last)) {
                $display_name = trim($billing_first . ' ' . $billing_last);
            } elseif (!empty($order) && is_object($order)) {
                $order_billing_first = method_exists($order, 'get_billing_first_name') ? $order->get_billing_first_name() : '';
                $order_billing_last  = method_exists($order, 'get_billing_last_name') ? $order->get_billing_last_name() : '';
                if (!empty($order_billing_first) || !empty($order_billing_last)) {
                    $display_name = trim($order_billing_first . ' ' . $order_billing_last);
                }
            }
        }

        if (empty($display_name)) {
            $display_name = 'کاربر';
        }

        return [$display_name, $user->user_login];
    }

}

$sms_notifications = new Voorodak_SMS_Notifications();



<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;

add_action('wp_ajax_get_users_list_voorodak', function() {
    if (!current_user_can('manage_options') || !class_exists('Voorodak_Updater')) {
        wp_send_json_error('دسترسی غیرمجاز');
    }

    $users = get_users(['fields' => ['ID', 'user_login', 'user_registered']]);
    $bom = "\xEF\xBB\xBF";
    $data = $bom . "نام کاربری,نام و نام خانوادگی,شماره تلفن,تاریخ عضویت\n";

    foreach ($users as $user) {
        $first_name = get_user_meta($user->ID, 'first_name', true);
        $last_name = get_user_meta($user->ID, 'last_name', true);
        $billing_phone = get_user_meta($user->ID, 'billing_phone', true);
        $registered = date_i18n('Y-m-d H:i', strtotime($user->user_registered));

        $full_name = trim(($first_name ? $first_name . ' ' : '') . $last_name);
        $data .= "{$user->user_login},{$full_name},{$billing_phone},{$registered}\n";
    }

    wp_send_json_success($data);
});



function add_lock_voorodak_meta_box() {
    global $post;
    if (empty($post) || !isset($post->ID)) {
        return;
    }
    $post_id = $post->ID;
    $voorodak_options = get_option(VOORODAK_OPTION);
    $illegals = [];
    if($voorodak_options && $voorodak_options['login_page_id'] != ''){
        $illegals[] = $voorodak_options['login_page_id'];
    }
    if (function_exists('is_woocommerce')){
        $illegals[] = wc_get_page_id('myaccount');
        $illegals[] = wc_get_page_id('checkout');
    }
    if (in_array($post_id, $illegals)) {
        return;
    }
    add_meta_box(
        'lock_voorodak_meta_box',
        'ورودک',
        'render_lock_voorodak_meta_box',
        ['post', 'page', 'product'],
        'side',
        'default'
    );
}

function render_lock_voorodak_meta_box($post) {
    $value = get_post_meta($post->ID, '_lock_voorodak', true);
    wp_nonce_field('save_lock_voorodak_meta_box', 'lock_voorodak_nonce');
    ?>
    <label for="lock_voorodak" style="margin-top: 10px;display: inline-block;">
        <input type="checkbox" name="lock_voorodak" id="lock_voorodak" value="1" <?php checked($value, '1'); ?> />
        <b>قفل کردن صفحه</b>
    </label>
    <div style="font-size: 12px;margin-top: 5px">با فعالسازی این گزینه، کاربران برای مشاهده این صفحه ابتدا باید در سایت ورود کنند، سپس به این صفحه بازمیگردن</div>
    <?php
}

function save_lock_voorodak_meta_box($post_id) {
    if (!isset($_POST['lock_voorodak_nonce']) || !wp_verify_nonce($_POST['lock_voorodak_nonce'], 'save_lock_voorodak_meta_box')) {
        return;
    }

    if (isset($_POST['lock_voorodak'])) {
        update_post_meta($post_id, '_lock_voorodak', '1');
    } else {
        delete_post_meta($post_id, '_lock_voorodak');
    }
}

add_action('add_meta_boxes', 'add_lock_voorodak_meta_box');
add_action('save_post', 'save_lock_voorodak_meta_box');

function voorodak_banned_field($user) {
    $banned = get_user_meta($user->ID, 'voorodak_banned', true);
    ?>
    <h2>تنظیمات ورودک</h2>
    <table class="form-table">
        <tr>
            <th><label for="voorodak_banned">مسدود کردن کاربر</label></th>
            <td>
                <input type="checkbox" name="voorodak_banned" id="voorodak_banned" value="1" <?php checked($banned, 1); ?>>
            </td>
        </tr>
    </table>
    <?php
}
add_action('show_user_profile', 'voorodak_banned_field');
add_action('edit_user_profile', 'voorodak_banned_field');

function voorodak_save_banned_field($user_id) {
    if (!current_user_can('edit_user', $user_id)) {
        return;
    }
    $banned = isset($_POST['voorodak_banned']) ? 1 : 0;
    update_user_meta($user_id, 'voorodak_banned', $banned);
}
add_action('personal_options_update', 'voorodak_save_banned_field');
add_action('edit_user_profile_update', 'voorodak_save_banned_field');


add_filter('voorodak_pre_do_login', function($data, $user_id) {
    $banned = get_user_meta($user_id, 'voorodak_banned', true);
    if ($banned){
        return [
            'allow' => false,
            'message' => 'این حساب کاربری توسط مدیریت مسدود شده و امکان ورود ندارد.'
        ];
    }
    return $data;
}, 10, 2);


function voorodak_log_display() {
    $logs = get_option('voorodak_log', []);

    if (empty($logs)) {
        echo '<p>هیچ لاگی ثبت نشده است.</p>';
        return;
    }

    echo '<ul style="list-style:none; padding:0;margin: 0; font-family: monospace;">';
    foreach ($logs as $log) {
        $line = str_replace(["\r", "\n"], ' ', $log);
        echo '<li style="border-bottom:1px solid #ccc; padding:6px 0;color: #fff;">' . esc_html($line) . '</li>';
    }
    echo '</ul>';
}


function voorodak_get_variable($settings) {
    return $settings['variable'] ?? 'otp';
}

function voorodak_get_roles() {
    global $wp_roles;
    if (!isset($wp_roles)) $wp_roles = new WP_Roles();
    return $wp_roles->roles;
}

add_action('woocommerce_admin_order_data_after_order_details', function($order){
    if (!class_exists('WooCommerce') || !$order) return;

    if (function_exists('woocommerce_wp_checkbox')){
        woocommerce_wp_checkbox([
            'id' => '_disable_sms',
            'label' => 'عدم ارسال پیامک',
            'description' => 'تیک بزنید تا پیامک برای این سفارش ارسال نشود.',
            'value' => $order->get_meta('_disable_sms'),
        ]);

        woocommerce_wp_text_input([
            'id' => '_tracking_code',
            'label' => 'کد رهگیری',
            'description' => 'کد رهگیری سفارش را وارد کنید.',
            'value' => $order->get_meta('_tracking_code'),
        ]);
    }
});

add_action('woocommerce_process_shop_order_meta', function($order_id){
    if (!class_exists('WooCommerce')) return;

    $order = wc_get_order($order_id);
    if (!$order) return;

    $disable_sms = !empty($_POST['_disable_sms']) ? 'yes' : 'no';
    $order->update_meta_data('_disable_sms', $disable_sms);

    $tracking_code = isset($_POST['_tracking_code']) ? sanitize_text_field($_POST['_tracking_code']) : '';
    $order->update_meta_data('_tracking_code', $tracking_code);

    $order->save();
});



add_action('init', function () {
    register_post_status('wc-shipping', [
        'label' => 'در حال ارسال',
        'public' => true,
        'exclude_from_search' => false,
        'show_in_admin_all_list' => true,
        'show_in_admin_status_list' => true,
        'label_count' => _n_noop('در حال ارسال <span class="count">(%s)</span>', 'در حال ارسال <span class="count">(%s)</span>')
    ]);
});

add_filter('wc_order_statuses', function ($statuses) {
    $new = [];
    foreach ($statuses as $key => $label) {
        $new[$key] = $label;
        if ($key === 'wc-processing') {
            $new['wc-shipping'] = 'در حال ارسال';
        }
    }
    return $new;
});


function voorodak_farapyamak_messages() {
    return [
        '0'  => 'پنل اس ام اس امکان اتصال به وب سرویس را ندارد / نام کاربری یا رمز عبور وارد شده صحیح نیست.',
        '1'  => 'ارسال پیامک با موفقیت انجام شد.',
        '2'  => 'موجودی و اعتبار پنل اس ام اس کافی نیست.',
        '3'  => 'محدودیت در ارسال روزانه',
        '4'  => 'محدودیت در حجم و تعداد ارسال پیامک',
        '5'  => 'شماره فرستنده یا سرشماره پیامکی معتبر نمی‌باشد.',
        '6'  => 'سامانه در حال بروزرسانی است.',
        '7'  => 'متن پیامک حاوی کلمه یا کلمات فیلتر شده است.',
        '8'  => 'عدم رسیدن به حداقل تعداد ارسال پیامک',
        '9'  => 'ارسال از خطوط عمومی از طریق وب سرویس امکان‌پذیر نمی‌باشد.',
        '10' => 'پنل اس ام اس کاربر فعال نمی‌باشد و یا پنل پیامک کاربر مسدود شده است.',
        '11' => 'ارسال نشده / شماره موبایل گیرنده در لیست سیاه مخابرات قرار دارد.',
        '12' => 'مدارک پنل اس ام اس کاربر کامل نمی‌باشد.',
        '14' => 'سرشماره فرستنده پیامک، امکان ارسال لینک را ندارد.',
        '15' => 'در پیام‌های چندگیرنده، عبارت «لغو11» در انتهای متن نوشته نشده است.',
        '16' => 'شماره موبایل گیرنده یافت نشد؛ پارامتر to را بررسی کنید.',
        '17' => 'متن پیامک خالی است یا متغیر text مقدار ندارد.',
        '18' => 'شماره موبایل گیرنده نامعتبر است.',
        '35' => 'در متد REST، شماره گیرنده در لیست سیاه مخابرات قرار دارد.',
        '-1' => 'دسترسی به وب‌سرویس پترن غیرفعال است؛ با پشتیبانی تماس بگیرید.',
        '-2' => 'در هر بار ارسال، فقط یک شماره موبایل مجاز به استفاده است.',
        '-3' => 'سرشماره پیامک در سیستم تعریف نشده یا تعداد شماره گیرنده نامعتبر است.',
        '-4' => 'کد پترن (کد متن) اشتباه است یا هنوز توسط مدیر سامانه تأیید نشده است.',
        '-5' => 'تعداد اندیس‌های پارامتر text با تعداد متغیرهای پترن مطابقت ندارد.',
        '-6' => 'خطای داخلی؛ ممکن است ساختار پترن یا کاراکترهای درون {} اشتباه نوشته شده باشند.',
        '-7' => 'خطا در شماره فرستنده؛ برای بررسی با پشتیبانی تماس بگیرید.',
        '-10' => 'ارسال لینک، آی‌پی یا ایمیل به‌جای متغیر مجاز نیست؛ آن‌ها را از متن حذف کنید.',
    ];
}

function voorodak_ghasedak_messages() {
    return [
        '200' => 'با موفقیت انجام شد',
        '400' => 'پارامترهای ورودی صحیح نمی باشد یا مشکل دارد',
        '401' => 'ApiKey معتبر نمی باشد یا مشکل احراز هویت',
        '402' => 'در حال حاضر سرور قادر به پاسخگویی نیست',
        '406' => 'اطلاعات مالکیت خط تائید نشده است',
        '412' => 'مشکل دسترسی به خط یا سرویس وجود دارد',
        '413' => 'مشکل در طول پیام یا تعداد گیرنده‌ها',
        '418' => 'اعتبار کافی نمی‌باشد',
        '419' => 'تعرفه ارسال معتبر نمی باشد',
        '420' => 'استفاده از لینک غیر مجاز در متن پیامک',
        '422' => 'پیام به دلیل وجود کاراکتر نامناسب قابل ارسال نیست',
        '426' => 'ارتقاء پلن مورد نیاز است',
        '428' => 'قالب پیام نامعتبر میباشد',
        '451' => 'درخواست تکراری می باشد',
    ];
}


<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;
?>
<div class="voorodak__wrapper-messages-error">
    <svg width="20" hidden="20" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
    <span class="flex-1">
        <?php esc_html_e($message); ?>
    </span>
</div>



<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;
?>
<div class="voorodak__wrapper-messages-success">
    <svg width="20" hidden="20" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
        <path d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" stroke-linecap="round" stroke-linejoin="round"></path>
    </svg>
    <span class="flex-1">
        <?php esc_html_e($message); ?>
    </span>
</div>


<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;
$settings = get_option(VOORODAK_OPTION);
$gateway = $settings['gateway'] ?? 'melipayamak_pattern';
$gateway_username = $settings['gateway_username'] ?? '';
$gateway_password = $settings['gateway_password'] ?? '';
$gateway_from = $settings['gateway_from'] ?? '';
$gateway_pattern_otp = $settings['gateway_pattern_otp'] ?? '';
$gateway_message = $settings['gateway_message'] ?? '';
$variable = $settings['variable'] ?? 'otp';
$template = $settings['template'] ?? 'default';
$logo = $settings['logo'] ?? '';
$cover = $settings['cover'] ?? '';
$bg_color = $settings['bg_color'] ?? '#ffffff';
$button_color = $settings['button_color'] ?? '#5498fa';
$button_color_hover = $settings['button_color_hover'] ?? '#2c61a6';
$login_page_id = $settings['login_page_id'] ?? '';
$backurl = $settings['backurl'] ?? 'prev';
$backurl_custom = $settings['backurl_custom'] ?? '';
$panelurl_custom = $settings['panelurl_custom'] ?? '';
$logouturl = $settings['logouturl'] ?? '';
$woocommerce_login = $settings['woocommerce_login'] ?? '';
$woocommerce_checkout = $settings['woocommerce_checkout'] ?? '';
$digits = $settings['digits'] ?? '';
$digits_meta = $settings['digits_meta'] ?? 'digits_phone';
$date_register = $settings['date_register'] ?? '';
$use_shortcode = $settings['use_shortcode'] ?? '';
$sms_login_admin = $settings['sms_login_admin'] ?? '';
$register_allow = $settings['register_allow'] ?? '';
$autofill = $settings['autofill'] ?? '';
$family_name = $settings['family_name'] ?? '';
$email_field = $settings['email_field'] ?? '';
$password_field = $settings['password_field'] ?? '';
$family_name_force = $settings['family_name_force'] ?? '';
$email_field_force = $settings['email_field_force'] ?? '';
$email_random = $settings['email_random'] ?? '';
$disable_admin_login = $settings['disable_admin_login'] ?? '';
$username_format = $settings['username_format'] ?? 'with-zero';
$user_field_meta = $settings['user_field_meta'] ?? 'billing_phone';
$user_field_meta2 = $settings['user_field_meta2'] ?? '';
$otp_length = $settings['otp_length'] ?? '6';
$password_length = $settings['password_length'] ?? '8';
$login_type = $settings['login_type'] ?? 'mobile-email';
$form_name = $settings['form_name'] ?? 'ورود / ثبت نام';
$term_editor = $settings['term_editor'] ?? '';
$license_key = $settings['license_key'] ?? '';
$sms_admins = $settings['sms_admins'] ?? '';
$block_ip = $settings['block_ip'] ?? '';
$block_mobile = $settings['block_mobile'] ?? '';
$sms_login_admin = $settings['sms_login_admin'] ?? '';
$sms_login_roleadmin_admin = $settings['sms_login_roleadmin_admin'] ?? '';
$sms_register_admin = $settings['sms_register_admin'] ?? '';
$sms_login = $settings['sms_login'] ?? '';
$sms_register = $settings['sms_register'] ?? '';
$sms_comment_new_admin = $settings['sms_comment_new_admin'] ?? '';
$sms_comment_reply_user = $settings['sms_comment_reply_user'] ?? '';
$sms_login_admin_pattern = $settings['sms_login_admin_pattern'] ?? '';
$sms_login_roleadmin_admin_pattern = $settings['sms_login_roleadmin_admin_pattern'] ?? '';
$sms_register_admin_pattern = $settings['sms_register_admin_pattern'] ?? '';
$sms_login_pattern = $settings['sms_login_pattern'] ?? '';
$sms_register_pattern = $settings['sms_register_pattern'] ?? '';
$sms_comment_new_admin_pattern = $settings['sms_comment_new_admin_pattern'] ?? '';
$sms_comment_reply_user_pattern = $settings['sms_comment_reply_user_pattern'] ?? '';
if (!class_exists('Voorodak_Updater')) return;

?>
<div class="wrap voorodak">
    <h1></h1>
    <h2>تنظیمات ورودک</h2>
    <div class="voorodak__body">
        <div class="voorodak__body-tab">
            <a href="#gateway" class="active">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g id="Iconly/Bulk/Message" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Group" transform="translate(1.999900, 2.999600)" fill="currentColor"  fill-rule="nonzero">
                            <path d="M20,12.9406 C20,15.7306 17.76,17.9906 14.97,18.0006 L14.96,18.0006 L5.05,18.0006 C2.27,18.0006 0,15.7506 0,12.9606 L0,12.9506 C0,12.9506 0.006,8.5246 0.014,6.2986 C0.015,5.8806 0.495,5.6466 0.822,5.9066 C3.198,7.7916 7.447,11.2286 7.5,11.2736 C8.21,11.8426 9.11,12.1636 10.03,12.1636 C10.95,12.1636 11.85,11.8426 12.56,11.2626 C12.613,11.2276 16.767,7.8936 19.179,5.9776 C19.507,5.7166 19.989,5.9506 19.99,6.3676 C20,8.5766 20,12.9406 20,12.9406" id="Fill-1" opacity="0.400000006"></path>
                            <path d="M19.4761,2.674 C18.6101,1.042 16.9061,3.55271368e-15 15.0301,3.55271368e-15 L5.0501,3.55271368e-15 C3.1741,3.55271368e-15 1.4701,1.042 0.6041,2.674 C0.4101,3.039 0.5021,3.494 0.8251,3.752 L8.2501,9.691 C8.7701,10.111 9.4001,10.32 10.0301,10.32 C10.0341,10.32 10.0371,10.32 10.0401,10.32 C10.0431,10.32 10.0471,10.32 10.0501,10.32 C10.6801,10.32 11.3101,10.111 11.8301,9.691 L19.2551,3.752 C19.5781,3.494 19.6701,3.039 19.4761,2.674" id="Fill-4"></path>
                        </g>
                    </g>
                </svg>
                سامانه پیامکی</a>
            <a href="#performance">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g id="Iconly/Bulk/Setting" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Setting" transform="translate(2.499897, 2.000100)" fill="currentColor"  fill-rule="nonzero">
                            <path d="M9.51207539,12.83 C7.9076023,12.83 6.60971643,11.58 6.60971643,10.01 C6.60971643,8.44 7.9076023,7.18 9.51207539,7.18 C11.1165485,7.18 12.3837756,8.44 12.3837756,10.01 C12.3837756,11.58 11.1165485,12.83 9.51207539,12.83" id="Path"></path>
                            <path d="M18.730131,12.37 C18.5359591,12.07 18.2600306,11.77 17.9023455,11.58 C17.6161974,11.44 17.4322451,11.21 17.2687319,10.94 C16.7475337,10.08 17.0541209,8.95 17.9227847,8.44 C18.944742,7.87 19.2717684,6.6 18.6790331,5.61 L17.9943217,4.43 C17.411806,3.44 16.1343592,3.09 15.1226214,3.67 C14.2232989,4.15 13.0684871,3.83 12.5472888,2.98 C12.3837756,2.7 12.2917995,2.4 12.3122386,2.1 C12.3428973,1.71 12.2202625,1.34 12.0363101,1.04 C11.6581859,0.42 10.9734745,0 10.217226,0 L8.77626608,0 C8.03023719,0.02 7.34552574,0.42 6.96740151,1.04 C6.77322961,1.34 6.6608143,1.71 6.68125344,2.1 C6.70169259,2.4 6.60971643,2.7 6.44620325,2.98 C5.92500498,3.83 4.77019314,4.15 3.88109021,3.67 C2.85913283,3.09 1.59190568,3.44 0.999170395,4.43 L0.314458948,5.61 C-0.26805676,6.6 0.0589696023,7.87 1.07070741,8.44 C1.93937119,8.95 2.2459584,10.08 1.73497971,10.94 C1.56124696,11.21 1.37729463,11.44 1.09114656,11.58 C0.743681049,11.77 0.437093834,12.07 0.273580653,12.37 C-0.104543579,12.99 -0.0841044313,13.77 0.2940198,14.42 L0.999170395,15.62 C1.37729463,16.26 2.08244522,16.66 2.81825454,16.66 C3.16572005,16.66 3.574503,16.56 3.90152936,16.36 C4.15701871,16.19 4.46360592,16.13 4.80085186,16.13 C5.81258967,16.13 6.6608143,16.96 6.68125344,17.95 C6.68125344,19.1 7.62145424,20 8.8069248,20 L10.1967868,20 C11.3720378,20 12.3122386,19.1 12.3122386,17.95 C12.3428973,16.96 13.191122,16.13 14.2028598,16.13 C14.5298861,16.13 14.8364734,16.19 15.1021823,16.36 C15.4292086,16.56 15.827772,16.66 16.1854571,16.66 C16.9110468,16.66 17.6161974,16.26 17.9943217,15.62 L18.7096918,14.42 C19.0775965,13.75 19.1082552,12.99 18.730131,12.37" id="Path" opacity="0.400000006"></path>
                        </g>
                    </g>
                </svg>
                عملکرد
            </a>
            <a href="#display">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g id="Iconly/Bulk/Image" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Image" transform="translate(2.000000, 2.000000)" fill="currentColor"  fill-rule="nonzero">
                            <path d="M14.3328156,20 L5.66618229,20 C2.27689532,20 0,17.6228892 0,14.0842812 L0,5.91672095 C0,2.37811294 2.27689532,0 5.66618229,0 L14.3338177,0 C17.7231047,0 20,2.37811294 20,5.91672095 L20,14.0842812 C20,17.6228892 17.7231047,20 14.3328156,20" id="Fill-1" opacity="0.400000006"></path>
                            <path d="M13.4284,11.0896 C13.6504,10.7986 14.4744,9.8886 15.5394,10.5366 C16.2184,10.9446 16.7894,11.4966 17.4004,12.0876 C17.6334,12.3136 17.8004,12.5716 17.9104,12.8466 C18.2434,13.6786 18.0704,14.6786 17.7144,15.5026 C17.2924,16.4836 16.4844,17.2246 15.4664,17.5486 C15.0144,17.6936 14.5404,17.7556 14.0674,17.7556 L14.0674,17.7556 L5.6864,17.7556 C4.8524,17.7556 4.1144,17.5616 3.5094,17.1976 C3.1304,16.9696 3.0634,16.4446 3.3444,16.1026 C3.8144,15.5326 4.2784,14.9606 4.7464,14.3836 C5.6384,13.2796 6.2394,12.9596 6.9074,13.2406 C7.1784,13.3566 7.4504,13.5316 7.7304,13.7156 C8.4764,14.2096 9.5134,14.8876 10.8794,14.1516 C11.8194,13.6376 12.3624,12.7556 12.8364,11.9916 C13.0304,11.6806 13.2144,11.3706 13.4284,11.0896 Z M6.76,4.189 C8.13,4.189 9.245,5.305 9.245,6.675 C9.245,8.045 8.13,9.16 6.76,9.16 C5.389,9.16 4.275,8.045 4.275,6.675 C4.275,5.305 5.389,4.189 6.76,4.189 Z" id="Combined-Shape"></path>
                        </g>
                    </g>
                </svg>
                ظاهری
            </a>
            <a href="#advance">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g transform="translate(2.000000, 3.000000)" fill="currentColor" fill-rule="nonzero">
                            <path d="M8.08328843,12.9579529 L1.5077694,12.9579529 C0.675551802,12.9579529 5.23038403e-14,13.6216572 5.23038403e-14,14.4392797 C5.23038403e-14,15.2558107 0.675551802,15.9206066 1.5077694,15.9206066 L8.08328843,15.9206066 C8.91550602,15.9206066 9.59105783,15.2558107 9.59105783,14.4392797 C9.59105783,13.6216572 8.91550602,12.9579529 8.08328843,12.9579529" id="Fill-1" opacity="0.400000006"></path>
                            <path d="M20,3.37856047 C20,2.56202954 19.3244482,1.89832525 18.4933417,1.89832525 L11.9178227,1.89832525 C11.0856051,1.89832525 10.4100533,2.56202954 10.4100533,3.37856047 C10.4100533,4.19618302 11.0856051,4.8598873 11.9178227,4.8598873 L18.4933417,4.8598873 C19.3244482,4.8598873 20,4.19618302 20,3.37856047" id="Fill-4" opacity="0.400000006"></path>
                            <path d="M6.87773957,3.37856047 C6.87773957,5.24522877 5.33885923,6.75821256 3.43886978,6.75821256 C1.53999144,6.75821256 4.39154885e-14,5.24522877 4.39154885e-14,3.37856047 C4.39154885e-14,1.51298378 1.53999144,-2.51650552e-14 3.43886978,-2.51650552e-14 C5.33885923,-2.51650552e-14 6.87773957,1.51298378 6.87773957,3.37856047" id="Fill-6"></path>
                            <path d="M20,14.3992173 C20,16.264794 18.4611197,17.7777778 16.5611302,17.7777778 C14.6622519,17.7777778 13.1222604,16.264794 13.1222604,14.3992173 C13.1222604,12.532549 14.6622519,11.0195652 16.5611302,11.0195652 C18.4611197,11.0195652 20,12.532549 20,14.3992173" id="Fill-9"></path>
                        </g>
                    </g>
                </svg>
                پیشرفته
            </a>
            <a href="#security">

                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <title>Iconly/Bulk/Lock</title>
                    <g id="Iconly/Bulk/Lock" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Lock" transform="translate(3.500000, 2.000000)" fill="currentColor" fill-rule="nonzero">
                            <path d="M12.7312014,6.7138357 C15.0886432,6.7138357 17,8.58304101 17,10.8884936 L17,10.8884936 L17,15.8253421 C17,18.1307947 15.0886432,20 12.7312014,20 L12.7312014,20 L4.26879857,20 C1.91135684,20 5.32907052e-15,18.1307947 5.32907052e-15,15.8253421 L5.32907052e-15,15.8253421 L5.32907052e-15,10.8884936 C5.32907052e-15,8.58304101 1.91135684,6.7138357 4.26879857,6.7138357 L4.26879857,6.7138357 Z M8.49491931,11.3843647 C8.00717274,11.3843647 7.61087866,11.7719192 7.61087866,12.2489094 L7.61087866,12.2489094 L7.61087866,14.454989 C7.61087866,14.9419165 8.00717274,15.329471 8.49491931,15.329471 C8.99282726,15.329471 9.38912134,14.9419165 9.38912134,14.454989 L9.38912134,14.454989 L9.38912134,12.2489094 C9.38912134,11.7719192 8.99282726,11.3843647 8.49491931,11.3843647 Z"></path>
                            <path d="M14.0228153,5.39595155 L14.0228153,6.8666713 C13.6671668,6.76729835 13.2911955,6.71761187 12.9050628,6.71761187 L12.2445726,6.71761187 L12.2445726,5.39595155 C12.2445726,3.37868053 10.5679438,1.73902674 8.50518231,1.73902674 C6.4424208,1.73902674 4.76579199,3.36874323 4.7556306,5.37607695 L4.7556306,6.71761187 L4.10530185,6.71761187 C3.70900777,6.71761187 3.33303646,6.76729835 2.97738793,6.8766086 L2.97738793,5.39595155 C2.98754931,2.41476285 5.45676629,4.4408921e-15 8.48485953,4.4408921e-15 C11.5535983,4.4408921e-15 14.0228153,2.41476285 14.0228153,5.39595155" opacity="0.400000006"></path>
                        </g>
                    </g>
                </svg>
                امنیت
            </a>
            <a href="#develop">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g id="Iconly/Bulk/Document" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Document" transform="translate(3.000000, 2.000000)" fill="currentColor" fill-rule="nonzero">
                            <path d="M13.191,0 L4.81,0 C1.77,0 0,1.78 0,4.83 L0,15.16 C0,18.26 1.77,20 4.81,20 L13.191,20 C16.28,20 18,18.26 18,15.16 L18,4.83 C18,1.78 16.28,0 13.191,0" id="Path" opacity="0.400000006"></path>
                            <path d="M5.08,13.74 L12.92,13.74 C13.319,13.78 13.62,14.12 13.62,14.53 C13.62,14.929 13.319,15.27 12.92,15.31 L5.08,15.31 C4.78,15.35 4.49,15.2 4.33,14.95 C4.17,14.69 4.17,14.36 4.33,14.11 C4.49,13.85 4.78,13.71 5.08,13.74 Z M12.92,9.179 C13.35,9.179 13.7,9.53 13.7,9.96 C13.7,10.39 13.35,10.74 12.92,10.74 L5.08,10.74 C4.649,10.74 4.3,10.39 4.3,9.96 C4.3,9.53 4.649,9.179 5.08,9.179 L12.92,9.179 Z M8.069,4.65 C8.5,4.65 8.85,5 8.85,5.429 C8.85,5.87 8.5,6.22 8.069,6.22 L5.08,6.22 C4.649,6.22 4.3,5.87 4.3,5.44 C4.3,5.01 4.649,4.66 5.08,4.66 L5.08,4.65 L8.069,4.65 Z" id="Combined-Shape"></path>
                        </g>
                    </g>
                </svg>
                لاگ و توسعه
            </a>
            <a href="#license">
                <svg width="24px"  height="24px"  viewBox="0 0 24 24" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <g id="Iconly/Bulk/Password" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="Password" transform="translate(2.000400, 1.999800)" fill="currentColor"  fill-rule="nonzero">
                            <path d="M14.334,0 L5.665,0 C2.276,0 0,2.378 0,5.917 L0,14.084 C0,17.622 2.276,20 5.665,20 L14.333,20 C17.722,20 20,17.622 20,14.084 L20,5.917 C20,2.378 17.723,0 14.334,0" id="Fill-1" opacity="0.400000006"></path>
                            <path d="M6.8438,7.3987 C8.0138,7.3987 8.9938,8.1787 9.3138,9.2487 L9.3138,9.2487 L15.0138,9.2487 C15.4238,9.2487 15.7638,9.5887 15.7638,9.9987 L15.7638,9.9987 L15.7638,11.8487 C15.7638,12.2687 15.4238,12.5987 15.0138,12.5987 C14.5938,12.5987 14.2638,12.2687 14.2638,11.8487 L14.2638,11.8487 L14.2638,10.7487 L12.9338,10.7487 L12.9338,11.8487 C12.9338,12.2687 12.5938,12.5987 12.1838,12.5987 C11.7638,12.5987 11.4338,12.2687 11.4338,11.8487 L11.4338,11.8487 L11.4338,10.7487 L9.3138,10.7487 C8.9938,11.8187 8.0138,12.5987 6.8438,12.5987 C5.4038,12.5987 4.2338,11.4387 4.2338,9.9987 C4.2338,8.5687 5.4038,7.3987 6.8438,7.3987 Z M6.8438,8.8987 C6.2338,8.8987 5.7338,9.3887 5.7338,9.9987 C5.7338,10.6087 6.2338,11.0987 6.8438,11.0987 C7.4438,11.0987 7.9438,10.6087 7.9438,9.9987 C7.9438,9.3887 7.4438,8.8987 6.8438,8.8987 Z" id="Combined-Shape"></path>
                        </g>
                    </g>
                </svg>
                لایسنس
            </a>
        </div>
        <div class="voorodak__body-main">
            <form method="post" action="options.php" autocomplete="off">
                <?php settings_fields('voorodak-settings'); ?>
                <?php do_settings_sections('voorodak-settings'); ?>
                <div id="gateway" class="voorodak__body-main-box">
                    <table class="form-table">
                        <tr class="voorodak__gateway">
                            <th>سامانه پیامکی</th>
                            <td>
                                <select name="voorodak_options[gateway]">
                                    <?php
                                    $gateways = Voorodak_SMS::gateways();
                                    foreach ($gateways as $gateway_value => $gateway_name):
                                        $gateway_value_safe = esc_attr($gateway_value);
                                        $gateway_name_safe = esc_html($gateway_name);
                                        ?>
                                        <option value="<?php echo $gateway_value_safe; ?>" <?php selected($gateway, $gateway_value_safe); ?>><?php echo $gateway_name_safe; ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                        </tr>
                        <tr class="voorodak__username">
                            <th>نام کاربری سامانه</th>
                            <td><input type="text" name="voorodak_options[gateway_username]"
                                       value="<?php echo esc_attr($gateway_username); ?>"/></td>
                        </tr>
                        <tr class="voorodak__password">
                            <th>رمز عبور سامانه</th>
                            <td><input type="text" name="voorodak_options[gateway_password]"
                                       value="<?php echo esc_attr($gateway_password); ?>"/></td>
                        </tr>
                        <tr class="voorodak__from">
                            <th>خط ارسال کننده</th>
                            <td><input type="text" name="voorodak_options[gateway_from]"
                                       value="<?php echo esc_attr($gateway_from); ?>"/></td>
                        </tr>
                        <tr class="voorodak__pattern">
                            <th>
                                کد الگو (پترن)
                                <span class="hint">متغیر فراخوانی کد : otp</span>
                                <span class="hint">از فیلد زیر میتوانید نام متغیر پیشفرض را تغییر دهید</span>
                            </th>
                            <td><input type="text" name="voorodak_options[gateway_pattern_otp]"
                                       value="<?php echo esc_attr($gateway_pattern_otp); ?>"/></td>
                        </tr>
                        <tr class="voorodak__message">
                            <th>متن پیامک
                            <span class="hint">متغیر کد تایید در پیام: %otp%</span>
                                <span class="hint">اگر از فیلد پایین نام متغیر پیشفرض را تغییر دادید، داخل متن پیام نیز آن را تغییر دهید</span>

                            </th>
                            <td><textarea rows="10" placeholder="کد تایید شما: %otp%" name="voorodak_options[gateway_message]"><?php echo esc_attr($gateway_message); ?></textarea></td></td>
                        </tr>
                        <tr class="voorodak__variable">
                            <th>متغیر کد تایید</th>
                            <td><input type="text" name="voorodak_options[variable]"
                                       value="<?php echo esc_attr($variable); ?>"/></td>
                        </tr>
                        <tr>
                            <th><h3>تست ارسال پیامک</h3>
                            <span class="hint">ابتدا اطلاعات پیامکی را وارد نمایید و ذخیره کنید سپس تست بگیرید.</span></th>
                            <td></td>
                        </tr>
                        <tr>
                            <th>
                                <input type="text" id="test_phone_number" placeholder="شماره موبایل شما">
                            </th>
                            <td>
                                <span id="test_phone_submit" class="button">ارسال پیامک</span>
                            </td>
                        </tr>
                        <tr id="test_phone_result" style="display: none">
                            <th>پاسخ</th>
                            <td style="word-break: break-word;"></td>
                        </tr>
                    </table>
                    <div class="sms-notifications">
                        <h3>تنظیمات سایر پیامک ها
                            <svg width="20" height="20" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="m19.5 8.25-7.5 7.5-7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </h3>
                        <div class="sms-notifications-main" style="display: none">
                            <?php if (!(empty($gateway)) && strpos($gateway, '_pattern') !== false) : ?>
                                <table class="form-table">
                                    <tr>
                                        <th>شماره موبایل مدیران
                                            <span class="hint">جهت اطلاع رسانی ها به مدیریت</span>
                                        </th>
                                        <td>
                                            <textarea rows="5" placeholder="در هر خط میتوانید یک شماره موبایل وارد نمایید" name="voorodak_options[sms_admins]"><?php echo esc_textarea($sms_admins); ?></textarea>
                                        </td>
                                    </tr>
                                </table>
                                <h4>پیامک های ورود / ثبت نام</h4>
                                <div class="sms-notifications-notice">
                                    <div  class="sms-notifications-notice-icon">
                                        <svg width="36" height="36" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                            <path d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" stroke-linecap="round" stroke-linejoin="round"></path>
                                        </svg>
                                        راهنما
                                    </div>
                                    <div class="sms-notifications-notice-text">
                                        <ul>
                                            <li>متغیرهای مجاز در الگو: <mark>name</mark>,<mark>username</mark>,<mark>userid</mark></li>
                                            <li>
                                                متن نمونه الگو (به کاربر):
                                                <div class="sms-notifications-notice-text-message">
                                                    name عزیز
                                                    <br>
                                                    ثبت نام شما با موفقیت انجام شد.
                                                    <br>
                                                    به جمع کاربران ما خوش آمدید.
                                                    <br>
                                                    آدرس سایت شما
                                                </div>
                                            </li>
                                            <li>
                                                متن نمونه الگو (به مدیریت):
                                                <div class="sms-notifications-notice-text-message">
                                                    کاربر جدیدی در سایت با نام name و نام کاربری username ثبت نام کرد.
                                                    <br>
                                                    آدرس سایت شما
                                                </div>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                                <table class="form-table">
                                    <tr>
                                        <th><label>پیامک بعد از ورود کاربر (به مدیریت)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_login_admin]" value="1" <?php checked($sms_login_admin, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_login_admin_pattern]"
                                                   value="<?php echo esc_attr($sms_login_admin_pattern); ?>"/></td>
                                    </tr>
                                    <tr>
                                        <th><label>پیامک بعد از ورود کاربر نقش مدیر (به مدیریت)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_login_roleadmin_admin]" value="1" <?php checked($sms_login_roleadmin_admin, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_login_roleadmin_admin_pattern]"
                                                   value="<?php echo esc_attr($sms_login_roleadmin_admin_pattern); ?>"/></td>
                                    </tr>
                                    <tr>
                                        <th><label>پیامک بعد از ثبت نام کاربر (به مدیریت)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_register_admin]" value="1" <?php checked($sms_register_admin, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_register_admin_pattern]"
                                                   value="<?php echo esc_attr($sms_register_admin_pattern); ?>"/></td>
                                    </tr>
                                    <tr>
                                        <th><label>پیامک بعد از ورود کاربر (به کاربر)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_login]" value="1" <?php checked($sms_login, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_login_pattern]"
                                                   value="<?php echo esc_attr($sms_login_pattern); ?>"/></td>
                                    </tr>
                                    <tr>
                                        <th><label>پیامک بعد از ثبت نام کاربر (به کاربر)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_register]" value="1" <?php checked($sms_register, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_register_pattern]"
                                                   value="<?php echo esc_attr($sms_register_pattern); ?>"/></td>
                                    </tr>
                                </table>
                                <h4>پیامک های دیدگاه ها</h4>
                                <div class="sms-notifications-notice">
                                    <div  class="sms-notifications-notice-icon">
                                        <svg width="36" height="36" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                            <path d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" stroke-linecap="round" stroke-linejoin="round"></path>
                                        </svg>
                                        راهنما
                                    </div>
                                    <div class="sms-notifications-notice-text">
                                        <ul>
                                            <li>متغیرهای مجاز در الگو: <mark>title</mark>,<mark>postlink</mark></li>
                                            <li>
                                                متن نمونه الگو:
                                                <div class="sms-notifications-notice-text-message">
                                                    سلام!
                                                    <br>
                                                    به کامنت شما در مطلب title پاسخ داده شد.
                                                    <br>
                                                    آدرس سایت شما
                                                </div>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                                <table class="form-table">
                                    <tr>
                                        <th><label>پیامک بعد از ثبت دیدگاه جدید (به مدیریت)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_comment_new_admin]" value="1" <?php checked($sms_comment_new_admin, '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_comment_new_admin_pattern]"
                                                   value="<?php echo esc_attr($sms_comment_new_admin_pattern); ?>"/></td>
                                    </tr>
                                    <tr>
                                        <th><label>پیامک بعد از پاسخ به دیدگاه کاربر (به کاربر)</label></th>
                                        <td><input type="checkbox" class="v-toggle" name="voorodak_options[sms_comment_reply_user]" value="1" <?php checked($sms_comment_reply_user ?? '1', '1'); ?> /></td>
                                    </tr>
                                    <tr>
                                        <th>
                                            کد الگو (پترن)
                                        </th>
                                        <td><input type="text" name="voorodak_options[sms_comment_reply_user_pattern]"
                                                   value="<?php echo esc_attr($sms_comment_reply_user_pattern); ?>"/></td>
                                    </tr>
                                </table>
                                <?php if (function_exists('is_woocommerce')): ?>
                                    <h4>پیامک های سفارشات ووکامرس</h4>
                                    <div class="sms-notifications-notice">
                                        <div  class="sms-notifications-notice-icon">
                                            <svg width="36" height="36" data-slot="icon" aria-hidden="true" fill="none" stroke-width="1.5" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                                <path d="m11.25 11.25.041-.02a.75.75 0 0 1 1.063.852l-.708 2.836a.75.75 0 0 0 1.063.853l.041-.021M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9-3.75h.008v.008H12V8.25Z" stroke-linecap="round" stroke-linejoin="round"></path>
                                            </svg>
                                            راهنما
                                        </div>
                                        <div class="sms-notifications-notice-text">
                                            <ul>
                                                <li>متغیرهای مجاز در الگو: <mark>name</mark>,<mark>orderid</mark>,<mark>total</mark>,<mark>tracking</mark></li>
                                                <li>
                                                    متن نمونه الگو (به کاربر):
                                                    <div class="sms-notifications-notice-text-message">
                                                        name عزیز
                                                        <br>
                                                        سفارش شما با شناسه orderid و با مبلغ total با موفقیت ثبت شد و در وضعیت تکمیل شده قرار گرفت.
                                                        <br>
                                                        آدرس سایت شما
                                                    </div>
                                                </li>
                                                
                                                <li>
                                                    متن نمونه الگو (به مدیریت):
                                                    <div class="sms-notifications-notice-text-message">
                                                        سفارش جدیدی به نام name و با شناسه orderid در سایت ثبت شد.
                                                        <br>
                                                        آدرس سایت شما
                                                    </div>
                                                </li>
                                            </ul>
                                        </div>
                                    </div>
                                    <table class="form-table">
                                        <?php
                                        $order_statuses = wc_get_order_statuses();
                                        foreach ($order_statuses as $status_key => $status_name):
                                            if ($status_key === 'wc-checkout-draft') {
                                                continue;
                                            }
                                            $option_key_admin = "sms_order_{$status_key}_admin";
                                            $option_key_admin_pattern = "sms_order_{$status_key}_admin_pattern";
                                            $option_key_user = "sms_order_{$status_key}_user";
                                            $option_key_user_pattern = "sms_order_{$status_key}_user_pattern";
                                            $checked_admin = $settings[$option_key_admin] ?? '';
                                            $value_admin_pattern = $settings[$option_key_admin_pattern] ?? '';
                                            $checked_user = $settings[$option_key_user] ?? '';
                                            $value_user_pattern = $settings[$option_key_user_pattern] ?? '';
                                            ?>
                                            <tr>
                                                <th><label>پیامک وضعیت سفارش "<?php echo esc_html($status_name); ?>" (به مدیریت)</label></th>
                                                <td><input type="checkbox" class="v-toggle" name="voorodak_options[<?php echo esc_attr($option_key_admin); ?>]" value="1" <?php checked($checked_admin, '1'); ?> /></td>
                                            </tr>
                                            <tr>
                                                <th>
                                                    کد الگو (پترن)
                                                </th>
                                                <td><input type="text" name="voorodak_options[<?php echo esc_attr($option_key_admin_pattern); ?>]"
                                                           value="<?php echo esc_attr($value_admin_pattern); ?>"/></td>
                                            </tr>
                                            <tr>
                                                <th><label>پیامک وضعیت سفارش "<?php echo esc_html($status_name); ?>" (به کاربر)</label></th>
                                                <td><input type="checkbox" class="v-toggle" name="voorodak_options[<?php echo esc_attr($option_key_user); ?>]" value="1" <?php checked($checked_user, '1'); ?> /></td>
                                            </tr>
                                            <tr>
                                                <th>
                                                    کد الگو (پترن)
                                                </th>
                                                <td><input type="text" name="voorodak_options[<?php echo esc_attr($option_key_user_pattern); ?>]"
                                                           value="<?php echo esc_attr($value_user_pattern); ?>"/></td>
                                            </tr>
                                        <?php endforeach;
                                        ?>
                                    </table>
                                <?php endif; ?>
                            <?php else: ?>
                                <div class="sms-notifications-notice">
                                    برای ارسال سایر پیامک ها نیاز هست که از یک سامانه از نوع <b style="display: inline-block;margin: 0 3px;">Pattern</b> استفاده نمایید
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                </div>
                <div id="performance" class="voorodak__body-main-box" style="display: none">
                    <table class="form-table">
                        <tr>
                            <th>صفحه ورود / ثبت نام</th>
                            <td>
                                <?php
                                $pages = get_pages();
                                $exclude_ids = [];
                                if (class_exists('WooCommerce')) {
                                    $wc_pages = ['myaccount', 'cart', 'checkout'];
                                    foreach ($wc_pages as $slug) {
                                        $page_id = wc_get_page_id($slug);
                                        if ($page_id > 0) {
                                            $exclude_ids[] = $page_id;
                                        }
                                    }
                                }
                                ?>
                                <select name="voorodak_options[login_page_id]">
                                    <?php foreach ($pages as $page) : ?>
                                        <?php if (!in_array($page->ID, $exclude_ids)) : ?>
                                            <option value="<?php echo esc_attr($page->ID); ?>" <?php selected($login_page_id, $page->ID); ?>>
                                                <?php echo esc_html($page->post_title); ?>
                                            </option>
                                        <?php endif; ?>
                                    <?php endforeach; ?>
                                </select>
                            </td>

                        </tr>
                        <tr class="voorodak__backurl">
                            <th>صفحه بعد از لاگین کاربر</th>
                            <td>
                                <label><input type="radio" name="voorodak_options[backurl]" value="prev" <?php checked($backurl, 'prev'); ?> />صفحه قبلی</label>
                                <label><input type="radio" name="voorodak_options[backurl]" value="home" <?php checked($backurl, 'home'); ?> />صفحه اصلی</label>
                                <label><input type="radio" name="voorodak_options[backurl]" value="custom" <?php checked($backurl, 'custom'); ?> />صفحه دلخواه</label>
                            </td>
                        </tr>
                        <tr class="voorodak__backurl-custom">
                            <th>لینک صفحه دلخواه</th>
                            <td><input placeholder="https:// لینک به صورت " type="text" name="voorodak_options[backurl_custom]"
                                       value="<?php echo esc_attr($backurl_custom); ?>"/></td>
                        </tr>
                        <tr class="voorodak__logouturl">
                            <th>لینک صفحه بعد از خروج</th>
                            <td><input placeholder="https:// لینک به صورت " type="text" name="voorodak_options[logouturl]"
                                       value="<?php echo esc_attr($logouturl); ?>"/></td>
                        </tr>
                        <tr class="voorodak__panelurl-custom">
                            <th>لینک پنل کاربری اختصاصی
                            <span class="hint">اگر پنل کاربری اختصاصی دارید، لینک آن را در این بخش وارد کنید تا صفحه ورود ثبت نام بعد از لاگین به این صفحه تغییر کند</span>
                            </th>
                            <td><input placeholder="https:// لینک به صورت " type="text" name="voorodak_options[panelurl_custom]"
                                       value="<?php echo esc_attr($panelurl_custom); ?>"/></td>
                        </tr>
                        <tr>
                            <th>فرمت ذخیره نام کاربری</th>
                            <td>
                                <select name="voorodak_options[username_format]">
                                    <option value="with-zero" <?php selected($username_format, 'with-zero'); ?>>با صفر اول (مثلا 09191234567)</option>
                                    <option value="without-zero" <?php selected($username_format, 'without-zero'); ?>>بدون صفر اول (مثلا 9191234567)</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>فرمت ورود کاربران</th>
                            <td>
                                <select name="voorodak_options[login_type]">
                                    <option value="mobile" <?php selected($login_type, 'mobile'); ?>>فقط با موبایل</option>
                                    <option value="mobile-email" <?php selected($login_type, 'mobile-email'); ?>>با موبایل و ایمیل</option>
                                    <option value="mobile-email-username" <?php selected($login_type, 'mobile-email-username'); ?>>با موبایل و ایمیل و نام کاربری</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>نقش کاربر بعد از ثبت‌نام
                                <span class="hint">
                                در انتخاب این گزینه بسیار دقت کنید! به صورت پیشفرض روی مشترک و مشتری (درصورت نصب ووکامرس) انتخاب میشود
                            </span>
                            </th>
                            <td>
                                <?php
                                $roles = voorodak_get_roles();
                                $default_role = function_exists('is_woocommerce') ? 'customer' : 'subscriber';
                                $saved_role = $settings['default_role'] ?? $default_role;
                                ?>
                                <select name="voorodak_options[default_role]">
                                    <?php foreach ($roles as $role_key => $role_data) : ?>
                                        <option value="<?php echo esc_attr($role_key); ?>" <?php selected($saved_role, $role_key); ?>>
                                            <?php echo esc_html(translate_user_role($role_data['name'])); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                        </tr>

                        <tr>
                            <th>طول کد یکبار مصرف</th>
                            <td>
                                <select name="voorodak_options[otp_length]">
                                    <option value="4" <?php selected($otp_length, '4'); ?>>4 رقم</option>
                                    <option value="5" <?php selected($otp_length, '5'); ?>>5 رقم</option>
                                    <option value="6" <?php selected($otp_length, '6'); ?>>6 رقم (پیشنهادی)</option>
                                    <option value="7" <?php selected($otp_length, '7'); ?>>7 رقم</option>
                                    <option value="8" <?php selected($otp_length, '8'); ?>>8 رقم</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>حداقل طول رمز عبور مجاز
                                <span class="hint">
                                به جهت امنیت بیشتر توصیه میکنیم زیر 8 حرف قرار ندهید
                            </span>
                            </th>
                            <td>
                                <select name="voorodak_options[password_length]">
                                    <option value="4" <?php selected($password_length, '4'); ?>>4 حرف</option>
                                    <option value="6" <?php selected($password_length, '6'); ?>>6 حرف</option>
                                    <option value="8" <?php selected($password_length, '8'); ?>>8 حرف (پیشنهادی)</option>
                                    <option value="10" <?php selected($password_length, '10'); ?>>10 حرف</option>
                                    <option value="12" <?php selected($password_length, '12'); ?>>12 حرف</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__autofill">قابلیت اتوفیل AutoFill</label></th>
                            <td><input type="checkbox" id="voorodak__autofill" name="voorodak_options[autofill]" value="1" <?php checked($autofill, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__register-allow">جلوگیری از ثبت نام کاربران</label></th>
                            <td><input type="checkbox" id="voorodak__register-allow" name="voorodak_options[register_allow]" value="1" <?php checked($register_allow, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__family-name">فیلد نام و نام خانوادگی در ثبت نام</label></th>
                            <td><input type="checkbox" id="voorodak__family-name" name="voorodak_options[family_name]" value="1" <?php checked($family_name, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__family-name-force">الزامی بودن نام و نام خانوادگی</label></th>
                            <td><input type="checkbox" id="voorodak__family-name-force" name="voorodak_options[family_name_force]" value="1" <?php checked($family_name_force, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__email-field">فیلد ایمیل در ثبت نام</label></th>
                            <td><input type="checkbox" id="voorodak__email-field" name="voorodak_options[email_field]" value="1" <?php checked($email_field, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__email-field-force">الزامی بودن ایمیل</label></th>
                            <td><input type="checkbox" id="voorodak__email-field-force" name="voorodak_options[email_field_force]" value="1" <?php checked($email_field_force, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__email-random">ساخت ایمیل تصادفی</label>
                            <span class="hint">در صورت نگرفتن ایمیل از کاربر</span>
                            </th>
                            <td><input type="checkbox" id="voorodak__email-random" name="voorodak_options[email_random]" value="1" <?php checked($email_random, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__password-field">فیلد رمز عبور در ثبت نام</label><span class="hint">این فیلد در صورت فعال شدن پیشفرض الزامی خواهد بود</span></th>
                            <td><input type="checkbox" id="voorodak__password-field" name="voorodak_options[password_field]" value="1" <?php checked($password_field, '1'); ?> /></td>
                        </tr>

                        <tr>
                            <th><label for="voorodak__digits">هماهنگی با کاربران قبلی</label></th>
                            <td><input type="checkbox" class="v-toggle" id="voorodak__digits" name="voorodak_options[digits]" value="1" <?php checked($digits, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th>
                                <label>کلید متا کاربران قبلی</label>
                            </th>
                            <td><input type="text" name="voorodak_options[digits_meta]" value="<?php echo esc_attr($digits_meta); ?>"/></td>
                        </tr>
                        <tr>
                            <th>
                                <h3>ووکامرس</h3>
                            </th>
                        </tr>
                        <tr>
                            <th><label for="voorodak__woocommerce-login">تغییر صفحه ورود/ثبت نام ووکامرس</label></th>
                            <td><input type="checkbox" id="voorodak__woocommerce-login" name="voorodak_options[woocommerce_login]" value="1" <?php checked($woocommerce_login, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th><label for="voorodak__woocommerce-checkout">کاربر در صفحه پرداخت، اول لاگین کند</label></th>
                            <td><input type="checkbox" id="voorodak__woocommerce-checkout" name="voorodak_options[woocommerce_checkout]" value="1" <?php checked($woocommerce_checkout, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th>فیلد سفارشی ذخیره موبایل کاربر
                            <span class="hint">
                                مقدار پیشفرض ووکامرس: billing_phone
                            </span>
                            </th>
                            <td><input type="text" name="voorodak_options[user_field_meta]"
                                       value="<?php echo esc_attr($user_field_meta); ?>"/></td>
                        </tr>
                        <tr>
                            <th>فیلد سفارشی ذخیره موبایل کاربر 2
                                <span class="hint">
                                ذخیره در فیلد سفارشی جدا و اختصاصی دیگر
                            </span>
                            </th>
                            <td><input type="text" name="voorodak_options[user_field_meta2]"
                                       value="<?php echo esc_attr($user_field_meta2); ?>"/></td>
                        </tr>
                    </table>
                </div>
                <div id="display" class="voorodak__body-main-box" style="display: none">
                    <table class="form-table">
                        <tr>
                            <th>قالب نمایش</th>
                            <td>
                                <select name="voorodak_options[template]">
                                    <option value="default" <?php selected($template, 'default'); ?>>پیشفرض</option>
                                    <option value="digikala" <?php selected($template, 'digikala'); ?>>دیجی کالا</option>
                                    <option value="zarinpal" <?php selected($template, 'zarinpal'); ?>>زرین پال</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>لوگو</th>
                            <td>
                                <input type="hidden" name="voorodak_options[logo]" id="voorodak__logo"
                                       value="<?php echo $logo; ?>"/>
                                <input type="button" id="voorodak__logo-upload-button" class="button" value="آپلود تصویر"/>
                                <input type="button" id="voorodak__logo-upload-remove" class="button"
                                       value="حذف تصویر" <?php echo empty($logo) ? 'style="display:none;"' : ''; ?> />
                                <div id="voorodak__logo-preview">
                                    <?php if ($logo) : ?>
                                        <img src="<?php echo $logo; ?>" style="max-width: 200px; max-height: 200px;"/>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th>تصویر کنار فرم (برای قالب زرین پال)</th>
                            <td>
                                <input type="hidden" name="voorodak_options[cover]" id="voorodak__cover"
                                       value="<?php echo $cover; ?>"/>
                                <input type="button" id="voorodak__cover-upload-button" class="button" value="آپلود تصویر"/>
                                <input type="button" id="voorodak__cover-upload-remove" class="button"
                                       value="حذف تصویر" <?php echo empty($cover) ? 'style="display:none;"' : ''; ?> />
                                <div id="voorodak__cover-preview">
                                    <?php if ($cover) : ?>
                                        <img src="<?php echo $cover; ?>" style="max-width: 200px; max-height: 200px;"/>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th>رنگ پس زمینه</th>
                            <td><input type="text" class="voorodak__color-picker" data-default-color="#ffffff"
                                       name="voorodak_options[bg_color]"
                                       value="<?php echo esc_attr($bg_color); ?>"/></td>
                        </tr>
                        <tr>
                            <th>رنگ دکمه</th>
                            <td><input type="text" class="voorodak__color-picker" data-default-color="#5498fa"
                                       name="voorodak_options[button_color]"
                                       value="<?php echo esc_attr($button_color); ?>"/></td>
                        </tr>
                        <tr>
                            <th>رنگ دکمه (هنگام هاور)</th>
                            <td><input type="text" class="voorodak__color-picker" data-default-color="#2c61a6"
                                       name="voorodak_options[button_color_hover]"
                                       value="<?php echo esc_attr($button_color_hover); ?>"/></td>
                        </tr>
                        <tr>
                            <th>متن اولیه فرم</th>
                            <td><input type="text" name="voorodak_options[form_name]"
                                       value="<?php echo esc_attr($form_name); ?>"/></td>
                        </tr>
                        <tr>
                            <th>
                                متن پذیرش قوانین و مقررات
                                <span class="hint">در صورت خالی بودن نمایش داده نخواهد شد</span>
                            </th>
                            <td>
                                <?php
                                wp_editor(
                                    $term_editor,
                                    'term_editor',
                                    array(
                                        'textarea_name' => 'voorodak_options[term_editor]',
                                        'media_buttons' => false,
                                        'teeny'         => true,
                                        'quicktags'     => false,
                                        'tinymce'       => array(
                                            'toolbar1' => 'bold,italic,underline,forecolor,link,unlink',
                                            'toolbar2' => '',
                                            'plugins'  => 'textcolor link'
                                        )
                                    )
                                );

                                ?>
                            </td>
                        </tr>
                    </table>
                </div>
                <div id="advance" class="voorodak__body-main-box" style="display: none;">
                    <table class="form-table">
                        <tr>
                            <th>نمایش تاریخ عضویت کاربران
                                <span class="hint">با فعال کردن این گزینه، تاریخ عضویت کاربران در صفحه لیست کاربران نمایش داده میشود.</span>
                            </th>
                            <td><input type="checkbox" name="voorodak_options[date_register]" value="1" <?php checked($date_register, '1'); ?> /></td>
                        </tr>
                        <tr>
                            <th>خروجی CSV کاربران</th>
                            <td><span id="download_list_users" class="button">دانلود لیست کاربران</span></td>
                        </tr>
                    </table>
                </div>
                <div id="security" class="voorodak__body-main-box" style="display: none;">
                    <table class="form-table">
                        <tr>
                            <th><label for="voorodak__disable-admin-login">بستن ورود نقش های ادمین</label>
                                <span class="hint">با فعال کردن این گزینه، از ورود ادمین ها با دسترسی مدیر کل توسط فرم ورودک جلوگیری میشود و فقط از طریق صفحه ورود وردپرس امکان ورود وجود دارد، برای تدابیر امنیتی بالا پیشنهاد میشود.</span>

                            </th>
                            <td><input type="checkbox" id="voorodak__disable-admin-login" name="voorodak_options[disable_admin_login]" value="1" <?php checked($disable_admin_login, '1'); ?> /></td>
                        </tr>

                        <tr>
                            <th>
                                تعداد درخواست مجاز
                                <span class="hint">حداکثر درخواست قبل از بلاک، 10 مقدار پیشنهادی میباشد</span>
                            </th>
                            <td>
                                <select name="voorodak_options[max_requests]">
                                    <?php
                                    $max_requests = $settings['max_requests'] ?? 10;
                                    foreach ([5,10,15,20,25,30] as $val) {
                                        echo '<option value="'.$val.'" '.selected($max_requests, $val, false).'>'.$val.'</option>';
                                    }
                                    ?>
                                </select>
                            </td>
                        </tr>

                        <tr>
                            <th>
                                مدت زمان بلاک (دقیقه)
                                <span class="hint">زمان مسدودسازی، 10 مقدار پیشنهادی میباشد</span>
                            </th>
                            <td>
                                <select name="voorodak_options[block_minutes]">
                                    <?php
                                    $block_minutes = $settings['block_minutes'] ?? 10;
                                    foreach ([5,10,15,20,25,30] as $val) {
                                        echo '<option value="'.$val.'" '.selected($block_minutes, $val, false).'>'.$val.' دقیقه</option>';
                                    }
                                    ?>
                                </select>
                            </td>
                        </tr>

                        <tr>
                            <th>بلک لیست موبایل
                                <span class="hint">مسدودسازی ارسال پیامک و ورود ثبت نام</span>
                            </th>
                            <td>
                                <textarea rows="5" placeholder="در هر خط میتوانید یک شماره موبایل وارد نمایید" name="voorodak_options[block_mobile]"><?php echo esc_textarea($block_mobile); ?></textarea>
                            </td>
                        </tr>
                        <tr>
                            <th>بلک لیست آیپی
                                <span class="hint">مسدودسازی آیپی</span>
                            </th>
                            <td>
                                <textarea rows="5" placeholder="در هر خط میتوانید یک آیپی وارد نمایید" name="voorodak_options[block_ip]"><?php echo esc_textarea($block_ip); ?></textarea>
                            </td>
                        </tr>
                    </table>
                </div>
                <div id="develop" class="voorodak__body-main-box" style="display: none;">
                    <table class="form-table">
<!--                        <tr>-->
<!--                            <th>استفاده از شورتکد-->
<!--                                <span class="hint">با فعالسازی این گزینه فایل های افزونه در تمام صفحات لود میشود تا بتوانید از شورتکد استفاده کنید (توصیه نمیشود)</span>-->
<!--                            </th>-->
<!--                            <td><input type="checkbox" name="voorodak_options[use_shortcode]" value="1" --><?php //checked($use_shortcode, '1'); ?><!-- /></td>-->
<!--                        </tr>-->
                        <tr style="border-bottom: 1px solid #eee">
                            <th>شورتکد دکمه ورود/ ثبت نام</th>
                            <td style="direction: ltr">
                                [voorodak_account_btn]
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #eee">
                            <th>شورتکد دکمه ورود/ ثبت نام
                            <span class="hint">مخصوص قالب آسترا</span>
                            </th>
                            <td style="direction: ltr">
                                [voorodak_account_btn style="astra"]
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #eee">
                            <th>نمایش نام کاربر در دکمه هنگام ورود
                                <span class="hint">با گزینه showname برابر با yes میتوانید نام کاربر را هنگام ورود در سایت درون دکمه، جای متن حساب کاربری نمیاش دهید </span>
                            </th>
                            <td style="direction: ltr">
                                [voorodak_account_btn showname="yes"]
                            </td>
                        </tr>

                    </table>
<!--                    <div class="doc-box">-->
<!--                        <h3>شورتکد افزونه</h3>-->
<!--                        <p>-->
<!--                        جهت استفاده از شورتکد ابتدا تیک بالا را فعال کنید، سپس میتوانید شورتکد را در ویجت های المنتور یا ادیتور برگه ها یا پاپ آپ های سفارشی خود آن را قرار دهید-->
<!--                        </p>-->
<!--                        <div class="code-box shortcode">-->
<!--                            <code>[voorodak]</code>-->
<!--                        </div>-->
<!--                    </div>-->

                    <div class="doc-box">
                        <h3>هوک بعد از لاگین</h3>
                        <p>
                            شما می‌توانید با استفاده از اکشن زیر، عملیات دلخواهی پس از ورود موفق کاربر انجام دهید:
                        </p>
                        <div class="code-box php">
                            <code>
                                &lt;?php
                                add_action('voorodak_after_do_login', function($user_id) {
                                // مثال: ثبت لاگ یا ارسال ایمیل خوش‌آمدگویی
                                error_log("کاربر با شناسه {$user_id} وارد شد.");
                                });
                                ?&gt;
                            </code>
                        </div>
                    </div>

                    <div class="doc-box">
                        <h3>هوک بعد از ثبت نام</h3>
                        <p>
                            شما می‌توانید با استفاده از اکشن زیر، عملیات دلخواهی پس از ثبت نام موفق کاربر انجام دهید:
                        </p>
                        <div class="code-box php">
                            <code>
                                &lt;?php
                                add_action('voorodak_after_do_register', function($user_id) {
                                // مثال: ثبت لاگ یا ارسال ایمیل خوش‌آمدگویی
                                error_log("کاربر با شناسه {$user_id} ثبت نام کرد.");
                                });
                                ?&gt;
                            </code>
                        </div>
                    </div>

                    <div class="doc-box">
                        <h3>وضعیت لاگ 10 درخواست آخر وب سرویس پیامکی</h3>
                        <div class="code-box" style="text-align: right;margin-top: 20px;padding: 8px;">
                           <?php echo voorodak_log_display(); ?>
                        </div>
                    </div>

                </div>

                <div id="license" class="voorodak__body-main-box" style="display: none">
                    <table class="form-table">
                        <tr class="voorodak__license">
                            <th>کلید لایسنس
                            <?php do_action('voorodak_before_sms_setting'); ?>
                            </th>
                            <td><input type="text" name="voorodak_options[license_key]" value="<?php echo esc_attr($license_key); ?>" /></td>
                        </tr>
                    </table>
                </div>
                <?php submit_button(); ?>
            </form>
            <div class="voorodak__body-main-hints">
                <div class="melipayamak">
                    <img src="<?php echo plugin_dir_url(__DIR__); ?>/assets/images/logo.svg" alt="">
                    <div class="melipayamak__main">
                        <h3>تخفیف ویژه ملی پیامک برای افزونه ورودک</h3>
                        <p>استفاده کنندگان افزونه ورودک میتوانند با کوپن زیر تا 10 درصد تخفیف از سامانه ملی پیامک خرید نمایند</p>
                    </div>
                    <div class="melipayamak__coupon">
                        <div class="melipayamak__coupon-main">
                            <div class="melipayamak__coupon-main-inner">MPQPTDF</div>
                        </div>
                    </div>
                </div>
                <div class="voorodak__body-main-hints-list">
                    <h3>راهنمای استفاده</h3>
                    <ol>
                        <li>یک سامانه پیامکی تهیه نمایید و اطلاعات حساب خود را در تنظیمات افزونه قرار دهید</li>
                        <li>یک برگه به طور خودکار در سایت شما با نام ورود ثبت نام ایجاد شده است ، که صفحه اختصاصی ورود ثبت نام شما میباشد
                            <a target="_blank" href="<?php echo esc_url(get_the_permalink($login_page_id)); ?>">مشاهده برگه</a> (باید در حالت غیر لاگین یعنی private یا incognito برگه را باز کنید تا ورود ثبت نام را مشاهده کنید) </li>
                        <li>لینک این صفحه را در تنظیمات سربرگ قالب خود یا المنتور در دکمه ورود ثبت نام قرار دهید تا در دسترس باشد</li>
                        <li>همچنین از تب ظاهری میتوانید برگه ورود ثبت نام را تغییر دهید و برگه دیگری را انتخاب نمایید</li>
                    </ol>
                    <div style="background: #0d9488;color:#fff;padding: 10px;text-align: center;border-radius: 10px">
                        اگر از افزونه <b>راکت</b> یا <b>لایت اسپید</b> استفاده میکنید، به بخش برگه ها بروید و حتما کش برگه ورود ثبت نام افزونه ورودک را از تنظیمات ویرایش آن برگه غیرفعال کنید تا کلید های امنیتی پلاگین کش نشوند
                    </div>
                </div>
                <div class="taktheme">
                    <a href="https://taktheme.com" target="_blank">
                        <img src="<?php echo plugin_dir_url(__DIR__); ?>/assets/images/taktheme.webp" alt="">
                    </a>
                    <p>در صورت وجود هرگونه مشکل در افزونه یا دریافت پشتیبانی میتوانید از طریق تلگرام به پشتیبانی تک تم پیام دهید</p>
                    <a href="https://t.me/taktheme_support" rel="nofollow" class="taktheme-support">پشتیبانی تلگرام</a>
                </div>
            </div>
        </div>
    </div>
</div>


<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;
$session_key = session_id();
$template = $settings['template'] ?? 'default';
$login_page_id = $settings['login_page_id'] ?? '';
$bg_color = $settings['bg_color'] ?? '#ffffff';
$button_color = $settings['button_color'] ?? '#5498fa';
$button_color_hover = $settings['button_color_hover'] ?? '#2c61a6';
$logo = $settings['logo'] ?? '';
$cover = $settings['cover'] ?? '';
$otp_length = $settings['otp_length'] ?? '6';
$family_name = $settings['family_name'] ?? '';
$email_field = $settings['email_field'] ?? '';
$password_field = $settings['password_field'] ?? '';
$login_type = $settings['login_type'] ?? 'mobile-email';
if ($login_type == 'mobile'){
    $username_placeholder = 'شماره موبایل';
}elseif ($login_type == 'mobile-email'){
    $username_placeholder = 'شماره موبایل یا ایمیل';
}else{
    $username_placeholder = 'شماره موبایل یا ایمیل یا نام کاربری';
}
$reset_token = $_GET['reset_token'] ?? null;
$form_name = $settings['form_name'] ?? 'ورود / ثبت نام';
$term_editor = $settings['term_editor'] ?? '';
$button_style = "style=\"--voorodak-button-color: " . esc_attr($button_color) . "; --voorodak-button-color-hover: " . esc_attr($button_color_hover) . ";\"";
?>
<div class="voorodak voorodak-<?php echo esc_attr($template); ?>" style="background: <?php echo esc_attr($bg_color); ?>">
    <div class="voorodak__wrapper" <?php echo $button_style; ?>>
        <?php if ($template == 'zarinpal'): ?>
        <div class='voorodak__wrapper-main-right'>
        <?php endif; ?>
        <div class="voorodak__wrapper-main">
            <div class="voorodak__wrapper-main-head">
                <svg style="display: none" class="20" height="20" data-slot="icon" aria-hidden="true" fill="none" stroke-width="2" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" stroke-linecap="round" stroke-linejoin="round"></path>
                </svg>
                <?php if ($logo): ?>
                    <a href="<?php echo home_url(); ?>">
                        <img src="<?php echo esc_attr($logo); ?>" width="150" height="65" alt="<?php bloginfo('name'); ?>">
                    </a>
                <?php endif; ?>
            </div>
            <?php if (!$reset_token): ?>
                <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-username">
                    <div class="voorodak__wrapper-main-box-title"><?php esc_html_e($form_name); ?></div>
                    <div class="voorodak__wrapper-main-box-description">
                        <p>سلام!</p>
                        <?php if ($login_type == 'mobile'){
                            $placeholder_inter = 'شماره موبایل';
                        }elseif ($login_type == 'mobile-email'){
                            $placeholder_inter = 'شماره موبایل یا ایمیل';
                        }else{
                            $placeholder_inter = 'اطلاعات کاربری';
                        } ?>
                        <p>لطفا <?php esc_html_e($placeholder_inter); ?> خود را وارد کنید</p>
                    </div>
                    <div class="voorodak__wrapper-main-box-field">
                        <input type="text" name="voorodak__username" placeholder="<?php echo esc_attr($username_placeholder); ?>" autocomplete="off"<?php if ($login_type == 'mobile') echo ' inputmode="numeric"'; ?>>
                    </div>
                    <button id="voorodak__submit-username">ورود</button>
                    <?php if($term_editor): ?>
                    <div class="voorodak__terms">
                        <?php echo $term_editor; ?>
                    </div>
                    <?php endif; ?>
                </form>
                <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-otp" style="display: none">
                    <div class="voorodak__wrapper-main-box-title">کد تایید</div>
                    <div class="voorodak__wrapper-main-box-description"></div>
                    <div class="voorodak__wrapper-main-box-field">
                        <?php if($family_name): ?>
                        <input type="text" name="voorodak__first_name" placeholder="نام" autocomplete="off">
                        <input type="text" name="voorodak__last_name" placeholder="نام خانوادگی" autocomplete="off">
                        <div class="clear"></div>
                        <?php endif; ?>
                        <?php if ($email_field): ?>
                        <input type="text" name="voorodak__email" placeholder="ایمیل" autocomplete="off">
                        <?php endif; ?>
                        <?php if ($password_field): ?>
                        <input type="password" name="voorodak__password_register" placeholder="رمز عبور" autocomplete="off">
                        <?php endif; ?>
                        <input type="text" class="otp-field1" name="voorodak__otp" placeholder="کد تایید" inputmode="numeric" maxlength="<?php echo esc_attr($otp_length) ?>" autocomplete="one-time-code">
                    </div>
                    <?php if ($login_type != 'mobile'): ?>
                    <div class="voorodak__wrapper-main-box-action">
                        <a href="#voorodak__wrapper-main-password">ورود با رمز عبور
                            <svg width="12" height="12" data-slot="icon" aria-hidden="true" fill="none" stroke-width="3" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15.75 19.5 8.25 12l7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </a>
                    </div>
                    <?php endif; ?>
                    <div class="voorodak__wrapper-main-box-timer">
                        <div class="voorodak__wrapper-main-box-timer-countdown">
                            <span>02:00</span>
                            تا دریافت مجدد کد
                        </div>
                        <div class="voorodak__wrapper-main-box-timer-resend" style="display: none;">
                            دریافت کد
                            <svg width="12" height="12" data-slot="icon" aria-hidden="true" fill="none" stroke-width="3" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15.75 19.5 8.25 12l7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </div>
                    </div>
                    <button id="voorodak__submit-otp">تایید</button>
                </form>
                <?php if ($login_type != 'mobile'): ?>
                <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-password" style="display: none">
                    <div class="voorodak__wrapper-main-box-title">رمز عبور را وارد کنید</div>
                    <div class="voorodak__wrapper-main-box-field">
                        <input type="password" name="voorodak__password" placeholder="رمز عبور" autocomplete="off">
                    </div>
                    <div class="voorodak__wrapper-main-box-action">
                        <a href="#voorodak__wrapper-main-otp">ورود با رمز یکبار مصرف
                            <svg width="12" height="12" data-slot="icon" aria-hidden="true" fill="none" stroke-width="3" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15.75 19.5 8.25 12l7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </a>
                        <a href="#voorodak__wrapper-main-forget">فراموشی رمز عبور
                            <svg width="12" height="12" data-slot="icon" aria-hidden="true" fill="none" stroke-width="3" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15.75 19.5 8.25 12l7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </a>
                    </div>
                    <button id="voorodak__submit-password">تایید</button>
                </form>
                <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-forget" style="display: none">
                    <div class="voorodak__wrapper-main-box-title">فراموشی رمز عبور</div>
                    <div class="voorodak__wrapper-main-box-field">
                        <input type="text" name="voorodak__username-forget" placeholder="شماره موبایل یا ایمیل" autocomplete="off">
                    </div>
                    <button id="voorodak__submit-forget">تایید</button>
                </form>
                <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-otp-reset" style="display: none">
                    <div class="voorodak__wrapper-main-box-title">کد تایید</div>
                    <div class="voorodak__wrapper-main-box-field">
                        <input type="text" class="otp-field2" name="voorodak__otp-reset" placeholder="کد تایید" inputmode="numeric" maxlength="<?php echo esc_attr($otp_length) ?>" autocomplete="one-time-code">
                    </div>
                    <div class="voorodak__wrapper-main-box-timer">
                        <div class="voorodak__wrapper-main-box-timer-countdown">
                            <span>02:00</span>
                            تا دریافت مجدد کد
                        </div>
                        <div class="voorodak__wrapper-main-box-timer-resend" style="display: none;">
                            دریافت کد
                            <svg width="12" height="12" data-slot="icon" aria-hidden="true" fill="none" stroke-width="3" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15.75 19.5 8.25 12l7.5-7.5" stroke-linecap="round" stroke-linejoin="round"></path>
                            </svg>
                        </div>
                    </div>
                    <button id="voorodak__submit-otp-reset">تایید</button>
                </form>
                <?php endif; ?>
            <?php endif; ?>
            <?php if ($login_type != 'mobile'): ?>
            <form method="post" action="" class="voorodak__wrapper-main-box" id="voorodak__wrapper-main-reset"<?php echo !$reset_token ? ' style="display: none"' : ''; ?>>
                <div class="voorodak__wrapper-main-box-title">تغییر رمز عبور</div>
                <div class="voorodak__wrapper-main-box-field">
                    <input type="password" name="voorodak__new-password" placeholder="رمز عبور جدید" autocomplete="off">
                </div>
                <div class="voorodak__wrapper-main-box-field">
                    <input type="password" name="voorodak__new-password2" placeholder="تکرار رمز عبور جدید" autocomplete="off">
                </div>
                <input type="hidden" name="voorodak__reset-token" value="<?php echo esc_attr($reset_token); ?>">
                <button id="voorodak__submit-reset">تایید</button>
            </form>
            <?php endif; ?>
        </div>
        <div class="voorodak__wrapper-messages"></div>
        <?php if ($template == 'zarinpal'): ?>
        </div><div class='voorodak__wrapper-main-left' style="background-color: <?php echo ($cover) ? 'transparent' : esc_attr($button_color) ; ?>">
            <?php if ($cover && !wp_is_mobile()): ?>
                <img src="<?php echo esc_attr($cover); ?>" width="600" height="500" alt="<?php bloginfo('name'); ?>">
            <?php endif; ?>
        </div></div>
        <?php endif; ?>
    </div>
</div>


<?php
// Exit if accessed directly.
defined('ABSPATH') || exit;
?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<?php echo do_shortcode('[voorodak]'); ?>
<?php wp_footer(); ?>
</body>
</html>

jQuery(document).ready(function () {

    let voorodak_ajax = true;
    let voorodak_error = true;
    const voorodak_messages = jQuery(".voorodak__wrapper-messages");
    const voorodak_security = voorodak_data.security;
    const voorodak_otp_length = voorodak_data.otp_length;
    const voorodak_password_length = voorodak_data.password_length;
    const voorodak_login_url = voorodak_data.login_url;
    const voorodak_backurl = voorodak_data.backurl;
    const voorodak_login_type = voorodak_data.login_type;
    const voorodak_mobile_regex = /^09[0-9]{9}$/;
    const voorodak_email_regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const voorodak_number_regex = /^-?\d+$/;

    function autoFillOTP(selector) {
        if (!("OTPCredential" in window)) return

        const otpInput = document.querySelector(selector)
        if (!otpInput) return

        const otpForm = otpInput.closest("form")
        if (!otpForm) return

        const submitBtn = otpForm.querySelector("button")

        const abortController = new AbortController()

        otpForm.addEventListener("submit", e => {
            e.preventDefault()
            abortController.abort()
        })

        navigator.credentials.get({
            otp: { transport: ["sms"] },
            signal: abortController.signal
        }).then(otp => {
            otpInput.value = otp.code
            if (submitBtn) {
                submitBtn.click()
            }
        }).catch(() => {})
    }



    jQuery('.voorodak__wrapper-main-box-field input').bind("input", function () {
        var pn = ["۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹"];
        var en = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"];
        var cache = jQuery(this).val();
        for (var i = 0; i < 10; i++) {
            var regex_fa = new RegExp(pn[i], 'g');
            cache = cache.replace(regex_fa, en[i]);
        }
        jQuery(this).val(cache);
    });

    jQuery(".voorodak__wrapper-main-box-action a").click(function (e) {
        e.preventDefault();
        var target = jQuery(this).attr('href');
        jQuery(".voorodak__wrapper-main-box").hide();
        jQuery(target).fadeIn();
        voorodak_messages.html('');
    });

    jQuery(".voorodak__wrapper-main-head svg").click(function (){
        jQuery(this).hide();
        jQuery(".voorodak__wrapper-main-box").hide();
        jQuery("#voorodak__wrapper-main-username").fadeIn();
    });

    function removeValidationMessages() {
        jQuery(".voorodak__wrapper-main-box-field-invalid").next('span').remove();
        jQuery(".voorodak__wrapper-main-box-field-invalid").removeClass('voorodak__wrapper-main-box-field-invalid');
    }

    function addValidationMessage(element, message) {
        element.addClass('voorodak__wrapper-main-box-field-invalid').after('<span>' + message + '</span>');
    }

    function validateUsername(element) {
        var value = element.val().trim();
        removeValidationMessages();
        if (value.length < 1) {
            addValidationMessage(element, 'لطفا این قسمت را خالی نگذارید');
            voorodak_error = true;
            return;
        }
        if (voorodak_login_type === 'mobile' && !voorodak_mobile_regex.test(value)) {
            addValidationMessage(element, 'شماره موبایل صحیح نمی‌باشد.');
            voorodak_error = true;
            return;
        } else if (voorodak_login_type === 'mobile-email' && !voorodak_mobile_regex.test(value) && !voorodak_email_regex.test(value)) {
            addValidationMessage(element, 'شماره موبایل یا ایمیل صحیح نمی‌باشد.');
            voorodak_error = true;
            return;
        } else {
            voorodak_error = false;
        }
    }

    function validateOTP(element) {
        var value = element.val().trim();
        removeValidationMessages();
        if (value.length !== parseInt(voorodak_otp_length)){
            addValidationMessage(element, 'کد تایید باید ' + voorodak_otp_length + ' رقم باشد');
            voorodak_error = true;
        } else if (!voorodak_number_regex.test(value)) {
            addValidationMessage(element, 'کد تایید باید عددی باشد');
            voorodak_error = true;
        } else {
            voorodak_error = false;
        }
    }

    function validatePassword(element) {
        var value = element.val().trim();
        removeValidationMessages();
        if (value.length < voorodak_password_length) {
            addValidationMessage(element, 'رمز عبور باید حداقل ' + voorodak_password_length + ' حرف باشد');
            voorodak_error = true;
        } else {
            voorodak_error = false;
        }
    }

    jQuery("input[name=voorodak__username],input[name=voorodak__username-forget]").focusout(function(){
        validateUsername(jQuery(this));
    });

    jQuery("input[name=voorodak__otp],input[name=voorodak__otp-reset]").focusout(function(){
        validateOTP(jQuery(this));
    });

    jQuery("input[name=voorodak__otp],input[name=voorodak__otp-reset]").on('input', function () {
        var value = jQuery(this).val().trim();
        if (value.length >= parseInt(voorodak_otp_length)) {
            jQuery(jQuery(this)).parent().nextAll('button').trigger('click');
        }
    });

    jQuery("input[name=voorodak__password],input[name=voorodak__new-password]").focusout(function(){
        validatePassword(jQuery(this));
    });

    jQuery('.voorodak__wrapper-main form').on('submit', function (e) {
        e.preventDefault();
    });

    var intervalId;
    let duration = 120;
    const voorodak_timer = jQuery(".voorodak__wrapper-main-box-timer-countdown span");
    const timerKey = 'savedTimer';
    const startTimeKey = 'startTime';
    function startTimer(duration, display) {
        var timer = duration, minutes, seconds;
        intervalId = setInterval(function () {
            minutes = parseInt(timer / 60, 10);
            seconds = parseInt(timer % 60, 10);
            minutes = minutes < 10 ? "0" + minutes : minutes;
            seconds = seconds < 10 ? "0" + seconds : seconds;
            display.text(minutes + ":" + seconds);
            if (--timer < 0) {
                clearInterval(intervalId);
                localStorage.removeItem(timerKey);
                localStorage.removeItem(startTimeKey);
                jQuery('.voorodak__wrapper-main-box-timer-resend').fadeIn();
                jQuery('.voorodak__wrapper-main-box-timer-countdown').hide();
            }else {
                jQuery('.voorodak__wrapper-main-box-timer-resend').hide();
                jQuery('.voorodak__wrapper-main-box-timer-countdown').fadeIn();
            }
        }, 1000);
    }

    function resumeTimer() {
        const savedTimer = localStorage.getItem(timerKey);
        const savedStartTime = localStorage.getItem(startTimeKey);
        if (savedTimer && savedStartTime) {
            const elapsedTime = Math.floor((Date.now() - savedStartTime) / 1000);
            const remainingTime = savedTimer - elapsedTime;
            if (remainingTime > 0) {
                startTimer(remainingTime, voorodak_timer);
            } else {
                localStorage.removeItem(timerKey);
                localStorage.removeItem(startTimeKey);
            }
        }
    }
    resumeTimer();

    function ajaxRequest(data, beforeSendCallback, successCallback, errorCallback) {
        if (voorodak_ajax && !voorodak_error) {
            jQuery.ajax({
                url: voorodak_data.ajax_url,
                data: data,
                dataType: 'json',
                type: 'post',
                timeout: 20000,
                beforeSend: beforeSendCallback,
                error: errorCallback,
                success: successCallback
            });
        }
    }

    jQuery(document).on('click', '#voorodak__submit-username', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var username_element = jQuery("input[name=voorodak__username]");
        var captcha_element = jQuery("input[name=voorodak__captcha]");
        var username = username_element.val();
        var captcha = captcha_element.val();
        validateUsername(username_element);
        ajaxRequest(
            {
                'action': action,
                'username': username,
                'captcha': captcha,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    jQuery("#voorodak__wrapper-main-username").hide();
                    jQuery(".voorodak__wrapper-main-head svg").fadeIn();
                    if (voorodak_mobile_regex.test(username)){
                        if (response.data.sent) {
                            if (intervalId) {
                                clearInterval(intervalId);
                            }
                            voorodak_timer.text("02:00");
                            localStorage.setItem(startTimeKey, Date.now());
                            localStorage.setItem(timerKey, duration);
                            startTimer(duration, voorodak_timer);
                        }
                        jQuery('#voorodak__wrapper-main-otp .voorodak__wrapper-main-box-description').html(response.data.description);
                        if (response.data.register){
                            jQuery(".voorodak__wrapper-main-box-action").css('display','none');
                            jQuery("input[name=voorodak__first_name],input[name=voorodak__last_name],input[name=voorodak__email],input[name=voorodak__password_register]").css('display','block');
                            if (voorodak_data.autofill === "1") {
                                autoFillOTP('.otp-field1');
                            }
                        }else {
                            jQuery("input[name=voorodak__first_name],input[name=voorodak__last_name],input[name=voorodak__email],input[name=voorodak__password_register]").css('display','none');
                            jQuery(".voorodak__wrapper-main-box-action").css('display','flex');
                            jQuery("a[href='#voorodak__wrapper-main-otp']").css('display','inline-flex');
                            if (voorodak_data.autofill === "1") {
                                autoFillOTP('.otp-field1');
                            }
                        }
                        jQuery("#voorodak__wrapper-main-otp").fadeIn();
                    }else {
                        jQuery("a[href='#voorodak__wrapper-main-otp']").css('display','none');
                        jQuery("#voorodak__wrapper-main-password").fadeIn();
                    }
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    jQuery(document).on('click', '#voorodak__submit-otp', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var username = jQuery("input[name=voorodak__username]").val();
        var first_name = jQuery("input[name=voorodak__first_name]").val();
        var last_name = jQuery("input[name=voorodak__last_name]").val();
        var email = jQuery("input[name=voorodak__email]").val();
        var password = jQuery("input[name=voorodak__password_register]").val();
        var otp_element = jQuery("input[name=voorodak__otp]");
        var otp = otp_element.val();
        validateOTP(otp_element);
        ajaxRequest(
            {
                'action': action,
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'password': password,
                'otp': otp,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    voorodak_ajax = false;
                    window.location = voorodak_backurl;
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    jQuery(document).on('click', '#voorodak__submit-password', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var username = jQuery("input[name=voorodak__username]").val();
        var password_element = jQuery("input[name=voorodak__password]");
        var password = password_element.val();
        validatePassword(password_element);
        ajaxRequest(
            {
                'action': action,
                'username': username,
                'password': password,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    voorodak_ajax = false;
                    window.location = voorodak_backurl;
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    jQuery(document).on('click', '#voorodak__submit-forget', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var username_element = jQuery("input[name=voorodak__username-forget]");
        var username = username_element.val();
        validateUsername(username_element);
        ajaxRequest(
            {
                'action': action,
                'username': username,
                'login_url': voorodak_login_url,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    if (voorodak_mobile_regex.test(username)){
                        if (response.data.sent) {
                            if (intervalId) {
                                clearInterval(intervalId);
                            }
                            voorodak_timer.text("02:00");
                            localStorage.setItem(startTimeKey, Date.now());
                            localStorage.setItem(timerKey, duration);
                            startTimer(duration, voorodak_timer);
                        }
                        jQuery("#voorodak__wrapper-main-otp-reset").fadeIn();
                        jQuery("#voorodak__wrapper-main-forget").hide();
                        if (voorodak_data.autofill === "1") {
                            autoFillOTP('.otp-field2');
                        }
                    }
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    jQuery(document).on('click', '#voorodak__submit-otp-reset', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var username = jQuery("input[name=voorodak__username-forget]").val();
        var otp_element = jQuery("input[name=voorodak__otp-reset]");
        var otp = otp_element.val();
        validateOTP(otp_element);
        ajaxRequest(
            {
                'action': action,
                'username': username,
                'otp': otp,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    if (voorodak_mobile_regex.test(username)){
                        jQuery("#voorodak__wrapper-main-otp-reset").hide();
                        jQuery("#voorodak__wrapper-main-reset").fadeIn();
                        jQuery("input[name=voorodak__reset-token]").val(response.data.reset_token);
                    }
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    jQuery(document).on('click', '#voorodak__submit-reset', function () {
        var button = jQuery(this);
        var button_init = button.html();
        var action = jQuery(this).attr('id');
        var new_password_element = jQuery("input[name=voorodak__new-password]");
        var new_password = new_password_element.val();
        var new_password2 = jQuery("input[name=voorodak__new-password2]").val();
        var reset_token = jQuery("input[name=voorodak__reset-token]").val();
        validatePassword(new_password_element);
        ajaxRequest(
            {
                'action': action,
                'new_password': new_password,
                'new_password2': new_password2,
                'reset_token': reset_token,
                'security': voorodak_security,
            },
            function () {
                voorodak_ajax = false;
                voorodak_messages.html('');
                button.html('<div class="lds-ellipsis"><div></div><div></div><div></div><div></div></div>');
            },
            function (response) {
                voorodak_ajax = true;
                button.html(button_init);
                voorodak_messages.html(response.data.message);
                if (response.success) {
                    voorodak_ajax = false;
                    window.location = voorodak_backurl;
                }
            },
            function () {
                voorodak_ajax = true;
                button.html(button_init);
            }
        );

    });

    if(jQuery('.voorodak__wrapper-main-box-timer').length) {
        jQuery('.voorodak__wrapper-main-box-timer-resend').on('click', function () {
            jQuery(".voorodak__wrapper-main-box-timer-countdown").fadeIn();
            jQuery(this).hide();
        });
        jQuery('#voorodak__wrapper-main-otp .voorodak__wrapper-main-box-timer-resend').on('click', function () {
            jQuery("#voorodak__submit-username").trigger("click");
        });
        jQuery('#voorodak__wrapper-main-otp-reset .voorodak__wrapper-main-box-timer-resend').on('click', function () {
            jQuery("#voorodak__submit-forget").trigger("click");
        });
    }

});


jQuery(document).ready(function () {
    jQuery('#download_list_users').on('click', function(e) {
        var btnText = jQuery('#download_list_users').html();
        e.preventDefault();
        jQuery.ajax({
            url: voorodak_admin_ajax.ajax_url,
            type: 'POST',
            data: { action: 'get_users_list_voorodak' },
            beforeSend: function() {
                jQuery('#download_list_users').html('در حال دریافت...').toggleClass('disabled');
            },
            success: function(response) {
                jQuery('#download_list_users').html(btnText).toggleClass('disabled');
                if (response.success) {
                    let blob = new Blob([response.data], { type: 'text/csv;charset=utf-8;' });
                    let link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = 'users_list.csv';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                } else {
                    alert('خطا در دریافت لیست کاربران');
                }
            },
            error: function() {
                alert('خطا در ارسال درخواست');
                jQuery('#download_list_users').html(btnText).toggleClass('disabled');
            }
        });
    });
    jQuery('#test_phone_submit').on('click', function(e) {
        var btn = jQuery('#test_phone_submit').html();
        e.preventDefault();
        var phone = jQuery('#test_phone_number').val();
        jQuery.ajax({
            url: voorodak_admin_ajax.ajax_url,
            type: 'POST',
            data: {
                action: 'submit_test_phone',
                phone: phone
            },
            beforeSend: function (){
                jQuery('#test_phone_submit').html('در حال ارسال').toggleClass('disabled');
            },
            success: function(response) {
                console.log(response.data);
                jQuery('#test_phone_submit').html(btn).toggleClass('disabled');
                jQuery("#test_phone_result").fadeIn();
                jQuery("#test_phone_result td").html(response.data);
            }
        });
    });
    jQuery('.v-toggle').on('change', function () {
        jQuery(this).closest('tr').next('tr').toggle(jQuery(this).is(':checked'));
    }).trigger('change');
    jQuery(".sms-notifications h3").click(function (){
        jQuery(this).next().slideToggle(500);
        jQuery(this).toggleClass('activate');
    });
    function checkFieldsSmart(){
        var selected_value = jQuery('.voorodak__gateway').find(":selected").val();
        if (selected_value.indexOf('pattern') >= 0){
            jQuery(".voorodak__message").hide();
            jQuery(".voorodak__pattern").fadeIn();
        }else {
            jQuery(".voorodak__message").fadeIn();
            jQuery(".voorodak__pattern").hide();
        }

        if (selected_value.indexOf('kavenegar_pattern') >= 0 || selected_value.indexOf('payamresan_pattern') >= 0 || selected_value.indexOf('ghasedak_pattern') >= 0 || selected_value.indexOf('smsir_pattern') >= 0 || selected_value.indexOf('rahpayam_pattern') >= 0) {
            jQuery(".voorodak__username").find('th').text('کلید API');
            jQuery(".voorodak__password").hide();
            jQuery(".voorodak__from").hide();
        } else if (selected_value.indexOf('farapayamak_pattern') >= 0 || selected_value.indexOf('payamito_pattern') >= 0 || selected_value.indexOf('melipayamak_pattern') >= 0 || selected_value.indexOf('melipayamakrest_pattern') >= 0) {
            jQuery(".voorodak__from").hide();
        } else if (selected_value.indexOf('farazsmsnew_pattern') >= 0 || selected_value.indexOf('sabanovin') >= 0 || selected_value.indexOf('raygansms_pattern') >= 0) {
                jQuery(".voorodak__username").find('th').text('کلید API');
                jQuery(".voorodak__password").hide();
                jQuery(".voorodak__from").fadeIn();
        } else {
                jQuery(".voorodak__username").find('th').text('نام کاربری سامانه');
                jQuery(".voorodak__password").fadeIn();
                jQuery(".voorodak__from").fadeIn();
            }


        var redirect_checked = jQuery('.voorodak__backurl input[type=radio]:checked').val();
        if (redirect_checked == 'custom'){
            jQuery(".voorodak__backurl-custom").fadeIn();
        }else {
            jQuery(".voorodak__backurl-custom").hide();
        }
    }
    checkFieldsSmart();
    jQuery('.voorodak__gateway,.voorodak__backurl input[type=radio]').on('change', function () {
        checkFieldsSmart();
    });
    jQuery(".voorodak__body-tab a").click(function (e) {
        e.preventDefault();
        jQuery(".voorodak__body-tab a").removeClass('active');
        jQuery(this).addClass('active');
        var target = jQuery(this).attr('href');
        jQuery(".voorodak__body-main-box").hide();
        jQuery(target).fadeIn();
    });
    jQuery('.voorodak__color-picker').wpColorPicker();
    var mediaUploader;
    function initMediaUploader(buttonSelector, previewSelector, inputSelector, removeButtonSelector) {
        jQuery(buttonSelector).click(function(e) {
            e.preventDefault();
            if (mediaUploader) {
                mediaUploader.open();
                return;
            }
            mediaUploader = wp.media.frames.file_frame = wp.media({
                title: 'انتخاب تصویر پس زمینه',
                button: {
                    text: 'انتخاب تصویر'
                },
                multiple: false
            });
            mediaUploader.on('select', function() {
                var attachment = mediaUploader.state().get('selection').first().toJSON();
                jQuery(previewSelector).html('<img src="' + attachment.url + '" style="max-width: 200px; max-height: 200px;" />');
                jQuery(inputSelector).val(attachment.url);
                jQuery(removeButtonSelector).show();
            });
            mediaUploader.open();
        });

        jQuery(removeButtonSelector).click(function() {
            jQuery(previewSelector).html('');
            jQuery(inputSelector).val('');
            jQuery(this).hide();
        });
    }
    initMediaUploader('#voorodak__logo-upload-button', '#voorodak__logo-preview', 'input[name="voorodak_options[logo]"]', '#voorodak__logo-upload-remove');
    initMediaUploader('#voorodak__cover-upload-button', '#voorodak__cover-preview', 'input[name="voorodak_options[cover]"]', '#voorodak__cover-upload-remove');
});


.voorodak{background:#fff;padding:20px;display:flex;align-items:center;justify-content:center;overflow:auto;height:100vh}.voorodak__wrapper-messages>div{padding:15px;border-radius:10px;margin-top:15px;font-size:14px;display:flex;align-items:center}.voorodak__wrapper-messages>div svg{display:inline-block;margin-left:10px}.voorodak__wrapper-messages-success{background:#f0fdf4;color:#16a34a;border:1px solid #16a34a1f}.voorodak__wrapper-messages-error{background:#fef2f2;color:#dc2626;border:1px solid #dc26261f}.flex-1{flex:1}.voorodak__wrapper{font-family:inherit;max-width:400px;margin:0 auto;flex-basis:400px}.voorodak__wrapper-main-head{margin-bottom:15px;position:relative;height:70px}.voorodak__wrapper-main-head a img{display:block;margin:0 auto;object-fit:contain;height:70px}.voorodak__wrapper-main-head a{display:block;width:max-content;margin:0 auto}.voorodak__wrapper-main-head svg{cursor:pointer;position:absolute;height:20px;margin:auto;top:0;bottom:0}.voorodak__wrapper-main-box-title{display:block;font-size:20px;margin-bottom:20px;font-weight:700}.voorodak__wrapper-main-box-description{font-size:14px;color:#94a3b8;line-height:2;margin-bottom:15px;text-align:justify}.voorodak__wrapper-main-box-description p{margin:0}.voorodak-default .voorodak__wrapper-main .voorodak__wrapper-main-box{background:#fff;box-shadow:0 5px 25px rgb(0 0 0 / .07);padding:35px;border-radius:15px}.voorodak-digikala .voorodak__wrapper-main{border:1px solid #cbd5e1;padding:35px;border-radius:15px;background:#fff}@media screen and (max-width:576px){.voorodak-digikala .voorodak__wrapper-main,.voorodak-default .voorodak__wrapper-main>div:not(.voorodak__wrapper-main-head){padding:25px}}.voorodak__wrapper-main input[type=password],.voorodak__wrapper-main input[type=text]{all:unset}.voorodak__wrapper-main-box-field{margin-bottom:15px}.voorodak__wrapper-main-box-field input[type="password"],.voorodak__wrapper-main-box-field input[type="text"]{transition:0.3s;font-family:inherit;background:#f1f5f9;border-radius:10px!important;display:block;box-sizing:border-box;width:100%;height:54px;padding:0 12px;font-size:16px;border:1px solid #e2e8f0}.voorodak-digikala .voorodak__wrapper-main-box-field input[type="password"],.voorodak-digikala .voorodak__wrapper-main-box-field input[type="text"]{background:#fff;border-color:#cbd5e1}.voorodak__wrapper-main-box-field input[type="password"]:focus,.voorodak__wrapper-main-box-field input[type="text"]:focus{border-color:#94a3b8}#voorodak__wrapper-main-otp input[name='voorodak__otp'],#voorodak__wrapper-main-otp-reset input[name='voorodak__otp-reset']{letter-spacing:1rem;text-align:center}#voorodak__wrapper-main-otp input[name='voorodak__otp']::-moz-placeholder{letter-spacing:normal}#voorodak__wrapper-main-otp input[name='voorodak__otp']::placeholder{letter-spacing:normal}#voorodak__wrapper-main-otp-reset input[name='voorodak__otp-reset']::-moz-placeholder{letter-spacing:normal}#voorodak__wrapper-main-otp-reset input[name='voorodak__otp-reset']::placeholder{letter-spacing:normal}#voorodak__wrapper-main-otp input[name='voorodak__first_name']{float:right;width:48%;margin-bottom:1rem;text-align:center}#voorodak__wrapper-main-otp input[name='voorodak__last_name']{float:left;width:48%;margin-bottom:1rem;text-align:center}#voorodak__wrapper-main-otp input[name='voorodak__password_register'],#voorodak__wrapper-main-otp input[name='voorodak__email']{margin-bottom:1rem;text-align:center}.clear{clear:both}.voorodak .voorodak__wrapper-main button{font-family:inherit;height:54px;background:var(--voorodak-button-color);color:#fff;text-align:center;display:flex;align-items:center;justify-content:center;width:100%;border-radius:10px;transition:0.3s;border:none;cursor:pointer;font-size:16px;box-shadow:none;outline:none;box-sizing:border-box}.voorodak .voorodak__wrapper-main button:hover{background:var(--voorodak-button-color-hover)}.voorodak__wrapper-main-box-action{margin:15px 0;display:flex;flex-flow:column;justify-content:space-between}.voorodak__wrapper-main-box-timer-resend,.voorodak__wrapper-main-box-action a{color:var(--voorodak-button-color);font-size:13px;display:inline-flex;align-items:center;margin-bottom:10px;text-decoration:none;cursor:pointer;width:max-content}.voorodak__wrapper-main-box-timer-resend{margin-bottom:0}.voorodak__wrapper-main-box-timer-resend svg,.voorodak__wrapper-main-box-action a svg{display:inline-block;margin-right:4px;position:relative;top:.5px}.voorodak__wrapper-main-box-action a:hover{color:var(--voorodak-button-color)}.voorodak__wrapper-main-box-field-invalid{border-color:#ef4444!important}.voorodak__wrapper-main-box-field-invalid~span{font-size:13px;color:#ef4444;display:block;margin-top:7px}.voorodak__wrapper-main-box-timer{display:flex;align-items:center;justify-content:center;margin:15px 0;font-size:14px}.voorodak__wrapper-main-box-timer-countdown{color:#64748b}.voorodak__wrapper-main-box-timer-countdown span{display:inline-block;margin-left:5px}.lds-ellipsis,.lds-ellipsis div{box-sizing:border-box}.lds-ellipsis{display:flex;position:relative;width:80px;height:50px;align-items:center;justify-content:center;margin:0 auto}.lds-ellipsis div{position:absolute;top:19.333px;width:12.333px;height:12.333px;border-radius:50%;background:currentColor;animation-timing-function:cubic-bezier(0,1,1,0)}.lds-ellipsis div:nth-child(1){left:8px;animation:lds-ellipsis1 0.6s infinite}.lds-ellipsis div:nth-child(2){left:8px;animation:lds-ellipsis2 0.6s infinite}.lds-ellipsis div:nth-child(3){left:32px;animation:lds-ellipsis2 0.6s infinite}.lds-ellipsis div:nth-child(4){left:56px;animation:lds-ellipsis3 0.6s infinite}@keyframes lds-ellipsis1{0%{transform:scale(0)}100%{transform:scale(1)}}@keyframes lds-ellipsis3{0%{transform:scale(1)}100%{transform:scale(0)}}@keyframes lds-ellipsis2{0%{transform:translate(0,0)}100%{transform:translate(24px,0)}}.voorodak__terms{margin:0;margin-top:10px;text-align:center;font-size:12px}.voorodak__terms{margin:10px 0;text-align:center;font-size:12px}.voorodak__terms p{margin:0}.voorodak__terms a{text-decoration:none}@media screen and (min-width:992px){.voorodak.voorodak-zarinpal .voorodak__wrapper{display:flex;flex-wrap:wrap;border-radius:10px;overflow:hidden;max-width:992px;flex-basis:992px;margin:0 auto;box-shadow:0 5px 15px 0 rgb(31 32 35 / .07);background:#fff}.voorodak.voorodak-zarinpal .voorodak__wrapper>div{flex:1}.voorodak.voorodak-zarinpal .voorodak__wrapper .voorodak__wrapper-main-right{padding:30px;box-sizing:border-box;flex:0 0 450px;max-width:450px;position:relative}.voorodak.voorodak-zarinpal .voorodak__wrapper-main button{width:160px;display:flex;margin-right:auto}.voorodak.voorodak-zarinpal #voorodak__wrapper-main-otp,.voorodak.voorodak-zarinpal #voorodak__wrapper-main-otp-reset{display:flex;flex-wrap:wrap}.voorodak.voorodak-zarinpal .voorodak__wrapper-main-box-title{width:100%;margin-bottom:10px}.voorodak.voorodak-zarinpal #voorodak__wrapper-main-otp .voorodak__wrapper-main-box-action{width:100%;margin:0}.voorodak__wrapper-main-left img{object-fit:cover;height:100%;width:100%}}@media screen and (max-width:992px){.voorodak{align-items:flex-start;padding-top:50px}.voorodak__wrapper-main-left{display:none}.voorodak.voorodak-zarinpal .voorodak__wrapper{border-radius:10px;margin:0 auto;box-shadow:0 5px 15px 0 rgb(31 32 35 / .07);background:#fff;padding:25px}}.voorodak__body-main-hints-list div b{background:#0b7c72;padding:2px 5px;display:inline-block;font-weight:400;border-radius:5px}

@font-face {
    font-family: Vazir;
    src: url(../fonts/Vazir-Regular.woff2);
    font-weight: 400;
    font-display: swap;
}

.voorodak, .voorodak h1, .voorodak h2, .voorodak h3, .voorodak h4 {
    font-family: Vazir;
    font-weight: normal !important;
}

.wrap.voorodak h2 {
    background: #475569;
    color: #fff;
    width: max-content;
    margin-bottom: 0;
    padding: 12px 30px;
    border-radius: 15px 15px 0 0;
    margin-right: 22px;
    font-weight: 700;
}

.voorodak__body-main-box h3 {
    margin: 0 !important;
}

.voorodak__body {
    background: #fff;
    border-radius: 20px;
    padding: 20px 20px 0;
}

.voorodak__body-main {
    display: flex;
    flex-wrap: wrap;
}

.voorodak__body-main-hints {
    flex: 1;
    padding: 20px 20px 20px 0;
    box-sizing: border-box;
    border-right: 1px solid #dfdfe4;
}

.voorodak__body-main form {
    flex: 1;
    padding-left: 20px;
    box-sizing: border-box;
}

.voorodak form input[type="text"]:not(.voorodak-color-picker), .voorodak form select, .voorodak form textarea {
    min-width: 300px;
    max-width: 100%;
    border: 1px solid #94a3b8;
    padding: 7px 15px;
    box-shadow: 0 5px 5px rgb(0 0 0 / .06);
    border-radius: 8px;
    width: 100%;
}

.voorodak form textarea {
    padding: 12px 15px;
}

.voorodak form select {
    background-image: url("data:image/svg+xml;charset=utf-8,%3Csvg aria-hidden='true' xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 10 6'%3E%3Cpath stroke='%236B7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='m1 1 4 4 4-4'/%3E%3C/svg%3E");
    background-position: left .75rem center;
    background-repeat: no-repeat;
    background-size: .75em .75em;
    padding-left: 2.5rem;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
}

#voorodak__cover-preview img, #voorodak__logo-preview img {
    max-width: 85px !important;
    margin-top: 20px;
    box-sizing: border-box;
    object-fit: contain;
}

.voorodak__license input {
    text-align: left;
    width: 100%;
    direction: ltr;
}

#submit {
    padding: 6px 30px;
    border-radius: 7px;
}

.voorodak__body-tab {
    background: #1d4ed8;
    padding: 15px;
    border-radius: 15px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}

.voorodak__body-tab a {
    color: #fff;
    padding: 10px 15px;
    text-decoration: none;
    font-size: 16px;
    display: inline-flex;
    transition: 0.3s;
    border: 1px solid #ffffff1a !important;
    box-shadow: none !important;
    outline: none !important;
    border-radius: 10px;
    align-items: center;
}

.voorodak__body-tab a.active {
    background: #fff;
    color: #1d4ed8;
    pointer-events: none
}

.voorodak__body-tab a svg {
    margin-left: 10px;
}

.melipayamak {
    background: #f0fdf4;
    border-radius: 15px;
    padding: 20px;
    border: 3px dashed #52bb59;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
}

.taktheme {
    background: #f6f9fb;
    border: none;
    margin-top: 20px;
    padding: 30px 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-flow: column;
    border-radius: 15px;
}

.taktheme img {
    max-width: 100px;
    margin: 0 auto;
}

.melipayamak__main {
    padding-right: 20px;
    flex: 1;
}

.taktheme p {
    margin: 15px 0 !important;
    text-align: center;
}

.taktheme .taktheme-support {
    display: block;
    border-radius: 10px;
    padding: 10px 18px;
    font-size: 13px;
    color: #fff;
    text-decoration: none;
    background: linear-gradient(to right, #2766ec, #3980f5);
    box-shadow: none;
    outline: none;
}

.melipayamak__coupon-main {
    background: #ff6d6d;
    color: #fff;
    font-size: 21px;
    line-height: 1;
    display: inline-block;
    border-radius: 3px;
    position: relative;
    -webkit-transition: background .25s ease-in-out;
    -moz-transition: background .25s ease-in-out;
    -ms-transition: background .25s ease-in-out;
    -o-transition: background .25s ease-in-out;
    transition: background .25s ease-in-out;
    letter-spacing: 1px;
}

.melipayamak__coupon-main::before {
    left: -1px;
    border-radius: 0 8px 8px 0;
}

.melipayamak__coupon-main::after, .melipayamak__coupon-main::before {
    height: 16px;
    width: 8px;
    background: #f0fdf4;
    position: absolute;
    top: 0;
    bottom: 0;
    margin: auto 0;
    content: '';
}

.melipayamak__coupon-main::after {
    right: -1px;
    border-radius: 8px 0 0 8px;
}

.melipayamak__coupon-main-inner {
    padding: 15px 25px 15px 22px;
    border-left: 2px dashed #ec6363;
    margin-left: 25px;
    -webkit-transition: border-left-color .25s ease-in-out;
    -moz-transition: border-left-color .25s ease-in-out;
    -ms-transition: border-left-color .25s ease-in-out;
    -o-transition: border-left-color .25s ease-in-out;
    transition: border-left-color .25s ease-in-out;
}

.melipayamak__coupon {
    width: 100%;
    margin-top: 10px;
    text-align: center;
}

.voorodak__body-main-hints-list {
    background: #f0fdfa;
    color: #0d9488;
    border-radius: 15px;
    padding: 20px;
    margin-top: 20px;
}

.voorodak__body-main-hints-list ol {
    margin: 0;
    list-style-position: inside;
}

.voorodak__body-main-hints-list ol li {
    margin-bottom: 12px;
    line-height: 1.8;
    font-size: 14px;
}

.voorodak__body-main-hints-list mark {
    background: #14b8a6;
    color: #fff;
    padding: 3px 5px;
    display: inline-block;
    border-radius: 4px;
}

.taktheme p, .melipayamak__main p {
    font-size: 14px;
    line-height: 1.8;
    color: #64748b;
    margin-bottom: 0;
}

.voorodak__body-main-hints-list a {
    text-decoration: none;
    border-bottom: 1px solid #115e59;
    color: #115e59;
    display: inline-block;
    margin: 0 4px;
    outline: none;
    box-shadow: none;
}

.voorodak__backurl label {
    display: flex;
    margin-bottom: 15px;
    align-items: center;
}

.voorodak__backurl label input {
    margin-left: 7px !important;
    display: inline-block;
    position: relative;
    top: 2px;
}

.voorodak__logouturl input, .voorodak__backurl-custom input,.voorodak__panelurl-custom input {
    text-align: left;
    direction: ltr;
}

.voorodak__sms-message {
    display: block;
    margin-top: 10px;
    font-size: 13px;
    width: max-content;
    padding: 5px 10px;
    border-radius: 5px;
    color: #fff;
}

.voorodak__sms-message.active {
    background: #16a34a;
}

.voorodak__sms-message.deactive {
    background: #ef4444;
}

.hint {
    display: block;
    margin-top: 10px;
    font-size: 13px;
    color: #64748b;
}

#test_phone_number {
    width: auto !important;
    min-width: auto;
}

#test_phone_submit {
    height: 43.6px;
    display: inline-flex;
    align-items: center;
    border-radius: 5px;
}

#test_phone_submit.disabled {
    pointer-events: none;
    opacity: .8;
}

#test_phone_result td svg {
    display: none;
}

.voorodak__body-main input[type="checkbox"] {
    -webkit-appearance: none;
    -moz-appearance: none;
    appearance: none;
    width: 50px;
    height: 24px;
    background-color: #ccc;
    border-radius: 100px;
    position: relative;
    cursor: pointer;
    transition: background-color 0.3s ease;
    border: none !important;
    box-sizing: border-box;
    box-shadow: none !important;
}

.voorodak__body-main input[type="checkbox"]::before {
    content: '';
    position: absolute;
    width: 16px;
    height: 16px;
    background-color: #fff;
    border-radius: 50%;
    top: 3px;
    left: 3px;
    transition: transform 0.3s ease;
    transform: translate(1px, 1px);
    margin: 0 !important;
}

.voorodak__body-main input[type="checkbox"]:checked {
    background-color: #1d4ed8;
}

.voorodak__body-main input[type="checkbox"]:checked::before {
    transform: translate(26px, 1px);
}

#wp-term_editor-editor-container {
    border-radius: 8px;
    overflow: hidden;
}

.doc-box {
    background: #eeeeee6b;
    border-radius: 12px;
    margin: 20px 0;
    padding: 20px;
    border: 1px solid #e5e7eb;
}

.doc-box h2 {
    font-size: 20px;
    color: #1e40af;
    margin-bottom: 15px;
    border-right: 4px solid #3b82f6;
    padding-right: 10px;
}

.doc-box p {
    margin-bottom: 20px;
    font-size: 15px;
    color: #444;
}

.code-box {
    background: #1e293b;
    color: #f8fafc;
    padding: 20px 8px;
    border-radius: 8px;
    overflow-x: auto;
    font-family: Consolas, Monaco, monospace;
    font-size: 14px;
    direction: ltr;
    text-align: left;
    position: relative;
    padding-top: 40px;
    word-break: break-word;
}

.code-box > p {
    color: #f8fafc;
    text-align: right;
    margin: 0;
}

.code-box::before {
    position: absolute;
    top: 8px;
    left: 8px;
    background: #3b82f6;
    color: #fff;
    font-size: 12px;
    padding: 2px 6px;
    border-radius: 4px;
    letter-spacing: .5px;
}

.code-box.shortcode::before {
    content: "Shortcode";
}

.code-box.php::before {
    content: "PHP";
}

.code-box code {
    white-space: preserve-breaks;
    display: block;
    color: #fff;
}

.sms-notifications {
    background: #f6f5f9;
    border-radius: 15px;
    margin-top: 20px;
}

.sms-notifications h4 {
    background: #475569;
    color: #fff;
    border-radius: 12px;
    text-align: center;
    padding: 15px;
    font-size: 14px;
}

.voorodak__body-main .form-table th {
    min-width: 200px;
    font-weight: 400;
}

.sms-notifications-notice {
    background: #fff7ed;
    padding: 16px;
    border-radius: 12px;
    text-align: center;
    border: 1px solid #fed7aa;
    color: #d97706;
    margin: 20px 0;
    display: flex;
    align-items: center;
}

.sms-notifications h3 {
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    padding: 20px;
}

.sms-notifications h3 svg {
    transition: 0.3s;
}

.sms-notifications-main {
    padding: 0 20px 20px;
}

.sms-notifications h3.activate svg {
    transform: rotate(180deg);
}

.sms-notifications-notice-icon {
    display: flex;
    align-items: center;
    flex-flow: column;
    width: 115px;
}

.sms-notifications-notice-text {
    flex: 1;
    text-align: right;
}

.sms-notifications-notice-text ul {
    list-style: disc;
    list-style-position: initial;
}

.sms-notifications-notice-text mark {
    background: #d97706;
    color: #fff;
    border-radius: 4px;
    padding: 1px 5px;
    display: inline-block;
    margin: 0 5px;
}

.sms-notifications-notice-text-message {
    background: #fff;
    border-radius: 12px;
    padding: 12px;
    color: #444444c9;
    margin-top: 8px;
}

.voorodak__body-main p.submit {
    position: sticky;
    bottom: 0;
    background: #ffffff96;
    backdrop-filter: blur(10px);
    padding: 1rem;
}

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



