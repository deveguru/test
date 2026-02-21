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

