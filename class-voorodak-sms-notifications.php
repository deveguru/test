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


