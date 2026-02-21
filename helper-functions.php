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
