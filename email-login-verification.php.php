<?php
/*
Plugin Name: Email Login Shortcode
Description: Allows users to log in using their email without a password, by verifying their sign-in via email using a shortcode.
Version: 1.0
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}
function email_login_shortcode() {
    ob_start();
    ?>
    <form method="post" action="">
        <p>
            <label for="user_email"><?php _e('Email Address'); ?></label>
            <input type="email" name="user_email" id="user_email" required />
        </p>
        <p>
            <input type="submit" name="email_login_submit" value="<?php _e('Log In'); ?>" />
        </p>
    </form>
    <?php
    return ob_get_clean();
}
add_shortcode('email_login_form', 'email_login_shortcode');
function handle_email_login_submission() {
    if (isset($_POST['email_login_submit']) && isset($_POST['user_email'])) {
        $email = sanitize_email($_POST['user_email']);
        $user = get_user_by('email', $email);

        if ($user) {
            $token = bin2hex(random_bytes(16));
            update_user_meta($user->ID, 'login_verification_token', $token);
            update_user_meta($user->ID, 'login_verification_expiry', time() + 15 * 60); // 15 minutes expiry

            $login_url = wp_login_url() . "?token=$token&user=" . $user->ID;

            // Send email
            wp_mail($email, 'Login Verification', "Click the following link to log in: $login_url");

            echo '<p>' . __('A login link has been sent to your email address.') . '</p>';
        } else {
            echo '<p>' . __('No user found with this email address.') . '</p>';
        }
    }
}
add_action('template_redirect', 'handle_email_login_submission');
function verify_login_token() {
    if (isset($_GET['token']) && isset($_GET['user'])) {
        $user_id = intval($_GET['user']);
        $token = sanitize_text_field($_GET['token']);

        $stored_token = get_user_meta($user_id, 'login_verification_token', true);
        $expiry_time = get_user_meta($user_id, 'login_verification_expiry', true);

        if ($token === $stored_token && time() < $expiry_time) {
            wp_set_auth_cookie($user_id);
            delete_user_meta($user_id, 'login_verification_token');
            delete_user_meta($user_id, 'login_verification_expiry');
            wp_redirect(home_url());
            exit;
        } else {
            wp_redirect(wp_login_url() . '?error=invalid_token');
            exit;
        }
    }
}
add_action('init', 'verify_login_token');

function email_register_shortcode() {
    ob_start();
    ?>
    <form method="post" action="">
        <p>
            <label for="register_email"><?php _e('Email Address'); ?></label>
            <input type="email" name="register_email" id="register_email" required />
        </p>
        <p>
            <input type="submit" name="email_register_submit" value="<?php _e('Register'); ?>" />
        </p>
    </form>
    <?php
    return ob_get_clean();
}
add_shortcode('email_register_form', 'email_register_shortcode');

function handle_email_register_submission() {
    if (isset($_POST['email_register_submit']) && isset($_POST['register_email'])) {
        $email = sanitize_email($_POST['register_email']);

        if (email_exists($email)) {
            echo '<p>' . __('This email is already registered. Please log in.') . '</p>';
        } else {
            $token = bin2hex(random_bytes(16));
            $verification_url = add_query_arg(
                array(
                    'register_token' => $token,
                    'user_email' => urlencode($email),
                ),
                home_url('/verify-email')
            );

            // Store token and email in a temporary option
            add_option("email_verification_$token", $email, '', 'no');

            // Send verification email
            wp_mail($email, 'Verify Your Account', "Click the following link to verify your email and complete registration: $verification_url");

            echo '<p>' . __('A verification email has been sent to your email address. Please check your inbox to verify your account.') . '</p>';
        }
    }
}
add_action('template_redirect', 'handle_email_register_submission');

function verify_email_and_create_user() {
    if (isset($_GET['register_token']) && isset($_GET['user_email'])) {
        $token = sanitize_text_field($_GET['register_token']);
        $email = sanitize_email(urldecode($_GET['user_email']));

        // Retrieve the stored email
        $stored_email = get_option("email_verification_$token");

        if ($stored_email && $stored_email === $email) {
            // Create the user account
            $user_id = wp_create_user($email, wp_generate_password(), $email);
            
            if (is_wp_error($user_id)) {
                echo '<p>' . __('There was an error creating your account.') . '</p>';
            } else {
                // Automatically log in the user
                wp_set_auth_cookie($user_id);
                delete_option("email_verification_$token");
                wp_redirect(home_url());
                exit;
            }
        } else {
            echo '<p>' . __('Invalid or expired verification link.') . '</p>';
        }
    }
}
add_action('template_redirect', 'verify_email_and_create_user');

// add shortcode to show button to logout user and redirect to homepage
function logout_button_shortcode() {
    ob_start();
    ?>
    <form method="post" action="<?php echo wp_logout_url(home_url()); ?>">
        <input type="submit" value="<?php _e('Log Out'); ?>" />
    </form>
    <?php
    return ob_get_clean();
}
add_shortcode('logout_button', 'logout_button_shortcode');

// // hide admin bar for non-admin users
// add_action('after_setup_theme', 'remove_admin_bar');
// function remove_admin_bar() {
//     if (!current_user_can('administrator') && !is_admin()) {
//         show_admin_bar(false);
//     }
// }