<?php
/**
 * CSRF Protection Functions
 * 
 * This file contains functions for generating and validating CSRF tokens
 * to protect against Cross-Site Request Forgery attacks.
 */

/**
 * Generate a CSRF token and store it in the session
 * 
 * @return string The generated CSRF token
 */
function generateCSRFToken() {
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

/**
 * Validate a CSRF token against the one stored in the session
 * 
 * @param string $token The token to validate
 * @return bool True if the token is valid, false otherwise
 */
function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf']) || $token !== $_SESSION['csrf']) {
        return false;
    }
    return true;
}

/**
 * Output a hidden input field containing the CSRF token
 * 
 * @return void
 */
function outputCSRFToken() {
    $token = generateCSRFToken();
    echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}
?> 