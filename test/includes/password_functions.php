<?php
/**
 * Password hashing and verification functions
 * These functions implement secure password storage using SHA-256 with salt
 */

/**
 * Validate password complexity requirements
 * 
 * @param string $password The password to validate
 * @return array An array of error messages, empty if password is valid
 */
function validatePasswordComplexity($password) {
    $errors = [];
    
    // Check minimum length
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long";
    }
    
    // Check for uppercase letters
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter";
    }
    
    // Check for lowercase letters
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter";
    }
    
    // Check for numbers
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number";
    }
    
    // Check for special characters
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Password must contain at least one special character";
    }
    
    return $errors;
}

/**
 * Hash a password with a random salt
 * 
 * @param string $password The plain text password to hash
 * @return string The hashed password with salt in format: hash:salt
 */
function hashPassword($password) {
    // Validate password complexity
    $errors = validatePasswordComplexity($password);
    if (!empty($errors)) {
        // Throw an exception with the error messages
        throw new Exception(implode(", ", $errors));
    }
    
    // Generate a random salt
    $salt = bin2hex(random_bytes(16));
    
    // Combine password and salt
    $saltedPassword = $password . $salt;
    
    // Hash using SHA-256
    $hashedPassword = hash('sha256', $saltedPassword);
    
    // Return both hash and salt for storage
    return $hashedPassword . ':' . $salt;
}

/**
 * Verify a password against a stored hash
 * 
 * @param string $password The plain text password to verify
 * @param string $storedHash The stored hash in format: hash:salt
 * @return bool True if password matches, false otherwise
 */
function verifyPassword($password, $storedHash) {
    // Split stored hash and salt
    list($hash, $salt) = explode(':', $storedHash);
    
    // Hash the provided password with the same salt
    $saltedPassword = $password . $salt;
    $hashedPassword = hash('sha256', $saltedPassword);
    
    // Compare hashes
    return hash_equals($hash, $hashedPassword);
} 