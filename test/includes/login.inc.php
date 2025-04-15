<?php

// Include password functions
include_once 'password_functions.php';

function cleanChars($val) {
    // Convert special characters to HTML entities
    $val = htmlspecialchars($val, ENT_QUOTES, 'UTF-8');
    
    // Remove script tags and their contents
    $val = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $val);
    
    // Remove event handlers
    $val = preg_replace('/on\w+="[^"]*"/', '', $val);
    $val = preg_replace('/on\w+=\'[^\']*\'/', '', $val);
    
    return $val;
}

// Get client IP address
if(!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ipAddr=$_SERVER['HTTP_CLIENT_IP'];
} elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ipAddr=$_SERVER['HTTP_X_FORWARDED_FOR'];
} else {
    $ipAddr=$_SERVER['REMOTE_ADDR'];
}

session_start();

// Function to generate CAPTCHA
function generateCaptcha() {
    // Generate a random string of 6 characters
    $captchaString = substr(str_shuffle('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'), 0, 6);
    
    // Store the CAPTCHA in the session
    $_SESSION['captcha'] = $captchaString;
    
    return $captchaString;
}

// Function to check if CAPTCHA is required
function isCaptchaRequired($conn, $ipAddr) {
    // Check if there are recent failed attempts
    $checkFailedAttempts = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?";
    $stmt = $conn->prepare($checkFailedAttempts);
    $stmt->bind_param("s", $ipAddr);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $failedLoginCount = $row['failedLoginCount'];
        
        // Require CAPTCHA after 2 failed attempts
        if ($failedLoginCount >= 2) {
            return true;
        }
    }
    
    return false;
}

// Function to calculate lockout duration based on failed attempts
function calculateLockoutDuration($failedAttempts) {
    // Progressive delay: 1min, 5min, 15min, 30min, 1hour
    $delays = [60, 300, 900, 1800, 3600];
    $index = min($failedAttempts - 1, count($delays) - 1);
    return $delays[$index];
}

// Function to check if a user is locked out
function isUserLockedOut($conn, $uid, $ipAddr) {
    // Check IP-based lockout
    $checkIPLockout = "SELECT `failedLoginCount`, `timeStamp` FROM `failedLogins` WHERE `ip` = ?";
    $stmt = $conn->prepare($checkIPLockout);
    $stmt->bind_param("s", $ipAddr);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $failedLoginCount = $row['failedLoginCount'];
        $timeStamp = $row['timeStamp'];
        
        if ($failedLoginCount >= 5) {
            $lockoutDuration = calculateLockoutDuration($failedLoginCount);
            $currTime = date("Y-m-d H:i:s");
            $timeDiff = abs(strtotime($currTime) - strtotime($timeStamp));
            
            if ($timeDiff <= $lockoutDuration) {
                $_SESSION['timeLeft'] = $lockoutDuration - $timeDiff;
                $_SESSION['lockedOut'] = "Due to multiple failed logins you're now locked out, please try again in " . ceil(($_SESSION['timeLeft'] / 60)) . " minutes";
                return true;
            }
        }
    }
    
    // Check username-based lockout
    $checkUserLockout = "SELECT COUNT(*) as count FROM `loginEvents` WHERE `user_id` = ? AND `outcome` = 'fail' AND `timeStamp` > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
    $stmt = $conn->prepare($checkUserLockout);
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $failedAttempts = $row['count'];
        
        if ($failedAttempts >= 5) {
            $_SESSION['lockedOut'] = "This account has been locked due to multiple failed login attempts. Please try again later.";
            return true;
        }
    }
    
    return false;
}

// Function to track failed login attempt
function trackFailedAttempt($conn, $uid, $ipAddr) {
    // Record the failed attempt in loginEvents
    $time = date("Y-m-d H:i:s");
    $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'fail')";
    $stmt = $conn->prepare($recordLogin);
    $stmt->bind_param("sss", $ipAddr, $time, cleanChars($uid));
    
    if (!$stmt->execute()) {
        die("Error: " . $stmt->error);
    }
    
    // Update or insert into failedLogins table
    $checkClient = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?";
    $stmt = $conn->prepare($checkClient);
    $stmt->bind_param("s", $ipAddr);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $currTime = date("Y-m-d H:i:s");
    
    if ($result->num_rows == 0) {
        // New IP, insert record
        $addUser = "INSERT INTO `failedLogins` (`ip`, `timeStamp`, `failedLoginCount`, `lockOutCount`) VALUES (?, ?, '1', '0')";
        $stmt = $conn->prepare($addUser);
        $stmt->bind_param("ss", $ipAddr, $currTime);
    } else {
        // Existing IP, update count
        $updateCount = "UPDATE `failedLogins` SET `failedLoginCount` = `failedLoginCount` + 1, `timeStamp` = ? WHERE `ip` = ?";
        $stmt = $conn->prepare($updateCount);
        $stmt->bind_param("ss", $currTime, $ipAddr);
    }
    
    if (!$stmt->execute()) {
        die("Error: " . $stmt->error);
    }
}

if (isset($_POST['submit'])) {
    include 'dbh.inc.php';

    // Sanitize inputs
    $uid = $_POST['uid'];
    $pwd = $_POST['pwd'];
    $ipAddr = $ipAddr;
    
    // Check if CAPTCHA is required
    $captchaRequired = isCaptchaRequired($conn, $ipAddr);
    
    // If CAPTCHA is required, validate it
    if ($captchaRequired) {
        if (!isset($_POST['captcha']) || empty($_POST['captcha'])) {
            $_SESSION['failedMsg'] = "Please enter the CAPTCHA code.";
            $_SESSION['requireCaptcha'] = true;
            header("Location: ../index.php");
            exit();
        }
        
        if (!isset($_SESSION['captcha']) || $_POST['captcha'] !== $_SESSION['captcha']) {
            $_SESSION['failedMsg'] = "Invalid CAPTCHA code. Please try again.";
            $_SESSION['requireCaptcha'] = true;
            // Generate a new CAPTCHA for the next attempt
            generateCaptcha();
            header("Location: ../index.php");
            exit();
        }
    }

    // Check if user is locked out
    if (isUserLockedOut($conn, $uid, $ipAddr)) {
        header("Location: ../index.php");
        exit();
    }

    // Process login attempt
    processLogin($conn, $uid, $pwd, $ipAddr);
}

function processLogin($conn, $uid, $pwd, $ipAddr) {
    // Errors handlers
    // Check if inputs are empty
    if (empty($uid) || empty($pwd)) {
        header("Location: ../index.php?login=empty");
        failedLogin($uid, $ipAddr);
        exit();
    } else {
        try {
            // First get the user by username only
            $sql = "SELECT * FROM sapusers WHERE user_uid = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("s", $uid);
            $stmt->execute();
            $result = $stmt->get_result();
        } catch (Exception $e) {
            echo 'Caught exception: ',  $e->getMessage(), "\n";
            failedLogin($e->getMessage(), $ipAddr);
        }
        
        if ($result->num_rows < 1) {
            failedLogin($uid, $ipAddr);
        } else {
            if ($row = mysqli_fetch_assoc($result)) {
                // Get the stored password hash
                $storedHash = $row['user_pwd'];
                
                // Verify the password using the new function
                if (!verifyPassword($pwd, $storedHash)) {
                    failedLogin($uid, $ipAddr);
                } else {
                    // Reset failed login count on successful login
                    $resetCount = "UPDATE `failedLogins` SET `failedLoginCount` = '0' WHERE `ip` = ?";
                    $stmt = $conn->prepare($resetCount);
                    $stmt->bind_param("s", $ipAddr);
                    $stmt->execute();
                    
                    // Clear CAPTCHA requirement on successful login
                    unset($_SESSION['requireCaptcha']);
                    unset($_SESSION['captcha']);
                    
                    //Initiate session
                    $_SESSION['u_id'] = $row['user_id'];
                    $_SESSION['u_uid'] = $row['user_uid'];
                    $_SESSION['u_admin'] = $row['user_admin']; //Will be 0 for non admin users
                    
                    //Store successful login attempt, uid, timestamp, IP in log format for viewing at admin.php
                    $time = date("Y-m-d H:i:s");
                    $recordLogin = "INSERT INTO `loginEvents` (`ip`, `timeStamp`, `user_id`, `outcome`) VALUES (?, ?, ?, 'success')"; 
                    $stmt = $conn->prepare($recordLogin);
                    $cleanUid = cleanChars($uid);
                    $stmt->bind_param("sss", $ipAddr, $time, $cleanUid);

                    if(!$stmt->execute()) {
                        die("Error: " . $stmt->error);
                    } else {
                        header("Location: ../auth1.php");
                        exit();
                    }
                }
            }
        }
    }
} 

function failedLogin($uid, $ipAddr) {
    include "dbh.inc.php";
    
    //When login fails redirect to index and set the failedMsg variable so it can be displayed on index
    $_SESSION['failedMsg'] = "The username " . cleanChars($uid) . " and password could not be authenticated at this moment.";
    
    // Track the failed attempt
    trackFailedAttempt($conn, $uid, $ipAddr);
    
    // Check if CAPTCHA should be required after this failed attempt
    $checkFailedAttempts = "SELECT `failedLoginCount` FROM `failedLogins` WHERE `ip` = ?";
    $stmt = $conn->prepare($checkFailedAttempts);
    $stmt->bind_param("s", $ipAddr);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $failedLoginCount = $row['failedLoginCount'];
        
        // Require CAPTCHA after 2 failed attempts
        if ($failedLoginCount >= 2) {
            $_SESSION['requireCaptcha'] = true;
            // Generate a new CAPTCHA
            generateCaptcha();
        }
    }
    
    // Redirect to index page
    header("Location: ../index.php");
    exit();
}
