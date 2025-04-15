<?php
include_once 'includes/login.inc.php';
  // Set secure session parameters
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_only_cookies', 1);
    ini_set('session.cookie_samesite', 'Strict');
    
    // Set cache control headers to prevent caching
    header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
    header("Cache-Control: post-check=0, pre-check=0", false);
    header("Pragma: no-cache");
    header("Expires: Sat, 26 Jul 1997 05:00:00 GMT"); // Date in the past
    
    // Additional security headers
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
//    OWAS RECOMDS TO NOT USE X-XSS-Protection
    // header("X-XSS-Protection: 1; mode=block");
    
    // Set session name
    // session_name('SECUREAPP_SESSION');
    
    // Start session with secure parameters
    session_start([
        'cookie_lifetime' => 3600,
        'gc_maxlifetime' => 3600,
        'cookie_httponly' => true,
        'cookie_secure' => true,
        'cookie_samesite' => 'Strict'
    ]);

    //include_once 'includes/dbh.inc.php';
    if(!isset($_SESSION['u_id'])) {
        $session = 0;
    } else {
        $session = 1;
    }
    
    function addCacheBuster() {
        return "?v=" . time();
    }
    
    /*function cleanChars($val) {
        // Convert special characters to HTML entities
        $val = str_replace('&', '&amp;', $val);
        $val = str_replace('<', '&lt;', $val);
        $val = str_replace('>', '&gt;', $val);
        $val = str_replace('"', '&quot;', $val);
        $val = str_replace("'", '&#039;', $val);
        
        // Remove any remaining script tags and their content
        $val = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', '', $val);
        
        // Remove any event handlers
        $val = preg_replace('/on\w+="[^"]*"/i', '', $val);
        $val = preg_replace('/on\w+=\'[^\']*\'/i', '', $val);
        
        return $val;
    }

     */
?>

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>Super Secure Site</title>
<link rel="stylesheet" href="css/style.css<?php echo addCacheBuster(); ?>">
<script>
//Run the function on window.onload
    window.onload = function() {
    inactiveUser(); 
}
var inactiveUser = function () {
var timer;

//Relevant DOM Events in order to reset the time (whenever the user is deemed active)
window.onload = resetTimer;
document.onmousemove = resetTimer;
document.onkeypress = resetTimer;

//Only logout if the user is logged in
function logout() {
    var session='<?php echo $session;?>';
    if(session == 1) {
        location.href = './includes/logout.inc.php'
    } else {
        //No need to logout, they're not logged in
    }
}

function resetTimer() {
    clearTimeout(timer);
    timer = setTimeout(logout, 600000) //600000 10 minutes in milliseconds
}
};
</script>
</head>

<!--Keep the user logged in for 1 hour maximum-->
<meta http-equiv="refresh" content="3600;url=includes/logout.inc.php" />

<body>

<!--Navigation-->
<header>
<nav>
<div class="main-wrapper">
<ul class="nav-bar">
<li><a href="index.php">Home</a></li>
     
<?php
    if (!isset($_SESSION['u_id'])) {
        echo '<li><a href="register.php">Register</a></li>';
    }
    if (isset($_SESSION['u_uid'])) {
        $admin_status = $_SESSION['u_admin'];
        if (isset($_SESSION['u_id']) && $admin_status == 1) {
            echo '<li><a href="admin.php">Admin</a></li>';
            echo '<li><a href="auth1.php">Auth1</a></li>';
            echo '<li><a href="auth2.php?FileToView=public/Yellow.txt">Auth2</a></li>';
            echo '<li><a href="change.php">Change Password</a></li>';
        } else if (isset($_SESSION['u_id'])) {
            echo '<li><a href="auth1.php">Auth1</a></li>';
            echo '<li><a href="auth2.php?FileToView=public/Yellow.txt">Auth2</a></li>';
            echo '<li><a href="change.php">Change Password</a></li>';
        } 
    }
?>
</ul>

<div class="nav-login">
<?php
    if (isset($_SESSION['u_id'])) {
        echo '  <form class="" action="includes/logout.inc.php" method="POST">
        <button type="submit" name="submit"> Log out </button>
        </form>';
    } else {
        echo '  <form class="" action="includes/login.inc.php" method="POST">
        <input type="text" name="uid" value="" placeholder="Username">
        <input type="password" name="pwd" value="" placeholder="Password">';
        
        // Add CAPTCHA if required
        if (isset($_SESSION['requireCaptcha']) && $_SESSION['requireCaptcha'] === true) {
            // Generate a new CAPTCHA if not already set
            if (!isset($_SESSION['captcha'])) {
                include_once 'includes/login.inc.php';
                generateCaptcha();
            }
            
            echo '<div class="captcha-container">
                    <div class="captcha-code">' . $_SESSION['captcha'] . '</div>
                    <input type="text" name="captcha" placeholder="Enter CAPTCHA code" required>
                  </div>';
        }
        
        echo '<button type="submit" name="submit"> Login </button>
        </form>
        <a href="register.php"> Sign up </a>';
    }
?>

</div>
</div>
</nav>
</header>
