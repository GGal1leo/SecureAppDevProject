<!DOCTYPE html>
<html>
<head>
<style>
* {
  box-sizing: border-box;
}

.header, .footer {
  background-color: grey;
  color: white;
  padding: 15px;
}

.column {
  float: left;
  padding: 15px;
}

.clearfix::after {
  content: "";
  clear: both;
  display: table;
}

.menu {
  width: 25%;
}

.content {
  width: 75%;
}

.menu ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
}

.menu li {
  padding: 8px;
  margin-bottom: 8px;
  background-color: #33b5e5;
  color: #ffffff;
}

.menu li:hover {
  background-color: #0099cc;
}
</style>
</head>

<body>

<div class="header">
  <h1>Penetration Testing</h1>
</div>

<div class="clearfix">
  <div class="column menu">
    <ul>
      <li><a href="../index.php">Main Menu</a></li>
    </ul>
  </div>

  <div class="column content">
    <h1>Bypass Browser / Client Side Controls</h1>
    <p>Lab Objectives: 	To bypass client side controls & famularise yourself with the Zap proxy</p>
	<p>Note: 	Reflective XSS can also be identifed on this page.</p>
	<p></p>
	<p>

<?php
// define variables and set to empty values
$nameErr = $emailErr = $genderErr = $websiteErr = "";
$name = $email = $gender = $comment = $website = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["name"])) {
    $nameErr = "Name is required";
  } else {
    $name = test_input($_POST["name"]);
	
    // check if name only contains letters and whitespace
    //if (!preg_match("/^[a-zA-Z-' ]*$/",$name)) {
    //  $nameErr = "Only letters and white space allowed";
    //}
  }
  
  if (empty($_POST["email"])) {
    $emailErr = "Email is required";
  } else {
    $email = test_input($_POST["email"]);
    // check if e-mail address is well-formed
    //if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    //  $emailErr = "Invalid email format";
    //}
  }
    
  if (empty($_POST["website"])) {
    $website = "";
  } else {
    $website = test_input($_POST["website"]);
    // check if URL address syntax is valid (this regular expression also allows dashes in the URL)
    //if (!preg_match("/\b(?:(?:https?|ftp):\/\/|www\.)[-a-z0-9+&@#\/%?=~_|!:,.;]*[-a-z0-9+&@#\/%=~_|]/i",$website)) {
    //  $websiteErr = "Invalid URL";
    //}
  }

  if (empty($_POST["comment"])) {
    $comment = "";
  } else {
    $comment = test_input($_POST["comment"]);
  }

  if (empty($_POST["gender"])) {
    $genderErr = "Gender is required";
  } else {
    $gender = test_input($_POST["gender"]);
  }
}

function test_input($data) {
  //$data = htmlspecialchars($data);
  return $data;
}
?>

<h2>PHP Form Validation Example</h2>
<p><span class="error">* required field</span></p>

<!-- Change the method "POST" in the line below to "GET" and determine the difference via the Zap proxy --> 
<form method="post" action="<?php echo ($_SERVER["PHP_SELF"]);?>">  
  Name: <input type="text" name="name" maxlength="10" value="<?php echo $name;?>">
  <span class="error">* <?php echo $nameErr;?></span>
  <br><br>
  E-mail: <input type="text" name="email" maxlength="20" value="<?php echo $email;?>">
  <span class="error">* <?php echo $emailErr;?></span>
  <br><br>
  Website: <input type="text" name="website" maxlength="20" value="<?php echo $website;?>">
  <span class="error"><?php echo $websiteErr;?></span>
  <br><br>
  Comment: <textarea name="comment" maxlength="200" rows="5" cols="40"><?php echo $comment;?></textarea>
  <br><br>
  Gender:
  <input type="radio" name="gender" <?php if (isset($gender) && $gender=="female") echo "checked";?> value="female">Female
  <input type="radio" name="gender" <?php if (isset($gender) && $gender=="male") echo "checked";?> value="male">Male
  <input type="radio" name="gender" <?php if (isset($gender) && $gender=="other") echo "checked";?> value="other">Other  
  <span class="error">* <?php echo $genderErr;?></span>
  <br><br>
  <input type="submit" name="submit" value="Submit">  
</form>

<?php
echo "<h2>Your Input:</h2>";
echo $name;
echo "<br>";
echo $email;
echo "<br>";
echo $website;
echo "<br>";
echo $comment;
echo "<br>";
echo $gender;
?>
	
<p>
<h2>Browser Bypass Overview</h2>
<p>Browser-side input controls are features in web applications that help manage and validate what users type directly in their browsers. These controls often use HTML attributes and JavaScript to enforce rules like making fields mandatory, ensuring inputs follow certain formats, or keeping values within a specific range. They improve user experience by providing instant feedback and reducing the load on servers, but they aren't entirely secure.</p>

<h3>Types of Browser-Side Input Controls</h3>
<b>HTML Attributes:</b>Elements like required, min, max, and pattern help enforce basic validation rules without needing JavaScript.
<br><b>JavaScript Validation:</b>Scripts can offer more complex checks, such as verifying email formats or ensuring passwords meet certain standards.

<br><h3>Methods to Bypass These Controls</h3>
Even though these controls are useful, they can be bypassed because they run on the client side, where users have complete control over their browsers. 

<b><p>Common methods:</p></b>
<b>Turning Off JavaScript:</b>Users can disable JavaScript in their browsers, bypassing any validation logic implemented through scripts.
<b><br>Modifying HTML:</b> Browser developer tools allow users to inspect and change HTML elements directly, such as removing required attributes or altering input types.
<b><br>Intercepting Requests:</b> Tools like Zap proxy let users intercept HTTP requests between the browser and server, modify the data being sent, and forward it to the server. This approach allows users to bypass client-side checks and submit any data they want.<br>
<h3>Security Concerns</h3>
Relying only on client-side validation can lead to security issues. Since users can manipulate their browsers, it's essential to also perform validation on the server side to ensure data integrity and security. Server-side checks act as a safety net by verifying all incoming data before processing it.
<h3>Best Practices</h3>
<b>Dual Validation:</b> Use both client-side and server-side validation. Client-side checks enhance user experience with immediate feedback, while server-side checks ensure security by verifying all data before processing.<br>
<b>Regular Security Reviews:</b><br> Conduct frequent security audits and penetration tests to identify potential vulnerabilities in input handling.
<b><br>User Education:</b><br> Teach users safe practices to prevent social engineering attacks that could lead to input manipulation.
By recognizing the limitations of browser-side input controls and implementing strong server-side checks, developers can improve both the usability and security of their applications.
</div> 
  

	
</div>

<div class="footer">
  <p>Break me first then try fix me....</p>
</div>

</body>
</html>


