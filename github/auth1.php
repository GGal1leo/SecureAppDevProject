<?php
	include_once 'header.php';
	if (!isset($_SESSION['u_id'])) {
	header("Location: home.php");
	} else {
		$user_id = $_SESSION['u_id']; 
		$user_uid = $_SESSION['u_uid'];
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 1</h2>
				Only authenticated users should be able to see this Page(1).
            </div>
        </section>
	
<?php	
	echo "<br>";
	//Reflect user's name on the page
	if(isset($_SESSION['u_id'])) {
		$user_uid = $_SESSION['u_uid'];
		echo "You're logged in as " . cleanChars($user_uid);
	}
?>

<html>

<!-- https://hackersonlineclub.com/command-injection-cheatsheet/

Objectives
1. Obtain the directory structure on the server
2. obtain the network configuration of the server
3. Upload a file that will execuite on the server (.php file parhaps)
4. Run the file -->

<head>

</head>


<div class="header">

</div>

<div class="clearfix">
  <div class="column menu">

  </div>

  <div class="column content">
	<p></p>


  </div> 
  
  <div class="column content">
  <p><br>Enter your IP/host to ping.  
            <form method='get' action=''>
                <div class="form-group"> 
                    <label></label>
                    <input class="form-control" width="50%" placeholder="" name="target"></input> <br>
                    <div align="left"> <button class="btn btn-default" type="submit">Submit Button</button></div>
               </div> 
            </form>
	</p>

  <?php

	// CommandExecutor class to prevent command injection
	class CommandExecutor {
		private $allowedCommands = ['ping'];
		private $allowedOptions = ['-c', '-n', '-w'];
		private $maxLength = 15;
		
		public function executePing($target) {
			// Validate input
			if (!$this->validateInput($target)) {
				return "Invalid input: Please enter a valid IP address (e.g., 192.168.1.1) or hostname (e.g., example.com). Input must not contain dangerous characters.";
			}
			
			// Build command safely
			$command = $this->buildPingCommand($target);
			
			// Execute command
			return $this->executeCommand($command);
		}
		
		private function validateInput($input) {
			// Check length
			if (strlen($input) > $this->maxLength) {
				return false;
			}
			
			// Check for command injection characters
			$dangerousChars = [';', '&', '|', '`', '$', '>', '<', '*', '?', '~', '!', '#', '%', '^', '=', '+', '[', ']', '{', '}', '\\'];
			foreach ($dangerousChars as $char) {
				if (strpos($input, $char) !== false) {
					return false;
				}
			}
			
			// Validate IP address or hostname format
			if (!filter_var($input, FILTER_VALIDATE_IP) && !$this->isValidHostname($input)) {
				return false;
			}
			
			return true;
		}
		
		private function isValidHostname($hostname) {
			// Basic hostname validation
			// Allow letters, numbers, dots, and hyphens
			// Must start and end with a letter or number
			// Each segment must be between 1-63 characters
			// TLD must be at least 2 characters
			return (bool)preg_match('/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $hostname);
		}
		
		private function buildPingCommand($target) {
			$command = 'ping';
			
			// Add platform-specific options
			if (stristr(php_uname('s'), 'Windows NT')) {
				$command .= ' ' . escapeshellarg($target);
			} else {
				$command .= ' -c 3 ' . escapeshellarg($target);
			}
			
			return $command;
		}
		
		private function executeCommand($command) {
			// Execute command and capture output
			$output = [];
			$returnVar = 0;
			exec($command, $output, $returnVar);
			
			// Check for errors
			if ($returnVar !== 0) {
				return "Command execution failed";
			}
			
			return implode("\n", $output);
		}
	}

	try {
		if (isset($_REQUEST['target'])) {
			$target = $_REQUEST['target'];
			if($target){
				// Use the secure CommandExecutor class
				$executor = new CommandExecutor();
				$result = $executor->executePing($target);
				echo '<pre>' . cleanChars($result) . '</pre>';
			}
		}             
	}
	catch(Exception $e) {
		echo '<BR> Pass your payload to a parameter called name on the URL (HTTP GET request) ';
		echo '<BR><p><b>Example:</b>    http://localhost/Lab/dt/dt.php?target=IPaddress </p>';	
	}

	?>
	</div>
	
</div>

<div class="footer">
</div>

</body>
</html>



