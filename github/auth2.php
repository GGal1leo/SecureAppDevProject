<?php
	include_once 'header.php';
	if (!isset($_SESSION['u_id'])) {
		header("Location: home.php");
		exit();
	} else {
		$user_id = $_SESSION['u_id'];
		$user_uid = $_SESSION['u_uid'];
	}

	// Define allowed directories and file types
	$allowedDirs = [
		__DIR__ . '/public',
		__DIR__ . '/uploads'
	];
	$allowedExtensions = ['txt', 'pdf', 'jpg', 'png'];

	// Function to validate file path
	function validateFilePath($filePath, $allowedDirs) {
		// Normalize the path
		$realPath = realpath($filePath);
		if ($realPath === false) {
			return false;
		}
		
		// Check if the file is within allowed directories
		foreach ($allowedDirs as $dir) {
			if (strpos($realPath, $dir) === 0) {
				return true;
			}
		}
		
		return false;
	}

	// Function to validate file type
	function isAllowedFileType($filePath, $allowedExtensions) {
		$extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
		return in_array($extension, $allowedExtensions);
	}

	// Function to check file access permissions
	function checkFileAccess($filePath, $userId) {
		// Add your database check here if needed
		// For now, we'll just check if the file exists and is readable
		return is_readable($filePath);
	}
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Auth page 2</h2>
				<?php
				if (isset($_GET['FileToView'])) {
					$filePath = $_GET['FileToView'];
					
					// Validate and sanitize the file path
					if (!validateFilePath($filePath, $allowedDirs)) {
						echo "Invalid file path";
						exit();
					}
					
					// Check file type
					if (!isAllowedFileType($filePath, $allowedExtensions)) {
						echo "File type not allowed";
						exit();
					}
					
					// Check user permissions
					if (!checkFileAccess($filePath, $user_id)) {
						echo "Access denied";
						exit();
					}
     
					// Read and display file contents safely
					$content = file_get_contents($filePath);
					if ($content !== false) {
						// Use cleanChars to prevent XSS
						echo cleanChars($content);
					} else {
						echo "Error reading file";
					}
				} else {
					echo "No file specified";
				}
				?>
            </div>
        </section>

<?php
	include_once 'footer.php';
?>