<?php

    $dbServername = "localhost";
    $dbUsername = "monty";
    $dbPassword = "newpass";
    $dbName = "secureappdev";

	try{
    	$conn = mysqli_connect($dbServername, $dbUsername, $dbPassword, $dbName);
	}
	catch (PDOException $e) {
            //echo "Error: " . $e->getMessage();
	}
	
?>
