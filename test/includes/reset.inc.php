<?php

//If user is not logged in or requesting to reset, redirect
include 'dbh.inc.php';
include_once 'password_functions.php';
session_start();

if (!isset($_GET['reset'],$_SESSION['u_uid'])) {
    $_SESSION['resetError'] = "Error code 1";
    header("Location: ../index.php");
} else {
    $oldpass = $_GET['old'];
    $newConfirm = $_GET['new_confirm'];
    $newpass = $_GET['new'];

    if (empty($oldpass || $newpass)) {
        $_SESSION['resetError'] = "Error code 2";
    } else {
        
        $uid = $_SESSION['u_uid'];

        $checkOld = "SELECT * FROM `sapusers` WHERE `user_uid` = ?"; //$uid
        $stmt = $conn->prepare($checkOld);
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) { 

            $row = mysqli_fetch_assoc($result); 

            // Verify the old password using the new function
            if (!verifyPassword($oldpass, $row['user_pwd'])) {
                $_SESSION['resetError'] = "Error code 4";
                header("Location: ../index.php");
                exit();
            } else {
                if ($newConfirm == $newpass) { //confirm they match
                    try {
                        // Hash the new password using the new function
                        $hashedNewPass = hashPassword($newpass);

                        $changePass = "UPDATE `sapusers` SET `user_pwd` = ? WHERE `user_uid` = ?"; //$newpass, $uid
                        $stmt = $conn->prepare($changePass);
                        $stmt->bind_param("ss", $hashedNewPass, $uid);
                                
                        if(!$stmt->execute()) {
                            echo "Error: " . $stmt->error;
                        }

                        header("Location: ./logout.inc.php");
                        exit();
                    } catch (Exception $e) {
                        $_SESSION['resetError'] = "Password does not meet complexity requirements: " . $e->getMessage();
                        header("Location: ../index.php");
                        exit();
                    }
                } else {
                    $_SESSION['resetError'] = "Error code 5";
                    header("Location: ../index.php");
                    exit();
                }
            }
        } else {
            $_SESSION['resetError'] = "Error code 6"; 
            header("Location: ../index.php");
            exit();
        }
    }
}