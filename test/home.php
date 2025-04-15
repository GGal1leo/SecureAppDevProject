<?php
      include_once 'header.php';
?>
        <section class="main-container">
            <div class="main-wrapper">
                <h2>Homepage</h2>
				Welcome to this Super Secure PHP Application.
				
				<?php
					$conn = mysqli_connect("localhost","monty","newpass");
					
					 if(! $conn ) {
						die('Could not connect: ' . mysql_error());
					} else {
						if (!mysqli_query($conn,"CREATE DATABASE secureappdev")) {
							echo "Database already exists";
						}
					
					}
					
                ?>
				
            </div>
        </section>

<?php
	include_once 'footer.php';
?>