<?php
$hash = password_hash("MyPlaintextPassword123", PASSWORD_DEFAULT);
echo 'Hashed Value: ' . $hash;
?>
