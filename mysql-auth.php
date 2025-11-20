<?php
session_start();

/*
if (!file_exists($userlist) || !is_readable($userlist))
{
    $error = 'Login is current unavailable. Please try again later';
}
else
{
*/

$databaseServer   = 'localhost';
$sqlUsername      = 'signadmin';
$sqlPassword      = 'AllThePasswords!95';
$databaseName     = 'signusers';

$error = '';

// Pull username/password from POST if not already set
$username = isset($username) ? $username : ($_POST['username'] ?? '');
$password = isset($password) ? $password : ($_POST['password'] ?? '');

$username = trim($username);

// Basic sanity check
if (strlen($username) === 0 || strlen($username) > 16)
{
    $error = 'Incorrect username or password. Please try again.';
}
else
{
    // Connect to MySQL
    $databaseConnection = mysqli_connect($databaseServer, $sqlUsername, $sqlPassword, $databaseName);

    if (!$databaseConnection)
    {
        $error = 'Login is currently unavailable. Please try again later.';
    }
    else
    {
        // Prepared statement protects against SQL injection
        $statement = mysqli_prepare(
            $databaseConnection,
            'SELECT password FROM accounts WHERE account = ?'
        );

        if ($statement === false)
        {
            $error = 'Login is currently unavailable. Please try again later.';
        }
        else
        {
            mysqli_stmt_bind_param($statement, 's', $username);
            mysqli_stmt_execute($statement);

            $result = mysqli_stmt_get_result($statement);

            if ($result && $result->num_rows === 1)
            {
                $row = mysqli_fetch_assoc($result);
                $storedHash = $row['password'];

                // *** HASHED PASSWORD CHECK ***
                if (password_verify($password, $storedHash))
                {
                    // Optional: upgrade hash automatically if algo changes
                    if (password_needs_rehash($storedHash, PASSWORD_DEFAULT))
                    {
                        $newHash = password_hash($password, PASSWORD_DEFAULT);

                        $update = mysqli_prepare(
                            $databaseConnection,
                            'UPDATE accounts SET password = ? WHERE account = ?'
                        );
                        mysqli_stmt_bind_param($update, 'ss', $newHash, $username);
                        mysqli_stmt_execute($update);
                        mysqli_stmt_close($update);
                    }

                    $_SESSION['authenticated'] = $username;
                    session_regenerate_id(true);

                    header('Location: search.php');
                    exit;
                }
                else
                {
                    $error = 'Incorrect username or password. Please try again.';
                }
            }
            else
            {
                $error = 'Incorrect username or password. Please try again.';
            }

            if ($result)
            {
                mysqli_free_result($result);
            }

            mysqli_stmt_close($statement);
        }

        mysqli_close($databaseConnection);
    }
}

//}
?>
