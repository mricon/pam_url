<?

// we need at least 4 POST data elements. 
// 1. Authentication mode -> PAM_AUTH, PAM_SESS, PAM_ACCT, PAM_PASS
// 2. PSK, Pre Shared Key
// 3. USER
// 4. PASS

// DO SOURCE IP REGION CHECKS HERE, OTHERWISE BRUTEFORCE attacks might occur!!

$PSK = "hase";

if( isset($_POST["user"]) && isset($_POST["pass"]) && isset($_POST["mode"]) )
{
	$ret=0;

	switch($_POST["mode"])
	{
		case "PAM_SM_AUTH";
			// Perform authing here
			break;

		case "PAM_SM_ACCOUNT";
			// Perform account aging here
			break;

		case "PAM_SM_SESSION";
			// Perform session management here
			break;

		case "PAM_SM_PASSWORD";
			// Perform password changes here
			break;
	}

	if( 0 == $ret )
	{
		header("HTTP/1.1 200 OK");
		echo $PSK;
	}
	else
	{
		header("HTTP/1.1 400 Bad Request");
		echo "ACCESS DENIED";
	}
}
else
{
	header("HTTP/1.1 403 Forbidden");
	echo "ACCESS DENIED";
}
?>
