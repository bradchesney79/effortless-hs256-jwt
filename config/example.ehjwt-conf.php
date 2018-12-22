// This package uses, in most cases, a DB table to deny authorization for revoked, unexpired tokens.

// Please provide the connection details. Help me, help you...

// Wikipedia article about DSNs https://en.wikipedia.org/wiki/Data_source_name

/*
$dsn = 'mysql:host=localhost;dbname=example";
or
$dsn = 'mysql:host=localhost;port=3307;dbname=testdb';
or
$dsn = 'mysql:unix_socket=/tmp/mysql.sock;dbname=testdb';


$dbh = new PDO($dsn, $username, $password);

The above code is what is generally used for PHP PDO connections to mysql.

You will supply the dsn string, 'mysql:unix_socket=/tmp/mysql.sock;dbname=testdb', for instance; the username; and the password.

By specifying these things separately, this package supports a wider range of persistent data stores.


*/

return [
	
	'dsn' => null,

	'user' => null,

	'password' => null,

	'jwtSecret' => null

];

// Thanks AnrDaemon
