<?php
namespace BradChesney79;

use DateTime;
use DateTimeZone;
use Exception;
use LogicException;
use PDO;
use PDOException;
use RuntimeException;

class EHJWT
{
    // !!! ksort the properties to maintain repeatable order

    // properties
    /*
      iss: issuer, the website that issued the token
      sub: subject, the id of the entity being granted the token
          (int has an unsigned, numeric limit of 4294967295)
          (bigint has an unsigned, numeric limit of 18446744073709551615)
          (unix epoch as of "now" 1544897945)
      aud: audience, the users of the token-- generally a url or string
      exp: expires, the UTC UNIX epoch time stamp of when the token is no longer valid
      nbf: not before, the UTC UNIX epoch time stamp of when the token becomes valid
      iat: issued at, the UTC UNIX epoch time stamp of when the token was issued
      jti: JSON web token ID, a unique identifier for the JWT that facilitates revocation
    */

//    /**
//     * Issuer
//     *
//     * @var string
//     */
//    private string $iss = '';
//    /**
//     * Subject
//     *
//     * @var string
//     */
//    private string $sub = '';
//    /**
//     * Audience
//     *
//     * @var string
//     */
//    private string $aud = '';
//    /**
//     * Expiration Time
//     *
//     * @var string
//     */
//    private string $exp = '';
//    /**
//     * Not Before
//     *
//     * @var string
//     */
//    private string $nbf = '';
//    /**
//     * Issued At
//     *
//     * @var string
//     */
//    private string $iat = '';
//    /**
//     * JWT ID
//     *
//     * @var string
//     */
//    private string $jti = '';

    /**
     * Token Claims
     *
     * @var array
     */
    private array $tokenClaims = array();

//    /**
//     * @var string
//     */
//    private $jwtSecret = '';

    /**
     * @var string
     */
    private string $token = '';

    /**
     * The config data.
     *
     * @var array
     */
    protected $configurations = [];
//    protected $configurations = array('jwtSecret' => '', 'dsn' => '', 'dbUser' => '', 'dbPassword' => '');

//    /**
//     * Error Object
//     *
//     * @var object
//     */
//    public object $error;

//    /**
//     * Banned users data.
//     *
//     * @var array
//     */
//    public $bannedUsers = [];

    //    private const jwtHeader = array(
    //        'alg' => 'HS256',
    //        'typ' => 'JWT'
    //    );

    // methods
    
    public function __construct(string $secret = '', string $configFileNameWithPath = '', string $dsn = '', string $dbUser = '', string $dbPassword = '')
    {

        try {
            $this->setConfigurationsFromEnvVars();

            if(mb_strlen($configFileNameWithPath) > 0) {
                $this->setConfigurationsFromConfigFile($configFileNameWithPath);
            }

            $this->setConfigurationsFromArguments($secret, $dsn, $dbUser, $dbPassword);
        }

        catch(Exception $e) {
            throw new LogicException('Failure creating EHJWT object: ' . $e->getMessage(), 0);
        }

        return true;
    }
    
    private function setConfigurationsFromEnvVars()
    {

        $envVarNames = array('EHJWT_JWT_SECRET', 'EHJWT_DSN', 'EHJWT_DB_USER', 'EHJWT_DB_PASS');
        $settingConfigurationName = array('jwtSecret', 'dsn', 'dbUser', 'dbPassword');
        for ($i=0; $i<count($envVarNames); $i++) {
            $retrievedEnvironmentVariableValue = getenv($envVarNames[$i]);
            if (mb_strlen($retrievedEnvironmentVariableValue) > 0) {
                $this->configurations[$settingConfigurationName[$i]] = $retrievedEnvironmentVariableValue;
            }
        }
    }

    private function setConfigurationsFromConfigFile(string $configFileWithPath)
    {
        if (file_exists($configFileWithPath))
        {
            $configFileSettings = require $configFileWithPath;

            if (gettype($configFileSettings) !== 'array') {
                throw new RuntimeException('EHJWT config file does not return an array');
            }

            if (count($configFileSettings) == 0) {
                trigger_error('No valid configurations received from EHJWT config file', 8);
            }

            foreach(array('jwtSecret', 'dsn', 'dbUser', 'dbPassword') as $settingName) {
                $retrievedConfigFileVariableValue = $configFileSettings[$settingName];
                if (mb_strlen($retrievedConfigFileVariableValue) > 0) {
                    $this->configurations[$settingName] = $retrievedConfigFileVariableValue;
                }
            }
        }
    }

    private function setConfigurationsFromArguments(string $jwtSecret = '', string $dsn = '', string $dbUser = '', string $dbPassword = '')
    {
        foreach(array('jwtSecret', 'dsn', 'dbUser', 'dbPassword') as $settingName) {
            $argumentValue = ${"$settingName"};
            if (mb_strlen($argumentValue) > 0) {
                $this->configurations[$settingName] = $argumentValue;
            }
        }
    }

    public function addOrUpdateJwtClaim(string $key, $value, $requiredType = 'mixed')
    {
        // ToDo: Needs more validation or something ...added utf8

        if (gettype($value) == $requiredType || $requiredType === 'mixed')
        {
            if (mb_detect_encoding($value, 'UTF-8', true)) {
                $this->tokenClaims[$key] = $value;
                return true;
            }
            throw new RuntimeException('Specified JWT claim required encoding mismatch');
        }
        throw new RuntimeException('Specified JWT claim required type mismatch');
    }

    public function clearClaim(string $key)
    {
        if (isset($key)) {
            unset($this->tokenClaims[$key]);
        }
        return true;
    }

    private function jsonEncodeClaims()
    {
        return json_encode($this->tokenClaims, JSON_FORCE_OBJECT);
    }

    private function createSignature($base64UrlHeader, $base64UrlClaims)
    {
        $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);
        return $this->base64UrlEncode($jsonSignature);
    }

    public function createToken()
    {
        // convert from arrays to JSON objects
        // $jsonHeader = $this->jsonEncodeHeader();
        // $jsonHeader = '{"alg":"HS256","typ":"JWT"}';

        ksort($this->tokenClaims);

        $jsonClaims = $this->jsonEncodeClaims();

        // encode the header and claims to base64url string
        // $base64UrlHeader = $this->base64UrlEncode($jsonHeader);
        // The hash is always the same... don't bother computing it.
        $base64UrlHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

        $base64UrlClaims = $this->base64UrlEncode($jsonClaims);

        // create signature
        $jsonSignature = $this->createSignature($base64UrlHeader, $base64UrlClaims);

        // encode signature to base64url string
        $base64UrlSignature = $this->base64UrlEncode($jsonSignature);

        $tokenParts = array(
            $base64UrlHeader,
            $base64UrlClaims,
            $base64UrlSignature
        );

        $this->token = implode('.', $tokenParts);

        return true;
    }

    public function getUtcTime()
    {
        $date = new DateTime('now', new DateTimeZone('UTC'));
        return $date->getTimestamp();
    }

    public function loadToken(string $tokenString)
    {
        $this->token = $tokenString;
        if($this->validateToken()) {
            $tokenParts = explode('.', $tokenString);
            $this->tokenClaims =  $this->decodeTokenPayload($tokenParts[1]);
            return true;
        }
        $this->clearClaims();
        return false;
    }

//    public function validateToken(bool checkForStoredInvalidations = false)
    public function validateToken()
    {
        // create token object instance
        // load token
        // use this to validate
        $tokenParts = $this->getTokenParts();

        //$unpackedTokenHeader = $this->decodeTokenHeader($tokenParts[0]);

        $unpackedTokenPayload = $this->decodeTokenPayload($tokenParts[1]);

        // set config options

        // set object properties with header & payload values
        // set the claims properties
        $this->tokenClaims = $unpackedTokenPayload;

        // do the properties check out
        //if ($unpackedTokenHeader['alg'] !== 'HS256')
        if ($tokenParts[0] !== 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
        {
            // 'Wrong algorithm'
            throw new RuntimeException('Encryption algorithm tampered with', 0);
        }

        $utcTimeNow = $this->getUtcTime();

        if (!isset($unpackedTokenPayload['exp'])) {
            throw new RuntimeException("Expiration standard claim for JWT missing", 0);
        }
        $expiryTime = $unpackedTokenPayload['exp'];

        // a good JWT integration uses token expiration, I am forcing your hand

        if ($utcTimeNow > intval($expiryTime))
        {
            // 'Expired (exp)'
            throw new RuntimeException('Token is expired', 0);
        }

        $notBeforeTime = $unpackedTokenPayload['nbf'];

        // if nbf is set
        if (null !== $notBeforeTime)
        {
            if (intval($notBeforeTime) > $utcTimeNow)
            {
                // 'Too early for not before(nbf) value'
                throw new RuntimeException('Token issued before nbf header allows', 0);
            }
        }

        if (mb_strlen($this->configurations['dbUser']) > 0 && mb_strlen($this->configurations['dbPassword']) > 0) {

            // create DB connection
            if (strpos ($this->configurations['dsn'], ':') === false) {
                throw new RuntimeException('No valid DSN stored for connection to DB', 0);
            }

            $dbh = $this->makeRevocationTableDatabaseConnection();

            if(!$dbh instanceof PDO) {
                throw new RuntimeException('Cannot connect to the DB to check for revoked tokens and banned users', 0);
            }


            $lastCharacterOfUtcTimeNow = substr($utcTimeNow, -1);

            // clean out revoked token records if the UTC unix time ends in '0'
            if (0 == (intval($lastCharacterOfUtcTimeNow))) {
                $this->revocationTableCleanup($dbh, $utcTimeNow);
            }

            if (!isset($unpackedTokenPayload['sub'])) {
                throw new RuntimeException("Subject standard claim not set to check ban status");
            }

            // ToDo: fix bind statement
            $stmt = $dbh->prepare("SELECT * FROM revoked_ehjwt where sub = ?");
            $stmt->bindParam(1, $unpackedTokenPayload['sub']);

            // get records for this sub
            if ($stmt->execute())
            {
                while ($row = $stmt->fetch())
                {
                    // print_r($row);
                    // any records where jti is 0
                    if ($row['jti'] == 0 && $row['exp'] > $utcTimeNow)
                    {

                        // user is under an unexpired ban condition
                        return false;
                    }

                    if ($row['jti'] == $unpackedTokenPayload['jti'])
                    {

                        // token is revoked
                        return false;
                    }

                    // remove records for expired tokens to keep the table small and snappy
                    if ($row['exp'] < $utcTimeNow)
                    {

                        // deleteRevocation record
                        $this->deleteRecordFromRevocationTable($row['id']);
                    }
                }
            }


            // clean up DB artifacts
            $row = null;
            $stmt = null;


            if (!isset($unpackedTokenPayload['sub'])) {
                throw new RuntimeException("Subject standard claim not set to check ban status");
            }

            // ToDo: fix bind statement
            $stmt = $dbh->prepare("SELECT * FROM revoked_ehjwt where sub = ?");
            $stmt->bindParam(1, $unpackedTokenPayload['sub']);

            // get records for this sub
            if ($stmt->execute()) {
                while ($row = $stmt->fetch()) {
                    // print_r($row);
                    // any records where jti is 0
                    if ($row['jti'] == 0 && $row['exp'] > $utcTimeNow) {

                        // user is under an unexpired ban condition
                        return false;
                    }

                    if ($row['jti'] == $unpackedTokenPayload['jti']) {

                        // token is revoked
                        return false;
                    }

                    // remove records for expired tokens to keep the table small and snappy
                    if ($row['exp'] < $utcTimeNow) {

                        // deleteRevocation record
                        $this->deleteRecordFromRevocationTable($row['id']);
                    }
                }
            }

            // clean up DB artifacts
            $row = null;
            $stmt = null;
            $dbh = null;
        }


        $this->createToken();

        // verify the signature
        $recreatedToken = $this->getToken();
        $recreatedTokenParts = explode('.', $recreatedToken);
        $recreatedTokenSignature = $recreatedTokenParts[2];

        if ($recreatedTokenSignature !== $tokenParts['2'])
        {
            // 'signature invalid, potential tampering
            return false;
        }

        // the token checks out!
        return true;
    }

    public function revocationTableCleanup(PDO $databaseConnectionHandle, $utcTimeStamp) {

            try
            {
                $stmt = $databaseConnectionHandle->prepare("DELETE FROM revoked_ehjwt WHERE exp =< $utcTimeStamp");

                $stmt->execute();
            }
            catch(PDOException $e)
            {
                throw new RuntimeException('Ehjwt clear old revocation records error', 0);
            }

            // clean up DB artifacts
            $stmt = null;
    }

    private function getTokenParts()
    {
        $tokenParts = explode('.', $this->token);
        if ($this->verifyThreeMembers($tokenParts))
        {
            return $tokenParts;
        }
        throw new RuntimeException('Token does not contain three delimited sections', 0);
    }

    private function verifyThreeMembers(array $array)
    {

        if (3 !== count($array))
        {
            // 'Incorrect quantity of segments'
            return false;
        }
        return true;
    }

    private function makeRevocationTableDatabaseConnection()
    {
        return new PDO($this->configurations['dsn'], $this->configurations['dbUser'], $this->configurations['dbPassword'], array(
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_NAMED
        ));
    }

    private function deleteRecordFromRevocationTable(string $recordId)
    {
        try
        {
            $dbh = $this->makeRevocationTableDatabaseConnection();

            $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE id = ?");

            $stmt->bindParam(1, $recordId);

            $stmt->execute();
        }
        catch(PDOException $e) {
            throw new RuntimeException('Ehjwt delete revocation record error: ' . $e->getMessage(), 0);
        }
    }


//////////

    public function reissueToken(string $tokenString, int $newUtcTimestampExpiration)
    {
        if ($this->loadToken($tokenString)) {

            $this->addOrUpdateJwtClaim('exp', $newUtcTimestampExpiration);

            $this->createToken();

            return $this->getToken();
        }
        throw new RuntimeException('Invalid token submitted for reissue');
    }

    public function getToken()
    {
        // Make a new EHJWT object instance
        // populate the properties
        // Then use this to get a token
        return $this->token;
    }


//    private function decodeTokenHeader(string $jwtHeader)
//    {
//
//        $decodedHeader = json_decode($this->base64UrlDecode($jwtHeader) , true);
//
//        switch (json_last_error())
//        {
//            case JSON_ERROR_NONE:
//                $error = ''; // JSON is valid // No error has occurred
//
//                break;
//            case JSON_ERROR_DEPTH:
//                $error = 'The maximum stack depth has been exceeded from the JWT header.';
//                break;
//            case JSON_ERROR_STATE_MISMATCH:
//                $error = 'Invalid or malformed JWT header JSON.';
//                break;
//            case JSON_ERROR_CTRL_CHAR:
//                $error = ' JWT header control character error, possibly incorrectly encoded.';
//                break;
//            case JSON_ERROR_SYNTAX:
//                $error = 'Syntax error, JWT header malformed JSON.';
//                break;
//            // PHP >= 5.3.3
//
//            case JSON_ERROR_UTF8:
//                $error = 'Malformed UTF-8 JWT header characters, possibly incorrectly encoded.';
//                break;
//            // PHP >= 5.5.0
//
//            case JSON_ERROR_RECURSION:
//                $error = 'One or more recursive references in the JWT header value to be encoded.';
//                break;
//            // PHP >= 5.5.0
//
//            case JSON_ERROR_INF_OR_NAN:
//                $error = 'One or more NAN or INF values in the JWT header value to be encoded.';
//                break;
//            case JSON_ERROR_UNSUPPORTED_TYPE:
//                $error = 'A JWT header value of a type that cannot be encoded was given.';
//                break;
//            default:
//                $error = 'Unknown JWT header JSON error occured.';
//                break;
//        }
//
//        if ($error == '')
//        {
//            return $decodedHeader;
//        }
//        // 'Header does not decode'
//        throw new RuntimeException($error, 0);
//    }

    private function decodeTokenPayload($jwtPayload)
    {
        $decodedPayload = json_decode($this->base64UrlDecode($jwtPayload) , true);

        if (0 !== json_last_error()) {
            throw new RuntimeException("JWT payload json_decode() error: " . json_last_error_msg(), 0);
        }

        return $decodedPayload;

//        //--------------------------
//        switch (json_last_error())
//        {
//            case JSON_ERROR_NONE:
//                // JSON is valid, no error has occurred
//                $error = '';
//                break;
//            case JSON_ERROR_DEPTH:
//                $error = 'The maximum stack depth has been exceeded from the JWT payload.';
//                break;
//            case JSON_ERROR_STATE_MISMATCH:
//                $error = 'Invalid or malformed JWT payload JSON.';
//                break;
//            case JSON_ERROR_CTRL_CHAR:
//                $error = ' JWT payload control character error, possibly incorrectly encoded.';
//                break;
//            case JSON_ERROR_SYNTAX:
//                $error = 'Syntax error, JWT payload malformed JSON.';
//                break;
//            case JSON_ERROR_UTF8:
//                $error = 'Malformed UTF-8 JWT payload characters, possibly incorrectly encoded.';
//                break;
//            case JSON_ERROR_RECURSION:
//                $error = 'One or more recursive references in the JWT payload value to be encoded.';
//                break;
//            case JSON_ERROR_INF_OR_NAN:
//                $error = 'One or more NAN or INF values in the JWT payload value to be encoded.';
//                break;
//            case JSON_ERROR_UNSUPPORTED_TYPE:
//                $error = 'A JWT payload value of a type that cannot be encoded was given.';
//                break;
//            default:
//                $error = 'Unknown JWT payload JSON error occured.';
//                break;
//        }
//
//        if ($error == '')
//        {
//            return $decodedPayload;
//        }
//        // 'Payload does not decode'
//        throw new RuntimeException($error, 0);
    }



    // From here out claims are equal, standard and custom have parity
    public function getTokenClaims()
    {
        return $this->tokenClaims;
    }

    // private function base64UrlEncode(string $unencodedString) {
    //     return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($unencodedString));
    // }
    private function base64UrlEncode(string $unencodedString)
    {
        return rtrim(strtr(base64_encode($unencodedString) , '+/', '-_') , '=');
    }

    // private function base64UrlDecode(string $base64UrlEncodedString) {
    //     return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    // }
    private function base64UrlDecode(string $base64UrlEncodedString)
    {
        return base64_decode(str_pad(strtr($base64UrlEncodedString, '-_', '+/') , mb_strlen($base64UrlEncodedString) % 4, '=', STR_PAD_RIGHT));
    }

    private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims)
    {
        // sha256 is the only algorithm. sorry, not sorry.
        return hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlClaims, $this->configurations['jwtSecret'], true);
    }

    public function clearClaims()
    {
        $this->tokenClaims = [];
    }

    public function revokeToken()
    {

        // only add if the token is valid-- don't let imposters kill otherwise valid tokens
        if ($this->validateToken())
        {

            $revocationExpiration = (int)$this->tokenClaims['exp'] + 30;

            $this->writeRecordToRevocationTable($revocationExpiration);
        }
    }

    public function banUser(string $utcUnixTimestampBanExpiration)
    {
        $banExp = (int)$this->exp + 60;

        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end
        $this->writeRecordToRevocationTable($utcUnixTimestampBanExpiration, true);
    }

    public function permabanUser()
    {
        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end-- Tuesday after never
        $this->writeRecordToRevocationTable('18446744073709551615', true);
    }

    public function unbanUser()
    {
        $this->deleteRecordsFromRevocationTable();
    }

    private function setCustomClaims(array $customClaims)
    {
        foreach ($customClaims as $claimKey => $value)
        {
            try
            {
                if (mb_check_encoding($value, 'UTF-8'))
                {
                    $this->customClaims[$claimKey] = $value;
                    return true;
                }
                throw new RuntimeException('Ehjwt custom claim non-UTF-8 input string encoding error.', 0);
                return false;
            }
            catch(RuntimeException $e)
            {
                error_log($e->getMessage());
                return false;
            }
        }
    }

    private function writeRecordToRevocationTable(int $exp, bool $ban = false)
    {
        try
        {
            $userBanJtiPlaceholder = 0;

            $dbh = $this->makeRevocationTableDatabaseConnection();

            $stmt = $dbh->prepare("INSERT INTO revoked_ehjwt (jti, sub, exp) VALUES (?, ?, ?)");

            $stmt->bindParam(1, $this->tokenClaims['jti']);
            if ($ban)
            {
                $stmt->bindParam(1, $userBanJtiPlaceholder);
            }

            $stmt->bindParam(2, $this->tokenClaims['sub']);
            $stmt->bindParam(3, $exp);

            $stmt->execute();

            unset($dbh);
            unset($stmt);
        }
        catch(PDOException $e)
        {
            throw new RuntimeException('Ehjwt write revocation record error: ' . $e->getMessage() , 0);
        }
    }

    private function deleteRecordsFromRevocationTable()
    {
        try
        {
            try
            {
                $userBanJtiPlaceholder = 0;

                $dbh = $this->makeRevocationTableDatabaseConnection();

                $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE sub = ? AND jti = $userBanJtiPlaceholder");

                $stmt->bindParam(1, $this->sub);

                $stmt->execute();

                unset($dbh);
                unset($stmt);
            }
            catch(PDOException $e)
            {
                throw new RuntimeException('Ehjwt delete revocation record error: ' . $e->getMessage() , 0);
            }
        }
        catch(RuntimeException $e)
        {
            error_log($e->getMessage());
        }
    }






    // ToDo: Provide access to a list of banned users
    public function getBannedUsers()
    {
        if($this->retrieveBannedUsers()) {
            return $this->bannedUsers;
        }
        throw new RuntimeException('Could not retrieve banned user data', 0);
    }

    private function retrieveBannedUsers()
    {
        $this->makeRevocationTableDatabaseConnection();
        // select banned users
        // set banned users property
        $this->bannedUsers = array('Elvis');
        return true;
    }
}

