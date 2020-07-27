<?php
/**
 * Created by PhpStorm.
 * User: bchesney
 * Date: 11/7/18
 * Time: 3:33 PM
 */

namespace bradchesney79;

use PDO;

class Ehjwt
{


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

    /**
     * Issuer
     *
     * @var string
     */
    private string $iss = '';
    /**
     * Subject
     *
     * @var string
     */
    private string $sub = '';
    /**
     * Audience
     *
     * @var string
     */
    private string $aud = '';
    /**
     * Expiration Time
     *
     * @var string
     */
    private string $exp = '';
    /**
     * Not Before
     *
     * @var string
     */
    private string $nbf = '';
    /**
     * Issued At
     *
     * @var string
     */
    private string $iat = '';
    /**
     * JWT ID
     *
     * @var string
     */
    private string $jti = '';

    /**
     * Standard Claims
     *
     * @var array
     */
    private array $standardClaims = array();
    /**
     * Custom Claims
     *
     * @var array
     */
    private array $customClaims = array();

    /**
     * Token Claims
     *
     * @var array
     */
    private array $tokenClaims = array();

    /**
     * @var string
     */
    private $jwtSecret = '';

    /**
     * @var string
     */
    private string $token = '';

    /**
     * The config file with path.
     *
     * @var string
     */
    protected string $configFile;

    /**
     * The config data.
     *
     * @var array
     */
    protected array $config = [];

    /**
     * Error Object
     *
     * @var object
     */
    public object $error;

    private const jwtHeader = array( 'alg' => 'HS256', 'typ' => 'JWT');

    private string $enforceUsingEnvVars = '';

    // methods

    private function checkEnforceUsingEnvVars() {
        if (getenv('ESJWT_USE_ENV_VARS') == 'true') {
            $this->enforceUsingEnvVars = true;
            return true;
        }

        $this->enforceUsingEnvVars = false;
        return false;
    }
    
    private function retrieveEnvValue(string $envKey) {
        $envValue = getEnv($envKey);
        if (!$envValue) {
            return '';
        }
        return $envValue;
    }

    private function setDsnFromEnvVar() {
        $dsn = $this->retrieveEnvValue('ESJWT_DSN');
        if (strlen($dsn) > 0) {
            $this->dsn = $dsn;
        }
        return true;
    }

    private function setDbUserFromEnvVar()
    {
        $dbUser = $this->retrieveEnvValue('ESJWT_DB_USER');
        if (strlen($dbUser) > 0) {
            $this->dbUser = $dbUser;
        }
        return true;
    }

    private function setDbPasswordFromEnvVar() {
        $dbPassword = $this->retrieveEnvValue('ESJWT_DB_PASS');
        if (strlen($dbPassword) > 0) {
            $this->dbPassword = $dbPassword;
        }
        return true;
    }

    private function setJwtSecretFromEnvVar() {
        $jwtSecret = $this->retrieveEnvValue('ESJWT_JWT_SECRET');
        if (strlen($jwtSecret) > 0) {
            $this->jwtSecret = $jwtSecret;
        }
        return true;
    }

    private function setIssFromEnvVar() {
        $iss = $this->retrieveEnvValue('ESJWT_ISS');
        if (strlen($iss) > 0) {
            $this->iss = $iss;
        }
        return true;
    }

    private function setAudFromEnvVar() {
        $aud = $this->retrieveEnvValue('ESJWT_AUD');
        if (strlen($aud) > 0) {
            $this->aud = $aud;
        }
        return true;
    }

    private function setPropertiesFromEnvVars() {
        $this->setDsnFromEnvVar();
        $this->setDbUserFromEnvVar();
        $this->setDbPasswordFromEnvVar();
        $this->setJwtSecretFromEnvVar();
        $this->setIssFromEnvVar();
        $this->setAudFromEnvVar();
        return true;
    }

    private function setConfigFileProperty(string $configFileWithPath) {
        if (strlen($configFileWithPath) < 1) {
            $this->file = __DIR__.'/../config/ehjwt-conf.php';
        }
        else {
            $this->file = $configFileWithPath;
        }
    }

    private function loadConfigFile() {
        if (file_exists($this->configFile)) {
            $this->config = require $this->configFile;
        }
    }

    private function setDsnFromConfig() {
        $dsn = $this->config['dsn'];
        if (strlen($dsn) > 0) {
            $this->dsn = $dsn;
        }
        return true;
    }

    private function setDbUserFromConfig(){
        $dbUser = $this->config['dbUser'];
        if (strlen($dbUser) > 0) {
            $this->dbUser = $dbUser;
        }
        return true;
    }

    private function setDbPasswordFromConfig() {
        $dbPassword = $this->config['dbPassword'];
        if (strlen($dbPassword) > 0) {
            $this->dbPassword = $dbPassword;
        }
        return true;
    }

    private function setJwtSecretFromConfig() {
        $jwtSecret = $this->config['jwtSecret'];
        if (strlen($jwtSecret) > 0) {
            $this->jwtSecret = $jwtSecret;
        }
        return true;
    }

    private function setIssFromConfig() {
        $iss = $this->config['iss'];
        if (strlen($iss) > 0) {
            $this->iss = $iss;
        }
        return true;
    }

    private function setAudFromConfig() {
        $aud = $this->config['aud'];
        if (strlen($aud) > 0) {
            $this->aud = $aud;
        }
        return true;
    }

    private function setPropertiesFromConfigFile() {
        $this->setDsnFromConfig();
        $this->setDbUserFromConfig();
        $this->setDbPasswordFromConfig();
        $this->setJwtSecretFromConfig();
        $this->setIssFromConfig();
        $this->setAudFromConfig();
        return true;
    }

    private function setDsnFromArguments(string $dsn) {
        if (strlen($dsn) > 0) {
            $this->dsn = $dsn;
        }
        return true;
    }

    private function setDbUserFromArguments(string $dbUser) {
        if (strlen($dbUser) > 0) {
            $this->dbUser = $dbUser;
        }
        return true;
    }

    private function setDbPasswordFromArguments(string $dbPassword) {
        if (strlen($dbPassword) > 0) {
            $this->dbPassword = $dbPassword;
        }
        return true;
    }

    private function setJwtSecretFromArguments(string $jwtSecret) {
        if (strlen($jwtSecret) > 0) {
            $this->jwtSecret = $jwtSecret;
        }
        return true;
    }

    private function setIssFromArguments(string $iss) {
        if (strlen($iss) > 0) {
            $this->iss = $iss;
        }
        return true;
    }

    private function setAudFromArguments(string $aud) {
        if (strlen($aud) > 0) {
            $this->aud = $aud;
        }
        return true;
    }

    private function setPropertiesFromArguments(string $secret = '', string $dsn = '', string $dbUser = '', string $dbPassword = '', string $iss = '', string $aud = '') {
        $this->setDsnFromArguments($dsn);
        $this->setDbUserFromArguments($dbUser);
        $this->setDbPasswordFromArguments($dbPassword);
        $this->setJwtSecretFromArguments($secret);
        $this->setIssFromArguments($iss);
        $this->setAudFromArguments($aud);
        return true;
    }

    public function __construct(string $secret = '', string $file = '', string $dsn = '', string $dbUser = '', string $dbPassword = '', string $iss = '', string $aud = '') {

        $this->setPropertiesFromEnvVars();

        $this->checkEnforceUsingEnvVars();

        // var_dump('==========================================================');

        if ($this->enforceUsingEnvVars) {
            return true;
        }
        else {
            $this->setConfigFileProperty($file);
            $this->loadConfigFile();
            $this->setPropertiesFromConfigFile();
            $this->setPropertiesFromArguments($secret, $dsn, $dbUser, $dbPassword, $iss, $aud);
        }
        return true;
    }

    public function addOrUpdateAudProperty(string $aud) {
        if (strlen($aud) > 0) {
            $this->aud = $aud;
            return true;
        }
        return false;
    }

    public function addOrUpdateExpProperty(string $exp) {
        // ToDo: this is an expiration date, do better here Chesney...
        if (strlen($exp) > 0) {
            $this->exp = $exp;
            return true;
        }
        return false;
    }

    public function addOrUpdateIatProperty(string $iat) {
        if (strlen($iat) > 0) {
            $this->iat = $iat;
            return true;
        }
        return false;
    }

    private function addOrUpdateIssProperty(string $iss) {
        if (strlen($iss) > 0) {
            $this->iss = $iss;
            return true;
        }
        return false;
    }

    public function addOrUpdateJtiProperty(string $jti) {
        if (strlen($jti) > 0) {
            $this->jti = $jti;
            return true;
        }
        return false;
    }

    public function addOrUpdateNbfProperty(string $nbf) {
        if (strlen($nbf) > 0) {
            $this->nbf = $nbf;
            return true;
        }
        return false;
    }

    public function addOrUpdateSubProperty(string $sub) {
        if (strlen($sub) > 0) {
            $this->sub = $sub;
            return true;
        }
        return false;
    }

    private function setStandardClaims() {
        $this->standardClaims = [
            'aud' => $this->aud,
            'exp' => $this->exp,
            'iat' => $this->iat,
            'iss' => $this->iss,
            'jti' => $this->jti,
            'nbf' => $this->nbf,
            'sub' => $this->sub
        ];
        return true;
    }

    public function addOrUpdateCustomClaim(string $key, $value) {
        // listen, your users shouldn't set your token keys-- you should
        // no validation, be smart
        // ToDo: maybe add validation so someone doesn't shoot themselves in the foot
        if(strlen($key) > 0) {
            $this->customClaims[$key] = $value;
            return true;
        }
        return false;
    }

    private function setTokenClaims() {
        ksort($this->customClaims);

        foreach ($this->customClaims as $key => $value) {
            if (strlen($value) > 0) {
                $this->tokenClaims[$key] = $value;
            }
        };

        // standard claims set after to make custom claims the priority value, layered security strategy

        foreach ($this->standardClaims as $key => $value) {
            if (strlen($value)) {
                $this->tokenClaims[$key] = $value;
            }
        }

        ksort($this->tokenClaims);

        return true;
    }

    private function jsonEncodeHeader() {}

    private function jsonEncodeBody() {}

    private function createSignature() {}

    private function createToken() {
        // header as immutable constant
        // create body

        $this->setStandardClaims();

        $this->setTokenClaims();

        // convert from arrays to JSON objects

        $jsonHeader = json_encode(self::jwtHeader, JSON_FORCE_OBJECT);

        $jsonClaims = json_encode($this->tokenClaims, JSON_FORCE_OBJECT);

        // encode the header and claims to base64url string
        $base64UrlHeader = $this->base64UrlEncode($jsonHeader);

        $base64UrlClaims = $this->base64UrlEncode($jsonClaims);

        // create signature

        $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);

        // encode signature to base64url string
        $base64UrlSignature = $this->base64UrlEncode($jsonSignature);

        $tokenParts = array($base64UrlHeader, $base64UrlClaims, $base64UrlSignature);

        $this->token = implode('.', $tokenParts);

        return true;
    }

    public function getToken()
    {
        $this->createToken();
        return $this->token;
    }

    public function validateToken(string $tokenString)
    {
        $tokenParts = explode('.', $tokenString);

        if (3 !== count($tokenParts)) {
            //var_dump('segments');
            // 'Incorrect quantity of segments'
            return false;
        }

        //var_dump('header');
        $unpackedTokenHeader = json_decode($this->base64UrlDecode($tokenParts[0]), true);

        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                $error = ''; // JSON is valid // No error has occurred
                break;
            case JSON_ERROR_DEPTH:
                $error = 'The maximum stack depth has been exceeded.';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $error = 'Invalid or malformed JSON.';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $error = 'Control character error, possibly incorrectly encoded.';
                break;
            case JSON_ERROR_SYNTAX:
                $error = 'Syntax error, malformed JSON.';
                break;
            // PHP >= 5.3.3
            case JSON_ERROR_UTF8:
                $error = 'Malformed UTF-8 characters, possibly incorrectly encoded.';
                break;
            // PHP >= 5.5.0
            case JSON_ERROR_RECURSION:
                $error = 'One or more recursive references in the value to be encoded.';
                break;
            // PHP >= 5.5.0
            case JSON_ERROR_INF_OR_NAN:
                $error = 'One or more NAN or INF values in the value to be encoded.';
                break;
            case JSON_ERROR_UNSUPPORTED_TYPE:
                $error = 'A value of a type that cannot be encoded was given.';
                break;
            default:
                $error = 'Unknown JSON error occured.';
                break;
        }

        if ($error !== '') {
            //var_dump('undecodable header');
            // 'Header does not decode'
            return false;
        }

        //var_dump('payload');
        $unpackedTokenPayload = json_decode($this->base64UrlDecode($tokenParts[1]), true);

        switch (json_last_error()) {
            case JSON_ERROR_NONE:
                // JSON is valid, no error has occurred
                $error = '';
                break;
            case JSON_ERROR_DEPTH:
                $error = 'The maximum stack depth has been exceeded.';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $error = 'Invalid or malformed JSON.';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $error = 'Control character error, possibly incorrectly encoded.';
                break;
            case JSON_ERROR_SYNTAX:
                $error = 'Syntax error, malformed JSON.';
                break;
            case JSON_ERROR_UTF8:
                $error = 'Malformed UTF-8 characters, possibly incorrectly encoded.';
                break;
            case JSON_ERROR_RECURSION:
                $error = 'One or more recursive references in the value to be encoded.';
                break;
            case JSON_ERROR_INF_OR_NAN:
                $error = 'One or more NAN or INF values in the value to be encoded.';
                break;
            case JSON_ERROR_UNSUPPORTED_TYPE:
                $error = 'A value of a type that cannot be encoded was given.';
                break;
            default:
                $error = 'Unknown JSON error occured.';
                break;
    }

        if ($error !== '') {
            //var_dump('undecodable payload');
            // 'Payload does not decode'
            return false;
        }

        $unpackedTokenSignature = $tokenParts[2];

        if ($unpackedTokenHeader['alg'] !== 'HS256') {
            //var_dump('algorithm');
            // 'Wrong algorithm'
            return false;
        }

        $date = new \DateTime('now');

        $utcTimeNow = $date->getTimestamp();

        $expiryTime = $unpackedTokenPayload['exp'];

        // a good JWT integration uses token expiration, I am forcing your hand
        if (($utcTimeNow - $expiryTime) > 0) {
            //var_dump('expired');
            // 'Expired (exp)'
            return false;
        }

        $notBeforeTime = $unpackedTokenPayload['nbf'];

        // if nbf is set
        if (null !== $notBeforeTime) {
            if ($notBeforeTime > $utcTimeNow) {
                //var_dump('too early');
                // 'Too early for not before(nbf) value'
                return false;
            }
        }

        // create DB connection
        $dbh = new PDO($this->config['dsn'], $this->config['dbUser'], $this->config['dbPassword'], array(PDO::ATTR_PERSISTENT => true ));

        // clean out revoked token records if the UTC unix time ends in "0"
        if (0 == (substr($utcTimeNow, -1) + 0)) {
            try {
                $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE exp =< $utcTimeNow");
                
                $stmt->execute();
            } catch (PDOException $e) {
                error_log('Ehjwt clear old revocation records error: ' . $e->getMessage());
                throw new EhjwtClearOldRevocationRecordsFailException('Ehjwt clear old revocation records error: ' . $e->getMessage());
            }

            // clean up DB artifacts
            $stmt = null;
        }

        $stmt = $dbh->prepare("SELECT * FROM revoked_ehjwt where sub = ?");
        $stmt->bindParam(1, $unpackedTokenPayload['sub']);

        // get records for this sub
        if ($stmt->execute()) {
            while ($row = $stmt->fetch()) {
                // print_r($row);

                // any records where jti is 0
                if ($row['jti'] == 0 && $row['exp'] > $utcTimeNow) {
                    //var_dump('banned');
                    // user is under an unexpired ban condition
                    return false;
                }

                if ($row['jti'] == $unpackedTokenPayload['jti']) {
                    //var_dump('revoked');
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

        $this->createToken();

        // verify the signature
        $recreatedToken = $this->getToken();
        $recreatedTokenParts = explode('.', $recreatedToken);
        $recreatedTokenSignature = $recreatedTokenParts[2];

        if ($recreatedTokenSignature !== $tokenParts[2]) {
            // 'signature invalid, potential tampering
            return false;
        }

        // the token checks out!
        return true;
    }

    public function loadToken(string $tokenString)
    {
        $this->token = $tokenString;
        $this->unpackToken();
    }

    // From here out claims are equal, standard and custom have parity

    public function getClaims()
    {
        //$this->unpackToken($this->token);

        $standardClaims  = [
            'iss' => $this->iss,
            'sub' => $this->sub,
            'aud' => $this->aud,
            'exp' => $this->exp,
            'nbf' => $this->nbf,
            'iat' => $this->iat,
            'jti' => $this->jti
        ];

        if ($this->customClaims === null) {
            $this->customClaims = array();
        }

        $allClaims = array_merge($standardClaims, $this->customClaims);
        return $allClaims;
    }

    // private function base64UrlEncode(string $unencodedString) {
    //     return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($unencodedString));
    // }

    private function base64UrlEncode(string $unencodedString)
    {
        return rtrim(strtr(base64_encode($unencodedString), '+/', '-_'), '=');
    }

    // private function base64UrlDecode(string $base64UrlEncodedString) {
    //     return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    // }

    private function base64UrlDecode(string $base64UrlEncodedString)
    {
        return base64_decode(str_pad(strtr($base64UrlEncodedString, '-_', '+/'), strlen($base64UrlEncodedString) % 4, '=', STR_PAD_RIGHT));
    }

    private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims)
    {
        // sha256 is the only algorithm. sorry, not sorry.
        return hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlClaims, $this->jwtSecret, true);
    }

    public function clearClaims()
    {
        $this->iss = '';
        $this->sub = '';
        $this->aud = '';
        $this->exp = '';
        $this->nbf = '';
        $this->iat = '';
        $this->jti = '';

        $this->customClaims = [];
    }

    // ToDo: find a way to meld this into the new claim thingey
    public function OLDsetStandardClaims(array $standardClaims)
    {
        foreach ($standardClaims as $claimKey => $value) {
            if (mb_check_encoding($value, 'UTF-8')) {
                if (in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true)) {
                    $this->{$claimKey} = $value;
                } else {
                    $this->{$claimKey} = '';
                }
            } else {
                error_log('Ehjwt standard claim non-UTF-8 input string encoding error.');
                throw new EhjwtCustomClaimsInputStringException('Ehjwt standard claim non-UTF-8 input string encoding error.');
            }
        }
    }

    public function addTokenRevocationRecord(string $jti, string $sub, string $revocationExpiration)
    {

        // revoke a token with specific particulars
        // var_dump('addTokenRevocationRecord()');
        $this->writeRecordToRevocationTable($jti, $sub, $revocationExpiration);
    }

    public function revokeToken(string $token)
    {

        // unpack the token, add it to the revocation table

        $this->loadToken($token);

        $revocationExpiration = $this->exp + 30;

        // only add if the token is valid-- don't let imposters kill otherwise valid tokens
        if ($this->validateToken($this->token)) {
            writeRecordToRevocationTable($this->jti, $this->sub, $revocationExpiration);
        }
    }

    public function banUser(string $userSub, string $utcUnixEpochBanExpiration)
    {
        $banExp = $this->exp + 60;

        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end
        writeRecordToRevocationTable('0', $userSub, $utcUnixEpochBanExpiration);
    }

    public function permabanUser(string $userSub)
    {

        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end-- Tuesday after never
        writeRecordToRevocationTable('0', $userSub, '18446744073709551615');
    }

    public function setCustomClaims(array $customClaims)
    {
        foreach ($customClaims as $claimKey => $value) {
            if (mb_check_encoding($value, 'UTF-8')) {
                $this->customClaims[$claimKey] = $value;
            } else {
                error_log('Ehjwt custom claim non-UTF-8 input string encoding error.');
                throw new EhjwtCustomClaimsInputStringException('Ehjwt custom claim non-UTF-8 input string encoding error.');
            }
        }
    }

    private function writeRecordToRevocationTable(string $jti, string $sub, string $exp)
    {
        // var_dump('writeRecordToRevocationTable()');
        try {
            $dbh = new PDO($this->config['dsn'], $this->config['dbUser'], $this->config['dbPassword'], array(PDO::ATTR_PERSISTENT => true ));
            
            $stmt = $dbh->prepare("INSERT INTO revoked_ehjwt (jti, sub, exp) VALUES (?, ?, ?)");
            
            $stmt->bindParam(1, $jti);
            $stmt->bindParam(2, $sub);
            $stmt->bindParam(3, $exp);

            $stmt->execute();

            $dbh = null;
            $stmt = null;
        } catch (PDOException $e) {
            error_log('Ehjwt write revocation record error: ' . $e->getMessage());
            throw new EhjwtWriteRevocationRecordFailException('Ehjwt write revocation record error: ' . $e->getMessage());
        }
    }

    private function deleteRecordFromRevocationTable(string $recordId)
    {
        try {
            $dbh = new PDO($this->config['dsn'], $this->config['dbUser'], $this->config['dbPassword'], array(PDO::ATTR_PERSISTENT => true ));
            
            $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE id = ?");
            
            $stmt->bindParam(1, $recordId);

            $stmt->execute();
        } catch (PDOException $e) {
            error_log('Ehjwt delete revocation record error: ' . $e->getMessage());
            throw new EhjwtDeleteRevocationRecordFailException('Ehjwt write revocation record error: ' . $e->getMessage());
        }
    }

    public function deleteStandardClaims(string $standardClaimNamesCommaSeparated)
    {
        $standardClaims = explode(',', $standardClaimNamesCommaSeparated);
        foreach ($standardClaims as $claimKey) {
            $this->{$claimKey} = null;
        }
    }

    public function deleteCustomClaims(string $customClaimNamesCommaSeparated)
    {
        $customClaims = explode(',', $customClaimNamesCommaSeparated);
        foreach ($customClaims as $claimKey) {
            $this->customClaims[$claimKey] = null;
        }
    }

    private function unpackToken(bool $clearClaimsFirst = true)
    {
        if ($clearClaimsFirst === true) {
            $this->clearClaims();
        }

        $tokenParts = explode('.', $this->token);
        $tokenClaims = json_decode($this->base64UrlDecode($tokenParts[1]), true);
        foreach ($tokenClaims as $claimKey => $value) {
            // ToDo: in array this...
            if (in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true)) {
                $this->{$claimKey} = $value;
            } else {
                $this->customClaims[$claimKey] = $value;
            }
        }
    }
}

//

// DB Exceptions
class EhjwtWriteRevocationRecordFailException extends \Exception
{
};

class EhjwtDeleteRevocationRecordFailException extends \Exception
{
};
