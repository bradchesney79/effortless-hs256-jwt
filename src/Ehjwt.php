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
    private $iss = null;
    /**
     * Subject
     *
     * @var string
     */
    private $sub = null;
    /**
     * Audience
     *
     * @var string
     */
    private $aud = null;
    /**
     * Expiration Time
     *
     * @var string
     */
    private $exp = null;
    /**
     * Not Before
     *
     * @var string
     */
    private $nbf = null;
    /**
     * Issued At
     *
     * @var string
     */
    private $iat = null;
    /**
     * JWT ID
     *
     * @var string
     */
    private $jti = null;

    /**
     * @var array
     */
    private $customClaims = null;

    /**
     * @var string
     */
    private $jwtSecret = null;

    /**
     * @var string
     */
    private $token = null;

    /**
     * The config file path.
     *
     * @var string
     */
    protected $file;

    /**
     * The config data.
     *
     * @var stdClass
     */
    protected $config = [];

    /**
     *
     * @var object
     */
    public $error;

    private function enforceUsingEnvVars() {
        $useEnvVars = getenv('ESJWT_USE_ENV_VARS');
        if ($useEnvVars == "true") {
            return true;
        }
        return false;
    }

    public function __construct(string $secret = null, string $file = null, string $dsn = null, string $dbUser = null, string $dbPassword = null, string $iss = null, string $aud = null) {

        // var_dump('==========================================================');

        // load configuration from environment variables

        $dsnEnv = getenv('ESJWT_DSN');
        $dbUserEnv = getenv('ESJWT_DB_USER');
        $dbPasswordEnv = getenv('ESJWT_DB_PASS');
        $jwtSecretEnv = getenv('ESJWT_JWT_SECRET');
        $issEnv = getenv('ESJWT_ISS');
        $audEnv = getenv('ESJWT_AUD');
        

    

        if ($enforceUsingEnvVars()) {
            $this->config['dsn'] = $dsnEnv;

            $this->config['dbUser'] = $dbUserEnv;

            $this->config['dbPassword'] = $dbPasswordEnv;

            $this->jwtSecret = $jwtSecretEnv;

            $this->iss = $issEnv;

            $this->aud = $audEnv;

            return true;
        }
        else {
            if (is_null($file)) {
                $this->file = __DIR__.'/../config/ehjwt-conf.php';
            }
            else {
                $this->file = $file;
            }

            // check for config file existing before actual load
            if (file_exists($this->file)) {
                $config = require $this->file;
            }

            unset($file);

            $this->config['dsn'] = $dsn ?? $config['dsn'] ?? $dsnEnv;

            $this->config['dbUser'] = $dbUser ?? $config['dbUser'] ?? $dbUserEnv;

            $this->config['dbPassword'] = $dbPassword ?? $config['dbPassword'] ?? $dbPasswordEnv;

            $this->jwtSecret = $secret ?? $config['jwtSecret'] ?? $jwtSecretEnv;

            $this->iss = $iss ?? $config['iss'] ?? $issEnv;

            $this->aud = $iss ?? $config['aud'] ?? $audEnv;

        }

        unset($dsnEnv, $dbUserEnv, $dbPasswordEnv, $jwtSecretEnv, $issEnv, $audEnv, $useEnvVars);

    }

    public function createToken() {
        // create header
        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];
        // create body

        $standardClaims  = [
            'aud' => $this->aud,
            'exp' => $this->exp,
            'iat' => $this->iat,
            'iss' => $this->iss,
            'jti' => $this->jti,
            'nbf' => $this->nbf,
            'sub' => $this->sub
        ];

        ksort($this->customClaims);

        foreach ($this->customClaims as $key => $value) {
            if (null !== $value) {
                $tokenClaims[$key] = $value;
            }
        };

        foreach ($standardClaims as $key => $value) {
            if (null !== $value) {
                $tokenClaims[$key] = $value;
            }
        }

        ksort($tokenClaims);

        // convert from arrays to JSON objects

        $jsonHeader = json_encode($header,JSON_FORCE_OBJECT);

        $jsonClaims = json_encode($tokenClaims,JSON_FORCE_OBJECT);

        // encode the header and claims to base64url string
        $base64UrlHeader = $this->base64UrlEncode($jsonHeader);

        $base64UrlClaims = $this->base64UrlEncode($jsonClaims);

        // create signature

        $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);

        // encode signature to base64url string
        $base64UrlSignature = $this->base64UrlEncode($jsonSignature);

        $tokenParts = array($base64UrlHeader, $base64UrlClaims, $base64UrlSignature);

        $this->token = implode('.', $tokenParts);

        return $this->token;
    }

    public function getToken()
    {
        $this->createToken();
        return $this->token;
    }
    public function validateToken(string $tokenString) {

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
        if (($utcTimeNow - $expiryTime) > 0 ) {
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
            }

            catch (PDOException $e) {
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
                if($row['jti'] == 0 && $row['exp'] > $utcTimeNow) {
                    //var_dump('banned');
                    // user is under an unexpired ban condition
                    return false;
                }

                if($row['jti'] == $unpackedTokenPayload['jti']) {
                    //var_dump('revoked');
                    // token is revoked
                    return false;
                }

                // remove records for expired tokens to keep the table small and snappy
                if($row['exp'] < $utcTimeNow) {
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

    public function loadToken(string $tokenString) {
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

        if($this->customClaims === null) {
            $this->customClaims = array();
        }

        $allClaims = array_merge($standardClaims, $this->customClaims);
        return $allClaims;
    }

    // private function base64UrlEncode(string $unencodedString) {
    //     return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($unencodedString));
    // }

    private function base64UrlEncode(string $unencodedString) {
      return rtrim(strtr(base64_encode($unencodedString), '+/', '-_'), '=');
    }

    // private function base64UrlDecode(string $base64UrlEncodedString) {
    //     return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    // }

    private function base64UrlDecode(string $base64UrlEncodedString) {
        return base64_decode(str_pad(strtr($base64UrlEncodedString, '-_', '+/'), strlen($base64UrlEncodedString) % 4, '=', STR_PAD_RIGHT)); 
    }

    private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims) {
        // sha256 is the only algorithm. sorry, not sorry.
        return hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlClaims, $this->jwtSecret, true);
    }

    public function clearClaims () {
        $this->iss = null;
        $this->sub = null;
        $this->aud = null;
        $this->exp = null;
        $this->nbf = null;
        $this->iat = null;
        $this->jti = null;

        $this->customClaims = [];
    }

    public function setStandardClaims(array $standardClaims) {
        foreach ($standardClaims as $claimKey => $value) {
            if (mb_check_encoding($value, 'UTF-8')) {
                if (in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true )) {
                    $this->{$claimKey} = $value;
                }

                else {
                    $this->{$claimKey} = null;
                }
            }
            else {
                error_log('Ehjwt standard claim non-UTF-8 input string encoding error.');
                throw new EhjwtCustomClaimsInputStringException('Ehjwt standard claim non-UTF-8 input string encoding error.');
            }
        }
    }

    public function addTokenRevocationRecord(string $jti, string $sub, string $revocationExpiration) {

        // revoke a token with specific particulars
        // var_dump('addTokenRevocationRecord()');
        $this->writeRecordToRevocationTable($jti, $sub, $revocationExpiration);

    }

    public function revokeToken(string $token) {

        // unpack the token, add it to the revocation table

        $this->loadToken($token);

        $revocationExpiration = $this->exp + 30;

        // only add if the token is valid-- don't let imposters kill otherwise valid tokens
        if ($this->validateToken($this->token)) {

            writeRecordToRevocationTable($this->jti, $this->sub, $revocationExpiration);

        }

    }

    public function banUser(string $userSub, string $utcUnixEpochBanExpiration) {

        $banExp = $this->exp + 60;

        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end
        writeRecordToRevocationTable('0', $userSub, $utcUnixEpochBanExpiration);

    }

    public function permabanUser(string $userSub) {

        // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end-- Tuesday after never
        writeRecordToRevocationTable('0', $userSub, '18446744073709551615');

    }

    public function setCustomClaims(array $customClaims) {
        foreach ($customClaims as $claimKey => $value) {
            if (mb_check_encoding($value, 'UTF-8')) {
                $this->customClaims[$claimKey] = $value;
            }
            else {
                error_log('Ehjwt custom claim non-UTF-8 input string encoding error.');
                throw new EhjwtCustomClaimsInputStringException('Ehjwt custom claim non-UTF-8 input string encoding error.');
            }
        }
    }

    private function writeRecordToRevocationTable(string $jti, string $sub, string $exp) {
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
        }

        catch (PDOException $e) {
            error_log('Ehjwt write revocation record error: ' . $e->getMessage());
            throw new EhjwtWriteRevocationRecordFailException('Ehjwt write revocation record error: ' . $e->getMessage());
        }

    }

    private function deleteRecordFromRevocationTable(string $recordId) {

        try {
            $dbh = new PDO($this->config['dsn'], $this->config['dbUser'], $this->config['dbPassword'], array(PDO::ATTR_PERSISTENT => true ));
            
            $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE id = ?");
            
            $stmt->bindParam(1, $recordId);

            $stmt->execute();
        }

        catch (PDOException $e) {
            error_log('Ehjwt delete revocation record error: ' . $e->getMessage());
            throw new EhjwtDeleteRevocationRecordFailException('Ehjwt write revocation record error: ' . $e->getMessage());
        }

    }

    public function deleteStandardClaims(string $standardClaimNamesCommaSeparated) {
        $standardClaims = explode(',', $standardClaimNamesCommaSeparated);
        foreach ($standardClaims as $claimKey) {
            $this->{$claimKey} = null;
        }
    }


    public function deleteCustomClaims(string $customClaimNamesCommaSeparated) {
        $customClaims = explode(',', $customClaimNamesCommaSeparated);
        foreach ($customClaims as $claimKey) {
            $this->customClaims[$claimKey] = null;
        }
    }

    private function unpackToken(bool $clearClaimsFirst = true) {

        if ($clearClaimsFirst === true) {
            $this->clearClaims();
        }

        $tokenParts = explode('.', $this->token);
        $tokenClaims = json_decode($this->base64UrlDecode($tokenParts[1]), true);
        foreach ($tokenClaims as $claimKey => $value) {
            // ToDo: in array this...
            if (in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true )) {
                $this->{$claimKey} = $value;
            }
            else {
                $this->customClaims[$claimKey] = $value;
            }
        }
    }
}

// 

// DB Exceptions
class EhjwtWriteRevocationRecordFailException extends \Exception {};
class EhjwtDeleteRevocationRecordFailException extends \Exception {};
