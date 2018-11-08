<?php
/**
 * Created by PhpStorm.
 * User: bchesney
 * Date: 11/7/18
 * Time: 3:33 PM
 */

namespace bradchesney79\ehjwt;

use Dotenv\Dotenv;

class Ehjwt
{

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
    private $customClaims  = null;

    /**
     * @var string
     */
    private $secretKey  = null;

    /**
     * @var string
     */
    private $token;

    public function __constructor(String $configPathWithoutTrailingSlash = null, String $configFileName = 'ehjwt.conf.php')
    {
        // load the config file contents from specified location
        if (null !== $configPathWithoutTrailingSlash) {
            // get config location from $configPathAndFileName
                $configPath = $configPathWithoutTrailingSlash;
        }
        else {

            // try common locations

            // ./Ehjwt.conf.php here

            if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . $configFileName)) {

                $configPathWithoutTrailingSlash = __DIR__;

            }

            // ../Ehjwt.conf.php parent directory

            if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . $configFileName)) {

                $configPathWithoutTrailingSlash = __DIR__ . DIRECTORY_SEPARATOR . '..';

            }

            // ./config/Ehjwt.conf.php here/config

            if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $configFileName)) {

                $configPathWithoutTrailingSlash = __DIR__ . DIRECTORY_SEPARATOR . 'config';

            }

            // ../config/Ehjwt.conf.php parent/config

            if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $configFileName)) {

                $configPathWithoutTrailingSlash = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'config';
            }

            // ??? wordpress

            // project_root/config/Ehjwt.conf.php laravel

            if (function_exists(base_path())) {
                if (file_exists(base_path() . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $configFileName)) {
                    $configPathWithoutTrailingSlash = base_path() . DIRECTORY_SEPARATOR . 'config';
                }
            }
            // ??? drupal
        }

        // load the configuration settings

        $dotenv = new Dotenv($configPathWithoutTrailingSlash . DIRECTORY_SEPARATOR, $configFileName);
        $dotenv->load();

        // get the settings from the config file -- "the secretKey"

        $this->secretKey = 'theValueFromTheConfigFile=getenv(EFFORTLESS_HS256_SECRET_KEY)';
    }

    public function Ehjwt(String $configPathAndFileName = null)
    {
        $this->__constructor($configPathAndFileName);
    }

    public function createToken()
    {
        // create header
        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];
        // create body

        $standardClaims  = [
            'iss' => $this->iss,
            'sub' => $this->sub,
            'aud' => $this->aud,
            'exp' => $this->exp,
            'nbf' => $this->nbf,
            'iat' => $this->iat,
            'jti' => $this->jti
        ];

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

        // convert from arrays to JSON objects

        $jsonHeader = json_encode($header,JSON_FORCE_OBJECT);

        $jsonClaims = json_encode($tokenClaims,JSON_FORCE_OBJECT);

        // encode the header and claims to Base64Url String
        $base64UrlHeader = $this->base64UrlEncode($jsonHeader);

        $base64UrlClaims = $this->base64UrlEncode($jsonClaims));

        // create signature

        $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);

        // Encode Signature to Base64Url String
        $base64UrlSignature = $this->base64UrlEncode($jsonSignature);

        $tokenParts = array($base64UrlHeader, $base64UrlClaims, $base64UrlSignature);

        $this->token = implode('.', $tokenParts);

        return $this->token;
    }

    public function readToken()
    {
        $this->createToken();
        return $this->token;
    }

    public function validateToken(string $tokenString) {
        
        $this->loadToken($tokenString);
        
        $this->unpackToken()

        if (substr_count($tokenString, '.') !== 2) {
            // 'Incorrect quantity of segments'
            return false;
        }

        $tokenParts = (false !== $this->unpackToken($tokenString))?$this->unpackToken($tokenString):false;

        if($tokenParts && is_array($tokenParts)) {
            // 'Cannot unpack the token'
            return false;
        }

        if ($tokenParts['header']['alg'] !== 'HS256') {
            // 'Wrong algorithm'
            return false;
        }

        $date = new DateTime();

        $utcTimeNow = $date->format("U") ;

        $expiryTime = $tokenParts['body']['exp'];

        // a good JWT integration uses token expiration, I am forcing your hand
        if (($utcTimeNow - $this->exp) > 0 ) {
            // 'Expired (exp)'
            return false;
        }

        if ('not before is set...') {
            if ($this->nbf < $utcTimeNow) {
                // 'Too early for not before(nbf) value'
                return false;
            }
        }

        if ('record for this token in revoked tokens exists') {
            // 'Revoked'

            // clean out revoked token records if the UTC unix time ends in "0"
            if ((0 + 0) === (substr($utcTimeNow, -1) + 0)) {

            }

            return false;
        }

        if ()
    }

    public function revokeToken() {

    }

    public function loadToken(String $tokenString) {
        if ($this->validateToken($tokenString)) {
            $this->token = $tokenString;
        }
    }

    // From here out claims are equal, standard and custom have parity

    public function readClaims()
    {
        $this->unpackToken($this->token);
        return $this->customClaims;
    }

    public function updateClaims(Array $updatedClaims, Boolean ) {
        $startingClaims = $this->readClaims();
        //$adjustedClaims = array_merge($startingClaims, $updateClaims);
    }

    // can only directly remove custom claims
    // edit standard claims to equal null to remove them
    public function removeClaims(Array $claimKeys)
    {
        foreach ($claimKeys as $claimKey) {
            if ($key === 'iss' || 'sub' || 'aud' || 'exp' || 'nbf' || 'iat' || 'jti') {
                $this[$key] = null;
            }
            else {
                $this->customClaims[$key] = null;
            }
        }

        $this->createToken();
    }

    private function base64UrlEncode(string $unencodedString) {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($unencodedString));
    }

    private function base64UrlDecode(string $base64UrlEncodedString) {
        return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    }

    private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims) {
        // sha256 is the only algorithm. sorry, not sorry.
        return hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlClaims, $this->secretKey, true);
    }

    private function unpackToken(bool $clearClaimsFirst = false) {
        
        if ($clearClaimsFirst === true) {
            $this->iss = null;
            $this->sub = null;
            $this->aud = null;
            $this->exp = null;
            $this->nbf = null;
            $this->iat = null;
            $this->jti = null;

            $this->customClaims = [];
        }

        $tokenParts = explode('.', $this->token);
        $tokenClaims = json_decode($this->base64UrlDecode($tokenParts[1]));
        foreach ($tokenClaims as $key => $value) {
            if ($key === 'iss' || 'sub' || 'aud' || 'exp' || 'nbf' || 'iat' || 'jti') {
                $this[$key] = $value;
            }
            else {
                $this->customClaims[$key] = $value;
            }
        }
    }
}