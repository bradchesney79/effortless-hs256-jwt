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
        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($jsonHeader));

        $base64UrlClaims = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($jsonClaims));

        // create signature

        $jsonSignature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlClaims, $this->secretKey, true);

        // Encode Signature to Base64Url String
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($jsonSignature));

        $tokenParts = array($base64UrlHeader, $base64UrlClaims, $base64UrlSignature);
        $this->token = implode('.', $tokenParts);

        return $this->token;
    }

    public function readToken()
    {
        $this->createToken();
        return $this->token;
    }

    public function validateToken($tokenString) {

        $errors = '';
        $tokenParts = array();

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

    }

    public function revokeToken() {

    }

    public function loadToken(String $tokenString) {
        $this->validateToken($tokenString);

    }

    // From here out claims are equal, standard and custom have parity

    public function readClaims()
    {

    }

    public function updateClaims(Array $updateClaims) {

        $startingClaims = $this->readClaims();

        $adjustedClaims = array_merge($startingClaims, $updateClaims);

    }

    public function removeClaims(Array $claimKeys)
    {

    }

    private function unpackToken($tokenString) {

    }
}