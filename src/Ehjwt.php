<?php
/**
 * Created by PhpStorm.
 * User: bchesney
 * Date: 11/7/18
 * Time: 3:33 PM
 */

namespace bradchesney79;

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
    private $customClaims = null;

    /**
     * @var string
     */
    private $secretKey = null;

    /**
     * @var string
     */
    private $token = null;

    public function __construct(string $secret) {
        $this->secretKey = $secret;
    }

    public function Ehjwt(string $secret) {
        $this->__construct($secret);
    }

    public function createToken() {
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

        foreach (sort($this->customClaims) as $key => $value) {
            if (null !== $value) {
                $tokenClaims[$key] = $value;
            }
        };

        foreach (sort($standardClaims) as $key => $value) {
            if (null !== $value) {
                $tokenClaims[$key] = $value;
            }
        }

        // convert from arrays to JSON objects

        $jsonHeader = json_encode($header,JSON_FORCE_OBJECT);

        $jsonClaims = json_encode($tokenClaims,JSON_FORCE_OBJECT);

        // encode the header and claims to Base64Url String
        $base64UrlHeader = $this->base64UrlEncode($jsonHeader);

        $base64UrlClaims = $this->base64UrlEncode($jsonClaims);

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

        if (substr_count($tokenString, '.') !== 2) {
            // 'Incorrect quantity of segments'
            return false;
        }

        $loadedToken = explode('.', $this->token);
        $loadedTokenUnpackedHeader = json_decode($this->base64UrlDecode($loadedToken[0]), true);
        $loadedTokenUnpackedBody = json_decode($this->base64UrlDecode($loadedToken[1]), true);
        $loadedTokenSignature = $loadedToken[2];

        $this->unpackToken(true);

        if($loadedTokenUnpackedHeader && is_array($loadedTokenUnpackedHeader)) {
            // 'Cannot unpack the token'
            return false;
        }

        if ($loadedTokenUnpackedHeader['alg'] !== 'HS256') {
            // 'Wrong algorithm'
            return false;
        }

        $date = new \DateTime('now', 'UTC');

        $utcTimeNow = $date->format("U") ;

        $expiryTime = $loadedTokenUnpackedBody['exp'];

        // a good JWT integration uses token expiration, I am forcing your hand
        if (($utcTimeNow - $this->exp) > 0 ) {
            // 'Expired (exp)'
            return false;
        }

        // if nbf is set
        if (null !== $this->nbf) {
            if ($this->nbf < $utcTimeNow) {
                // 'Too early for not before(nbf) value'
                return false;
            }
        }

        //ToDo: all the database token stuff
        if ('record for this token in revoked tokens exists') {
            // 'Revoked'

            // clean out revoked token records if the UTC unix time ends in "0"
            if ((0 + 0) === (substr($utcTimeNow, -1) + 0)) {

            }

            return false;
        }

        $this->createToken();

        // verify the signature
        $recreatedToken = $this->readToken();
        $recreatedTokenParts = explode($recreatedToken);
        $recreatedTokenSignature = $recreatedTokenParts[3];

        if ($recreatedTokenSignature !== $loadedTokenSignature) {
            // 'signature invalid, potential tampering
            return false;
        }

        // the token checks out!
        return true;
    }

    public function revokeToken() {
        //ToDo: add a record for the token jti claim
    }

    public function loadToken(string $tokenString) {
        if ($this->validateToken($tokenString)) {
            $this->token = $tokenString;
        }
    }

    // From here out claims are equal, standard and custom have parity

    public function readClaims()
    {
        $this->unpackToken($this->token);

        $standardClaims  = [
            'iss' => $this->iss,
            'sub' => $this->sub,
            'aud' => $this->aud,
            'exp' => $this->exp,
            'nbf' => $this->nbf,
            'iat' => $this->iat,
            'jti' => $this->jti
        ];

        $allClaims = array_merge($standardClaims, $this->$standardClaims);
        return $allClaims;
    }

    public function updateClaims(Array $updatedClaims, bool $clearClaimsFirst) {
        if ($clearClaimsFirst === true) {
            $this->clearClaims();
        }

        foreach ($updatedClaims as $claimKey => $value) {
            if ( in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true ) ) {
            //if ($claimKey === 'iss' || 'sub' || 'aud' || 'exp' || 'nbf' || 'iat' || 'jti') {
                $this->{$claimKey} = $value;
            }
            else {
                $this->customClaims[$claimKey] = $value;
            }
        }

        $this->createToken();
    }

    // can only directly remove custom claims
    // edit standard claims to equal null to remove them
    public function removeClaims(Array $claimKeys)
    {
        foreach ($claimKeys as $claimKey) {
            if ($claimKey === 'iss' || 'sub' || 'aud' || 'exp' || 'nbf' || 'iat' || 'jti') {
                $this[$claimKey] = null;
            }
            else {
                $this->customClaims[$claimKey] = null;
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

    private function clearClaims () {
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
            if (in_array($claimKey, array('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'), true )) {
                $this->{$claimKey} = $value;
            }

            else {
                $this->{$claimKey} = null;
            }
        }
    }

    public function setStandardClaims(array $customClaims) {
        foreach ($customClaims as $claimKey => $value) {
            $this->customClaims[$claimKey] = $value;
        }
    }

    public function deleteStandardardClaims(array $standardClaimNamesCommaSeparated) {
        $standardClaims = explode(',', $standardClaimNamesCommaSeparated);
        foreach ($standardClaims as $claimKey) {
            $this->{$claimKey} = null;
        }
    }


    public function deleteCustomClaims(array $customClaimNamesCommaSeparated) {
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
        foreach ($tokenClaims as $key => $value) {
            // ToDo: in array this...
            if ($key === 'iss' || 'sub' || 'aud' || 'exp' || 'nbf' || 'iat' || 'jti') {
                $this->{$key} = $value;
            }
            else {
                $this->customClaims[$key] = $value;
            }
        }
    }
}