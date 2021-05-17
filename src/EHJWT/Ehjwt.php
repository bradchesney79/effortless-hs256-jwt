<?php
namespace BradChesney79;
use DateTime;
use DateTimeZone;
use Exception;
use LogicException;
use RuntimeException;
class EHJWT
{
    /*
      iss: issuer, the website that issued the token
      sub: subject, the id of the entity being granted the token
      aud: audience, the users of the token-- generally a url or string
      exp: expires, the UTC UNIX epoch time stamp of when the token is no longer valid
      nbf: not before, the UTC UNIX epoch time stamp of when the token becomes valid
      iat: issued at, the UTC UNIX epoch time stamp of when the token was issued
      jti: JSON web token ID, a unique identifier for the JWT that facilitates revocation

      DB/MySQL limits:
      int has an unsigned, numeric limit of 4294967295
      bigint has an unsigned, numeric limit of 18446744073709551615
      unix epoch as of "now" 1544897945
    */

    /**
     * Token Claims
     *
     * @var array
     */
    private array $tokenClaims = array();
    /**
     * @var string
     */
    private string $token = '';
    /**
     * The JWT secret
     *
     * @var string
     */
    protected $secret = '';

    //    /**
    //     * Error Object
    //     *
    //     * @var object
    //     */
    //    public object $error;

    // methods
    public function __construct(string $secret): bool
    {
        if (mb_strlen($secret) > 7) {
            $this->secret = $secret;
        }
        else {
            throw new LogicException('Failure creating EHJWT instance, requires 8+ length secret: ');
        }
        return true;
    }

    public function addOrUpdateJwtClaim(string $key, $value, $requiredType = 'mixed'): bool
    {
        // ToDo: Needs more validation or something ...added utf8
        if (gettype($value) == $requiredType || $requiredType === 'mixed') {
            if (mb_detect_encoding($value, 'UTF-8', true)) {
                $this->tokenClaims[$key] = $value;
                return true;
            }
            throw new RuntimeException('Specified JWT claim required encoding mismatch');
        }
        throw new RuntimeException('Specified JWT claim required type mismatch');
    }

    public function clearClaim(string $key): bool
    {
        if (isset($key)) {
            unset($this->tokenClaims[$key]);
        }
        return true;
    }

    private function jsonEncodeClaims(): string
    {
        return json_encode($this->tokenClaims, JSON_FORCE_OBJECT);
    }

    private function createSignature($base64UrlHeader, $base64UrlClaims): string
    {
        $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);
        return $this->base64UrlEncode($jsonSignature);
    }

    public function createToken(): bool
    {
        // !!! ksort to maintain properties in repeatable order
        ksort($this->tokenClaims);
        $jsonClaims = $this->jsonEncodeClaims();
        // The hash is always the same... don't bother computing it.
        $base64UrlHeader = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
        $base64UrlClaims = $this->base64UrlEncode($jsonClaims);
        $jsonSignature = $this->createSignature($base64UrlHeader, $base64UrlClaims);
        $base64UrlSignature = $this->base64UrlEncode($jsonSignature);
        $tokenParts = array(
            $base64UrlHeader,
            $base64UrlClaims,
            $base64UrlSignature
        );
        $this->token = implode('.', $tokenParts);
        return true;
    }

    public function getUtcTime(): int
    {
        $date = new DateTime('now', new DateTimeZone('UTC'));
        return $date->getTimestamp();
    }

    public function loadToken(string $tokenString): bool
    {
        $this->clearClaims();
        $this->token = $tokenString;
        if ($this->validateToken()) {
            $tokenParts = explode('.', $tokenString);
            $this->tokenClaims = $this->decodeTokenPayload($tokenParts[1]);
            return true;
        }
        return false;
    }

    public function validateToken(): bool
    {
        $tokenParts = $this->getTokenParts();
        $unpackedTokenPayload = $this->decodeTokenPayload($tokenParts[1]);
        $this->tokenClaims = $unpackedTokenPayload;
        if ($tokenParts[0] !== 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9') {
            throw new RuntimeException('Encryption algorithm tampered with', 0);
        }
        $utcTimeNow = $this->getUtcTime();
        if (!isset($unpackedTokenPayload['exp'])) {
            throw new RuntimeException("Expiration standard claim for JWT missing", 0);
        }
        $expiryTime = $unpackedTokenPayload['exp'];
        // a good JWT integration uses token expiration, I am forcing your hand
        if ($utcTimeNow > intval($expiryTime)) {
            // 'Expired (exp)'
            throw new RuntimeException('Token is expired', 0);
        }
        $notBeforeTime = $unpackedTokenPayload['nbf'];
        // if nbf is set
        if (null !== $notBeforeTime) {
            if (intval($notBeforeTime) > $utcTimeNow) {
                // 'Too early for not before(nbf) value'
                throw new RuntimeException('Token issued before nbf header allows', 0);
            }
        }

        if (!isset($unpackedTokenPayload['sub'])) {
            throw new RuntimeException("Subject standard claim not set to check ban status");
        }

        $this->createToken();
        $recreatedToken = $this->getToken();
        $recreatedTokenParts = explode('.', $recreatedToken);
        $recreatedTokenSignature = $recreatedTokenParts[2];
        if ($recreatedTokenSignature !== $tokenParts['2']) {
            //Signature invalid, potential tampering
            return false;
        }
        // the token checks out!
        return true;
    }

    private function getTokenParts(): array
    {
        $tokenParts = explode('.', $this->token);
        if ($this->verifyThreeMembers($tokenParts)) {
            return $tokenParts;
        }
        throw new RuntimeException('Token does not contain three delimited sections', 0);
    }

    private function verifyThreeMembers(array $array): bool
    {
        if (3 !== count($array)) {
            // 'Incorrect quantity of segments'
            return false;
        }
        return true;
    }

    public function reissueToken(string $tokenString, int $newUtcTimestampExpiration): string
    {
        if ($this->loadToken($tokenString)) {
            $this->addOrUpdateJwtClaim('exp', $newUtcTimestampExpiration);
            $this->createToken();
            return $this->getToken();
        }
    }

    public function getToken(): string
    {
        return $this->token;
    }

    private function decodeTokenPayload($jwtPayload): array
    {
        $decodedPayload = json_decode($this->base64UrlDecode($jwtPayload), true);
        if (0 !== json_last_error()) {
            throw new RuntimeException("JWT payload json_decode() error: " . json_last_error_msg(), 0);
        }
        return $decodedPayload;
    }

    public function getTokenClaims(): array
    {
        return $this->tokenClaims;
    }

    private function base64UrlEncode(string $unencodedString): string
    {
        return rtrim(strtr(base64_encode($unencodedString), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $base64UrlEncodedString): string
    {
        return base64_decode(str_pad(strtr($base64UrlEncodedString, '-_', '+/'), mb_strlen($base64UrlEncodedString) % 4, '=', STR_PAD_RIGHT));
    }

    private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims): string
    {
        // sha256 is the only algorithm. sorry, not sorry.
        return hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlClaims, $this->configurations['jwtSecret'], true);
    }

    public function clearClaims(): void
    {
        $this->tokenClaims = [];
    }
}