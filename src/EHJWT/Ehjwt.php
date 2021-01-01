<?php

namespace BradChesney79;

use bradchesney79\Ehjwt\EHJWT\Decoder;
use bradchesney79\Ehjwt\EHJWT\Model\RevokedJwt;
use bradchesney79\Ehjwt\EHJWT\Repository\RevokedJwtRepository;
use bradchesney79\Ehjwt\EHJWT\Validator;
use DateTime;
use DateTimeZone;
use PDO;
use RuntimeException;

/**
 * Class EHJWT
 *
 * @package BradChesney79
 */
class EHJWT {
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
  //===============================
  // Errors
  //===============================
  const ERROR_SPECIFIED_JWT_CLAIM_REQUIRED_ENCODING_MISMATCH = 'Specified JWT claim required encoding mismatch';
  const ERROR_SPECIFIED_JWT_CLAIM_REQUIRED_TYPE_MISMATCH = 'Specified JWT claim required type mismatch';
  const ERROR_TOKEN_DOES_NOT_CONTAIN_THREE_DELIMITED_SECTIONS = 'Token does not contain three delimited sections';
  //===============================
  // Time
  //===============================
  const TIME_NOW = 'now';
  const TIMEZONE_UTC = 'UTC';
  //===============================
  // Encoding
  //===============================
  const ENCODING_UTF_8 = 'UTF-8';
  const TYPE_MIXED = 'mixed';
  const BASE64_URL_HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  const SEPARATOR_PERIOD = '.';
  const KEY_EXP = 'exp';
  const JTI_BANNED_USER = 0;
  //===============================
  // Properties
  //===============================
  /**
   * @var Configuration
   */
  protected Configuration $configuration;
  /**
   * @var Validator
   */
  protected Validator $validator;
  /**
   * @var Decoder
   */
  protected Decoder $decoder;
  /**
   * @var RevokedJwtRepository
   */
  protected RevokedJwtRepository $revokedJwtRepository;
  /**
   * Token Claims
   *
   * @var array
   */
  private array $tokenClaims = [];
  /**
   * @var string
   */
  private string $token = '';

  /**
   * EHJWT constructor.
   *
   * @param Configuration $configuration The configuration
   * @param Validator|null $validator
   * @param Decoder|null $decoder
   * @param RevokedJwtRepository|null $revokedJwtRepository
   */
  public function __construct(Configuration $configuration,
                              Validator $validator = null,
                              Decoder $decoder = null,
                              RevokedJwtRepository $revokedJwtRepository = null) {
    $this->configuration = $configuration;

    // set default validator
    if ($validator === null) {
      $this->validator = new Validator($configuration);
    } else {
      $this->validator = $validator;
    }

    // set default decoder
    if ($decoder === null) {
      $this->decoder = new Decoder();
    } else {
      $this->decoder = $decoder;
    }

    // set default revoked jwt repository
    if ($revokedJwtRepository === null) {
      $this->revokedJwtRepository = new RevokedJwtRepository($configuration);
    } else {
      $this->revokedJwtRepository = $revokedJwtRepository;
    }
  }

  public function addOrUpdateJwtClaim(string $key, $value, $requiredType = self::TYPE_MIXED) {
    // ToDo: Needs more validation or something ...added utf8
    if (gettype($value) == $requiredType || $requiredType === self::TYPE_MIXED) {
      if (mb_detect_encoding($value, self::ENCODING_UTF_8, true)) {
        $this->tokenClaims[$key] = $value;
        return true;
      }
      throw new RuntimeException(self::ERROR_SPECIFIED_JWT_CLAIM_REQUIRED_ENCODING_MISMATCH);
    }
    throw new RuntimeException(self::ERROR_SPECIFIED_JWT_CLAIM_REQUIRED_TYPE_MISMATCH);
  }

  public function clearClaim(string $key) {
    if (isset($key)) {
      unset($this->tokenClaims[$key]);
    }
    return true;
  }

  private function jsonEncodeClaims() {
    return json_encode($this->tokenClaims, JSON_FORCE_OBJECT);
  }

  private function createSignature($base64UrlHeader, $base64UrlClaims) {
    $jsonSignature = $this->makeHmacHash($base64UrlHeader, $base64UrlClaims);
    return $this->base64UrlEncode($jsonSignature);
  }

  public function createToken() {
    // !!! ksort to maintain properties in repeatable order
    ksort($this->tokenClaims);
    $jsonClaims = $this->jsonEncodeClaims();
    // The hash is always the same... don't bother computing it.
    $base64UrlHeader = self::BASE64_URL_HEADER;
    $base64UrlClaims = $this->base64UrlEncode($jsonClaims);
    $jsonSignature = $this->createSignature($base64UrlHeader, $base64UrlClaims);
    $base64UrlSignature = $this->base64UrlEncode($jsonSignature);
    $tokenParts = [
        $base64UrlHeader,
        $base64UrlClaims,
        $base64UrlSignature
    ];
    $this->token = implode(self::SEPARATOR_PERIOD, $tokenParts);
    return true;
  }

  public function getUtcTime() {
    $date = new DateTime(self::TIME_NOW, new DateTimeZone(self::TIMEZONE_UTC));
    return $date->getTimestamp();
  }

  public function loadToken(string $tokenString) {
    $this->clearClaims();
    $this->token = $tokenString;
    if ($this->validator->validateToken($this->getTokenParts())) {
      $tokenParts = explode(self::SEPARATOR_PERIOD, $tokenString);
      $this->tokenClaims = $this->decoder->decodeTokenPayload($tokenParts[1]);
      return true;
    }
    return false;
  }

  public function revocationTableCleanup(int $utcTimeStamp) {
    $this->revokedJwtRepository->deleteJwtsOlderThanTimestamp($utcTimeStamp);
  }

  /**
   * @return string[]
   */
  private function getTokenParts(): array {
    $tokenParts = explode(self::SEPARATOR_PERIOD, $this->token);
    if ($this->verifyThreeMembers($tokenParts)) {
      return $tokenParts;
    }
    throw new RuntimeException(self::ERROR_TOKEN_DOES_NOT_CONTAIN_THREE_DELIMITED_SECTIONS, 0);
  }

  private function verifyThreeMembers(array $array): bool {
    if (3 !== count($array)) {
      // 'Incorrect quantity of segments'
      return false;
    }
    return true;
  }

  public function reissueToken(string $tokenString, int $newUtcTimestampExpiration) {
    if ($this->loadToken($tokenString)) {
      $this->addOrUpdateJwtClaim(self::KEY_EXP, $newUtcTimestampExpiration);
      $this->createToken();
    }
    return;
  }

  public function getTokenClaims() {
    return $this->tokenClaims;
  }

  private function base64UrlEncode(string $unencodedString) {
    return rtrim(strtr(base64_encode($unencodedString), '+/', '-_'), '=');
  }

  private function makeHmacHash(string $base64UrlHeader, string $base64UrlClaims) {
    // sha256 is the only algorithm. sorry, not sorry.
    return hash_hmac(
        'sha256',
        $base64UrlHeader . self::SEPARATOR_PERIOD . $base64UrlClaims,
        $this->configuration->getSecret(),
        true
    );
  }

  public function clearClaims() {
    $this->tokenClaims = [];
  }

  public function revokeToken() {
    // only add if the token is valid-- don't let imposters kill otherwise valid tokens
    if ($this->validator->validateToken($this->getTokenParts())) {
      $revocationExpiration = (int) $this->tokenClaims[self::KEY_EXP] + 30;
      $this->createRevokedJwt($revocationExpiration);
    }
  }

  public function banUser(string $utcUnixTimestampBanExpiration) {
    $banExp = (int) $this->tokenClaims[self::KEY_EXP] + 60;
    // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end
    $this->createRevokedJwt($utcUnixTimestampBanExpiration, true);
  }

  public function permabanUser() {
    // insert jti of 0, sub... the userId to ban, and UTC Unix epoch of ban end-- Tuesday after never
    $this->createRevokedJwt(4294967295, true);
  }

  public function unbanUser() {
    $this->revokedJwtRepository->deleteJwtsBySub($this->tokenClaims['sub']);
  }

  /**
   * @param int $exp
   * @param bool $ban
   */
  private function createRevokedJwt(int $exp, bool $ban = false) {
    $revokedJwt = new RevokedJwt();
    $revokedJwt->setJti($ban ? self::JTI_BANNED_USER : $this->tokenClaims['jti']);
    $revokedJwt->setSub($this->tokenClaims['sub']);
    $revokedJwt->setExp($exp);
    $this->revokedJwtRepository->createNewJwt($revokedJwt);
  }

  // ToDo: Provide access to a list of banned users
  public function retrieveBannedUsers() {
    $bannedUsers = [];

    $dbh = $this->makeRevocationTableDatabaseConnection();

    $stmt = $dbh->query('SELECT * FROM revoked_ehjwt WHERE `jti` = 0');

    if ($stmt->execute()) {
      while ($row = $stmt->fetch()) {
        $bannedUsers[] = $row;
      }
      return $bannedUsers;
    }
  }

  //===============================
  // Getters
  //===============================
  public function getToken() {
    return $this->token;
  }
}