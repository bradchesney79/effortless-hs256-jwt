<?php

namespace bradchesney79\Ehjwt\EHJWT;

use RuntimeException;/**
 * Class Validator
 * Handles validation of tokens
 *
 * @package bradchesney79\Ehjwt\EHJWT
 */
class Validator {
  const ERROR_ENCRYPTION_ALGORITHM_TAMPERED_WITH = 'Encryption algorithm tampered with';
  const ERROR_EXPIRATION_STANDARD_CLAIM_FOR_JWT_MISSING = "Expiration standard claim for JWT missing";
  const ERROR_TOKEN_IS_EXPIRED = 'Token is expired';
  const KEY_NBF = 'nbf';
  const ERROR_TOKEN_ISSUED_BEFORE_NBF_HEADER_ALLOWS = 'Token issued before nbf header allows';
  const ERROR_NO_VALID_DSN_STORED_FOR_CONNECTION_TO_DB = 'No valid DSN stored for connection to DB';
  const SEPERATOR_COLON = ':';
  const KEY_EXP = 'exp';
  const BASE64_URL_HEADER = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
  protected $configuration;

  /**
   * Validator constructor.
   *
   * @param $configuration
   */
  public function __construct($configuration) {
    $this->configuration = $configuration;
  }

  /**
   * Validates the Token and returns
   *
   * @param array $getTokenParts
   *
   * @return bool
   */
  public function validateToken(array $tokenParts): bool {
    $unpackedTokenPayload = $this->decodeTokenPayload($tokenParts[1]);

    $this->tokenClaims = $unpackedTokenPayload;
    if ($tokenParts[0] !== self::BASE64_URL_HEADER) {
      throw new RuntimeException(self::ERROR_ENCRYPTION_ALGORITHM_TAMPERED_WITH, 0);
    }
    $utcTimeNow = $this->getUtcTime();
    if (!isset($unpackedTokenPayload[self::KEY_EXP])) {
      throw new RuntimeException(self::ERROR_EXPIRATION_STANDARD_CLAIM_FOR_JWT_MISSING, 0);
    }
    $expiryTime = $unpackedTokenPayload[self::KEY_EXP];
    // a good JWT integration uses token expiration, I am forcing your hand
    if ($utcTimeNow > intval($expiryTime)) {
      // 'Expired (exp)'
      throw new RuntimeException(self::ERROR_TOKEN_IS_EXPIRED, 0);
    }
    $notBeforeTime = $unpackedTokenPayload[self::KEY_NBF];
    // if nbf is set
    if (null !== $notBeforeTime) {
      if (intval($notBeforeTime) > $utcTimeNow) {
        // 'Too early for not before(nbf) value'
        throw new RuntimeException(self::ERROR_TOKEN_ISSUED_BEFORE_NBF_HEADER_ALLOWS, 0);
      }
    }

    if (mb_strlen($this->configuration->getDbUser()) > 0
        && mb_strlen(
            $this->configuration->getDbPassword()
        ) > 0) {
      if (strpos($this->configuration->getDsn(), self::SEPERATOR_COLON) === false) {
        throw new RuntimeException(self::ERROR_NO_VALID_DSN_STORED_FOR_CONNECTION_TO_DB, 0);
      }
      try {
        $dbh = $this->makeRevocationTableDatabaseConnection();
      } catch (Exception $e) {
        throw new RuntimeException(
            'Cannot connect to the DB to check for revoked tokens and banned users', 0
        );
      }
      $lastCharacterOfJti = substr(strval($this->tokenClaims['jti']), -1);
      // clean out revoked token records if the UTC unix time ends in '0'
      if (0 == (intval($lastCharacterOfJti))) {
        $this->revocationTableCleanup($utcTimeNow);
      }
      if (!isset($unpackedTokenPayload['sub'])) {
        throw new RuntimeException("Subject standard claim not set to check ban status");
      }
      // ToDo: fix bind statement
      $stmt = $dbh->prepare("SELECT * FROM revoked_ehjwt where sub = ?");
      $stmt->bindParam(1, $unpackedTokenPayload['sub']);
      // get records for this sub
      if ($stmt->execute()) {
        while ($row = $stmt->fetch()) {
          if ($row['jti'] == 0 && $row[self::KEY_EXP] > $utcTimeNow) {
            // user is under an unexpired ban condition
            return false;
          }
          if ($row['jti'] == $unpackedTokenPayload['jti']) {
            // token is revoked
            return false;
          }
          // remove records for expired tokens to keep the table small and snappy
          if ($row[self::KEY_EXP] < $utcTimeNow) {
            // deleteRevocation record
            $this->deleteRecordFromRevocationTable($row['id']);
          }
        }
      }
    }

    $this->createToken();
    $recreatedToken = $this->getToken();
    $recreatedTokenParts = explode(self::SEPARATOR_PERIOD, $recreatedToken);
    $recreatedTokenSignature = $recreatedTokenParts[2];
    if ($recreatedTokenSignature !== $tokenParts['2']) {
      // 'signature invalid, potential tampering
      return false;
    }
    // the token checks out!
    return true;
  }
}