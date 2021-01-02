<?php

namespace bradchesney79\Ehjwt\EHJWT;

use RuntimeException;

/**
 * Class Decoder
 *
 * Handles decoding of the JWT
 *
 * @package bradchesney79\Ehjwt\EHJWT
 */
class Decoder {
  //===============================
  // Errors
  //===============================
  const ERROR_JWT_PAYLOAD_JSON_DECODE_ERROR = "JWT payload json_decode() error: ";

  /**
   * @param string $jwtPayload The second part of a period-concatenated jwt string.
   *
   * @return mixed
   */
  public function decodeTokenPayload(string $jwtPayload) {
    $decodedPayload = json_decode($this->base64UrlDecode($jwtPayload), true);
    if (0 !== json_last_error()) {
      throw new RuntimeException(self::ERROR_JWT_PAYLOAD_JSON_DECODE_ERROR . json_last_error_msg(), 0);
    }
    return $decodedPayload;
  }

  /**
   * Base64 decodes the string
   *
   * @param string $base64UrlEncodedString
   *
   * @return false|string
   */
  private function base64UrlDecode(string $base64UrlEncodedString) {
    return base64_decode(
        str_pad(
            strtr($base64UrlEncodedString, '-_', '+/'),
            mb_strlen($base64UrlEncodedString) % 4,
            '=',
            STR_PAD_RIGHT
        )
    );
  }
}