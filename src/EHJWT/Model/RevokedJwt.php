<?php

namespace bradchesney79\Ehjwt\EHJWT\Model;

/**
 * Class RevokedJwt
 *
 * @package bradchesney79\Ehjwt\EHJWT\Model
 */
class RevokedJwt {
  protected $jti;
  protected $sub;
  protected $exp;

  /**
   * RevokedJwt constructor.
   */
  public function __construct() {
  }

  /**
   * @return mixed
   */
  public function getJti() {
    return $this->jti;
  }

  /**
   * @param mixed $jti
   */
  public function setJti($jti): void {
    $this->jti = $jti;
  }

  /**
   * @return mixed
   */
  public function getSub() {
    return $this->sub;
  }

  /**
   * @param mixed $sub
   */
  public function setSub($sub): void {
    $this->sub = $sub;
  }

  /**
   * @return mixed
   */
  public function getExp() {
    return $this->exp;
  }

  /**
   * @param mixed $exp
   */
  public function setExp($exp): void {
    $this->exp = $exp;
  }


}