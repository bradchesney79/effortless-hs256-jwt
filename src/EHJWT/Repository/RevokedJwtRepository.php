<?php

namespace bradchesney79\Ehjwt\EHJWT\Repository;

use BradChesney79\Configuration;
use bradchesney79\Ehjwt\EHJWT\Model\RevokedJwt;
use PDO;

/**
 * Class RevokedJwtRepository
 * Handles persistence for RevokedJwts
 *
 * @package bradchesney79\Ehjwt\EHJWT\Repository
 */
class RevokedJwtRepository {
  protected Configuration $configuration;

  /**
   * RevokedJwtRepository constructor.
   *
   * @param $configuration
   */
  public function __construct(Configuration $configuration) {
    $this->configuration = $configuration;
  }

  /**
   * Deletes RevokedJwts that are older than the given timestamp
   *
   * @param int $utcTimeStamp
   */
  public function deleteJwtsOlderThanTimestamp(int $utcTimeStamp) {
    $dbh = $this->connect();
    $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE `exp` <= $utcTimeStamp");
    $stmt->execute();
  }

  /**
   * Deletes RevokedJwts by their id
   *
   * @param string $id
   *
   * @return bool
   */
  public function deleteJwtsById(string $id) {
    $dbh = $this->connect();
    $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE id = ?");
    $stmt->bindParam(1, $id);
    return $stmt->execute();
  }

  /**
   * Connects to the database
   *
   * @return PDO
   */
  private function connect() {
    return new PDO(
        $this->configuration->getDsn(),
        $this->configuration->getDbUser(),
        $this->configuration->getDbPassword(),
        [
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_NAMED
        ]
    );
  }

  /**
   * Creates a new RevokedJwt
   *
   * @param RevokedJwt $revokedJwt
   *
   * @return mixed
   */
  public function createNewJwt(RevokedJwt $revokedJwt) {
    $dbh = $this->connect();
    $stmt = $dbh->prepare(
        <<<SQL
            INSERT INTO revoked_ehjwt (jti, sub, exp) 
            VALUES (:jwt, :sub, :exp)
        SQL
    );
    $stmt->bindValue('jwt', $revokedJwt->getJti());
    $stmt->bindValue('sub', $revokedJwt->getSub());
    $stmt->bindValue('exp', $revokedJwt->getExp());
    return $stmt->execute();
  }

  /**
   * Deletes RevokedJwts by their sub value
   *
   * @param $sub
   *
   * @return bool
   */
  public function deleteJwtsBySub(string $sub): bool {
    $dbh = $this->connect();
    $stmt = $dbh->prepare(
        <<<SQL
            DELETE FROM revoked_ehjwt 
            WHERE sub = :sub 
              AND jti = 0
        SQL
    );
    $stmt->bindValue('sub', $sub);
    return $stmt->execute();
  }
}