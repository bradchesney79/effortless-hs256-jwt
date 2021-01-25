<?php

namespace BradChesney79;

/**
 * Class Configuration
 *
 * @package BradChesney79
 */
class Configuration {
  //===============================
  // Config Constants
  //===============================
  const CONFIG_JWT_SECRET = 'jwtSecret';
  const CONFIG_DSN = 'dsn';
  const CONFIG_DB_USER = 'dbUser';
  const CONFIG_DB_PASSWORD = 'dbPassword';

  //===============================
  // Env var constants
  //===============================
  const ENV_VAR_EHJWT_JWT_SECRET = 'EHJWT_JWT_SECRET';
  const ENV_VAR_EHJWT_DSN = 'EHJWT_DSN';
  const ENV_VAR_EHJWT_DB_USER = 'EHJWT_DB_USER';
  const ENV_VAR_EHJWT_DB_PASS = 'EHJWT_DB_PASS';

  //===============================
  // Properties
  //===============================
  /** @var string */
  protected string $secret;
  /** @var string */
  protected string $filename;
  protected string $dbUser;
  protected string $dbPassword;
  protected string $dsn;
  // todo create a `fromEnvVars` method here: (old code below)
  //  private function setConfigurationsFromEnvVars() {
  //    foreach ($this->envVarNames as $envVarName) {
  //      $retrievedEnvironmentVariableValue = getenv($envVarName);
  //      if (mb_strlen($retrievedEnvironmentVariableValue) > 0) {
  //        $this->configurations[$envVarName] = $retrievedEnvironmentVariableValue;
  //      }
  //    }
  //  }

  // todo create a `fromConfigFile` method here: (old code below)
  //  private function setConfigurationsFromConfigFile(string $configFileWithPath) {
  //    if (file_exists($configFileWithPath)) {
  //      $configFileSettings = require $configFileWithPath;
  //      if (gettype($configFileSettings) !== 'array') {
  //        throw new RuntimeException('EHJWT config file does not return an array');
  //      }
  //      if (count($configFileSettings) == 0) {
  //        trigger_error('No valid configurations received from EHJWT config file', 8);
  //      }
  //      foreach ($this->settingConfigurationNames as $settingName) {
  //        $retrievedConfigFileVariableValue = $configFileSettings[$settingName];
  //        if (mb_strlen($retrievedConfigFileVariableValue) > 0) {
  //          $this->configurations[$settingName] = $retrievedConfigFileVariableValue;
  //        }
  //      }
  //    }
  //  }

  public static function newInstance() {
    return new static;
  }

  public function withSecret(string $secret): Configuration {
    $this->secret = $secret;
    return $this;
  }

  public function withFilename(string $filename): Configuration {
    $this->filename = $filename;
    return $this;
  }

  public function withDsn(string $dsn): Configuration {
    $this->dsn = $dsn;
    return $this;
  }

  public function withDbUser(string $dbUser): Configuration {
    $this->dbUser = $dbUser;
    return $this;
  }

  public function withDbPassword(string $dbPassword): Configuration {
    $this->dbPassword = $dbPassword;
    return $this;
  }

  /**
   * @return string
   */
  public function getSecret(): string {
    return $this->secret;
  }

  /**
   * @return string
   */
  public function getFilename(): string {
    return $this->filename;
  }

  /**
   * @return string
   */
  public function getDsn(): string {
    return $this->dsn;
  }

  /**
   * @return string
   */
  public function getDbUser(): string {
    return $this->dbUser;
  }

  /**
   * @return string
   */
  public function getDbPassword(): string {
    return $this->dbPassword;
  }
}