<?php
/**
 * Created by PhpStorm.
 * User: bchesney
 * Date: 11/7/18
 * Time: 3:33 PM
 */

namespace bradchesney79\ehjwt;

use vlucas\phpdotenv;

class Ehjwt
{

    /**
     * Issuer
     *
     * @var string
     */
    private $iss;
    /**
     * Subject
     *
     * @var string
     */
    private $sub;
    /**
     * Audience
     *
     * @var string
     */
    private $aud;
    /**
     * Expiration Time
     *
     * @var string
     */
    private $exp;
    /**
     * Not Before
     *
     * @var string
     */
    private $nbf;
    /**
     * Issued At
     *
     * @var string
     */
    private $iat;
    /**
     * JWT ID
     *
     * @var string
     */
    private $jti;

    /**
     * @var array
     */
    private $customClaims;

    /**
     * @var string
     */
    private $token;

    public function __constructor(String $configPathAndFilename = null)
    {
        // load the config file contents from specified location
        if (
        $getenv('JWT_CONFIG_FILE')) {
            // get config location from $configPathAndFileName
        } else {
            if () {
                // get config location from en
            } else {
                // try common locations

                // ./Ehjwt.conf.php here

                // ../Ehjwt.conf.php parent directory

                // ./config/Ehjwt.conf.php here/config

                // ../config/Ehjwt.conf.php parent/config

                // ??? wordpress

                // project_root/config/Ehjwt.conf.php laravel

                // ??? drupal
            }
        }
    }

    public function Ehjwt(String $configPathAndFileName = null)
    {
        $this->__constructor($configPathAndFileName);
    }

// Standard Claims require string parameters on creation
    public function createToken(String $standard_claims)
    {
        // create header
        $header = [
            'alg' => 'HS256',
            'typ' => 'JWT'
        ];
        // create body

        // create signature
    }

    public function readToken()
    {
        return $this->token;
    }

    public function validateToken() {

    }

    public function revokeToken() {

    }

    // From here out claims are equal, standard and custom have parity

    public function readClaims()
    {

    }

    public function updateClaims() {

    }

    public function removeClaims(Array $claimKeys)
    {

    }
}