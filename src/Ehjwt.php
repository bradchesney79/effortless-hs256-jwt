<?php

use vlucas\phpdotenv;

class Ehjwt {

private String $token;

public function __constructor(String $configPathAndFilename = null) {
	// load the config file contents from specified location
	if () {
		// get config location from $configPathAndFileName
}
	else {
		if () {
			// get config location from en	
		}
		else {
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

public function Ehjwt(String $configPathAndFileName = null) {
	$this->__constructor($configPathAndFileName);
}

// Standard Claims require string parameters on creation
public function createToken(String $standard_claims) {
	// create header
	$header = [
		'alg' => 'HS256',
  		'typ' => 'JWT'
	];
	// create body

	// create signature
}

public function readToken() {
	return $this->token;
}

// From here out claims are equal, standard and custom have parity

public function readClaims(

public function editClaims(Array $claims) {

}



public function removeClaims(Array $claimKeys) {

}

