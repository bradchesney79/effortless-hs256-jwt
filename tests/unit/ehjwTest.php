<?php

require 'src/Ehjwt.php';

use PHPUnit\Framework\TestCase;
use bradchesney79\Ehjwt;

class ehjwtTest extends TestCase
{

	public function testAssertTrueIsTrue() {
		// Even if the rest of the world is exploding,
		// this test should pass.
		// You should at least have one passing test.
        $this->assertTrue(true);
    }

    public function testSecretLoads() {
    	$secret = 'secret';

		$reflectionClass = new ReflectionClass('bradchesney79\Ehjwt');
		$reflectionProperty = $reflectionClass->getProperty('jwtSecret');
		$reflectionProperty->setAccessible(true);

		// Check that the secret is set by the __construct function
		$this->assertEquals($secret, $reflectionProperty->getValue(new Ehjwt('secret')));
    }


    public function testCreateToken() {
    	$secret = 'secret';

		$jwt = new Ehjwt($secret);

		$now = time();
		$expires = time() + 30 * 60;

/*
        iss: issuer, the website that issued the token
        sub: subject, the id of the entity being granted the token 
            (int has an unsigned, numeric limit of 4294967295)
            (bigint has an unsigned, numeric limit of 18446744073709551615)
        	(unix epoch as of "now" 1544897945)
		aud: audience, the users of the token-- generally a url or string
        exp: expires, the UTC UNIX epoch time stamp of when the token is no longer valid
        nbf: not before, the UTC UNIX epoch time stamp of when the token becomes valid
        iat: issued at, the UTC UNIX epoch time stamp of when the token was issued
        jti: JSON web token ID, a unique identifier for the JWT that facilitates revocation 
*/

		$standardClaims = array(
	        'iss'=>'rustbeltrebellion.com',
	        'sub'=>'15448979450000000000',
	        'aud'=>'rustbeltrebellion.com',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$customClaims = array(
			'age' => '39',
			'sex' => 'male',
			'location' => 'Davenport, Iowa'
		);

		$jwt->setCustomClaims($customClaims);

		// $jwt->deleteStandardClaims('aud');

		// $jwt->deleteCustomClaims('location');

		$jwt->createToken();

		$expectedAlgorithmChunk = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

		$jwtChunks = explode('.',$jwt->getToken());

		$jwtChunksCount = count($jwtChunks);

		$actualAlgorithmChunk = $jwtChunks[0];

		// Check that there are three parts to the JWT
		$this->assertEquals(3, $jwtChunksCount);

		// Check that the algorithm chunk is predictably HS256
		$this->assertEquals($expectedAlgorithmChunk, $actualAlgorithmChunk);
    }

    public function testCreateTokenWithConstructorParameters() {
    	$secret = 'secret';

		$jwt = new Ehjwt($secret, null, 'mysql:host=localhost;dbname=ehjwt', 'root', 'password', 'rustbeltrebellion.com', 'rustbeltrebellion.com');

		$now = time();
		$expires = time() + 30 * 60;

/*
        iss: issuer, the website that issued the token
        sub: subject, the id of the entity being granted the token 
            (int has an unsigned, numeric limit of 4294967295)
            (bigint has an unsigned, numeric limit of 18446744073709551615)
        	(unix epoch as of "now" 1544897945)
		aud: audience, the users of the token-- generally a url or string
        exp: expires, the UTC UNIX epoch time stamp of when the token is no longer valid
        nbf: not before, the UTC UNIX epoch time stamp of when the token becomes valid
        iat: issued at, the UTC UNIX epoch time stamp of when the token was issued
        jti: JSON web token ID, a unique identifier for the JWT that facilitates revocation 
*/

		$standardClaims = array(
	        'sub'=>'15448979450000000000',
	        'exp'=>'1546353624',
	        'nbf'=>'1546352624',
	        'iat'=>'1546352624',
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$customClaims = array(
			'age' => '39',
			'sex' => 'male',
			'location' => 'Davenport, Iowa'
		);

		$jwt->setCustomClaims($customClaims);

		// $jwt->deleteStandardClaims('aud');

		// $jwt->deleteCustomClaims('location');

		$jwt->createToken();

		$expectedAlgorithmChunk = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
		$expectedPayloadChunk = 'eyJhZ2UiOiIzOSIsImxvY2F0aW9uIjoiRGF2ZW5wb3J0LCBJb3dhIiwic2V4IjoibWFsZSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9uLmNvbSIsImV4cCI6IjE1NDYzNTM2MjQiLCJpYXQiOiIxNTQ2MzUyNjI0IiwianRpIjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjE1NDYzNTI2MjQiLCJzdWIiOiIxNTQ0ODk3OTQ1MDAwMDAwMDAwMCJ9';
		$expectedCheckSumChunk = 'g3hLhBGJLuc7c6JPvAAcPbHS3zP1TAz63rJeyzV5hlo';

		$jwtChunks = explode('.',$jwt->getToken());

		$jwtChunksCount = count($jwtChunks);

		$actualAlgorithmChunk = $jwtChunks[0];
		$actualPayloadChunk = $jwtChunks[1];
		$actualChecksumChunk = $jwtChunks[2];

		// Check that there are three parts to the JWT
		$this->assertEquals(3, $jwtChunksCount);

		// Check that the algorithm chunk is predictably HS256
		$this->assertEquals($expectedAlgorithmChunk, $actualAlgorithmChunk);
		$this->assertEquals($expectedPayloadChunk, $actualPayloadChunk);
		$this->assertEquals($expectedCheckSumChunk, $actualChecksumChunk);
    }

    public function testLoadToken() {
    	    	$secret = 'secret';

		$jwt = new Ehjwt($secret);

		$now = time();
		$expires = time() + 30 * 60;

		$standardClaims = array(
	        'iss'=>'rustbeltrebellion.com',
	        'sub'=>'15448979450000000000',
	        'aud'=>'rustbeltrebellion.com',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$customClaims = array(
			'age' => '39',
			'sex' => 'male',
			'location' => 'Davenport, Iowa'
		);

		$jwt->setCustomClaims($customClaims);

		$jwt->createToken();

		$token = $jwt->getToken();

		$newJwt = new Ehjwt('secret');

		$newJwt->loadToken($token);

		$claims = $newJwt->getClaims();

		$checkValues = [];

	    $checkValues['iss'] = 'rustbeltrebellion.com';
	    $checkValues['sub'] = '15448979450000000000';
	    $checkValues['aud'] = 'rustbeltrebellion.com';
	    $checkValues['exp'] = $expires;
	    $checkValues['nbf'] = $now;
	    $checkValues['iat'] = $now;
	    $checkValues['jti'] = '1234567890';
	    $checkValues['age'] = '39';
	    $checkValues['location'] = 'Davenport, Iowa';
	    $checkValues['sex'] = 'male';

	    $this->assertEquals($claims['iss'], $checkValues['iss']);
	    $this->assertEquals($claims['sub'], $checkValues['sub']);
	    $this->assertEquals($claims['aud'], $checkValues['aud']);
	    $this->assertEquals($claims['exp'], $checkValues['exp']);
	    $this->assertEquals($claims['nbf'], $checkValues['nbf']);
	    $this->assertEquals($claims['iat'], $checkValues['iat']);
	    $this->assertEquals($claims['jti'], $checkValues['jti']);
	    $this->assertEquals($claims['age'], $checkValues['age']);
	    $this->assertEquals($claims['location'], $checkValues['location']);
	    $this->assertEquals($claims['sex'], $checkValues['sex']);
    }

    public function testEnvironmentVarsLoad() {

    	//$dsn = addslashes(mysql:host=localhost);
		$dsn = 'mysql:host=localhost';

    	putenv('ESJWT_DSN=' . $dsn);

        putenv('ESJWT_DB_USER=root');

        putenv('ESJWT_DB_PASS=password');

        putenv('ESJWT_JWT_SECRET=secrets');

        putenv('ESJWT_ISS=rustbeltrebellion.com');

        putenv('ESJWT_AUD=list255.com');

        $now = time();
		$expires = time() + 30 * 60;

		$jwt = new Ehjwt(null, "NonExistentFile");

		$standardClaims = array(
	        'sub'=>'15448979450000000000',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$claims = $jwt->getClaims();

        $checkValues = [];

	    $checkValues['iss'] = 'rustbeltrebellion.com';
	    $checkValues['aud'] = 'list255.com';


	    $this->assertEquals($claims['iss'], $checkValues['iss']);
	    $this->assertEquals($claims['aud'], $checkValues['aud']);
    }

    public function testEnvironmentVarsStrictLoad() {

    	//$dsn = addslashes(mysql:host=localhost);
		$dsn = 'mysql:host=localhost';

    	putenv('ESJWT_DSN=' . $dsn);

        putenv('ESJWT_DB_USER=root');

        putenv('ESJWT_DB_PASS=password');

        putenv('ESJWT_JWT_SECRET=secrets');

        putenv('ESJWT_ISS=rustbeltrebellion.com');

        putenv('ESJWT_AUD=list255.com');

        putenv('ESJWT_USE_ENV_VARS=true');

        $now = time();
		$expires = time() + 30 * 60;

		$jwt = new Ehjwt(null, "NonExistentFile");

		$standardClaims = array(
	        'sub'=>'15448979450000000000',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$claims = $jwt->getClaims();

        $checkValues = [];

	    $checkValues['iss'] = 'rustbeltrebellion.com';
	    $checkValues['aud'] = 'list255.com';


	    $this->assertEquals($claims['iss'], $checkValues['iss']);
	    $this->assertEquals($claims['aud'], $checkValues['aud']);
    }

    public function testChunksInvalidToken() {
    	$secret = 'secret';

		$jwt = new Ehjwt($secret);

		$now = time();
		$expires = time() + 30 * 60;

		$standardClaims = array(
	        'iss'=>'rustbeltrebellion.com',
	        'sub'=>'15448979450000000000',
	        'aud'=>'rustbeltrebellion.com',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$customClaims = array(
			'age' => '39',
			'sex' => 'male',
			'location' => 'Davenport, Iowa'
		);

		$jwt->setCustomClaims($customClaims);

		$jwt->createToken();

		$token = $jwt->getToken();

		$cutOffPoint = strpos($token, '.');

		$brokenToken = substr( $token, $cutOffPoint + 1);

		$this->assertEquals(Ehjwt::validateToken($brokenToken), false);
    }

    public function testInvalidToken() {
    	$secret = 'secret';

		$jwt = new Ehjwt($secret);

		$now = time();
		$expires = time() + 30 * 60;

		$standardClaims = array(
	        'iss'=>'rustbeltrebellion.com',
	        'sub'=>'15448979450000000000',
	        'aud'=>'rustbeltrebellion.com',
	        'exp'=>"$expires",
	        'nbf'=>"$now",
	        'iat'=>"$now",
	        'jti'=>'1234567890'
		);
		$jwt->setStandardClaims($standardClaims);

		$customClaims = array(
			'age' => '39',
			'sex' => 'male',
			'location' => 'Davenport, Iowa'
		);

		$jwt->setCustomClaims($customClaims);

		$jwt->createToken();

		$token = $jwt->getToken();

		$newJwt = new Ehjwt('secret');

		$newJwt->loadToken($token);

		$claims = $newJwt->getClaims();

		$checkValues = [];

	    $checkValues['iss'] = 'rustbeltrebellion.com';
	    $checkValues['sub'] = '15448979450000000000';
	    $checkValues['aud'] = 'rustbeltrebellion.com';
	    $checkValues['exp'] = $expires;
	    $checkValues['nbf'] = $now;
	    $checkValues['iat'] = $now;
	    $checkValues['jti'] = '1234567890';
	    $checkValues['age'] = '39';
	    $checkValues['location'] = 'Davenport, Iowa';
	    $checkValues['sex'] = 'male';

	    $this->assertEquals($claims['iss'], $checkValues['iss']);
	    $this->assertEquals($claims['sub'], $checkValues['sub']);
	    $this->assertEquals($claims['aud'], $checkValues['aud']);
	    $this->assertEquals($claims['exp'], $checkValues['exp']);
	    $this->assertEquals($claims['nbf'], $checkValues['nbf']);
	    $this->assertEquals($claims['iat'], $checkValues['iat']);
	    $this->assertEquals($claims['jti'], $checkValues['jti']);
	    $this->assertEquals($claims['age'], $checkValues['age']);
	    $this->assertEquals($claims['location'], $checkValues['location']);
	    $this->assertEquals($claims['sex'], $checkValues['sex']);
    }
 //    public function testConfigFileVarsLoad() {
	// 	$secret = 'secret';

 //    	$jwt = new Ehjwt($secret);

	// }
}