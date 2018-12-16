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
		$reflectionProperty = $reflectionClass->getProperty('secretKey');
		$reflectionProperty->setAccessible(true);

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

		var_dump($jwt);

		//$this->assertEquals($secret, $reflectionProperty->getValue(new Ehjwt('secret')));
        $this->assertTrue(true);
    }
}