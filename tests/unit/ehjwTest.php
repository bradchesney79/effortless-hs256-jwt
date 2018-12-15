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
		$reflectionProperty->getValue(new Ehjwt($secret));

		$this->assertEquals($secret, $reflectionProperty->getValue(new Ehjwt('secret')));
    }
}
