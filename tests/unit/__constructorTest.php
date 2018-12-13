<?php

require 'src/Ehjwt.php';

use PHPUnit\Framework\TestCase;

//use bradchesney79\Ehjwt;

//require 'src/Ehjwt.php';

use bradchesney79\Ehjwt;

class __constructorTest extends TestCase
{
    public function testAssertTrueIsTrue()
    {
        $this->assertTrue(true);
    }

    public function testConfigLoads() {
    	$jwt = new Ehjwt('ehjwt.conf.php.example', );
    	$secretKey = $jwt->enableTestingPrivateSecretKeyProperty();
    	$this->assertEquals('This should be really, really, really, really long with CAPITALS, lowercase, numb3r5, and spec!a| characters', $secretKey[0], 'Secret Keys in __constructorTest Do Not Match');
    }
}
