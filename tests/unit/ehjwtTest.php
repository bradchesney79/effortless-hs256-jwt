<?php

require 'src/EHJWT/Ehjwt.php';
require 'vendor/autoload.php';

use PHPUnit\Framework\TestCase;
use BradChesney79\EHJWT;

/**
 * @coversDefaultClass \BradChesney79\EHJWT
 */

class ehjwtTest extends TestCase
{
    /**
     * Call protected/private method of a class.
     *
     * @param object &$object Instantiated object that we will run method on.
     * @param string $methodName Method name to call
     * @param array $parameters Array of parameters to pass into method.
     *
     * @return mixed Method return.
     * @throws \ReflectionException
     */
    public function invokePrivateMethod(&$object, $methodName, array $parameters = array())
    {
        $reflection = new \ReflectionClass(get_class($object));
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);
        return $method->invokeArgs($object, $parameters);
    }

//    /**
//     * Get protected/private property of a class.
//     *
//     * @param object &$object Instantiated object that we will get property from
//     * @param string $propertyName Property to get
//     *
//     * @return mixed Property return.
//     * @throws ReflectionException
//     */
//    public function getPrivateProperty(&$object, $propertyName)
//    {
//        $reflection = new \ReflectionClass(get_class($object));
//        $property = $reflection->getProperty($propertyName);
//        $property->setAccessible(true);
//        return $property->getValue($object);
//    }

     /**
     * @coversNothing
     */
    public function testAssertTrueIsTrue()
    {
        // Even if the rest of the world is exploding,
        // this test should pass.
        // You should have at least this one passing test
        // ...when testing is configured correctly.
        $this->assertTrue(true);
    }

    /**
    * @covers ::__construct
    */

    public function testObjectInstanceIsCreated()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString','DBUser', 'DBPassword', 'BradChesney.com', 'user');
        $this->assertInstanceOf(EHJWT::class, $jwt);
    }

    public function testDsnArgumentSettings ()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString','DBUser', 'DBPassword', 'BradChesney.com', 'user');

        $jwt->createToken();
        $expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0.R3NfZXdBdjhaQW1xMkpSc3E1d3p4NnE2M2F6WW55WFd4UGlrdDJtMUpPcw';
        $this->assertEquals($expectedToken, $jwt->getToken());
    }

    public function testClaimsAreAdded() {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString','DBUser', 'DBPassword', 'BradChesney.com', 'user');
        $jwt->addOrUpdateIatProperty('10000');
        $jwt->addOrUpdateNbfProperty('0');
        $jwt->addOrUpdateSubProperty('1000');
        $jwt->addOrUpdateJtiProperty('1');
        $jwt->addOrUpdateExpProperty('1887525317');

        $jwt->addOrUpdateCustomClaim('age', '39');
        $jwt->addOrUpdateCustomClaim('sex', 'male');
        $jwt->addOrUpdateCustomClaim('location', 'Davenport, Iowa');

        $jwt->createToken();
        $claims = $jwt->getTokenClaims();

        $this->assertEquals('BradChesney.com', $claims['iss']);
        $this->assertEquals('user', $claims['aud']);
        $this->assertEquals('10000', $claims['iat']);
        $this->assertEquals('0', $claims['nbf']);
        $this->assertEquals('1000', $claims['sub']);
        $this->assertEquals('1', $claims['jti']);
        $this->assertEquals('1887525317', $claims['exp']);

        $this->assertEquals('39', $claims['age']);
        $this->assertEquals('male', $claims['sex']);
        $this->assertEquals('Davenport, Iowa', $claims['location']);
    }

    public function testValidateToken()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password', 'BradChesney.com', 'user');
        $jwt->addOrUpdateIatProperty('10000');
        $jwt->addOrUpdateNbfProperty('0');
        $jwt->addOrUpdateSubProperty('1000');
        $jwt->addOrUpdateJtiProperty('1');
        $jwt->addOrUpdateExpProperty('1887525317');

        $jwt->addOrUpdateCustomClaim('age', '39');
        $jwt->addOrUpdateCustomClaim('sex', 'male');
        $jwt->addOrUpdateCustomClaim('location', 'Davenport, Iowa');

        $jwt->createToken();

        $tokenString = $jwt->getToken();

        unset($jwt);

        $jwt2 = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password', 'BradChesney.com', 'user');
        $jwt2->loadToken($tokenString);
        $itVerks = $jwt2->validateToken();
        $this->assertEquals(true, $itVerks);
    }

    public function testLoadingConfigFile() {

        $this->assertFileNotExists('custom-config.conf');
        if(!file_exists('custom-config.conf')) {
            // create custom config file
            $customConfigFile = fopen("custom-config.conf", "w");
            $txt = "Jane Doe\n";
            fwrite($customConfigFile, $txt);
            fclose($customConfigFile);


            // delete custom config file
            unlink(custom-config.conf);
        }
    }

//    public function testCreateToken()
//    {
//        $jwt = new EHJWT('jwtSecret', '', 'DSNString','DBUser', 'DBPassword', 'BradChesney.com', 'user');
//        $jwt->addOrUpdateIatProperty('10000');
//        $jwt->addOrUpdateNbfProperty('0');
//        $jwt->addOrUpdateSubProperty('1000');
//        $jwt->addOrUpdateJtiProperty('1');
//        $jwt->addOrUpdateExpProperty('1887525317');
//
//        $jwt->createToken();
//
//        $jwt->addOrUpdateCustomClaim('age', '39');
//        $jwt->addOrUpdateCustomClaim('sex', 'male');
//        $jwt->addOrUpdateCustomClaim('location', 'Davenport, Iowa');
//    }
//
//            //var_dump($standardClaims);
//
//$this->assertEquals('BradChesney.com', $standardClaims['iss']);
//$this->assertEquals('user', $standardClaims['aud']);
//$this->assertEquals('10000', $standardClaims['iat']);
//$this->assertEquals('0', $standardClaims['nbf']);
//$this->assertEquals('1000', $standardClaims['sub']);
//$this->assertEquals('1', $standardClaims['jti']);
//$this->assertEquals('1887525317', $standardClaims['exp']);
//
//        $standardClaims = array(
//            'iss'=>'rustbeltrebellion.com',
//            'sub'=>'15448979450000000000',
//            'aud'=>'rustbeltrebellion.com',
//            'exp'=>"$expires",
//            'nbf'=>"$now",
//            'iat'=>"$now",
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        // $jwt->deleteStandardClaims('aud');
//
//        // $jwt->deleteCustomClaims('location');
//
//        $jwt->createToken();
//
//        $expectedAlgorithmChunk = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
//
//        $jwtChunks = explode('.', $jwt->getToken());
//
//        $jwtChunksCount = count($jwtChunks);
//
//        $actualAlgorithmChunk = $jwtChunks[0];
//
//        // Check that there are three parts to the JWT
//        $this->assertEquals(3, $jwtChunksCount);
//
//        // Check that the algorithm chunk is predictably HS256
//        $this->assertEquals($expectedAlgorithmChunk, $actualAlgorithmChunk);
//    }
//
//
//
//    public function testLoadToken()
//    {
//        // var_dump('testLoadToken()');
//        $secret = 'secret';
//
//        $jwt = new Ehjwt($secret);
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        $standardClaims = array(
//            'iss'=>'rustbeltrebellion.com',
//            'sub'=>'15448979450000000000',
//            'aud'=>'rustbeltrebellion.com',
//            'exp'=>"$expires",
//            'nbf'=>"$now",
//            'iat'=>"$now",
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        $jwt->createToken();
//
//        $token = $jwt->getToken();
//
//        $newJwt = new Ehjwt('secret');
//
//        $newJwt->loadToken($token);
//
//        $claims = $newJwt->getClaims();
//
//        $checkValues = [];
//
//        $checkValues['iss'] = 'rustbeltrebellion.com';
//        $checkValues['sub'] = '15448979450000000000';
//        $checkValues['aud'] = 'rustbeltrebellion.com';
//        $checkValues['exp'] = $expires;
//        $checkValues['nbf'] = $now;
//        $checkValues['iat'] = $now;
//        $checkValues['jti'] = '1234567890';
//        $checkValues['age'] = '39';
//        $checkValues['location'] = 'Davenport, Iowa';
//        $checkValues['sex'] = 'male';
//
//        $this->assertEquals($claims['iss'], $checkValues['iss']);
//        $this->assertEquals($claims['sub'], $checkValues['sub']);
//        $this->assertEquals($claims['aud'], $checkValues['aud']);
//        $this->assertEquals($claims['exp'], $checkValues['exp']);
//        $this->assertEquals($claims['nbf'], $checkValues['nbf']);
//        $this->assertEquals($claims['iat'], $checkValues['iat']);
//        $this->assertEquals($claims['jti'], $checkValues['jti']);
//        $this->assertEquals($claims['age'], $checkValues['age']);
//        $this->assertEquals($claims['location'], $checkValues['location']);
//        $this->assertEquals($claims['sex'], $checkValues['sex']);
//    }
//
//
//
//
//
//    //   public function testChunksInvalidToken() {
//    // var_dump('testChunksInvalidToken()');
//    //   	$secret = 'secret';
//
//    // $jwt = new Ehjwt($secret);
//
//    // $now = time();
//    // $expires = time() + 30 * 60;
//
//    // $standardClaims = array(
//    //        'iss'=>'rustbeltrebellion.com',
//    //        'sub'=>'15448979450000000000',
//    //        'aud'=>'rustbeltrebellion.com',
//    //        'exp'=>"$expires",
//    //        'nbf'=>"$now",
//    //        'iat'=>"$now",
//    //        'jti'=>'1234567890'
//    // );
//    // $jwt->setStandardClaims($standardClaims);
//
//    // $customClaims = array(
//    // 	'age' => '39',
//    // 	'sex' => 'male',
//    // 	'location' => 'Davenport, Iowa'
//    // );
//
//    // $jwt->setCustomClaims($customClaims);
//
//    // $jwt->createToken();
//
//    // $token = $jwt->getToken();
//
//    // $cutOffPoint = strpos($token, '.');
//
//    // $brokenToken = substr( $token, $cutOffPoint + 1);
//
//    // $validationResult = Ehjwt::validateToken($brokenToken);
//
//    // var_dump($this);
//
//    // $this->assertEquals($validationResult, false);
//    //   }
//
//    public function testCreateTokenWithConstructorParameters()
//    {
//        // var_dump('testCreateTokenWithConstructorParameters()');
//        $secret = 'secret';
//
//        $jwt = new Ehjwt($secret, null, 'mysql:host=127.0.0.1;dbname=ehjwts', 'roots', 'passwords', 'rustbeltrebellions.com', 'rustbeltrebellions.com');
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        /*
//                iss: issuer, the website that issued the token
//                sub: subject, the id of the entity being granted the token
//                    (int has an unsigned, numeric limit of 4294967295)
//                    (bigint has an unsigned, numeric limit of 18446744073709551615)
//                    (unix epoch as of "now" 1544897945)
//                aud: audience, the users of the token-- generally a url or string
//                exp: expires, the UTC UNIX epoch time stamp of when the token is no longer valid
//                nbf: not before, the UTC UNIX epoch time stamp of when the token becomes valid
//                iat: issued at, the UTC UNIX epoch time stamp of when the token was issued
//                jti: JSON web token ID, a unique identifier for the JWT that facilitates revocation
//        */
//
//        $standardClaims = array(
//            'sub'=>'15448979450000000000',
//            'exp'=>'1546353624',
//            'nbf'=>'1546352624',
//            'iat'=>'1546352624',
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        $jwt->createToken();
//
//        $expectedAlgorithmChunk = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
//        $expectedPayloadChunk = 'eyJhZ2UiOiIzOSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9ucy5jb20iLCJleHAiOiIxNTQ2MzUzNjI0IiwiaWF0IjoiMTU0NjM1MjYyNCIsImlzcyI6InJ1c3RiZWx0cmViZWxsaW9ucy5jb20iLCJqdGkiOiIxMjM0NTY3ODkwIiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIxNTQ2MzUyNjI0Iiwic2V4IjoibWFsZSIsInN1YiI6IjE1NDQ4OTc5NDUwMDAwMDAwMDAwIn0';
//        $expectedCheckSumChunk = '4x7nDT8UmmZx1wkG7B4pj_GJ8AV06XF_pjEv1JoQViE';
//
//        $jwtChunks = explode('.', $jwt->getToken());
//
//        $jwtChunksCount = count($jwtChunks);
//
//        $actualAlgorithmChunk = $jwtChunks[0];
//        $actualPayloadChunk = $jwtChunks[1];
//        $actualChecksumChunk = $jwtChunks[2];
//
//        // Check that there are three parts to the JWT
//        $this->assertEquals(3, $jwtChunksCount);
//
//        // Check that the algorithm chunk is predictably HS256
//        $this->assertEquals($expectedAlgorithmChunk, $actualAlgorithmChunk);
//        $this->assertEquals($expectedPayloadChunk, $actualPayloadChunk);
//        $this->assertEquals($expectedCheckSumChunk, $actualChecksumChunk);
//    }
//
//    public function testAlgorithmHeaderInvalidToken()
//    {
//        // var_dump('testAlgorithmHeaderInvalidToken()');
//
//        $jwt = new Ehjwt();
//
//        $brokenToken = 'zI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImxvY2F0aW9uIjoiRGF2ZW5wb3J0LCBJb3dhIiwic2V4IjoibWFsZSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9uLmNvbSIsImV4cCI6IjE1NDYzNTM2MjQiLCJpYXQiOiIxNTQ2MzUyNjI0IiwianRpIjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjE1NDYzNTI2MjQiLCJzdWIiOiIxNTQ0ODk3OTQ1MDAwMDAwMDAwMCJ9.g3hLhBGJLuc7c6JPvAAcPbHS3zP1TAz63rJeyzV5hlo';
//
//        $validationResult = $jwt->validateToken($brokenToken);
//
//        $this->assertEquals($validationResult, false);
//    }
//
//    public function testPayloadInvalidToken()
//    {
//        // var_dump('testPayloadToken()');
//
//        $jwt = new Ehjwt();
//
//        $brokenToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW9uIjoiRGF2ZW5wb3J0LCBJb3dhIiwic2V4IjoibWFsZSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9uLmNvbSIsImV4cCI6IjE1NDYzNTM2MjQiLCJpYXQiOiIxNTQ2MzUyNjI0IiwianRpIjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjE1NDYzNTI2MjQiLCJzdWIiOiIxNTQ0ODk3OTQ1MDAwMDAwMDAwMCJ9.g3hLhBGJLuc7c6JPvAAcPbHS3zP1TAz63rJeyzV5hlo';
//
//        $validationResult = $jwt->validateToken($brokenToken);
//
//        $this->assertEquals($validationResult, false);
//    }
//
//    public function testWrongAlgorithmHeaderInvalidToken()
//    {
//
//            // var_dump('testWrongAlgorithmHeaderInvalidToken()');
//        $secret = 'secret';
//
//        $jwt = new Ehjwt($secret, null, 'mysql:host=localhost;dbname=ehjwt', 'root', 'password', 'rustbeltrebellion.com', 'rustbeltrebellion.com');
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//
//
//        $standardClaims = array(
//            'sub'=>'15448979450000000000',
//            'exp'=>'1546353624',
//            'nbf'=>'1546352624',
//            'iat'=>'1546352624',
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        $jwt->createToken();
//
//        $token = $jwt->getToken();
//
//        $tokenParts = explode('.', $token);
//
//        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', $tokenParts[0]);
//    }
//
//    public function testBeforeNotBeforeInvalidToken()
//    {
//        //var_dump('testBeforeNotBeforeInvalidToken()');
//
//        $jwt = new Ehjwt('secret');
//
//        $brokenToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9uLmNvbSIsImV4cCI6IjIxNDc0ODM2NDAiLCJpYXQiOiIxNTQ2MzUyNjI0IiwianRpIjoiMTIzNDU2Nzg5MCIsImxvY2F0aW9uIjoiRGF2ZW5wb3J0LCBJb3dhIiwibmJmIjoiMTk0NzQ4MzY0NyIsInNleCI6Im1hbGUiLCJzdWIiOiIxNTQ0ODk3OTQ1MDAwMDAwMDAwMCJ9.rGHGnyHMj3GODBB8XPa6chpl-IPFKdLfDJqlvih518Y';
//
//        $jwt->loadToken($brokenToken);
//
//        $validationResult = $jwt->validateToken($brokenToken);
//
//        $this->assertEquals($validationResult, false);
//    }
//
//    public function testExpiredInvalidToken()
//    {
//        // var_dump('testAlgorithmHeaderInvalidToken()');
//
//        $jwt = new Ehjwt();
//
//        $brokenToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImxvY2F0aW9uIjoiRGF2ZW5wb3J0LCBJb3dhIiwic2V4IjoibWFsZSIsImF1ZCI6InJ1c3RiZWx0cmViZWxsaW9uLmNvbSIsImV4cCI6IjE1NDYzNTM2MjQiLCJpYXQiOiIxNTQ2MzUyNjI0IiwianRpIjoiMTIzNDU2Nzg5MCIsIm5iZiI6IjE1NDYzNTI2MjQiLCJzdWIiOiIxNTQ0ODk3OTQ1MDAwMDAwMDAwMCJ9.g3hLhBGJLuc7c6JPvAAcPbHS3zP1TAz63rJeyzV5hlo';
//
//        $validationResult = $jwt->validateToken($brokenToken);
//
//        $this->assertEquals($validationResult, false);
//    }
//
//    public function testAddBannedRecord()
//    {
//        // var_dump('testBannedRecord()');
//
//        $jwt = new Ehjwt();
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        $standardClaims = array(
//            'sub'=> '15448979460000000000',
//            'exp'=> $expires,
//            'nbf'=> $now,
//            'iat'=> $now,
//            'jti'=>'1234567890'
//        );
//
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        $jwt->createToken();
//
//        $token = $jwt->getToken();
//
//        $claims = $jwt->getClaims();
//
//        $jwt->addTokenRevocationRecord(0, $claims['sub'], $claims['exp'] + 30);
//
//        $validationResult = $jwt->validateToken($token);
//
//        // print_r('$validationResult: ' . $validationResult);
//
//        $this->assertEquals(false, $validationResult);
//    }
//
//    public function testAddRevocationRecord()
//    {
//        // var_dump('testAddRevocationRecord()');
//
//        $jwt = new Ehjwt();
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        $standardClaims = array(
//            'sub'=> '15448979450000000000',
//            'exp'=> $expires,
//            'nbf'=> $now,
//            'iat'=> $now,
//            'jti'=>'1234567890'
//        );
//
//        $jwt->setStandardClaims($standardClaims);
//
//        $customClaims = array(
//            'age' => '39',
//            'sex' => 'male',
//            'location' => 'Davenport, Iowa'
//        );
//
//        $jwt->setCustomClaims($customClaims);
//
//        $jwt->createToken();
//
//        $token = $jwt->getToken();
//
//        $claims = $jwt->getClaims();
//
//        $jwt->addTokenRevocationRecord($claims['jti'], $claims['sub'], $claims['exp'] + 30);
//
//        $validationResult = $jwt->validateToken($token);
//
//        $this->assertEquals(false, $validationResult);
//    }
//
//    public function testEnvironmentVarsLoad()
//    {
//        // var_dump('testEnvironmentVarsLoad()');
//
//        //$dsn = addslashes(mysql:host=localhost);
//        $dsn = 'mysql:host=localhost';
//
//        putenv('ESJWT_DSN=' . $dsn);
//
//        putenv('ESJWT_DB_USER=root');
//
//        putenv('ESJWT_DB_PASS=password');
//
//        putenv('ESJWT_JWT_SECRET=secrets');
//
//        putenv('ESJWT_ISS=rustbeltrebellion.com');
//
//        putenv('ESJWT_AUD=list255.com');
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        $jwt = new Ehjwt(null, "NonExistentFile");
//
//        $standardClaims = array(
//            'sub'=>'15448979450000000000',
//            'exp'=>"$expires",
//            'nbf'=>"$now",
//            'iat'=>"$now",
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $claims = $jwt->getClaims();
//
//        $checkValues = [];
//
//        $checkValues['iss'] = 'rustbeltrebellion.com';
//        $checkValues['aud'] = 'list255.com';
//
//
//        $this->assertEquals($claims['iss'], $checkValues['iss']);
//        $this->assertEquals($claims['aud'], $checkValues['aud']);
//    }
//
//    public function testEnvironmentVarsStrictLoad()
//    {
//        // var_dump('testEnvironmentVarsStrictLoad()');
//
//        //$dsn = addslashes(mysql:host=localhost);
//        $dsn = 'mysql:host=localhost';
//
//        putenv('ESJWT_DSN=' . $dsn);
//
//        putenv('ESJWT_DB_USER=root');
//
//        putenv('ESJWT_DB_PASS=password');
//
//        putenv('ESJWT_JWT_SECRET=secrets');
//
//        putenv('ESJWT_ISS=rustbeltrebellion.com');
//
//        putenv('ESJWT_AUD=list255.com');
//
//        putenv('ESJWT_USE_ENV_VARS=true');
//
//        $now = time();
//        $expires = time() + 30 * 60;
//
//        $jwt = new Ehjwt(null, "NonExistentFile");
//
//        $standardClaims = array(
//            'sub'=>'15448979450000000000',
//            'exp'=>"$expires",
//            'nbf'=>"$now",
//            'iat'=>"$now",
//            'jti'=>'1234567890'
//        );
//        $jwt->setStandardClaims($standardClaims);
//
//        $claims = $jwt->getClaims();
//
//        $checkValues = [];
//
//        $checkValues['iss'] = 'rustbeltrebellion.com';
//        $checkValues['aud'] = 'list255.com';
//
//
//        $this->assertEquals($claims['iss'], $checkValues['iss']);
//        $this->assertEquals($claims['aud'], $checkValues['aud']);
//
//
//        putenv('ESJWT_DSN');
//
//        putenv('ESJWT_DB_USER');
//
//        putenv('ESJWT_DB_PASS');
//
//        putenv('ESJWT_JWT_SECRET');
//
//        putenv('ESJWT_ISS');
//
//        putenv('ESJWT_AUD');
//
//        putenv('ESJWT_USE_ENV_VARS');
//    }
}
