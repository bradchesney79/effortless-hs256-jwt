<?php
require 'src/EHJWT/Ehjwt.php';
require 'vendor/autoload.php';
use PHPUnit\Framework\TestCase;
use BradChesney79\EHJWT;
//use ArgumentCountError;

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
    /**
     * Get protected/private property of a class.
     *
     * @param object &$object Instantiated object that we will get property from
     * @param string $propertyName Property to get
     *
     * @return mixed Property return.
     * @throws ReflectionException
     */
    public function getPrivateProperty(&$object, $propertyName)
    {
        $reflection = new \ReflectionClass(get_class($object));
        $property = $reflection->getProperty($propertyName);
        $property->setAccessible(true);
        return $property->getValue($object);
    }
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
        $jwt = new EHJWT('jwtSecret');
        $this->assertInstanceOf(EHJWT::class , $jwt);
    }
    
    public function testObjectInstantiationFails()
    {
        $this->expectException('RuntimeException');
        $this->assertFalse($jwt = new EHJWT("jwtSecr"));
    }

    public function testLoadTokenWithIntArgument()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('RuntimeException');
        $jwt->loadToken(99);
    }
    public function testLoadTokenWithBooleanArgument()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('RuntimeException');
        $jwt->loadToken(false);
    }
    public function testLoadTokenWithNullArgument()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('TypeError');
        $jwt->loadToken(null);
    }
    public function testLoadTokenWithEmptyArgument()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('RuntimeException');
        $jwt->loadToken('');
    }
    public function testClaimsAreAdded()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '2');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->addOrUpdateJwtClaim('age', '39');
        $jwt->addOrUpdateJwtClaim('sex', 'male');
        $jwt->addOrUpdateJwtClaim('location', 'Davenport, Iowa');
        $jwt->createToken();
        $claims = $jwt->getTokenClaims();
        $this->assertEquals('BradChesney.com', $claims['iss']);
        $this->assertEquals('user', $claims['aud']);
        $this->assertEquals('10000', $claims['iat']);
        $this->assertEquals('0', $claims['nbf']);
        $this->assertEquals('1000', $claims['sub']);
        $this->assertEquals('2', $claims['jti']);
        $this->assertEquals('1887525317', $claims['exp']);
        $this->assertEquals('39', $claims['age']);
        $this->assertEquals('male', $claims['sex']);
        $this->assertEquals('Davenport, Iowa', $claims['location']);
    }
    public function testClaimsAreAddedWithWrongEncoding()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('RuntimeException');
        $jwt->addOrUpdateJwtClaim('aud', mb_convert_encoding('ЂˬǄ', 'UTF-16'));
    }
    public function testClaimsAreAddedWithWrongType()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->expectException('RuntimeException');
        $jwt->addOrUpdateJwtClaim('aud', mb_convert_encoding('ЂˬǄ', 'UTF-16') , 'int');
    }
    public function testClearingClaims()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '1');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->addOrUpdateJwtClaim('age', '39');
        $jwt->addOrUpdateJwtClaim('sex', 'male');
        $jwt->addOrUpdateJwtClaim('location', 'Davenport, Iowa');
        $jwt->createToken();
        $tokenString = $jwt->getToken();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiIxIiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UmN1TVZrMVVxVzdWdmNidTlVTFQ1R1lKd3NZNnB0elV0SmRxaDh6UEZ2OA', $tokenString);
        //        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiIxIiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.Z1M4X1NDcldzLUMyMWE1SVhKc1ZvM2JjUVBQWWZtVG9oUmdHN3dRWE5Jdw', $tokenString);
        $jwt->clearClaim('sex');
        $jwt->createToken();
        $tokenString = $jwt->getToken();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiIxIiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic3ViIjoiMTAwMCJ9.V29JU3ZrMTBHY1JDS2lTaTRHLUtqeEdzNVRxVnY5NjJLcTI5NnpLRnJvWQ', $tokenString);
        //        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiIxIiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic3ViIjoiMTAwMCJ9.Q2lkU1BGZ3gxMDF2Vi1BUEhVZ0tYT3R3WTh6TV9kWEU5cjFibTlIdTFFcw', $tokenString);
        $jwt->clearClaims();
        $jwt->createToken();
        $tokenString = $jwt->getToken();
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.eHhUSkFuWFY5VG16bzZaTElmSVNhVFV3bnpHZzJiUjlCaUxZLWhOQ2hTbw', $tokenString);
    }
    public function testValidateToken()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '4');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->addOrUpdateJwtClaim('age', '39');
        $jwt->addOrUpdateJwtClaim('sex', 'male');
        $jwt->addOrUpdateJwtClaim('location', 'Davenport, Iowa');
        $jwt->createToken();
        $tokenString = $jwt->getToken();
        $itVerks = $jwt->validateToken();
        $this->assertEquals(true, $itVerks);
        $this->assertEquals('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ', $tokenString);
    }
    public function testValidateBadToken()
    {
        $jwt = new EHJWT('jwtSecret');
        $this->assertFalse($jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQ'));
    }
    public function testValidateExpiredToken()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
        $jwt->clearClaim('exp');
        $jwt->createToken();
        $this->expectException('RuntimeException');
        $jwt->validateToken();
    }
    public function testValidateNotBeforeToken()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
        $jwt->addOrUpdateJwtClaim('nbf', '1887525317');
        $jwt->createToken();
        $this->expectException('RuntimeException');
        $jwt->validateToken();
    }
    public function testValidateTokenNoSub()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        //        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '4');
        $timestamp = $jwt->getUtcTime() + 1000;
        $jwt->addOrUpdateJwtClaim('exp', "$timestamp");
        $jwt->createToken();
        $this->expectException('RuntimeException');
        $jwt->validateToken();
    }
    public function testReissueToken()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '4');
        $timestamp = $jwt->getUtcTime() + 1000;
        $jwt->addOrUpdateJwtClaim('exp', "$timestamp");
        $jwt->createToken();
        $token = $jwt->getToken();
        unset($jwt);
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $utcTimePlusBuffer = $jwt->getUtcTime() + 2000;
        $jwt->reissueToken($token, $utcTimePlusBuffer);
        $claims = $jwt->getTokenClaims();
        $this->assertEquals($utcTimePlusBuffer, $claims['exp']);
    }
    public function testReissueTokenExpiredException()
    {
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '1000');
        $jwt->addOrUpdateJwtClaim('jti', '4');
        $timestamp = $jwt->getUtcTime() - 100;
        $jwt->addOrUpdateJwtClaim('exp', "$timestamp");
        $jwt->addOrUpdateJwtClaim('age', '39');
        $jwt->addOrUpdateJwtClaim('sex', 'male');
        $jwt->addOrUpdateJwtClaim('location', 'Davenport, Iowa');
        $jwt->createToken();
        $token = $jwt->getToken();
        unset($jwt);
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->addOrUpdateJwtClaim('exp', strval($jwt->getUtcTime() - 100));
        $utcTimePlusBuffer = $jwt->getUtcTime() + 100;
        $this->expectException('\RuntimeException');
        $jwt->reissueToken($token, $utcTimePlusBuffer);
    }
    public function testValidateWithBadPayload()
    {
        $encodedHeaders = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
        $unencodedPayload = (json_encode(array(
                'bananas' => 'b-a-n-a-n-a-s'
            ) , true) . 'error text');
        $encodedPayload = base64_encode($unencodedPayload);
        $secret = 'secret';
        $signature = hash_hmac('sha256', "$encodedHeaders.$encodedPayload", $secret, true);
        $encodedSignature = rtrim(strtr(base64_encode($signature) , '+/', '-_') , '=');
        $jwt = new EHJWT('jwtSecret');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $this->expectException('RuntimeException');
        $jwt->loadToken("$encodedHeaders.$encodedPayload.$encodedSignature");
    }
    public function testBadHeader()
    {
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('Encryption algorithm tampered with');
        $jwt = new EHJWT('jwtSecret');
        $jwt->loadToken('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0.R3NfZXdBdjhaQW1xMkpSc3E1d3p4NnE2M2F6WW55WFd4UGlrdDJtMUpPcw');
    }
    public function testIncompleteToken()
    {
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('Token does not contain three delimited sections');
        $jwt = new EHJWT('jwtSecret');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0');
    }
}