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
        $jwt = new EHJWT('', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->assertInstanceOf(EHJWT::class , $jwt);
    }
    public function testLoadingEnvVars()
    {
        // create token using env vars
        $jwt = new EHJWT();
        $configurations = $this->getPrivateProperty($jwt, 'configurations');
        $this->assertEquals('envsecret', $configurations['jwtSecret']);
    }

    public function testLoadingConfigFile()
    {
        if (file_exists('config/custom-config-conf.php'))
        {
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 0');
            }
        }
        $this->assertFileDoesNotExist('config/custom-config-conf.php');
        if (!file_exists('config/custom-config-conf.php'))
        {
            // create custom config file
            $customConfigFile = fopen("config/custom-config-conf.php", "w");
            // fill file with config info
            fwrite($customConfigFile, "<?php\n");
            fwrite($customConfigFile, "return [\n");
            fwrite($customConfigFile, "'dsn' => 'mysql:host=localhost;dbname=ehjwt',\n");
            fwrite($customConfigFile, "'dbUser' => 'brad',\n");
            fwrite($customConfigFile, "'dbPassword' => 'password',\n");
            fwrite($customConfigFile, "'jwtSecret' => 'Secret',\n");
            fwrite($customConfigFile, "];");
            fclose($customConfigFile);
            // create token using config file
            $jwt = new EHJWT('', 'config/custom-config-conf.php', '', '', '');
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
            // delete custom config file
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 1');
            }
            $this->assertFileDoesNotExist('config/custom-config-conf.php');
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
        $this->assertFileDoesNotExist('config/custom-config-conf.php');
    }
    public function testLoadingConfigFileWithEmptyArray()
    {
        if (file_exists('config/custom-config-conf.php'))
        {
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 0');
            }
        }
        if (!file_exists('config/custom-config-conf.php'))
        {
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            /////////////////////////////////////////////////////
            // create custom config file
            $customConfigFile = fopen("config/custom-config-conf.php", "w");
            // fill file with config info
            fwrite($customConfigFile, "<?php\n");
            fwrite($customConfigFile, "return [];");
            fclose($customConfigFile);
            $this->expectException('LogicException');
            $jwt = new EHJWT('', 'config/custom-config-conf.php', '', '', '');
            unset($jwt);
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 2');
            }
            $this->assertFileDoesNotExist('config/custom-config-conf.php');
        }
        $this->assertFileDoesNotExist('config/custom-config-conf.php');
    }
    public function testLoadingConfigFileWithEmptyReturn()
    {
        if (file_exists('config/custom-config-conf.php'))
        {
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 3');
            }
        }
        if (!file_exists('config/custom-config-conf.php'))
        {
            // create custom config file
            $customConfigFile = fopen("config/custom-config-conf.php", "w");
            // fill file with config info
            fwrite($customConfigFile, "<?php\n");
            fwrite($customConfigFile, "return;");
            //fwrite($customConfigFile, $txt);
            fclose($customConfigFile);
            $this->expectException('LogicException');
            // create token using config file
            $jwt = new EHJWT('', 'config/custom-config-conf.php', '', '', '');
            if (!unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 3');
            }
            $this->assertFileDoesNotExist('config/custom-config-conf.php');
        }
        if (file_exists('config/custom-config-conf.php'))
        {
            if (unlink('config/custom-config-conf.php'))
            {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone. 4');
            }
        }
    }
    public function testDsnArgumentSettings()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $jwt->createToken();
        $expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0.R3NfZXdBdjhaQW1xMkpSc3E1d3p4NnE2M2F6WW55WFd4UGlrdDJtMUpPcw';
        $this->assertEquals($expectedToken, $jwt->getToken());
    }
    public function testLoadTokenWithIntArgument()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('RuntimeException');
        $jwt->loadToken(99);
    }
    public function testLoadTokenWithBooleanArgument()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('RuntimeException');
        $jwt->loadToken(false);
    }
    public function testLoadTokenWithNullArgument()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('TypeError');
        $jwt->loadToken(null);
    }
    public function testLoadTokenWithEmptyArgument()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('ArgumentCountError');
        $jwt->loadToken();
    }
    public function testClaimsAreAdded()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
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
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('RuntimeException');
        $jwt->addOrUpdateJwtClaim('aud', mb_convert_encoding('ЂˬǄ', 'UTF-16'));
    }
    public function testClaimsAreAddedWithWrongType()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword');
        $this->expectException('RuntimeException');
        $jwt->addOrUpdateJwtClaim('aud', mb_convert_encoding('ЂˬǄ', 'UTF-16') , 'int');
    }
    public function testClearingClaims()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
    public function testValidateExpiredToken()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
        $jwt->clearClaim('exp');
        $jwt->createToken();
        $this->expectException('RuntimeException');
        $jwt->validateToken();
    }
    public function testValidateNotBeforeToken()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
        $jwt->addOrUpdateJwtClaim('nbf', '1887525317');
        $jwt->createToken();
        $this->expectException('RuntimeException');
        $jwt->validateToken();
    }
    public function testValidateTokenNoDsn()
    {
        $jwt = new EHJWT('jwtSecret', '', 'q', 'brad', 'password');
        $this->expectException('RuntimeException');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
    }
    public function testValidateTokenBadDsn()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=monkey', 'brad', 'password');
        $this->expectException('RuntimeException');
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZ2UiOiIzOSIsImF1ZCI6InVzZXIiLCJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJpc3MiOiJCcmFkQ2hlc25leS5jb20iLCJqdGkiOiI0IiwibG9jYXRpb24iOiJEYXZlbnBvcnQsIElvd2EiLCJuYmYiOiIwIiwic2V4IjoibWFsZSIsInN1YiI6IjEwMDAifQ.UUl3bFh5c2pDckFiQUdqUHBQcjV6cmgtWlFzOC1SWjhicmxvR1FoMk9jQQ');
    }
    public function testValidateTokenNoSub()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $utcTimePlusBuffer = $jwt->getUtcTime() + 2000;
        $jwt->reissueToken($token, $utcTimePlusBuffer);
        $claims = $jwt->getTokenClaims();
        $this->assertEquals($utcTimePlusBuffer, $claims['exp']);
    }
    public function testReissueTokenExpiredException()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
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
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iss', 'BradChesney.com');
        $jwt->addOrUpdateJwtClaim('aud', 'user');
        $this->expectException('\RuntimeException');
        $jwt->loadToken("$encodedHeaders.$encodedPayload.$encodedSignature");
    }
    public function testBadHeader()
    {
        $this->expectException('\RuntimeException');
        $this->expectExceptionMessage('Encryption algorithm tampered with');
        $jwt = new EHJWT();
        $jwt->loadToken('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0.R3NfZXdBdjhaQW1xMkpSc3E1d3p4NnE2M2F6WW55WFd4UGlrdDJtMUpPcw');
    }
    public function testIncompleteToken()
    {
        $this->expectException('\RuntimeException');
        $this->expectExceptionMessage('Token does not contain three delimited sections');
        $jwt = new EHJWT();
        $jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0');
    }
    public function testTokenRevocation()
    {
        $jwt = new EHJWT('', 'config/jwt-config-conf.php', '', '', '');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '314159');
        $jwt->addOrUpdateJwtClaim('jti', '1');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->addOrUpdateJwtClaim('age', '39');
        $jwt->addOrUpdateJwtClaim('sex', 'male');
        $jwt->addOrUpdateJwtClaim('location', 'Davenport, Iowa');
        $jwt->createToken();
        $token = $jwt->getToken();
        $jwt->revokeToken();
        unset($jwt);
        $otherJwt = new EHJWT();

        $result = $otherJwt->loadToken($token);
        $configurations = $this->getPrivateProperty($otherJwt, 'configurations');
        $dbh = new PDO($configurations['dsn'], $configurations['dbUser'], $configurations['dbPassword']);
        $stmt = $dbh->prepare("DELETE FROM revoked_ehjwt WHERE `jti` = 1 AND `sub` = 314159");
        $stmt->execute();
        $this->assertFalse($result);
    }
    public function testRevocationTableCleanup()
    {
        $jwt = new EHJWT('', 'config/jwt-config-conf.php', '', '', '');
        $configurations = $this->getPrivateProperty($jwt, 'configurations');
        $dbh = new PDO($configurations['dsn'], $configurations['dbUser'], $configurations['dbPassword']);
        $dbh->query('DELETE FROM revoked_ehjwt WHERE 6 = 6');
        $dbh->query('INSERT INTO revoked_ehjwt (`jti`, `sub`, `exp`) VALUES (6,1000,1)');
        // assert that a record with jti of '6' exists and that the expiration is 1
        if ($stmt2 = $dbh->query('SELECT * FROM revoked_ehjwt WHERE `jti` = 6'))
        {
            $x0 = 0;
            while ($row = $stmt2->fetch())
            {
                $this->assertEquals($row['jti'], 6);
                $this->assertEquals($row['exp'], 1);
                $x0++;
            }
            $this->assertEquals(1, $x0);
        }
        $jwt->revocationTableCleanup($jwt->getUtcTime());
        // check that there are not any records with a 'jti' of '6'
        if ($stmt3 = $dbh->query('SELECT * FROM revoked_ehjwt WHERE `jti` = 6'))
        {
            $x1 = 0;
            while ($row = $stmt3->fetch())
            {
                $x1++;
            }
        }
        $this->assertEquals(0, $x1);
    }
    public function testRevocationTableCleanupBadDsn()
    {
        // ToDo: Yeah not sure I can trigger a bad dsn situation
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->revocationTableCleanup($jwt->getUtcTime());
        $this->assertTrue(true);
    }
    public function testBanUser()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '314159');
        $jwt->addOrUpdateJwtClaim('jti', '7');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->createToken();
        $jwt->banUser(1887525417);
        $this->assertFalse($jwt->validateToken());
    }
    public function testUnbanUser()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '314159');
        $jwt->addOrUpdateJwtClaim('jti', '7');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->unbanUser();
        $jwt->createToken();
        $this->assertTrue($jwt->validateToken());
    }
    public function testRemoveExpiredRevokedTokens()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '3141592');
        $jwt->addOrUpdateJwtClaim('jti', '9');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $configurations = $this->getPrivateProperty($jwt, 'configurations');
        $dsn = $configurations['dsn'];
        $user = $configurations['dbUser'];
        $pass = $configurations['dbPassword'];
        $dbh = new PDO($dsn, $user, $pass);
        $stm = $dbh->query('DELETE FROM revoked_ehjwt WHERE `sub` = 314515951');
        $stmt = $dbh->query('INSERT INTO revoked_ehjwt (`jti`, `sub`, `exp`) VALUES (8,3141592,1)');
        $stmt0 = $dbh->query('SELECT * FROM revoked_ehjwt WHERE `sub` = 3141592');
        $x0 = 0;
        while ($row = $stmt0->fetch())
        {
            $this->assertEquals($row['jti'], 8);
            $x0++;
        }
        $this->assertEquals($x0, 1);
        $jwt->createToken();
        $jwt->validateToken();
        $stmt1 = $dbh->prepare('SELECT * FROM revoked_ehjwt WHERE `sub` = 3141592');
        $stmt1->execute();
        $x1 = 0;
        while ($row = $stmt1->fetch())
        {
            $this->assertEquals($row['jti'], 8);
            $x1++;
        }
        $this->assertEquals($x1, 0);
    }
    public function testValidateTokensRemoveExpired()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '3141592');
        $jwt->addOrUpdateJwtClaim('jti', '9');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $configurations = $this->getPrivateProperty($jwt, 'configurations');
        $dsn = $configurations['dsn'];
        $user = $configurations['dbUser'];
        $pass = $configurations['dbPassword'];
        $dbh = new PDO($dsn, $user, $pass);
        // insert expired token
        $dbh->query('INSERT INTO revoked_ehjwt `jti`, `sub`, `exp` VALUES (3, 3141592, 5)');
        $stmt1 = $dbh->query('SELECT * FROM revoked_ehjwt');
        while ($row = $stmt1->fetch())
        {
            $this->assertEquals($row['jti'], 3);
            $this->assertEquals($row['sub'], 3141592);
        }
        $jwt->createToken();
        $jwt->validateToken();
        $stmt2 = $dbh->query('SELECT * FROM revoked_ehjwt WHERE `jti` = 3 AND `sub` = 3141592');
        $x = 0;
        while ($row = $stmt2->fetch())
        {
            $x++;
        }
        $this->assertEquals(0, $x);
    }
    public function testPermabanUser()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '314159');
        $jwt->addOrUpdateJwtClaim('jti', '7');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->createToken();
        $jwt->permabanUser();
        $this->assertFalse($jwt->validateToken());
    }

    public function testRetrievievalForBannedUsers() {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $this->assertEquals(count($jwt->retrieveBannedUsers()), 1);
    }

    public function testRevokeToken()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $jwt->addOrUpdateJwtClaim('iat', '10000');
        $jwt->addOrUpdateJwtClaim('nbf', '0');
        $jwt->addOrUpdateJwtClaim('sub', '31415926');
        $jwt->addOrUpdateJwtClaim('jti', '80');
        $jwt->addOrUpdateJwtClaim('exp', '1887525317');
        $jwt->createToken();
        $jwt->revokeToken();
        $this->assertFalse($jwt->validateToken());
    }

    public function testBadTokenSignature()
    {
        $jwt = new EHJWT('jwtSecret', '', 'mysql:host=localhost;dbname=EHJWT', 'brad', 'password');
        $this->assertFalse($jwt->loadToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxODg3NTI1MzE3IiwiaWF0IjoiMTAwMDAiLCJqdGkiOiI4MDEiLCJuYmYiOiIwIiwic3ViIjoiMzYifQ.M0NHcHF6bHB0YTVlOVc2S2JHWnZCREFFRWQzV2U3bjlqa3JCMzlFY2x'));
    }
}