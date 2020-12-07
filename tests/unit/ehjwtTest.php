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
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword', 'BradChesney.com', 'user');
        $this->assertInstanceOf(EHJWT::class, $jwt);
    }

    public function testLoadingEnvVars()
    {

        // create token using env vars

        $jwt = new EHJWT();

        $jwt->createToken();
        $claims = $jwt->getTokenClaims();

        // add elvis to the test db

        $bannedUsers = $jwt->getBannedUsers();


        $this->assertEquals('env.BradChesney.com', $claims['iss']);
        $this->assertEquals('envusers', $claims['aud']);

        // ToDo: yeah, elvis is going to need replaced with an actual array of test data


        $this->assertEquals('Elvis', $bannedUsers[0]);


    }

    public function testLoadingConfigFile()
    {

        $this->assertFileDoesNotExist('config/custom-config-conf.php');

        if (!file_exists('config/custom-config-conf.php')) {
            // create custom config file
            $customConfigFile = fopen("config/custom-config-conf.php", "w");

            // fill file with config info

            fwrite($customConfigFile, "<?php\n");
            fwrite($customConfigFile, "return [\n");
            fwrite($customConfigFile, "'dsn' => 'mysql:host=localhost;dbname=ehjwt',\n");
            fwrite($customConfigFile, "'dbUser' => 'brad',\n");
            fwrite($customConfigFile, "'dbPassword' => 'password',\n");
            fwrite($customConfigFile, "'jwtSecret' => 'Secret',\n");
            fwrite($customConfigFile, "'iss' => 'BradChesney.com',\n");
            fwrite($customConfigFile, "'aud' => 'users',\n");
            fwrite($customConfigFile, "];");

            //fwrite($customConfigFile, $txt);
            fclose($customConfigFile);

            // create token using config file

            $jwt = new EHJWT('', 'config/custom-config-conf.php', '', '', '', '', '');
            $jwt->addOrUpdateIatProperty('10000');
            $jwt->addOrUpdateNbfProperty('0');
            $jwt->addOrUpdateSubProperty('1000');
            $jwt->addOrUpdateJtiProperty('1');
            $jwt->addOrUpdateExpProperty('1887525317');

            $jwt->addOrUpdateCustomClaim('age', '39');
            $jwt->addOrUpdateCustomClaim('sex', 'male');
            $jwt->addOrUpdateCustomClaim('location', 'Davenport, Iowa');


            // delete custom config file
            if (!unlink('config/custom-config-conf.php')) {
                error_log('EHJWT LoadingConfigFile test config file not deleted. Sadness. Everybody... sadness. Frowny faces everyone.');
            }
            $this->assertFileDoesNotExist('config/custom-config-conf.php');

            $jwt->createToken();
            $claims = $jwt->getTokenClaims();

            $this->assertEquals('BradChesney.com', $claims['iss']);
            $this->assertEquals('users', $claims['aud']);
            $this->assertEquals('10000', $claims['iat']);
            $this->assertEquals('0', $claims['nbf']);
            $this->assertEquals('1000', $claims['sub']);
            $this->assertEquals('1', $claims['jti']);
            $this->assertEquals('1887525317', $claims['exp']);

            $this->assertEquals('39', $claims['age']);
            $this->assertEquals('male', $claims['sex']);
            $this->assertEquals('Davenport, Iowa', $claims['location']);
        }
    }

    public function testDsnArgumentSettings()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword', 'BradChesney.com', 'user');

        $jwt->createToken();
        $expectedToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ1c2VyIiwiaXNzIjoiQnJhZENoZXNuZXkuY29tIn0.R3NfZXdBdjhaQW1xMkpSc3E1d3p4NnE2M2F6WW55WFd4UGlrdDJtMUpPcw';
        $this->assertEquals($expectedToken, $jwt->getToken());
    }

    public function testClaimsAreAdded()
    {
        $jwt = new EHJWT('jwtSecret', '', 'DSNString', 'DBUser', 'DBPassword', 'BradChesney.com', 'user');
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

}