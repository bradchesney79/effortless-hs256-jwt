<span style="color:red">I believe I have brought the library to a usable and critiquable state. As of now, December of 2020, I consider this library beta code.</span>

I created this package because I didn't love the existing libraries out there. Also, this package has only a dependency on the PDO database driver, JSON, and mbstring extensions being avaialble.

So, this is a low level library designed to:

- Allow you to rest easy that the algorithm will always be HS256
- Allow you to create a JWT Token string with standard and custom claims
- Allow you to edit claims
- Allow you to remove claims
- Allow you to retrieve a JWT Token string
- Allow you to read token claims
- Allow you to validate a token

## Step 1 - Install:

You will need a modern version of PHP installed, PHP v7.4+.

**Add via composer or git clone, or wget the class file, or good old cut/paste and require_once()**

```bash
composer require bradchesney79/effortless-hs256-jwt
```

*Ccreate the object with 'secret' parameter as such:*
```php
$jwt = new Ehjwt($secretString);
```

## Step 1a

*Unwashed heathens that resist using composer will need something like this:*

```php
require_once 'path/to/Ehjwt.php';
```

require_once, include, include_once... only you will really know what is best for you.

Installation via composer is not required-- I just think it is the best way


## Step 2 - Usage with Composer:

### Make the code available:

Be sure to do the completely normal PHP require or require_once of vendor/autoload.php

```php
use BradChesney79/EHJWT;
```


### Create a token, append/update claims, get the token string:

```php
$jwtToken = new EHJWT('SuperSecretStringUsedForOneWayEncryption');


// the globally unique ID of this token and its series of potential reissues
$jwtToken->addOrUpdateJwtClaim('jti', '1234567890'); // it is a string. nothing more, nothing less.

// issued at
$jwtToken->addOrUpdateJwtClaim('iat', '305078400'); // my birthday...

// when this incarnation of the jwt will die as a UTC timestamp
$jwtToken->addOrUpdateJwtClaim('exp', '1887525317'); // when the T-800 comes to kill Sarah Connor

// the subject-- I use this for the publicly facing user ID
$jwtToken->addOrUpdateJwtClaim('sub', 'bradchesney79@gmail.com');

// ...I'll be honest. I don't use the not before field.
// It isn't useful to me in my software designs.
// But, it will throw an exception if you try to use it before allowed.
// $jwtToken->addOrUpdateJwtClaim('nbf', 0); // January 1st, 1970

// One of many allowable custom, private claims-- but, beware, smaller the better.
$jwtToken->addOrUpdateJwtClaim('key','value');


$jwtToken->createToken(); // this internally populates the JWT string property of your instance

echo $jwtToken->getToken(); // this gives you the three part, period delimited string stored in the JWT string property
```

### Validate a token, read token claims, remove token claims:

```php
$jwtToken = new EHJWT('SuperSecretStringUsedForOneWayEncryption');

if ($jwtToken->loadToken('fdsafdsafdsafdsa'.'fdsfdsafdsafdsa'.'fdsafdfadsfdsafdsa')) {
    $sessionDataArray = $jwtToken->getTokenClaims();
}

$this->clearClaims();
```

## Step A - Test:

Ensure that the phpdbg and xdebug extensions are avaialble to make developer life easier on yourself

Run the tests with the PHPUnit installed in the dev dependencies

You need to set up the database and provide valid connection credentials

```bash
mysql -u{{dbUser}} -p < schema/ehjwt-mysql.sql

vendor/bin/phpmd src/EHJWT/  html cleancode --suffixes php --reportfile build/phpmd.html

vendor/bin/phpunit
```

## Step B - Count Lines of Code:

```bash
cloc --exclude-dir=vendor,build .
```

11/2020 1,800
12/2020 1,638
05/2021 1,087
ToDo:

- Turn detection of RuntimeException tests to also test the exception message for specificity

- Make the README not awful

- Use https://gist.github.com/soulmachine/b368ce7292ddd7f91c15accccc02b8df
  ...as the basis for instructions on how to functionally use this library beyond syntax and logical flow

Caveats:

- Use is limited to PHP 7.4+ platforms

- I am not positive this library is production ready yet

- I have made decisions that force you to use this library in the closest to best practices using a specific secret key as I could manage. Other libraries allow you more freedom-- potentially to shoot yourself in the foot.

- There is no storage of who or what tokens are out there. You cannot see if one exists with this library. You can only validate and leverage tokens that come back to you.