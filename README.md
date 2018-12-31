So, this is a low level library designed to:

- Allow you to specify the config parameters via passing them as arguments in the Ehjwt object instantiation
- Allow you to specify a path and config file or use a config file in a default location with a default name of config/ehjwt-conf.php
- Allow you to specify the config parameters with environment variables
- Allow you to specify an environment variable that prevents overriding the environment variables
- Allow you to set environment variables to specify the encryption key and a database or other PDO compatible persistent data store particulars
- Allow you to be confident about settings, my library uses your environment variables, config file, or arguments passed to the instantiation constructor in that order for all configurable values
- Allow you to rest easy that the algorithm will always be HS256
- Allow you to create a JWT Token string with standard "claims" some prefilled according to the config file
- Allow you to append custom claims
- Allow you to edit custom claims
- Allow you to remove custom claims
- Allow you to retrieve a JWT Token string
- Allow you to read token claims
- Allow you to validate a token
- Allow you to revoke a token
- Allow you to temporarily or permanently revoke all tokens associated with an identified user

## Step 1 Install:

### Add via composer or git clone or good old cut/paste and require_once()


### Supply the necessary particulars; a PDO DB DSN, a PDO DB user, a PDO DB password, and a "system secret"
- Make env vars available to PHP
- Copy and edit the example config file to the config directory which shares the same parent directory as the composer vendor directory

*--I use composer. But if I didn't, the parent directory of my webroot directory is where I would put it*


*Alternatively, you may skip using env vars or a config file and create the object with parameters as the configs to use as such:*
*'$jwt = new Ehjwt($secretString, null, $dsn, $dbUser, $dbPassword);'*

### Run the db install script

## Step 1a

Installation via composer is not required-- I just think it is the best way

```bash
composer require bradchesney79/effortless-hs256-jwt
```

*If you have a composer.lock file, substitute composer update in place of composer require...*

## Step 2 Usage:


### Make the code available:


Be sure to do the completely normal PHP require or require_once of vendor/autoload.php

```php
use bradchesney79/ehjwt;
```

*Unwashed heathens that resist using composer will need something like this:*

```php
require_once 'path/bradchesney79/effortless-hs256-jwt/src/Ehjwt.php';
```


### Create a token:


### Read the token string:


### Validate a token:


### Revoke a token:


### Read token claims:


### Edit token claims:


### Append/update token claims:


### Remove token claims:


## Step A Test:

Run the tests with the PHPUnit installed in the dev dependencies

```php
./vendor/bin/phpunit 
```

ToDo:

- Update tests to include all the config possibilities

- Finish the code that revokes tokens

- Write tests for token revocation

- Write the token creation code

- Finish the validation code

- Use https://gist.github.com/soulmachine/b368ce7292ddd7f91c15accccc02b8df as the basis for instructions on how to use this library


Caveats:

- I have made decisions that force you to use this library in the closest to best practices using a specific secret key as I could manage. Other libraries allow you more freedom-- potentially to shoot yourself in the foot.

- There is no storage of who or what tokens are out there. You cannot see if one exists. You can only validate and leverage tokens that come back to you.

- Banning isn't part of the JWT standard-- but, it seemed like a simple to create and convenient mechanism to expose-- and no one has to use that functionality.