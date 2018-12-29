So, this is a low level library designed to:

- Allow you to specify a path and config file or use a config file in a default location with a default name of config/ehjwt-conf.php
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


### Edit the config file


### Run the db install script


## Step 2 Usage:


### Make the code available:

```php
use bradchesney79/ehjwt;
```

```php
require_once 'path/bradchesney79/ehjwt/Ehjwt.php';
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

- Finish the code that revokes tokens

- Write the token creation code

- Finish the validation code

- Add the iss and aud from the config or env vars to the constructor logic

- Use https://gist.github.com/soulmachine/b368ce7292ddd7f91c15accccc02b8df as the basis for instructions on how to use this library


Caveats:

- I have made decisions that force you to use this library in the closest to best practices using a specific secret key as I could manage. Other libraries allow you more freedom-- potentially to shoot yourself in the foot.

- There is no storage of who or what tokens are out there. You cannot see if one exists. You can only validate and leverage ones that come back to you.