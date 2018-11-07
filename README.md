So, this is a low level library designed to:

Allow you to specify a conspicuously named ehjwt.php config file
Allow you to set environment variables to specify the encryption key and config file location
Allow you to place a config file in common project locations for autoloading
Allow you to be confident about settings, my library uses your config file for all configurable values
Allow you to rest easy that the algorithm will always be HS256
Allow you to create a JWT Token string with standard "claims" some prefilled according to the config file
Allow you to append custom claims
Allow you to edit custom claims
Allow you to remove custom claims
Allow you to retrieve a JWT Token string
Allow you to read token claims
Allow you to validate a token
Allow you to revoke a token

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


### Append to a token:


### Edit token claims:


### Remove token claims:


### Get a token string:


### Read token claims:


### Validate a token:


### Revoke a token:

ToDo:

Write the token creation code
Write the database creation script
Write the read claims code
