<?php
declare(strict_types=1);

/**
 * Register to PSR-4 autoloader.
 *
 * @return void
 */
function simplecache_register()
{
    spl_autoload_register('ehjwt_autoload', true, false);
}

/**
 * PSR-4 autoloader.
 *
 * @param string $className
 *
 * @return void
 */
function ehjwt_autoload($className)
{
    $prefix = 'BradChesney79\\EHJWT\\';
    $dir = __DIR__ . '/src/EHJWT';

    if (0 === strpos($className, $prefix)) {
        $parts = explode('\\', substr($className, strlen($prefix)));
        $filepath = $dir . '/' . implode('/', $parts) . '.php';

        if (is_file($filepath)) {
            require $filepath;
        }
    }
}

simplecache_register();