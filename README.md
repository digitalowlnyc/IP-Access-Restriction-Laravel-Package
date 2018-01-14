# bluenest/laravel-ip-restriction-middleware
Laravel middleware for restricting HTTP access by IP address or addresses.

# Installation

Add via composer:

`composer require bluenest/laravel-ip-restriction-middleware`

Then add the following middleware in app/Http/kernel.php:

```php
\BlueNest\Laravel\Http\Middleware\IpRestrictionMiddleware::class,
```

# Configuration

Add the following configuration settings in your .env file:

```
IP_ACCESS_ALLOW_DENY_DEFAULT=DENY
IP_ACCESS_BLACKLIST=
IP_ACCESS_WHITELIST=127.0.0.1
IP_ACCESS_DENY_MESSAGE="Please contact an administrator"
IP_ACCESS_DENY_HTTP_STATUS_CODE=500
IP_ACCESS_LOG_DENIALS=true
```