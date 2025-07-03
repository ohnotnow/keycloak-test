# Laravel SSO with Keycloak Example

This is just a repo to demo using our SSO via Keycloak.

The main files to look at are :

* `app/Http/Controllers/Auth/SSOController.php`
* `app/Providers/AppServiceProvider.php`
* `routes/web.php`
* `config/sso.php`
* `config/services.php` (the 'keyclock' section)
* `database/migrations/0001_01_01_000000_create_users_table.php` (the usual modifications)

You also need the following two composer packages :
```sh
composer require laravel/socialite socialiteproviders/keycloak
```

The main .env variables which need to be set :
```sh
KEYCLOAK_BASE_URL=
KEYCLOAK_REALM=
KEYCLOAK_CLIENT_ID=
KEYCLOAK_CLIENT_SECRET=
KEYCLOAK_REDIRECT_URI=

SSO_ENABLED=1
# optionally
SSO_AUTOCREATE_NEW_USERS=1
SSO_ALLOW_STUDENTS=1
SSO_ADMINS_ONLY=1
```
