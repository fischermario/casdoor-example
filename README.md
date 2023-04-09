# Casdoor SAML example using Keycloak 6.0.1

You should adjust the file `env-template` to meet your needs (especially to avoid port collisions).

1. Prerequisites: Make sure that you have Docker installed. The tools `curl`, `jq`, `openssl` and `xmllint` are also needed on the host system.

2. Give permission to `deploy.sh`:

```
chmod +x deploy.sh
```

3. Run `deploy.sh`:

```
./deploy.sh
```

You should see the following output:

```
Removing network casdoor-example_casdoor-net
WARNING: Network casdoor-example_casdoor-net not found.
Removing network casdoor-example_default
WARNING: Network casdoor-example_default not found.
Creating network "casdoor-example_casdoor-net" with the default driver
Creating network "casdoor-example_default" with the default driver
Creating casdoor-example_keycloak_1 ... done
Waiting for Keycloak server..
Added 'admin' to '/opt/jboss/keycloak/standalone/configuration/keycloak-add-user.json', restart server to load user
Restarting casdoor-example_keycloak_1 ... done
Waiting for Keycloak server..
[KEYCLOAK] Requesting token
[KEYCLOAK] Creating new realm 'Casdoor'
[KEYCLOAK] Adding SAML client '/api/acs' to realm 'Casdoor'
[KEYCLOAK] Getting ID of SAML client '/api/acs'
[KEYCLOAK] Updating properties of SAML client '/api/acs'
[KEYCLOAK] Adding user 'test' to realm 'Casdoor'
[KEYCLOAK] Getting ID of user 'test'
[KEYCLOAK] Setting password of user 'test'
[KEYCLOAK] Getting SAML cert and URL data
[KEYCLOAK] Logout
Creating casdoor-example_db_1 ... done
Creating casdoor-example_casdoor_1 ... done
Waiting for Casdoor server....
[CASDOOR] Requesting token
[CASDOOR] Getting the application's clientId and clientSecret
[CASDOOR] Getting the application's certificate
[CASDOOR] Logout
Creating casdoor-example_frontend_1 ... done
Creating casdoor-example_backend_1  ... done
-------------------------------------------------------------
Finished!

Now please go to
>>>  http://auth.testhost.int:8333  <<<
and test the application!

For direct login via Casdoor use:
Casdoor app user name: testlocal
Casdoor app user password: xxxxxx

For login via Casdoor -> Keycloak use:
Keycloak realm user name: test
Keycloak realm user password: xxxxxx

Please use the following credentials for logging in to Keycloak:
Keycloak admin user name: admin
Keycloak admin user password: xxxxxx
```

During the run of `deploy.sh` credentials for the aforementioned users are created.

Please be aware that every run of `deploy.sh` will remove all containers and redeploy the example.
