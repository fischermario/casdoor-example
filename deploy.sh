#!/bin/bash

# Exit in case of error
set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

# Export all config variables to current environment (otherwise envsubst will fail)
set -o allexport

DOCKER_BRIDGE_IP=$(ip -4 -br addr show docker0 | awk '{gsub(/\/.+$/,"",$3); print $3}')
MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)
MYSQL_PASSWORD=$(openssl rand -hex 16)

# ======================================================================

main() {
    echo "# This file was automatically generated and should not be edited" > $SCRIPT_DIR/.env
    cat $SCRIPT_DIR/env-template >> $SCRIPT_DIR/.env
    echo "DOCKER_BRIDGE_IP=$DOCKER_BRIDGE_IP" >> $SCRIPT_DIR/.env
    echo "MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD" >> $SCRIPT_DIR/.env
    echo "MYSQL_PASSWORD=$MYSQL_PASSWORD" >> $SCRIPT_DIR/.env

    source $SCRIPT_DIR/.env
    if [ "$?" -ne "0" ]; then
        echo "ERROR: cannot read the file $SCRIPT_DIR/.env"
        exit 1
    fi

    # ------------------------------------------------------------------

    DOMAIN_CHECK=$(nslookup $APP_DOMAIN)

    if [ "$?" -eq "1" ]; then
        echo "ERROR: app domain '$APP_DOMAIN' is not reachable!"
        echo "Please add the following line to your /etc/hosts file:"
        echo "$DOCKER_BRIDGE_IP $APP_DOMAIN"
        exit 1
    fi

    # ------------------------------------------------------------------

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME down

    # ------------------------------------------------------------------

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME up -d keycloak

    # ------------------------------------------------------------------

    wait_for_service "Keycloak" "$KEYCLOAK_URL"

    _KEYCLOAK_ADMIN_PASSWD=$(openssl rand -hex 3)

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME \
        exec keycloak /opt/jboss/keycloak/bin/add-user-keycloak.sh \
        -u $KEYCLOAK_ADMIN_USER -p $_KEYCLOAK_ADMIN_PASSWD

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME \
        restart keycloak

    # ------------------------------------------------------------------
    
    wait_for_service "Keycloak" "$KEYCLOAK_URL"

    _KEYCLOAK_USER_PASSWD=$(openssl rand -hex 3)

    echo "[KEYCLOAK] Requesting token"
    _KEYCLOAK_TOKEN=$(curl -s -X POST \
        "${KEYCLOAK_URL}/auth/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${KEYCLOAK_ADMIN_USER}" \
        -d "password=${_KEYCLOAK_ADMIN_PASSWD}" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r '.access_token')
    #echo $_KEYCLOAK_TOKEN
    if [ "$_KEYCLOAK_TOKEN" = "null" ]; then
        echo "ERROR: Wrong username/password"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Creating new realm '$KEYCLOAK_REALM'"
    #echo "$(generate_realm_payload "$KEYCLOAK_REALM")"
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X POST \
        "${KEYCLOAK_URL}/auth/admin/realms" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN" \
        -d "$(generate_realm_payload "$KEYCLOAK_REALM")")
    if [ "$_STATUS" -ne "201" ]; then
        echo "ERROR: creating new realm '$KEYCLOAK_REALM' failed" \
             "($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Adding SAML client '$KEYCLOAK_CLIENT_ID' to realm '$KEYCLOAK_REALM'"
    #echo "$(generate_client_payload \
    #    "$KEYCLOAK_CLIENT_ID" \
    #    "$KEYCLOAK_ADMIN_URL" \
    #    "$KEYCLOAK_REDIRECT_URI" \
    #    "$KEYCLOAK_ROOT_URL" )"
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X POST \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/clients" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN" \
        -d "$(generate_client_payload \
            "$KEYCLOAK_CLIENT_ID" \
            "$KEYCLOAK_ADMIN_URL" \
            "$KEYCLOAK_REDIRECT_URI" \
            "$KEYCLOAK_ROOT_URL")")
    if [ "$_STATUS" -ne "201" ]; then
        echo "ERROR: adding SAML client '$KEYCLOAK_CLIENT_ID' to" \
             "realm '$KEYCLOAK_REALM' failed ($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Getting ID of SAML client '$KEYCLOAK_CLIENT_ID'"
    CLIENTS=$(curl -s -X GET \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/clients" \
        -H "Accept: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN")
    #echo $CLIENTS | jq .
    _KEYCLOAK_CLIENT_ID=""
    for row in $(echo "${CLIENTS}" | jq -r '.[] | @base64'); do
        _jq() {
            echo ${row} | base64 --decode | jq -r ${1}
        }
        if [ "$(_jq '.clientId')" = "$KEYCLOAK_CLIENT_ID" ]; then
            _KEYCLOAK_CLIENT_ID=$(_jq '.id')
            break
        fi
    done
    if [ "$_KEYCLOAK_CLIENT_ID" = "" ]; then
        echo "ERROR: could not find ID of SAML client" \
             "'$KEYCLOAK_CLIENT_ID'"
        exit 1
    fi
    #echo $_KEYCLOAK_CLIENT_ID
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Updating properties of SAML client '$KEYCLOAK_CLIENT_ID'"
    #echo $(generate_client_update_payload "$KEYCLOAK_CLIENT_ID")
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X PUT \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/clients/${_KEYCLOAK_CLIENT_ID}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN" \
        -d "$(generate_client_update_payload "$KEYCLOAK_CLIENT_ID")")
    if [ "$_STATUS" -ne "204" ]; then
        echo "ERROR: updating properties of SAML client" \
             "'$KEYCLOAK_CLIENT_ID' failed ($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Adding user '$KEYCLOAK_USER_NAME' to realm '$KEYCLOAK_REALM'"
    #echo "$(generate_user_payload "$KEYCLOAK_USER_NAME")"
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X POST \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/users" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN" \
        -d "$(generate_user_payload "$KEYCLOAK_USER_NAME")")
    if [ "$_STATUS" -ne "201" ]; then
        echo "ERROR: adding user '$KEYCLOAK_USER_NAME' to realm" \
             "'$KEYCLOAK_REALM' failed ($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Getting ID of user '$KEYCLOAK_USER_NAME'"
    USERS=$(curl -s -X GET \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/users" \
        -H "Accept: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN")
    #echo $USERS | jq .
    _KEYCLOAK_USER_ID=""
    for row in $(echo "${USERS}" | jq -r '.[] | @base64'); do
        _jq() {
            echo ${row} | base64 --decode | jq -r ${1}
        }
        if [ "$(_jq '.username')" = "$KEYCLOAK_USER_NAME" ]; then
            _KEYCLOAK_USER_ID=$(_jq '.id')
            break
        fi
    done
    if [ "$_KEYCLOAK_USER_ID" = "" ]; then
        echo "ERROR: could not find user '$KEYCLOAK_USER_NAME'"
        exit 1
    fi
    #echo $_KEYCLOAK_USER_ID
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Setting password of user '$KEYCLOAK_USER_NAME'"
    #echo $(generate_reset_password_payload $_KEYCLOAK_USER_PASSWD)
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X PUT \
        "${KEYCLOAK_URL}/auth/admin/realms/${KEYCLOAK_REALM}/users/${_KEYCLOAK_USER_ID}/reset-password" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN" \
        -d "$(generate_reset_password_payload "$_KEYCLOAK_USER_PASSWD")")
    if [ "$_STATUS" -ne "204" ]; then
        echo "ERROR: changing the password of the user" \
             "'$KEYCLOAK_USER_NAME' failed ($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Getting SAML cert and URL data"
    #echo "$(get_saml_cert_xpath)"
    # export for later use in template
    export SAML_XML_DESC=$(curl -s \
        "${KEYCLOAK_URL}/auth/realms/${KEYCLOAK_REALM}/protocol/saml/descriptor")
    export SAML_CERT=$(echo -n $SAML_XML_DESC | xmllint \
        --xpath "$(get_saml_cert_xpath)" -)
    export SAML_ISSUER_URL=$(echo -n $SAML_XML_DESC | xmllint \
        --xpath "$(get_saml_issuer_url_xpath)" -)
    export SAML_ENDPOINT_URL=$(echo -n $SAML_XML_DESC | xmllint \
        --xpath "$(get_saml_endpoint_url_xpath)" -)
    #echo "$SAML_CERT"
    #echo "$SAML_ISSUER_URL"
    #echo "$SAML_ENDPOINT_URL"
    # ------------------------------------------------------------------
    echo "[KEYCLOAK] Logout"
    _STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" -X GET \
        "${KEYCLOAK_URL}/auth/realms/master/protocol/openid-connect/logout" \
        -H "Authorization: Bearer $_KEYCLOAK_TOKEN")
    if [ "$_STATUS" -ne "200" ]; then
        echo "ERROR: logout failed ($_STATUS)"
        exit 1
    fi
    # ------------------------------------------------------------------

    _CASDOOR_APP_USER_PASSWD=$(openssl rand -hex 3)

    envsubst < $SCRIPT_DIR/conf/casdoor.conf-template > $SCRIPT_DIR/conf/casdoor.conf
    envsubst < $SCRIPT_DIR/conf/init_data.json-template > $SCRIPT_DIR/conf/init_data.json

    # ------------------------------------------------------------------

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME up -d db casdoor

    # ------------------------------------------------------------------

    wait_for_service "Casdoor" "$CASDOOR_URL"

    echo "[CASDOOR] Requesting token"
    #echo "$(generate_login_payload "$CASDOOR_ADMIN_USER" "$_CASDOOR_ADMIN_PASSWD")"
    _RESP=$(curl -s -c $CASDOOR_COOKIE_PATH -X POST \
        -H "Content-Type: application/json" \
        -d "$(generate_login_payload "$CASDOOR_ADMIN_USER" "$_CASDOOR_ADMIN_PASSWD")" \
        $CASDOOR_URL/api/login | jq -r '.status')
    if [ "$_RESP" != "ok" ]; then
        echo "ERROR: Wrong username/password"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[CASDOOR] Getting the application's clientId and clientSecret"
    _APP_DATA=$(curl -s -b $CASDOOR_COOKIE_PATH \
        $CASDOOR_URL/api/get-application?id=admin/app-test)
    export _CASDOOR_CLIENT_ID=$(echo -n "$_APP_DATA" | jq -r '.clientId')
    export _CASDOOR_CLIENT_SECRET=$(echo -n "$_APP_DATA" | jq -r '.clientSecret')
    #echo "$_CASDOOR_CLIENT_ID"
    #echo "$_CASDOOR_CLIENT_SECRET"
    if [ "$_CASDOOR_CLIENT_ID" = "" ] || [ "$_CASDOOR_CLIENT_SECRET" = "" ]; then
        echo "ERROR: could not find the application"
        exit 1
    fi
    # ------------------------------------------------------------------
    echo "[CASDOOR] Getting the application's certificate"
    export _CASDOOR_CERT=$(curl -s -b $CASDOOR_COOKIE_PATH \
        $CASDOOR_URL/api/get-cert?id=admin/cert-test | jq -r '.certificate')
    if [ "$_CASDOOR_CERT" = "" ]; then
        echo "ERROR: could not find the certificate"
        exit 1
    fi
    #echo "$_CASDOOR_CERT"
    # ------------------------------------------------------------------
    echo "[CASDOOR] Logout"
    _RESP=$(curl -s -b $CASDOOR_COOKIE_PATH \
        $CASDOOR_URL/api/logout | jq -r '.status')
    if [ "$_RESP" != "ok" ]; then
        echo "ERROR: Logout failed"
        exit 1
    fi
    rm $CASDOOR_COOKIE_PATH

    # ------------------------------------------------------------------

    envsubst < $SCRIPT_DIR/app/src/App.js-template > $SCRIPT_DIR/app/src/App.js
    envsubst < $SCRIPT_DIR/app/src/Setting.js-template > $SCRIPT_DIR/app/src/Setting.js
    envsubst < $SCRIPT_DIR/app/backend/server.js-template > $SCRIPT_DIR/app/backend/server.js

    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME build --no-cache backend frontend
    docker-compose -f $SCRIPT_DIR/docker-compose.yml -p $APP_NAME up -d backend frontend

    # ------------------------------------------------------------------

    echo "-------------------------------------------------------------"
    echo "Finished!"
    echo ""
    echo "Now please go to"
    echo ">>>  $APP_URL  <<<"
    echo "and test the application!"
    echo ""
    echo "For direct login via Casdoor use:" 
    echo "Casdoor app user name: $CASDOOR_APP_USER_NAME"
    echo "Casdoor app user password: $_CASDOOR_APP_USER_PASSWD"
    echo ""
    echo "For login via Casdoor -> Keycloak use:"
    echo "Keycloak realm user name: $KEYCLOAK_USER_NAME"
    echo "Keycloak realm user password: $_KEYCLOAK_USER_PASSWD"
    echo ""
    echo "Please use the following credentials for Keycloak admin console:"
    echo "Keycloak admin user name: $KEYCLOAK_ADMIN_USER"
    echo "Keycloak admin user password: $_KEYCLOAK_ADMIN_PASSWD"
}

# ======================================================================

wait_for_service() {
    if [ "$1" = "" ] || [ "$2" = "" ]; then
        echo "ERROR: wait_for_service must be called at least" \
             "with serviceName and serviceUrl parameters"
        exit 1
    fi

    echo -n "Waiting for $1 server"
    until $(curl -o /dev/null -s -I -f $2); do
        printf '.'
        sleep 1
    done
    echo ""
}

# ======================================================================

generate_realm_payload() {
    if [ "$1" = "" ]; then
        echo "ERROR: generate_realm_payload must be called" \
             "with realmName parameter"
        exit 1
    fi

    cat <<EOF
{
    "id": "$1",
    "realm": "$1",
    "enabled": true
}
EOF
}

# ======================================================================

generate_client_payload() {
    # $1 .. clientId 
    # $2 .. adminUrl / consumer_url_redirect / consumer_url_post
    # $3 .. redirectUri
    # $4 .. rootUrl (optional)
    if [ "$1" = "" ] || [ "$2" = "" ] || [ "$3" = "" ]; then
        echo "ERROR: generate_client_payload must be called at least" \
             "with clientId, adminUrl, redirectUri parameters"
        exit 1
    fi

    cat <<EOF
{
    "clientId": "$1",
    "rootUrl": "$4",
    "adminUrl": "$2",
    "redirectUris": [
        "$3"
    ],
    "protocol": "saml",
    "attributes": {
        "saml.assertion.signature": "false",
        "saml_assertion_consumer_url_redirect": "$2",
        "saml.force.post.binding": "false",
        "saml_assertion_consumer_url_post": "$2",
        "saml_force_name_id_format": "true"
    }
}
EOF
}

# ======================================================================

generate_client_update_payload() {
    if [ "$1" = "" ]; then
        echo "ERROR: generate_client_update_payload must be called" \
             "with clientId parameter"
        exit 1
    fi

    cat <<EOF
{
    "clientId": "$1",
    "attributes": {
        "saml.multivalued.roles": "false",
        "saml.encrypt": "false",
        "saml.server.signature.keyinfo.ext": "false",
        "exclude.session.state.from.auth.response": "false",
        "saml.client.signature": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "display.on.consent.screen": "false",
        "saml.onetimeuse.condition": "false"
    }
}
EOF
}

# ======================================================================

generate_user_payload() {
    if [ "$1" = "" ]; then
        echo "ERROR: generate_user_payload must be called with" \
             "username parameter"
        exit 1
    fi

    cat <<EOF
{
    "username": "$1",
    "enabled": true,
    "emailVerified": true
}
EOF
}

# ======================================================================

generate_reset_password_payload() {
    if [ "$1" = "" ]; then
        echo "ERROR: generate_reset_password_payload must be called" \
             "with password parameter"
        exit 1
    fi

    cat <<EOF
{
    "type": "password",
    "value": "$1",
    "temporary": false
}
EOF
}

# ======================================================================

generate_login_payload() {
    cat <<EOF
{
    "application": "app-built-in",
    "organization": "built-in",
    "username": "admin",
    "password": "123",
    "type": "login"
}
EOF
}

# ======================================================================

get_saml_cert_xpath() {
(
cat<<EOF
/*[local-name()='EntitiesDescriptor']
/*[local-name()='EntityDescriptor']
/*[local-name()='IDPSSODescriptor']
/*[local-name()='KeyDescriptor']
/*[local-name()='KeyInfo']
/*[local-name()='X509Data']
/*[local-name()='X509Certificate']/text()
EOF
) | tr -d '\n' | sed 's/ //g'
}

# ======================================================================

get_saml_issuer_url_xpath() {
(
cat<<EOF
string(
/*[local-name()='EntitiesDescriptor']
/*[local-name()='EntityDescriptor']
/@entityID
)
EOF
) | tr -d '\n' | sed 's/ //g'
}

# ======================================================================

get_saml_endpoint_url_xpath() {
(
cat<<EOF
string(
/*[local-name()='EntitiesDescriptor']
/*[local-name()='EntityDescriptor']
/*[local-name()='IDPSSODescriptor']
/*[local-name()='SingleSignOnService'][1]
/@Location
)
EOF
) | tr -d '\n' | sed 's/ //g'
}

# ======================================================================

main "$@"

set +o allexport
