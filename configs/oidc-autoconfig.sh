#! /bin/bash

ISSUER=$1

if [ -z $ISSUER ]; then
    echo "*** Require issuer argument!"
else
    AUTO_EP="$ISSUER/.well-known/openid-configuration"
    echo "Querying issuer $ISSUER configuration endpoint $AUTO_EP"

    CFG=$(curl -s $AUTO_EP)

    export OAUTH2_URL=$(echo $CFG | jq -r .authorization_endpoint)
    export OAUTH2_TOKEN_URL=$(echo $CFG | jq -r .token_endpoint)
    export OAUTH2_USERINFO_URL=$(echo $CFG | jq -r .userinfo_endpoint)
    export OIDC_END_SESSION_URL=$(echo $CFG | jq -r .end_session_endpoint)
    export OIDC_JWKS_URL=$(echo $CFG | jq -r .jwks_uri)
    echo "Env variables:"
    env |egrep 'OIDC|OAUTH2'
fi
