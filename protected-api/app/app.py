#!/usr/bin/env python

import os
import flask
import requests
import json
import logging
import jose

from authlib.jose import jwt, jwk, JsonWebKey
from jose import jwt as jose_jwt

app = flask.Flask('protected-api')

app_port = int(os.getenv('APP_PORT', '5002'))
oidc_jwks_url = os.getenv('OIDC_JWKS_URL', 'http://127.0.0.1:5000/.well-known/jwks.json')

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('protected-api')

def token_get_jwk(token):
    response = requests.get(oidc_jwks_url)
    jwks = response.json()
    log.info("Got JWKS '{}'".format(jwks))
    hdr = jose_jwt.get_unverified_header(token)
    log.info("JWT header '{}'".format(hdr))
    for jwk in jwks['keys']:
        if 'kid' in jwk.keys() and jwk['kid'] == hdr['kid']:
            return jwk
    return None

@app.route('/api', methods=['GET'])
def api():
    req = flask.request
    access_token = req.headers.get('Authorization', None)
    if not access_token:
        return 'Authentication required', 401

    # TODO: Validate access-token

    access_token_parts = access_token.split(' ')
    if access_token_parts[0].lower() != 'bearer' or len(access_token_parts) != 2:
        return 'Invalid authorization', 401

    access_token = access_token_parts[1]
    log.info("API: Access token: '{}'".format(access_token))

    unverified_access_token_json = jose_jwt.get_unverified_claims(access_token)
    log.info('API: Unverified claims {}'.format(unverified_access_token_json))

    # TODO: Validate that we have an 'iss' claim and that its one we trust
    
    token_pub_jwk_json = token_get_jwk(access_token)
    token_pub_jwk = JsonWebKey.import_key(token_pub_jwk_json)

    access_token_json = jwt.decode(access_token, token_pub_jwk)

    scope = access_token_json['scope']
    log.info("API: Scope '{}'".format(scope))

    # TODO: Validate audience in access token covers /api
    log.info("API: Access token audience: '{}'".format(access_token_json['aud']))

    api_response = {
        'access token scope': access_token_json['scope'],
    }

    if 'http://localhost:5002/api' in scope.split(' '):
        api_response['info'] = 'the access token allow access to the api'
    else:
        api_response['info'] = 'the access token DO NOT allow access to the api'
    
    return flask.Response(json.dumps(api_response), mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app_port)
