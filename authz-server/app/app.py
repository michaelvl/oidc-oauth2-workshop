#!/usr/bin/env python

import os
import flask
import datetime
import json
import uuid
import urllib
import logging

from authlib.jose import jwt, jwk, JsonWebKey

app = flask.Flask('oauth2-server')

requests = dict()
codes = dict()

jwt_key = os.getenv('JWT_KEY', 'jwt-key')
app_port = int(os.getenv('APP_PORT', '5000'))
own_base_url = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000')
api_base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5002/api')


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('oauth2-server')

with open(jwt_key, 'rb') as f:
    key_data = f.read()
signing_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})
with open(jwt_key+'.pub', 'rb') as f:
    key_data = f.read()
signing_key_pub = JsonWebKey.import_key(key_data, {'kty': 'RSA'})
signing_key_pub['kid'] = signing_key_pub.thumbprint()


def build_url(url, **kwargs):
    return '{}?{}'.format(url, urllib.parse.urlencode(kwargs))

def issue_token(subject, audience, claims, expiry):
    claims['sub'] = subject
    claims['iss'] = own_base_url
    claims['aud'] = audience
    claims['iat'] = datetime.datetime.utcnow()
    claims['exp'] = expiry

    header = {'alg': 'RS256', 'kid': signing_key_pub['kid'] }
    token = jwt.encode(header, claims, signing_key).decode("ascii")
    return token


@app.route('/authorize', methods=['GET'])
def authorize():
    # TODO: Validate client-id and redirection URL
    req = flask.request
    client_id = req.args.get('client_id')
    scope = req.args.get('scope')
    redirect_uri = req.args.get('redirect_uri')
    state = req.args.get('state')
    reqid = str(uuid.uuid4())
    requests[reqid] = {'scope': scope, 'client_id': client_id, 'redirect_uri': redirect_uri, 'state': state}
    log.info("AUTHORIZE: Scope: '{}', client-id: '{}', state: {}, using request id: {}".format(scope, client_id, state, reqid))
    return flask.render_template('authorize.html', client_id=client_id, scope=scope, reqid=reqid)

@app.route('/approve', methods=['POST'])
def approve():
    req = flask.request
    reqid = req.form.get('reqid')
    user = req.form.get('username')
    password = req.form.get('password')

    log.info("APPROVE: User: '{}', request id: {}".format(user, reqid))

    if not 'approve' in req.form:
        return flask.render_template('error.html', text='Not approved')
    if password != 'valid':
        return flask.render_template('error.html', text='Authentication error')

    # TODO: Check age of request
    if reqid not in requests.keys():
        return flask.render_template('error.html', text='Unknown request ID')
    request = requests[reqid]
    del requests[reqid]   # Request only valid once

    # TODO: validate scope is allowed for client

    log.info("User: '{}' authorized scope: '{}' for client_id: '{}'".format(user, request['scope'], request['client_id']))

    code = str(uuid.uuid4())

    codes[code] = {'request': request, 'user': user}

    redir_url = build_url(request['redirect_uri'], code=code, state=request['state'])
    log.info("Redirecting to callback '{}'".format(redir_url))
    return flask.redirect(redir_url, code=303)

@app.route('/token', methods=['POST'])
def token():
    req = flask.request
    client_auth = req.headers.get('Authorization')

    log.info("GET-TOKEN: Client auth: '{}'".format(client_auth))

    # TODO: Validate client auth

    code = req.form.get('code')
    grant_type = req.form.get('grant_type')
    redir_uri = req.form.get('redirection_uri')

    if code not in codes:
        return flask.render_template('error.html', text='Invalid code')

    log.info("GET-TOKEN: Valid code: '{}'".format(code))

    code_meta = codes[code]
    del codes[code]    # Code can only be used once
    request = code_meta['request']
    user = code_meta['user']

    # TODO: Validate that code is not too old
    # TODO: Validate that code matches cliend_id
    # TODO: Validate uri and grant type matches code

    own_url = req.base_url.removesuffix('/token')
    access_token = issue_token(user, audience=[api_base_url, own_url+'/userinfo'],
                               claims={
                                   'token_use': 'access',
                                   'scope': request['scope']},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(minutes=5))
    refresh_token = issue_token(user, audience=[api_base_url, own_url+'/userinfo'],
                                claims={
                                    'token_use': 'refresh',
                                    'scope': request['scope']},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(days=1))
    response = {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'Bearer'}

    if 'openid' in request['scope']:
        claims = dict()
        # See https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims for what claims to include in access token
        if 'profile' in request['scope']:
            claims['name'] = 'Name of user {}'.format(user)
        response['id_token'] = issue_token(user, request['client_id'], claims, datetime.datetime.utcnow()+datetime.timedelta(minutes=60))

    return response

@app.route('/userinfo', methods=['GET'])
def userinfo():
    req = flask.request
    access_token = req.headers.get('Authorization', None)
    # TODO: if not access_token

    # TODO: Validate access-token

    log.info("GET-USERINFO: Access token: '{}'".format(access_token))

    access_token_parts = access_token.split()
    if access_token_parts[0].lower() != 'bearer' or len(access_token_parts) != 2:
        return flask.render_template('error.html', text='Invalid authorization')

    access_token = access_token_parts[1]

    # FIXME
    with open('jwt-key.pub', 'rb') as f:
        key_data = f.read()
    pub_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

    access_token_json = jwt.decode(access_token, pub_key)
    scope = access_token_json['scope']

    # TODO: Validate audience in access token covers /userinfo
    log.info("GET-USERINFO: Access token audience: '{}'".format(access_token_json['aud']))

    log.info("GET-USERINFO: Scope '{}'".format(scope))

    claims = dict()
    # See https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims for what claims to include in access token
    if 'profile' in scope:
            claims['name'] = 'Name of user'

    return claims

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks = { 'keys': [ signing_key_pub.as_dict() ] }
    return flask.Response(json.dumps(jwks), mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app_port)
