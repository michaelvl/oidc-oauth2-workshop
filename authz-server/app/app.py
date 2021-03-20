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

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('oauth2-server')

def build_url(url, **kwargs):
    return '{}?{}'.format(url, urllib.parse.urlencode(kwargs))

def issue_token(sub, claims):
    with open(jwt_key, 'rb') as f:
        key_data = f.read()
    key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

    claims['sub'] = sub
    #claims['groups'] = ['user']
    claims['iss'] = 'oauth2-server'
    claims['aud'] ='*'
    claims['iat'] = datetime.datetime.utcnow()
    claims['exp'] = datetime.datetime(year=2030, month=1, day=1)

    header = {'alg': 'RS256'}
    token = jwt.encode(header, claims, key).decode("ascii")
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

    # See https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
    claims = dict()
    if request['scope'] == 'openid':
        claims['sub'] = user

    token = issue_token(user, claims)
    response = {'id_token': token, 'access_token': token, 'token_type': 'Bearer'}

    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
