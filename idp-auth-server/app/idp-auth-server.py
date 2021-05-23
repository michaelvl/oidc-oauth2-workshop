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

auth_context = dict()
code_metadata = dict()
sessions = dict()

jwt_key = os.getenv('JWT_KEY', 'jwt-key')
app_port = int(os.getenv('APP_PORT', '5001'))
own_base_url = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5001')
api_base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5002/api')
SESSION_COOKIE_NAME='session'


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
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)

    log.info('Session cookie: {}'.format(session_cookie))
    if session_cookie in sessions:
        log.info('This is a valid session, short-cutting login process...')
        return issue_code_and_redirect(sessions[session_cookie])
    else:
        log.info('This is not a valid session!')

    global auth_context
    auth_context[reqid] = {'scope': scope, 'client_id': client_id, 'redirect_uri': redirect_uri, 'state': state}
    log.info("AUTHORIZE: Scope: '{}', client-id: '{}', state: {}, using request id: {}".format(scope, client_id, state, reqid))
    return flask.render_template('authorize.html', client_id=client_id, scope=scope, reqid=reqid)

@app.route('/approve', methods=['POST'])
def approve():
    req = flask.request
    reqid = req.form.get('reqid')
    subject = req.form.get('username')
    password = req.form.get('password')
    access_token_lifetime = int(req.form.get('access_token_lifetime'))
    refresh_token_lifetime = int(req.form.get('refresh_token_lifetime'))
    set_cookie = req.form.get('set_cookie')

    log.info("APPROVE: User: '{}', request id: {}".format(subject, reqid))

    if not 'approve' in req.form:
        return flask.render_template('error.html', text='Not approved')
    if password != 'valid':
        return flask.render_template('error.html', text='Authentication error')

    # TODO: Check age of request
    global auth_context
    if reqid not in auth_context.keys():
        return flask.render_template('error.html', text='Unknown request ID')
    auth_ctx = auth_context[reqid]
    del auth_context[reqid]   # Auth request only valid once

    # TODO: validate scope is allowed for client

    log.info("User: '{}' authorized scope: '{}' for client_id: '{}'".format(subject, auth_ctx['scope'], auth_ctx['client_id']))

    session_id = str(uuid.uuid4())
    session_meta = {'subject': subject,
                    'session_id': session_id,
                    'client_id': auth_ctx['client_id'],
                    'scope': auth_ctx['scope'],
                    'redirect_uri': auth_ctx['redirect_uri'],
                    'state': auth_ctx['state'],
                    'access_token_lifetime': access_token_lifetime,
                    'refresh_token_lifetime' : refresh_token_lifetime,
                    'set_cookie': set_cookie}
    sessions[session_id] = session_meta
    log.info('Created session {}'.format(session_id))

    return issue_code_and_redirect(session_meta)

def issue_code_and_redirect(session_meta):
    code = str(uuid.uuid4())
    global code_metadata
    code_metadata[code] = session_meta

    redir_url = build_url(session_meta['redirect_uri'], code=code, state=session_meta['state'])
    log.info("Redirecting to callback '{}'".format(redir_url))
    resp = flask.make_response(flask.redirect(redir_url, code=303))

    if session_meta['set_cookie']:
        resp.set_cookie(SESSION_COOKIE_NAME, session_meta['session_id'], samesite='Lax', httponly=True)

    return resp

@app.route('/token', methods=['POST'])
def token():
    req = flask.request
    client_auth = req.headers.get('Authorization')

    log.info("GET-TOKEN: Client auth: '{}'".format(client_auth))

    # TODO: Validate client auth

    grant_type = req.form.get('grant_type')
    log.info("GET-TOKEN: Grant type: '{}'".format(grant_type))

    if grant_type == 'authorization_code':
        code = req.form.get('code')
        redir_uri = req.form.get('redirection_uri')

        if code not in code_metadata:
            return flask.render_template('error.html', text='Invalid code')

        log.info("GET-TOKEN: Valid code: '{}'".format(code))

        session_meta = code_metadata[code]
        del code_metadata[code]    # Code can only be used once

        # TODO: Validate that code is not too old
        # TODO: Validate that code matches cliend_id
        # TODO: Validate redir_uri and grant type matches code

        # Context comes from session metadata
        subject = session_meta['subject']
        scope = session_meta['scope']
        client_id = session_meta['client_id']
        session_id = session_meta['session_id']
        access_token_lifetime = session_meta['access_token_lifetime']
        refresh_token_lifetime = session_meta['refresh_token_lifetime']

    elif grant_type == 'refresh_token':
        refresh_token = req.form.get('refresh_token')
        log.info('GET-TOKEN: Refresh token {}'.format(refresh_token))

        # TODO: Validate refresh token

        # FIXME
        with open('jwt-key.pub', 'rb') as f:
            key_data = f.read()
        pub_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

        refresh_token_json = jwt.decode(refresh_token, pub_key)

        # Context comes from refresh token
        session_id = refresh_token_json['session_id']
        subject = refresh_token_json['sub']
        scope = refresh_token_json['scope']
        client_id = refresh_token_json['client_id']
        access_token_lifetime = refresh_token_json['access_token_lifetime']
        refresh_token_lifetime = refresh_token_json['refresh_token_lifetime']

    else:
        log.error("GET-TOKEN: Invalid grant type: '{}'".format(grant_type))
        return 400

    # Issue tokens (shared for both 'authorization_code' and 'refresh_token' grants)
    own_url = req.base_url.removesuffix('/token')
    access_token = issue_token(subject, audience=[api_base_url, own_url+'/userinfo'],
                               claims={
                                   'token_use': 'access',
                                   'scope': scope},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(seconds=access_token_lifetime))
    refresh_token = issue_token(subject, audience=own_url+'/token',
                                claims={
                                    'client_id': client_id,
                                    'session_id': session_id,
                                    'access_token_lifetime': access_token_lifetime,
                                    'refresh_token_lifetime' : refresh_token_lifetime,
                                    'token_use': 'refresh',
                                    'scope': scope},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(seconds=refresh_token_lifetime))
    response = {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'Bearer'}
    if 'openid' in scope:
        claims = dict()
        # See https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims for what claims to include in access token
        if 'profile' in scope:
            claims['name'] = 'Name of user {}'.format(subject)
        response['id_token'] = issue_token(subject, client_id, claims, datetime.datetime.utcnow()+datetime.timedelta(minutes=60))

    return flask.Response(json.dumps(response), mimetype='application/json')
    
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
        claims['name'] = 'Name of user is {}'.format(access_token_json['sub'].capitalize())

    return claims

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks = { 'keys': [ signing_key_pub.as_dict() ] }
    return flask.Response(json.dumps(jwks), mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app_port)
