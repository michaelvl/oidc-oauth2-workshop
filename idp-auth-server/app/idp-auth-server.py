#!/usr/bin/env python
#
# Copyright, Michael Vittrup Larsen
# Origin: https://github.com/MichaelVL/oidc-oauth2-workshop

import os
import flask
from flask_cors import CORS
import datetime
import json
import uuid
import urllib
import base64
import hashlib
import logging

from authlib.jose import jwt, jwk, JsonWebKey

app = flask.Flask('oauth2-server')
CORS(app, resources={r"/*": {"origins": "*"}})

auth_context = dict()
code_metadata = dict()
sessions = dict()

jwt_key = os.getenv('JWT_KEY', 'jwt-key')
app_port = int(os.getenv('APP_PORT', '5001'))
own_base_url = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5001')
api_base_url = os.getenv('API_BASE_URL', 'http://127.0.0.1:5002/api')
SESSION_COOKIE_NAME='session'


logging.basicConfig()
log = logging.getLogger('oauth2-server')
log.setLevel(logging.DEBUG)

with open(jwt_key, 'rb') as f:
    key_data = f.read()
signing_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})
with open(jwt_key+'.pub', 'rb') as f:
    key_data = f.read()
signing_key_pub = JsonWebKey.import_key(key_data, {'kty': 'RSA'})
signing_key_pub['kid'] = signing_key_pub.thumbprint()


def get_session_by_subject(sub):
    for session_id in sessions.keys():
        if sessions[session_id]['subject'] == sub:
            return session_id
    return None

def get_client_session_by_id(session, client_id):
    for cs in session['client_sessions']:
        if cs['client_id']==client_id:
            return cs
    return None

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

def log_request(prefix, req):
    '''Log a Flask HTTP request (header and body)'''
    data = req.get_data()
    log.debug('{} # {} {}'.format(prefix, req.method, req.path))
    for hdr in req.headers:
        log.debug('{} # {}: {}'.format(prefix, hdr[0], hdr[1]))
    log.debug(prefix+' #')
    for ln in data.decode("ascii").split('\n'):
        log.debug('{} # {}'.format(prefix, ln))
        
@app.route('/', methods=['GET'])
def index():
    return flask.render_template('index.html', sessions=sessions)

@app.route('/<path:text>', methods=['GET'])
def all_routes(text):
    log.info("Path '{}'".format(text))
    if text in ['style.css']:
        return flask.Response(flask.render_template(text), mimetype='text/css')

@app.route('/logout', methods=['POST'])
def logout():
    req = flask.request
    session_id = req.form.get('sessionid')
    log.info('Logout, session: {}'.format(session_id))

    global sessions
    del sessions[session_id]

    resp = flask.make_response(flask.redirect(own_base_url, code=303))
    return resp

@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    # TODO: Validate client-id and redirection URL
    req = flask.request
    client_id = req.values.get('client_id')
    scope = req.values.get('scope')
    redirect_uri = req.values.get('redirect_uri')
    state = req.values.get('state')
    nonce = req.values.get('nonce')
    prompt = req.values.get('prompt')
    code_challenge_method = req.values.get('code_challenge_method')
    code_challenge = req.values.get('code_challenge')

    reqid = str(uuid.uuid4())
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)

    log.info('Session cookie: {}'.format(session_cookie))
    if session_cookie in sessions:
        log.info('This is an existing session identified by the session cookie, short-cutting login process...')
        return issue_code_and_redirect(sessions[session_cookie], client_id, state, nonce)
    else:
        log.info('No session cookie')
        if prompt == 'none':
            id_token_hint = req.form.get('id_token_hint')
            id_token_claims = jwt.decode(id_token_hint, signing_key_pub)
            log.info('ID token hint claims: {}'.format(id_token_claims))
            if own_base_url not in id_token_claims['aud']:
                log.error('ID token hint not for us')
                redir_url = build_url(redirect_uri, error='login_required', state=state)
                response = flask.make_response(flask.redirect(redir_url, code=303))
                return response

            existing_session_id = get_session_by_subject(id_token_claims['sub'])
            if existing_session_id:
                log.info('Found existing session {}'.format(existing_session_id))
                # FIXME
                return issue_code_and_redirect(sessions[existing_session_id], client_id, state, nonce)
            else:
                # FIXME
                log.info('No existing session found')
                data = {'error': 'login_required'}
                headers = {'Content-type': 'application/x-www-form-urlencoded'}
                response = flask.make_response(data, 403, headers)
                return response

    global auth_context
    auth_context[reqid] = {'scope': scope,
                           'client_id': client_id,
                           'redirect_uri': redirect_uri,
                           'state': state,
                           'nonce': nonce,
                           'code_challenge': code_challenge,
                           'code_challenge_method': code_challenge_method,
    }
    log.info("AUTHENTICATE: Requesting login. Scope: '{}', client-id: '{}', state: {}, using request id: {}".format(scope, client_id, state, reqid))
    return flask.render_template('authenticate.html', reqid=reqid)

@app.route('/login', methods=['POST'])
def login():
    req = flask.request
    reqid = req.form.get('reqid')
    subject = req.form.get('username')
    password = req.form.get('password')

    if password != 'valid':
        return flask.render_template('error.html', text='Authentication error')

    scope = auth_context[reqid]['scope']
    client_id = auth_context[reqid]['client_id']
    state = auth_context[reqid]['state']
    auth_context[reqid]['subject'] = subject

    log.info("LOGIN: Requesting authorization. Scope: '{}', client-id: '{}', state: {}, using request id: {}".format(scope, client_id, state, reqid))
    return flask.render_template('authorize.html', client_id=client_id, scope=scope, reqid=reqid)

@app.route('/approve', methods=['POST'])
def approve():
    req = flask.request
    reqid = req.form.get('reqid')
    subject = auth_context[reqid]['subject']

    log.info("APPROVE: User: '{}', request id: {}".format(subject, reqid))

    if not 'approve' in req.form:
        return flask.render_template('error.html', text='Not approved')

    # TODO: Check age of request
    if reqid not in auth_context.keys():
        return flask.render_template('error.html', text='Unknown request ID')
    auth_ctx = auth_context[reqid]
    del auth_context[reqid]   # Auth request only valid once

    # TODO: validate scope is allowed for client

    log.info("User: '{}' authorized scope: '{}' for client_id: '{}'".format(subject, auth_ctx['scope'], auth_ctx['client_id']))

    existing_session_id = get_session_by_subject(subject)
    if existing_session_id:
        session_id = existing_session_id
    else:
        session_id = str(uuid.uuid4())

    session = {'subject': subject,
               'session_id': session_id,
               'client_sessions': [
                   {
                       'client_id': auth_ctx['client_id'],
                       'scope': auth_ctx['scope'],
                       'redirect_uri': auth_ctx['redirect_uri'],
                       'code_challenge': auth_ctx['code_challenge'],
                       'code_challenge_method': auth_ctx['code_challenge_method']
                   }
               ]
    }
    sessions[session_id] = session
    log.info('Created session {}'.format(session_id))

    return issue_code_and_redirect(session, auth_ctx['client_id'], auth_ctx['state'], auth_ctx['nonce'])

def issue_code_and_redirect(session, client_id, state, nonce):
    code = str(uuid.uuid4())
    global code_metadata
    code_metadata[code] = {'session_id': session['session_id'], 'client_id': client_id, 'nonce': nonce}

    client_session = get_client_session_by_id(session, client_id)
    redir_url = build_url(client_session['redirect_uri'], code=code, state=state)
    log.info("Redirecting to callback '{}'".format(redir_url))
    resp = flask.make_response(flask.redirect(redir_url, code=303))

    resp.set_cookie(SESSION_COOKIE_NAME, session['session_id'], samesite='Lax', httponly=True)

    return resp

@app.route('/token', methods=['POST'])
def token():
    req = flask.request
    log_request('GET-TOKEN', req)
    client_auth = req.headers.get('Authorization')

    log.info("GET-TOKEN: Client auth: '{}'".format(client_auth))

    # TODO: Validate client auth

    grant_type = req.form.get('grant_type')
    log.info("GET-TOKEN: Grant type: '{}'".format(grant_type))

    if grant_type == 'authorization_code':
        code = req.form.get('code')
        redir_uri = req.form.get('redirection_uri')
        code_verifier = req.form.get('code_verifier')

        if code not in code_metadata:
            return flask.make_response(flask.render_template('error.html', text='Invalid code'), 403)

        log.info("GET-TOKEN: Valid code: '{}'".format(code))

        session_id = code_metadata[code]['session_id']
        client_id = code_metadata[code]['client_id']
        nonce = code_metadata[code]['nonce']
        del code_metadata[code]    # Code can only be used once

        # TODO: Validate that code is not too old
        # TODO: Validate redir_uri and grant type matches code

        # Context comes from session metadata
        session = sessions[session_id]
        subject = session['subject']
        client_session = get_client_session_by_id(session, client_id)

        if client_session['code_challenge']:
            log.info("GET-TOKEN: Challenge '{}', verifier '{}', method '{}'".format(client_session['code_challenge'], code_verifier, client_session['code_challenge_method']))
            if client_session['code_challenge_method'] == 'plain' and code_verifier != client_session['code_challenge']:
                return flask.make_response('error=invalid_grant', 403)
            elif client_session['code_challenge_method'] == 'S256':
                digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
                our_code_challenge = base64.urlsafe_b64encode(digest).decode('ascii')[:-1]
                log.info("Self-encoded challenge '{}', got challenge '{}'".format(our_code_challenge, client_session['code_challenge']))
                if our_code_challenge != client_session['code_challenge']:
                    return flask.make_response('error=invalid_grant', 403)
            else:
                return flask.make_response('error=invalid_grant', 403)
        
        scope = client_session['scope']
        access_token_lifetime = 1200
        refresh_token_lifetime = 3600

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
        nonce = refresh_token_json['nonce']

    else:
        log.error("GET-TOKEN: Invalid grant type: '{}'".format(grant_type))
        return 400

    # Issue tokens (shared for both 'authorization_code' and 'refresh_token' grants)
    log.info('GET-TOKEN: Issuing tokens!')
    access_token = issue_token(subject, audience=[api_base_url, own_base_url+'/userinfo'],
                               claims={
                                   'token_use': 'access',
                                   'scope': scope},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(seconds=access_token_lifetime))
    refresh_token = issue_token(subject, audience=own_base_url+'/token',
                                claims={
                                    'client_id': client_id,
                                    'session_id': session_id,
                                    'access_token_lifetime': access_token_lifetime,
                                    'refresh_token_lifetime' : refresh_token_lifetime,
                                    'nonce': nonce,
                                    'token_use': 'refresh',
                                    'scope': scope},
                               expiry=datetime.datetime.utcnow()+datetime.timedelta(seconds=refresh_token_lifetime))
    response = {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'Bearer'}
    if 'openid' in scope:
        claims = dict()
        # See https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims for what claims to include in access token
        if 'profile' in scope:
            claims['name'] = 'Name of user {}'.format(subject.capitalize())
            claims['preferred_username'] = subject.capitalize()
            if nonce:
                claims['nonce'] = nonce
        response['id_token'] = issue_token(subject, [client_id, own_base_url], claims, datetime.datetime.utcnow()+datetime.timedelta(minutes=60))

    return flask.Response(json.dumps(response), mimetype='application/json')
    
@app.route('/userinfo', methods=['GET'])
def userinfo():
    req = flask.request
    log_request('GET-USERINFO', req)
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

@app.route('/endsession', methods=['GET', 'POST'])
def endsession():
    req = flask.request
    id_token_hint = req.values.get('id_token_hint')
    redir_url = req.values.get('post_logout_redirect_uri')

    # TODO: Validate id_token_hint was issued by us

    id_token_claims = jwt.decode(id_token_hint, signing_key_pub)

    if own_base_url not in id_token_claims['aud']:
        log.error('END-SESSION: ID token hint not for us')
        return flask.render_template('error.html', text='ID token not for us')

    log.info('END-SESSION: ID token hint claims: {}'.format(id_token_claims))
    existing_session_id = get_session_by_subject(id_token_claims['sub'])
    if existing_session_id:
        session = sessions[existing_session_id]
        return flask.render_template('endsession.html', session_id=existing_session_id,
                                     subject=session['subject'], redir_url=redir_url)
    else:
        return flask.render_template('error.html', text='Error logging out')

@app.route('/endsession-approve', methods=['GET', 'POST'])
def endsession_approve():
    req = flask.request
    session_id = req.form.get('sessionid')
    redir_url = req.form.get('redirurl')

    log.info('END-SESSION-APPROVE: Ending session: {}'.format(session_id))
    del sessions[session_id]

    resp = flask.make_response(flask.redirect(redir_url, code=303))
    return resp

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks = { 'keys': [ signing_key_pub.as_dict() ] }
    return flask.Response(json.dumps(jwks), mimetype='application/json')

@app.route('/.well-known/openid-configuration', methods=['GET'])
def openid_configuration():
    config = { 'issuer': own_base_url,
               'authorization_endpoint': own_base_url+'/authorize',
               'token_endpoint': own_base_url+'/token',
               'userinfo_endpoint': own_base_url+'/userinfo',
               'jwks_uri': own_base_url+'/.well-known/jwks.json',
               'end_session_endpoint': own_base_url+'/endsession'}
    return flask.Response(json.dumps(config), mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app_port)
