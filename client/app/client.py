#!/usr/bin/env python
#
# Copyright, Michael Vittrup Larsen
# Origin: https://github.com/MichaelVL/oidc-oauth2-workshop

import os
import flask
import requests
import urllib
import uuid
import base64
import json
import logging
import jose

from authlib.jose import jwt, jwk, JsonWebKey
from jose import jwt as jose_jwt

app = flask.Flask('oauth2-client')

logging.basicConfig()
log = logging.getLogger('oauth2-client')
log.setLevel(logging.DEBUG)
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

outstanding_requests = dict()
sessions = dict()

oauth2_url = os.getenv('OAUTH2_URL', 'http://localhost:5001/authorize')
oauth2_token_url = os.getenv('OAUTH2_TOKEN_URL', 'http://localhost:5001/token')
oauth2_userinfo_url = os.getenv('OAUTH2_USERINFO_URL', 'http://localhost:5001/userinfo')
oidc_end_session_url = os.getenv('OIDC_END_SESSION_URL', 'http://localhost:5001/endsession')
oidc_jwks_url = os.getenv('OIDC_JWKS_URL', 'http://localhost:5001/.well-known/jwks.json')
client_id = os.getenv('CLIENT_ID', 'client-123-id')
client_secret = os.getenv('CLIENT_SECRET', 'client-123-password')
app_port = int(os.getenv('APP_PORT', '5000'))
api_base_url = os.getenv('API_BASE_URL', 'http://localhost:5002')

own_url = 'http://localhost:5000'
redirect_uri = 'http://localhost:5000/callback'

SESSION_COOKIE_NAME='client-session'

def build_url(url, **kwargs):
    return '{}?{}'.format(url, urllib.parse.urlencode(kwargs))

def encode_client_creds(client_id, client_secret):
    creds = '{}:{}'.format(urllib.parse.quote_plus(client_id), urllib.parse.quote_plus(client_secret))
    return base64.b64encode(creds.encode('ascii')).decode('ascii')

def json_pretty_print(json_data):
    return json.dumps(json_data, indent=4, sort_keys=True)

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

def log_response(prefix, response):
    for k,v in response.headers.items():
        log.debug('{} # {}: {}'.format(prefix, k, v))
    log.debug(prefix+' #')
    for ln in response.text.split('\n'):
        log.debug('{} # {}'.format(prefix, ln))

@app.route('/', methods=['GET'])
def index():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    if session_cookie in sessions:
        session = sessions[session_cookie]
        log.info('ID token claims: {}'.format(session['id_token_claims']))
        username=session['id_token_claims'].get('preferred_username', session['id_token_claims']['sub'])
        return flask.render_template('token.html',
                                     id_token=session['id_token'],
                                     id_token_parsed=json_pretty_print(session['id_token_claims']),
                                     subject=session['id_token_claims']['sub'],
                                     username=username,
                                     access_token=session['access_token'],
                                     refresh_token=session['refresh_token'])
    else:
        return flask.render_template('index.html', client_id=client_id, oauth2_url=oauth2_url)

@app.route('/<path:text>', methods=['GET'])
def all_routes(text):
    log.info("Path '{}'".format(text))
    if text in ['style.css']:
        return flask.Response(flask.render_template(text), mimetype='text/css')

@app.route('/login', methods=['POST'])
def login():
    req = flask.request
    scope = req.form.get('scope')
    response_type = 'code'
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    redir_url = build_url(oauth2_url, response_type=response_type, client_id=client_id, scope=scope, redirect_uri=redirect_uri, state=state, nonce=nonce)
    session_id = str(uuid.uuid4())
    session = {'scope': scope}
    sessions[session_id] = session
    log.info('Created session {}'.format(session_id))
    outstanding_requests[state] = {'session_id': session_id, 'nonce': nonce}
    log.info("Redirecting LOGIN to '{}'".format(redir_url))
    return flask.redirect(redir_url, code=303)

@app.route('/callback', methods=['GET'])
def callback():
    req = flask.request

    code = req.args.get('code')
    state = req.args.get('state')

    # Check state is valid for an outstanding request
    if state not in outstanding_requests:
        log.error('State not valid: {}'.format(state))
    req_out = outstanding_requests[state]
    session_id = req_out['session_id']
    nonce = req_out['nonce']
    del outstanding_requests[state]
    log.info('Found outstanding request: {} for state {}'.format(req_out, state))

    # TODO: Check callback against outstanding requests (e.g. against Cross-Site Request Forgery)

    log.info("Got callback with code {}, state {}".format(code, state))
    if not code:
        log.error('Received no code, deleting session: {}'.format(session_id))
        resp = flask.make_response(flask.redirect(own_url, code=303))
        resp.set_cookie(SESSION_COOKIE_NAME, '', samesite='Lax', httponly=True, expires=0)
        del sessions[session_id]
        return resp

    data = {'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri}
    headers = {'Authorization': 'Basic '+encode_client_creds(client_id, client_secret),
               'Content-type': 'application/x-www-form-urlencoded'}

    log.info("Getting token from url: '{}'".format(oauth2_token_url))
    response = requests.post(oauth2_token_url, data=data, headers=headers)
    log_response('CALLBACK', response)

    if response.status_code != 200:
        return 'Failed with status {}: {}'.format(response.status_code, response.text)

    response_json = response.json()
    for token_type in ['id_token', 'access_token', 'refresh_token']:
        if token_type in response_json:
            log.info("Got {} token '{}'".format(token_type, response_json[token_type]))

    id_token = response_json['id_token']
    access_token=response_json['access_token']
    refresh_token=response_json['refresh_token']

    token_pub_jwk_json = token_get_jwk(id_token)
    token_pub_jwk = JsonWebKey.import_key(token_pub_jwk_json)

    claims = jwt.decode(id_token, token_pub_jwk)

    if nonce and ('nonce' not in claims or claims['nonce'] != nonce):
        log.error('Nonce mismatch, expected {}, got claims {}'.format(nonce), claims)

    session_id = req_out['session_id']
    session = sessions[session_id]
    scope = session['scope']
    session = {'id_token': id_token,
               'id_token_claims': claims,
               'access_token': access_token,
               'refresh_token' : refresh_token,
               'scope': scope}
    sessions[session_id] = session

    resp = flask.make_response(flask.redirect(own_url, code=303))
    resp.set_cookie(SESSION_COOKIE_NAME, session_id, samesite='Lax', httponly=True)
    return resp

@app.route('/getuserinfo', methods=['POST'])
def get_userinfo():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    session_id = session_cookie
    if session_id in sessions:
        session = sessions[session_id]
    else:
        return flask.make_response(flask.redirect(own_url, code=303))

    log.info('Get UserInfo, access-token: {}'.format(session['access_token']))

    # FIXME bearer, type
    headers = {'Authorization': 'Bearer ' + session['access_token']}

    log.info("Getting userinfo from url: '{}'".format(oauth2_userinfo_url))
    response = requests.get(oauth2_userinfo_url, headers=headers)
    log_response('GET-USERINFO', response)

    if response.status_code != 200:
        return 'Failed with status {}'.format(response.status_code)

    response_json = response.json()
    return flask.render_template('userinfo.html', access_token=session['access_token'],
                                 userinfo=json_pretty_print(response_json))

@app.route('/read-api', methods=['POST'])
def read_api():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    session_id = session_cookie
    if session_id in sessions:
        session = sessions[session_id]
    else:
        return flask.make_response(flask.redirect(own_url, code=303))

    log.info('Read API, session: {}'.format(session_id))

    # FIXME bearer, type
    auth_token_usage = req.form.get('auth-token-usage')
    log.info('Read API, token usage: {}'.format(auth_token_usage))
    if auth_token_usage == 'authentication-header':
        headers = {'Authorization': 'Bearer ' + session['access_token']}
    else:
        headers = {}

    log.info("Reading from API url: '{}'".format(api_base_url))
    response = requests.get(api_base_url+'/api', headers=headers)
    log_response('READ-API', response)

    if response.status_code != 200:
        return 'Failed with code {}, headers: {}'.format(response.status_code, response.headers)

    response_json = response.json()
    return flask.render_template('read-api.html', access_token=session['access_token'],
                                 api_data=json_pretty_print(response_json))

@app.route('/refresh-token', methods=['POST'])
def refresh_token():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    session_id = session_cookie
    if session_id in sessions:
        session = sessions[session_id]
    else:
        return flask.make_response(flask.redirect(own_url, code=303))

    log.info('Refresh token, session {}'.format(session_id))

    data = {'refresh_token': session['refresh_token'],
            'grant_type': 'refresh_token'}
    headers = {'Authorization': 'Basic '+encode_client_creds(client_id, client_secret),
               'Content-type': 'application/x-www-form-urlencoded'}

    log.info("Refresh token from url: '{}'".format(oauth2_token_url))
    response = requests.post(oauth2_token_url, data=data, headers=headers)
    log_response('REFRESH-TOKEN', response)

    if response.status_code != 200:
        return 'Failed with status {}: {}'.format(response.status_code, response.text)

    response_json = response.json()
    for token_type in ['id_token', 'access_token', 'refresh_token']:
        if token_type in response_json:
            log.info("Got {} token '{}'".format(token_type, response_json[token_type]))

    if 'id_token' in response_json:
        id_token = response_json['id_token']

        token_pub_jwk_json = token_get_jwk(id_token)
        token_pub_jwk = JsonWebKey.import_key(token_pub_jwk_json)

        claims = jwt.decode(id_token, token_pub_jwk)

        session['id_token'] = id_token,
        session['id_token_claims'] = claims

    if 'access_token' in response_json:
        session['access_token'] = response_json['access_token']

    if 'refresh_token' in response_json:
        session['refresh_token'] = response_json['refresh_token']
    sessions[session_cookie] = session

    resp = flask.make_response(flask.redirect(own_url, code=303))
    return resp

@app.route('/logout', methods=['POST'])
def logout():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    if session_cookie not in sessions:
        return flask.make_response(flask.redirect(own_url, code=303))

    session_id = session_cookie
    session = sessions[session_id]

    log.info('Logout, session {}'.format(session_id))

    del sessions[session_id]
    redir_url = build_url(oidc_end_session_url, id_token_hint=session['id_token'], post_logout_redirect_uri=own_url)
    log.info('Logout, using redir url {}'.format(redir_url))
    resp = flask.make_response(flask.redirect(redir_url, code=303))
    resp.set_cookie(SESSION_COOKIE_NAME, '', samesite='Lax', httponly=True, expires=0)
    return resp

@app.route('/checklogin', methods=['POST'])
def check_login():
    req = flask.request
    session_cookie = req.cookies.get(SESSION_COOKIE_NAME)
    session_id = session_cookie
    if session_id in sessions:
        session = sessions[session_id]
    else:
        return flask.make_response(flask.redirect(own_url, code=303))

    log.info('Check login, session id {}: {}'.format(session_id, session))

    state = str(uuid.uuid4())
    data = {'response_type': 'code',
            'scope': session['scope'],
            'redirect_uri': redirect_uri,
            'client_id': client_id,
            'state': state,
            'id_token_hint': session['id_token'],
            'prompt': 'none'}
    headers = {'Authorization': 'Basic '+encode_client_creds(client_id, client_secret),
               'Content-type': 'application/x-www-form-urlencoded'}

    outstanding_requests[state] = {'session_id': session_id}

    log.info("Check login using url: '{}', state {}".format(oauth2_url, state))
    response = requests.post(oauth2_url, data=data, headers=headers)
    log.info('Got status code: {}'.format(response.status_code))

    resp = flask.make_response(flask.redirect(own_url, code=303))
    if response.status_code != 200:
        log.info('Clear session and cookie')
        resp.set_cookie(SESSION_COOKIE_NAME, '', samesite='Lax', httponly=True, expires=0)
        del sessions[session_id]

    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=app_port)
