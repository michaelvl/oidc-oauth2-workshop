#!/usr/bin/env python

import os
import flask
import requests
import urllib
import uuid
import json
import logging

from authlib.jose import jwt, jwk, JsonWebKey

app = flask.Flask('oauth2-client')

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('oauth2-client')

oauth2_url = os.getenv('OAUTH2_URL', 'http://127.0.0.1:5000/authorize')
oauth2_token_url = os.getenv('OAUTH2_TOKEN_URL', 'http://127.0.0.1:5000/token')
oauth2_userinfo_url = os.getenv('OAUTH2_USERINFO_URL', 'http://127.0.0.1:5000/userinfo')
client_id = os.getenv('CLIENT_ID', 'client-123-id')
client_password = os.getenv('CLIENT_PASSWORD', 'client-123-password')
redirect_uri = 'http://127.0.0.1:5001/callback'

def build_url(url, **kwargs):
    return '{}?{}'.format(url, urllib.parse.urlencode(kwargs))

def encode_client_creds(client_id, client_password):
    return '{}:{}'.format(urllib.parse.quote_plus(client_id), urllib.parse.quote_plus(client_password))

def json_pretty_print(json_data):
    return json.dumps(json_data, indent=4, sort_keys=True)

@app.route('/', methods=['GET'])
def index():
    return flask.render_template('index.html')

@app.route('/gettoken', methods=['POST'])
def gettoken():
    req = flask.request
    scope = req.form.get('scope')
    response_type = 'code'
    state = str(uuid.uuid4())
    redir_url = build_url(oauth2_url, response_type=response_type, client_id=client_id, scope=scope, redirect_uri=redirect_uri, state=state)
    log.info("Redirecting get-token to '{}'".format(redir_url))
    return flask.redirect(redir_url, code=303)

@app.route('/callback', methods=['GET'])
def callback():
    req = flask.request

    code = req.args.get('code')
    state = req.args.get('state')

    # TODO: Check state is valid for an outstanding request

    log.info("Got callback with code '{}'".format(code))

    data = {'code': code,
            'grant_type': 'authorization_code',
            'redirection_uri': redirect_uri}
    headers = {'Authorization': 'Basic '+encode_client_creds(client_id, client_password)}

    log.info("Getting token from url: '{}'".format(oauth2_token_url))
    response = requests.post(oauth2_token_url, data=data, headers=headers)

    if response.status_code != 200:
        return 'Failed with status {}'.format(response.status_code)

    response_json = response.json()
    for token_type in ['id_token', 'access_token', 'refresh_token']:
        if token_type in response_json:
            log.info("Got {} token '{}'".format(token_type, response_json[token_type]))

    # FIXME
    with open('jwt-key.pub', 'rb') as f:
        key_data = f.read()
    pub_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

    claims = jwt.decode(response_json['id_token'], pub_key)

    return flask.render_template('token.html',
                                 id_token=response_json['id_token'],
                                 id_token_parsed=json_pretty_print(claims),
                                 access_token=response_json['access_token'])

@app.route('/getuserinfo', methods=['POST'])
def get_userinfo():
    req = flask.request
    access_token = req.form.get('accesstoken')
    log.info('Get UserInfo, access-token: {}'.format(access_token))

    # FIXME bearer, type
    headers = {'Authorization': 'Bearer '+access_token}

    log.info("Getting userinfo from url: '{}'".format(oauth2_userinfo_url))
    response = requests.get(oauth2_userinfo_url, headers=headers)

    if response.status_code != 200:
        return 'Failed with status {}'.format(response.status_code)

    response_json = response.json()
    return flask.render_template('userinfo.html', access_token=access_token,
                                 userinfo=json_pretty_print(response_json))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
