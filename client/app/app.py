#!/usr/bin/env python

import os
import flask
import requests
import urllib
import uuid
import logging

from authlib.jose import jwt, jwk, JsonWebKey

app = flask.Flask('oauth2-client')

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('oauth2-client')

oauth2_url = os.getenv('OAUTH2_URL', 'http://127.0.0.1:5000/authorize')
oauth2_token_url = os.getenv('OAUTH2_TOKEN_URL', 'http://127.0.0.1:5000/token')
redirect_uri = 'http://127.0.0.1:5001/callback'

def build_url(url, **kwargs):
    return '{}?{}'.format(url, urllib.parse.urlencode(kwargs))

@app.route('/', methods=['GET'])
def index():
    return flask.render_template('index.html')

@app.route('/gettoken', methods=['POST'])
def gettoken():
    req = flask.request
    scope = req.form.get('scope')
    client_id = 'client-id-123'
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
    headers = {'Authorization': 'Basic xxx:yyy'}

    log.info("Getting token from url: '{}'".format(oauth2_token_url))
    response = requests.post(oauth2_token_url, data=data, headers=headers)

    if response.status_code != 200:
        return 'Failed with status {}'.format(response.status_code)

    response_json = response.json()
    log.info("Got id token '{}'".format(response_json['id_token']))
    log.info("Got access token '{}'".format(response_json['access_token']))

    # FIXME
    with open('jwt-key.pub', 'rb') as f:
        key_data = f.read()
    pub_key = JsonWebKey.import_key(key_data, {'kty': 'RSA'})

    claims = jwt.decode(response_json['id_token'], pub_key)
    return flask.render_template('token.html', token=response_json['id_token'], token_parsed=claims)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
