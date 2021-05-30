#! /bin/bash

export OAUTH2_URL=http://localhost:5001/authorize
export OAUTH2_TOKEN_URL=http://localhost:5001/token
export OAUTH2_USERINFO_URL=http://localhost:5001/userinfo
export OIDC_JWKS_URL=http://localhost:5001/.well-known/jwks.json
export CLIENT_ID=client-123-id
export CLIENT_SECRET=client-123-password

export API_BASE_URL=http://localhost:5002
