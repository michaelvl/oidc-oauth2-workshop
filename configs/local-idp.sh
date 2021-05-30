#! /bin/bash

source configs/oidc-autoconfig.sh localhost:5001
export CLIENT_ID=client-123-id
export CLIENT_SECRET=client-123-password

export API_BASE_URL=http://localhost:5002
