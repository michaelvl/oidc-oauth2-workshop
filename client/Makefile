-include Makefile.local

IMAGE ?= michaelvl/oauth2-client
VERSION ?= v1

.PHONY: build
build:
	docker build -t $(IMAGE):$(VERSION) .

#.PHONY: push
#push:
#	docker push $(IMAGE):$(VERSION)

.PHONY: run
run:
	docker run --rm -p5000:5000 $(IMAGE):$(VERSION)

.PHONY: dev
dev:
	docker run --net host --rm -v $(shell pwd)/app:/usr/src/app:ro -e FLASK_APP=app.py -e FLASK_ENV=development -e OAUTH2_URL -e OAUTH2_TOKEN_URL -e OAUTH2_USERINFO_URL -eOIDC_END_SESSION_URL -e OIDC_JWKS_URL -e CLIENT_ID -e CLIENT_SECRET -e API_BASE_URL -p5000:5000 $(IMAGE):$(VERSION)
