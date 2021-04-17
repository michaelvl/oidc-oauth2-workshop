-include Makefile.local

IMAGE ?= michaelvl/protected-api
VERSION ?= v1

.PHONY: build
build:
	docker build -t $(IMAGE):$(VERSION) .

#.PHONY: push
#push:
#	docker push $(IMAGE):$(VERSION)

.PHONY: run
run:
	docker run --rm -p5002:5002 $(IMAGE):$(VERSION)

.PHONY: dev
dev:
	docker run --net host --rm -v $(shell pwd)/app:/usr/src/app:ro -e FLASK_APP=app.py -e FLASK_ENV=development -e OIDC_JWKS_URL -p5002:5002 $(IMAGE):$(VERSION)
