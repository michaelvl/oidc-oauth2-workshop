-include Makefile.local

IMAGE ?= michaelvl/oauth2-server
VERSION ?= v1

.PHONY: build
build:
	docker build -t $(IMAGE):$(VERSION) .

#.PHONY: push
#push:
#	docker push $(IMAGE):$(VERSION)

.PHONY: run
run:
	docker run --rm -p5001:5001 $(IMAGE):$(VERSION)

.PHONY: dev
dev:
	docker run --rm -v $(shell pwd)/app:/usr/src/app:ro -e ACCESS_TOKEN_LIFETIME -e REFRESH_TOKEN_LIFETIME -e FLASK_APP=app.py -e FLASK_ENV=development -p5001:5001 $(IMAGE):$(VERSION)
