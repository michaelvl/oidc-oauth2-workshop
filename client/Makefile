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
	docker run --rm -p5001:5001 $(IMAGE):$(VERSION)

.PHONY: dev
dev:
	docker run --net host --rm -v $(shell pwd)/app:/usr/src/app:ro -e FLASK_APP=app.py -e FLASK_ENV=development -p5001:5001 $(IMAGE):$(VERSION)
