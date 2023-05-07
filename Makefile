#################
.PHONY: setup-cluster
setup-cluster: create-cluster deploy-metallb deploy-gateway-api deploy-contour deploy-contour-gateway-api

#################
KUBERNETES_VERSION ?= 1.25.3

.PHONY: create-cluster
create-cluster:
	cat kubernetes/kind-config.yaml_tpl | k8s_ver=${KUBERNETES_VERSION} envsubst > kubernetes/kind-config.yaml
	kind create cluster --name kind --config kubernetes/kind-config.yaml
	rm kubernetes/kind-config.yaml

.PHONY: delete-cluster
delete-cluster:
	kind delete cluster --name kind

#################
.PHONY: container
container:
	docker build -t oidc-oauth2-workshop:latest .

#################
.PHONY: cluster-load-image
cluster-load-image:
	kind load docker-image oidc-oauth2-workshop:latest --name kind

#################
GATEWAY_API_VERSION ?= v0.6.2

.PHONY: deploy-gateway-api
deploy-gateway-api:
	#kubectl apply -k github.com/kubernetes-sigs/gateway-api/config/crd?ref=$(GATEWAY_API_VERSION)
	kubectl apply -k github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=$(GATEWAY_API_VERSION)

#################
# https://github.com/bitnami/charts/tree/main/bitnami/contour
.PHONY: deploy-contour
deploy-contour:
	helm upgrade -i --repo https://charts.bitnami.com/bitnami contour contour -n projectcontour --version 11.3.1 --create-namespace

CONTOUR_GATEWAY_API_VERSION ?= v1.24.4
.PHONY: deploy-contour-gateway-api
deploy-contour-gateway-api:
	kubectl apply -f https://raw.githubusercontent.com/projectcontour/contour/$(CONTOUR_GATEWAY_API_VERSION)/examples/gateway-provisioner/00-common.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcontour/contour/$(CONTOUR_GATEWAY_API_VERSION)/examples/gateway-provisioner/01-roles.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcontour/contour/$(CONTOUR_GATEWAY_API_VERSION)/examples/gateway-provisioner/02-rolebindings.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcontour/contour/$(CONTOUR_GATEWAY_API_VERSION)/examples/gateway-provisioner/03-gateway-provisioner.yaml
	kubectl apply -f https://raw.githubusercontent.com/projectcontour/contour/$(CONTOUR_GATEWAY_API_VERSION)/examples/gateway/03-gatewayclass.yaml

#################
# https://kind.sigs.k8s.io/docs/user/loadbalancer/
.PHONY: deploy-metallb
deploy-metallb:
	kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml
	kubectl -n metallb-system rollout status deployment controller --timeout=90s
	scripts/kind-metallb-configure.sh
