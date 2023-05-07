# Deploying on a Kubernetes KIND Cluster

This instruction describes ho to deploy the three components using a KIND cluste.

```
make setup-cluster container cluster-load-image
```

```
kubectl apply -f kubernetes/identity-provider.yaml -f kubernetes/identity-provider-gateway.yaml
kubectl apply -f kubernetes/client-gateway.yaml
```

```
export CLIENT_HOSTNAME=`kubectl get gateway client -o jsonpath='{.status.addresses[0].value}'`
export IDP_HOSTNAME=`kubectl get gateway idp -o jsonpath='{.status.addresses[0].value}'`
```

```
cat kubernetes/client.yaml | envsubst | kubectl apply -f -
cat kubernetes/protected-api.yaml | envsubst | kubectl apply -f -
```
