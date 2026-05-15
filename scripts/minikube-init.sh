#!/bin/bash

set -e

cd "$(dirname "$0")/.."

IMAGE_TAG=${1?Usage: minikube-init.sh <image-tag>}

echo "Starting Minikube..."
minikube start
kubectl config use-context minikube
minikube addons enable ingress

echo "Waiting for ingress controller to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s

echo "Removing stale admission webhook..."
kubectl delete validatingwebhookconfigurations ingress-nginx-admission --ignore-not-found

echo "Applying Kubernetes manifests..."
(cd k8s/overlays/minikube && kustomize edit set image wongyx/phishing-url-scanner:"$IMAGE_TAG")
kubectl apply -k k8s/overlays/minikube/

echo "Updating /etc/hosts..."
sudo sed -i '/myapp.local/d' /etc/hosts
echo "$(minikube ip) myapp.local" | sudo tee -a /etc/hosts