#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <image-tag>"
  exit 1
fi

export IMAGE_TAG=$1

echo "Starting Minikube..."
minikube start
minikube addons enable ingress

echo "Waiting for ingress controller to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s

echo "Removing stale admission webhook..."
kubectl delete validatingwebhookconfigurations ingress-nginx-admission --ignore-not-found

echo "Applying Kubernetes manifests..."
kubectl apply -f k8s/namespace.yml
kubectl apply -f k8s/configmap.yml
kubectl apply -f k8s/secret.yml
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/ingress.yml
envsubst < k8s/app/deployment.yml | kubectl apply -f -
kubectl apply -f k8s/app/hpa.yml
kubectl apply -f k8s/app/service.yml

echo "Updating /etc/hosts..."
sudo sed -i '/myapp.local/d' /etc/hosts
echo "$(minikube ip) myapp.local" | sudo tee -a /etc/hosts