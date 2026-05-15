#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Only touch the cluster if minikube has a profile and it's reachable.
if minikube status >/dev/null 2>&1; then
  echo "==> Switching kubectl context to minikube..."
  kubectl config use-context minikube

  echo "==> Deleting k8s resources..."
  kubectl delete -k k8s/overlays/minikube/ --ignore-not-found
fi

echo "==> Removing myapp.local from /etc/hosts..."
sudo sed -i '/myapp.local/d' /etc/hosts

echo "==> Deleting minikube cluster..."
minikube delete

echo "==> Teardown complete."
