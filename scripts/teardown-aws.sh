#!/usr/bin/env bash
set -euo pipefail

EKS_CLUSTER_NAME=$(terraform -chdir=terraform output -raw eks_cluster_name 2>/dev/null || true)

if [ -n "$EKS_CLUSTER_NAME" ]; then
  # 1. Delete k8s resources (removes the Ingress, triggering ALB deletion by the controller)
  echo "==> Deleting k8s resources..."
  kubectl delete -k k8s/overlays/aws/ --ignore-not-found

  # 2. Wait for ALB to be fully deleted BEFORE uninstalling the controller
  echo "==> Waiting for ALB to be deleted (this may take 1-3 minutes)..."
  until [ -z "$(aws elbv2 describe-load-balancers \
      --query "LoadBalancers[?contains(LoadBalancerName, 'k8s-phishing')].LoadBalancerArn" \
      --output text 2>/dev/null)" ]; do
    echo "    ALB still exists, waiting..."
    sleep 15
  done
  echo "    ALB deleted."

  # 3. Uninstall Helm releases
  echo "==> Uninstalling ALB controller..."
  helm uninstall aws-load-balancer-controller -n kube-system 2>/dev/null || true
  echo "==> Uninstalling External Secrets Operator..."
  helm uninstall external-secrets -n external-secrets 2>/dev/null || true
fi

# 4. Destroy all infrastructure
echo "==> Running terraform destroy..."
terraform -chdir=terraform destroy -auto-approve

echo "==> Teardown complete."