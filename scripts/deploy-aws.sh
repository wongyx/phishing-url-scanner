#!/usr/bin/env bash
set -euo pipefail

IMAGE_TAG=${1?Usage: deploy-aws.sh <image-tag>}

cd "$(dirname "$0")/.."

# 1. Provision infrastructure (first terraform apply -- creates everything except Cloudflare CNAME)
echo "==> Applying Terraform..."
AWS_PROFILE="scanner"
terraform -chdir=terraform apply -auto-approve

# 2. Read Terraform outputs needed for Helm and kubectl
EKS_CLUSTER_NAME=$(terraform -chdir=terraform output -raw eks_cluster_name)
VPC_ID=$(terraform -chdir=terraform output -raw vpc_id)
ALB_ROLE_ARN=$(terraform -chdir=terraform output -raw alb_controller_role_arn)
ESO_ROLE_ARN=$(terraform -chdir=terraform output -raw eso_role_arn)
RDS_ENDPOINT=$(terraform -chdir=terraform output -raw rds_endpoint)

# 3. Configure kubectl
echo "==> Configuring kubectl..."
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME"

# 4. Install ALB controller (idempotent -- helm upgrade --install)
echo "==> Installing ALB controller..."
helm repo add eks https://aws.github.io/eks-charts --force-update
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName="$EKS_CLUSTER_NAME" \
  --set vpcId="$VPC_ID" \
  --set serviceAccount.create=true \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="$ALB_ROLE_ARN"

# Wait for ALB controller webhook to be ready (its webhook intercepts Service creates during ESO install)
kubectl wait --for=condition=Available deployment/aws-load-balancer-controller \
  -n kube-system --timeout=120s

# 5. Install External Secrets Operator (idempotent -- helm upgrade --install)
echo "==> Installing External Secrets Operator..."
helm repo add external-secrets https://charts.external-secrets.io --force-update
helm upgrade --install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="$ESO_ROLE_ARN"

# Wait for ESO CRDs and controller to be ready before applying ExternalSecret resources.
# The validating webhook lives in a separate deployment; its endpoints must be registered
# before any ExternalSecret can be created, otherwise the admission webhook call fails.
kubectl wait --for=condition=Available deployment/external-secrets \
  deployment/external-secrets-webhook deployment/external-secrets-cert-controller \
  -n external-secrets --timeout=180s
kubectl wait --for=jsonpath='{.subsets[0].addresses[0].ip}' \
  endpoints/external-secrets-webhook -n external-secrets --timeout=120s

# 6. Deploy application
echo "==> Deploying to EKS with image tag: $IMAGE_TAG..."
(cd k8s/overlays/aws && kustomize edit set image wongyx/phishing-url-scanner:"$IMAGE_TAG")
# Stamp the RDS endpoint into the configmap patch so DB_HOST resolves correctly in AWS
sed -i "s|DB_HOST:.*|DB_HOST: ${RDS_ENDPOINT}|" k8s/overlays/aws/patches/configmap.yml
kubectl apply -k k8s/overlays/aws/

# 7. Wait for ALB to be provisioned, then update Cloudflare CNAME (second terraform apply)
echo "==> Waiting for ALB to be provisioned..."
kubectl wait --for=jsonpath='{.status.loadBalancer.ingress[0].hostname}' \
  ingress/ingress-nginx -n phishing-url-scanner --timeout=120s

ALB_DNS_NAME=$(kubectl get ingress ingress-nginx -n phishing-url-scanner \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

echo "==> Updating Cloudflare DNS to point to $ALB_DNS_NAME..."
terraform -chdir=terraform apply -auto-approve -var="alb_dns_name=$ALB_DNS_NAME"

echo "==> Done!"