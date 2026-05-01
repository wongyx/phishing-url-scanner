variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "phishing-url-scanner"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "app_domain" {
  description = "Full domain name for the app (e.g. scanner.yourdomain.com)"
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for the domain"
  type        = string
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token with DNS edit permissions"
  type        = string
  sensitive   = true
}

variable "alb_dns_name" {
  description = "ALB DNS name, populated after first k8s deployment"
  type        = string
  default     = ""
}

variable "virustotal_api_key" {
  description = "API key to access VirusTotal"
  type        = string
  sensitive   = true
}

variable "safe_browsing_api_key" {
  description = "API key to access Google Safe Browsing"
  type        = string
  sensitive   = true
}