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