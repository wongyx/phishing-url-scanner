# ACM DNS validation records — created on first apply so ACM can issue the cert
resource "cloudflare_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.app.domain_validation_options : dvo.domain_name => dvo
  }

  zone_id = var.cloudflare_zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  content = each.value.resource_record_value
  proxied = false # validation records must not be proxied
  ttl     = 60
}

# App CNAME — only created on second apply once the ALB hostname is known
resource "cloudflare_record" "app" {
  count = var.alb_dns_name != "" ? 1 : 0

  zone_id = var.cloudflare_zone_id
  name    = "scanner"
  type    = "CNAME"
  content = var.alb_dns_name
  proxied = true
  ttl     = 1 # auto TTL when proxied
}
