resource "aws_secretsmanager_secret" "app" {
  name                    = "phishing-url-scanner/app"
  recovery_window_in_days = 0

  tags = {
    Name = "${var.cluster_name}-secrets"
  }
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    DB_HOST               = aws_db_instance.main.address
    DB_USER               = local.db_username
    DB_PASSWORD           = random_password.db.result
    DB_NAME               = aws_db_instance.main.db_name
    VIRUSTOTAL_API_KEY    = var.virustotal_api_key
    SAFE_BROWSING_API_KEY = var.safe_browsing_api_key
  })
}
