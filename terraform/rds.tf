locals {
  db_username = "phishingchecker_admin"
}

resource "random_password" "db" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_db_subnet_group" "main" {
  name        = "${var.project_name}-db-subnet-group"
  description = "Private subnet group for RDS"
  subnet_ids  = aws_subnet.private[*].id

  tags = {
    Name = "${var.project_name}-db-subnet-group"
  }
}

resource "aws_db_parameter_group" "postgres16" {
  name   = "${var.project_name}-postgres16"
  family = "postgres16"

  tags = {
    Name = "${var.project_name}-postgres16"
  }
}

resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-postgres"
  db_name    = "phishingchecker"

  engine               = "postgres"
  engine_version       = "16"
  parameter_group_name = aws_db_parameter_group.postgres16.name

  instance_class        = "db.t3.micro"
  allocated_storage     = 20
  storage_type          = "gp3"
  storage_encrypted     = true

  username = local.db_username
  password = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  multi_az               = false # Single-AZ to stay on free tier, minimize cost

  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"
  copy_tags_to_snapshot   = true

  skip_final_snapshot = true
  deletion_protection = false # Since this is a learning project, I will have a lot of terraform destroy

  performance_insights_enabled = false
  monitoring_interval          = 0

  tags = {
    Name = "${var.project_name}-postgres"
  }
}
