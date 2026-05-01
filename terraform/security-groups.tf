# SG for RDS
resource "aws_security_group" "rds" {
  name   = "${var.project_name}-rds-sg"
  vpc_id = aws_vpc.main.id

  # Only need inbound traffic, db should not initiate outbound traffic
  ingress {
    description     = "PostgreSQL from app layer"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_eks_cluster.main.vpc_config[0].cluster_security_group_id]
  }

  tags = {
    Name = "${var.project_name}-rds-sg"
  }
}
