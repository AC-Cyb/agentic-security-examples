# Deliberately insecure example for testing the policy agent.

resource "aws_s3_bucket" "logs" {
  bucket = "company-app-logs"
  acl    = "public-read"
}

resource "aws_security_group" "db" {
  name = "db-sg"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier        = "main-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
}

resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = "some-role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
