terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

###############################################################################
# Networking (replace subnet/security group IDs with ones from your VPC)
###############################################################################

resource "aws_db_subnet_group" "video_app" {
  name       = "${var.environment}-video-app-db-subnet-group"
  subnet_ids = var.db_subnet_ids
}

resource "aws_elasticache_subnet_group" "memcached" {
  name       = "${var.environment}-video-app-cache-subnet-group"
  subnet_ids = var.cache_subnet_ids
}

resource "aws_security_group" "app" {
  name        = "${var.environment}-video-app-app-sg"
  description = "App instance security group"
  vpc_id      = var.vpc_id

  # Allow outgoing traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "${var.environment}-video-app-db-sg"
  description = "Allow Postgres access from app SG"
  vpc_id      = var.vpc_id

  ingress {
    description      = "App nodes"
    from_port        = 5432
    to_port          = 5432
    protocol         = "tcp"
    security_groups  = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "memcached" {
  name        = "${var.environment}-video-app-memcached-sg"
  description = "Allow Memcached access from app SG"
  vpc_id      = var.vpc_id

  ingress {
    description      = "App nodes"
    from_port        = 11211
    to_port          = 11211
    protocol         = "tcp"
    security_groups  = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

###############################################################################
# S3 bucket for video objects
###############################################################################

resource "aws_s3_bucket" "videos" {
  bucket        = "${var.environment}-video-transcode-bucket-${var.unique_suffix}"
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "videos" {
  bucket = aws_s3_bucket.videos.id

  versioning_configuration {
    status = "Enabled"
  }
}

###############################################################################
# RDS (Postgres)
###############################################################################

resource "aws_db_instance" "postgres" {
  identifier              = "${var.environment}-video-app-db"
  engine                  = "postgres"
  engine_version          = "14.12"
  instance_class          = var.db_instance_class
  username                = var.db_username
  password                = var.db_password
  db_name                 = var.db_name
  allocated_storage       = 20
  db_subnet_group_name    = aws_db_subnet_group.video_app.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  skip_final_snapshot     = true
  apply_immediately       = true
  publicly_accessible     = false
  tags                    = var.tags
}

###############################################################################
# ElastiCache (Memcached)
###############################################################################

resource "aws_elasticache_cluster" "memcached" {
  cluster_id          = "${var.environment}-video-app-cache"
  engine              = "memcached"
  node_type           = var.memcached_node_type
  num_cache_nodes     = 1
  port                = 11211
  subnet_group_name   = aws_elasticache_subnet_group.memcached.name
  security_group_ids  = [aws_security_group.memcached.id]
  maintenance_window  = "sun:23:00-sun:23:30"
  tags                = var.tags
}

###############################################################################
# Parameter Store (non-secret config)
###############################################################################

resource "aws_ssm_parameter" "pg_host" {
  name  = "${var.parameter_path_prefix}/PGHOST"
  type  = "String"
  value = aws_db_instance.postgres.address
  tags  = var.tags
}

resource "aws_ssm_parameter" "pg_database" {
  name  = "${var.parameter_path_prefix}/PGDATABASE"
  type  = "String"
  value = var.db_name
  tags  = var.tags
}

resource "aws_ssm_parameter" "pg_port" {
  name  = "${var.parameter_path_prefix}/PGPORT"
  type  = "String"
  value = "5432"
  tags  = var.tags
}

resource "aws_ssm_parameter" "s3_bucket" {
  name  = "${var.parameter_path_prefix}/S3_BUCKET"
  type  = "String"
  value = aws_s3_bucket.videos.bucket
  tags  = var.tags
}

resource "aws_ssm_parameter" "memcached_address" {
  name  = "${var.parameter_path_prefix}/MEMCACHED_ADDRESS"
  type  = "String"
  value = aws_elasticache_cluster.memcached.configuration_endpoint_address
  tags  = var.tags
}

resource "aws_ssm_parameter" "app_port" {
  name  = "${var.parameter_path_prefix}/PORT"
  type  = "String"
  value = tostring(var.app_port)
  tags  = var.tags
}

resource "aws_ssm_parameter" "aws_region" {
  name  = "${var.parameter_path_prefix}/AWS_REGION"
  type  = "String"
  value = var.aws_region
  tags  = var.tags
}

###############################################################################
# Secrets Manager (sensitive values)
###############################################################################

resource "aws_secretsmanager_secret" "app" {
  name = var.secrets_name
  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id     = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    PGUSER                = var.db_username,
    PGPASSWORD            = var.db_password,
    COGNITO_CLIENT_SECRET = var.cognito_client_secret,
    JWT_SECRET            = var.jwt_secret
  })
}

###############################################################################
# IAM role for EC2/app instance
###############################################################################

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "app" {
  name = "${var.environment}-video-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "app" {
  name = "${var.environment}-video-app-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ssm:GetParameters",
          "ssm:DescribeParameters"
        ],
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter${var.parameter_path_prefix}/*"
      },
      {
        Effect   = "Allow",
        Action   = ["sqs:SendMessage"],
        Resource = aws_sqs_queue.transcode.arn
      },
      {
        Effect = "Allow",
        Action = [ "secretsmanager:GetSecretValue" ],
        Resource = aws_secretsmanager_secret.app.arn
      },
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.videos.arn,
          "${aws_s3_bucket.videos.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

###############################################################################
# SQS for transcode jobs + DLQ
###############################################################################

resource "aws_sqs_queue" "transcode_dlq" {
  name                      = "${var.environment}-video-app-transcode-dlq"
  message_retention_seconds = 1209600
  tags                      = var.tags
}

resource "aws_sqs_queue" "transcode" {
  name                              = "${var.environment}-video-app-transcode"
  visibility_timeout_seconds        = 300
  message_retention_seconds         = 345600
  receive_wait_time_seconds         = 20
  redrive_policy                    = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.transcode_dlq.arn,
    maxReceiveCount     = 5
  })
  tags = var.tags
}

resource "aws_ssm_parameter" "queue_url" {
  name  = "${var.parameter_path_prefix}/QUEUE_URL"
  type  = "String"
  value = aws_sqs_queue.transcode.id
  tags  = var.tags
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.environment}-video-app-instance-profile"
  role = aws_iam_role.app.name
}
