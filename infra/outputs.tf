output "s3_bucket_name" {
  value = aws_s3_bucket.videos.bucket
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.address
}

output "memcached_endpoint" {
  value = aws_elasticache_cluster.memcached.configuration_endpoint_address
}

output "ssm_parameter_prefix" {
  value = var.parameter_path_prefix
}

output "secrets_manager_arn" {
  value = aws_secretsmanager_secret.app.arn
}

output "iam_instance_profile" {
  value = aws_iam_instance_profile.app.name
}
