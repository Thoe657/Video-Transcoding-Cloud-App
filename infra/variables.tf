variable "aws_region" {
  type    = string
  default = "ap-southeast-2"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "unique_suffix" {
  type        = string
  description = "Unique suffix for bucket naming (e.g. student number)"
}

variable "vpc_id" {
  type = string
}

variable "db_subnet_ids" {
  type = list(string)
}

variable "cache_subnet_ids" {
  type = list(string)
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "db_username" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "db_name" {
  type    = string
  default = "cohort_2025"
}

variable "memcached_node_type" {
  type    = string
  default = "cache.t3.micro"
}

variable "cognito_client_secret" {
  type      = string
  sensitive = true
}

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "app_port" {
  type    = number
  default = 3000
}

variable "parameter_path_prefix" {
  type    = string
  default = "/n11977132/videoapp/param"
}

variable "secrets_name" {
  type    = string
  default = "n11977132-videoapp-secrets"
}

variable "tags" {
  type    = map(string)
  default = { Project = "video-app" }
}
