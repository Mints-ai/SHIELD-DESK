terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "ShieldDesk"
      ManagedBy   = "Terraform"
    }
  }
}

# 1. VPC & Networking Module (2 AZs, public + private subnets, NAT gateway)
module "vpc" {
  source = "./modules/vpc"

  vpc_cidr = var.vpc_cidr
  azs      = var.availability_zones
}

# 2. Amazon EKS Cluster Module (v1.29, auto-scaling worker nodes)
module "eks" {
  source = "./modules/eks"

  cluster_name    = "shielddesk-${var.environment}-eks"
  cluster_version = "1.29"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnet_ids

  min_size     = 3
  max_size     = 20
  desired_size = 3
  instance_type = "t3.medium"
}

# 3. PostgreSQL 16 RDS Multi-AZ Instance
module "rds" {
  source = "./modules/rds"

  identifier         = "shielddesk-${var.environment}-db"
  allocated_storage  = 50
  engine_version     = "16.2"
  instance_class     = "db.t3.medium"
  multi_az           = true
  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.database_subnet_ids
  database_name      = "shielddesk"
}

# 4. ElastiCache Redis 7 Cluster
module "redis" {
  source = "./modules/elasticache"

  cluster_id      = "shielddesk-${var.environment}-cache"
  node_type       = "cache.t3.medium"
  num_cache_nodes = 2
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.database_subnet_ids
}

# 5. S3 Storage Buckets (SSE-S3 encrypted, non-public)
module "s3" {
  source = "./modules/s3"

  environment = var.environment
  bucket_prefixes = [
    "scan-reports",
    "audit-logs",
    "compliance-evidence",
    "backups"
  ]
}
