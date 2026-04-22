# Zero-Trust Network Segmentation Module
# Implements NIST 800-53 SC-7, AC-4 controls
# Ref: ADR-001 Network Segmentation Strategy

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# =============================================================================
# Variables
# =============================================================================

variable "environment" {
  description = "Deployment environment (dev, staging, production)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "vpc_cidr_blocks" {
  description = "CIDR blocks for each trust zone VPC"
  type = object({
    web_tier        = string
    app_tier        = string
    data_tier       = string
    management_tier = string
  })
  default = {
    web_tier        = "10.1.0.0/16"
    app_tier        = "10.2.0.0/16"
    data_tier       = "10.3.0.0/16"
    management_tier = "10.4.0.0/16"
  }
}

variable "availability_zones" {
  description = "Availability zones for high availability deployment"
  type        = list(string)
  default     = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs on all subnets (required for zero-trust visibility)"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "CloudWatch log retention for flow logs (NIST AU-9)"
  type        = number
  default     = 365
}

# =============================================================================
# Web Tier VPC (DMZ)
# Trust Level: Low — internet-facing workloads
# =============================================================================

resource "aws_vpc" "web_tier" {
  cidr_block           = var.vpc_cidr_blocks.web_tier
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name          = "zt-${var.environment}-web-tier"
    TrustZone     = "web-dmz"
    Classification = "public-facing"
    Compliance    = "NIST-SC-7"
  }
}

resource "aws_subnet" "web_public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.web_tier.id
  cidr_block              = cidrsubnet(var.vpc_cidr_blocks.web_tier, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false  # No auto-assign public IPs (security)

  tags = {
    Name      = "zt-${var.environment}-web-public-${var.availability_zones[count.index]}"
    TrustZone = "web-dmz"
    Tier      = "public"
  }
}

resource "aws_subnet" "web_private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.web_tier.id
  cidr_block        = cidrsubnet(var.vpc_cidr_blocks.web_tier, 8, count.index + 10)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name      = "zt-${var.environment}-web-private-${var.availability_zones[count.index]}"
    TrustZone = "web-dmz"
    Tier      = "private"
  }
}

# =============================================================================
# Application Tier VPC
# Trust Level: Medium — internal services, APIs, workers
# =============================================================================

resource "aws_vpc" "app_tier" {
  cidr_block           = var.vpc_cidr_blocks.app_tier
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name          = "zt-${var.environment}-app-tier"
    TrustZone     = "application"
    Classification = "internal"
    Compliance    = "NIST-SC-7"
  }
}

resource "aws_subnet" "app_private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.app_tier.id
  cidr_block        = cidrsubnet(var.vpc_cidr_blocks.app_tier, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name      = "zt-${var.environment}-app-private-${var.availability_zones[count.index]}"
    TrustZone = "application"
  }
}

# =============================================================================
# Data Tier VPC
# Trust Level: High — databases, object storage, encryption at rest
# =============================================================================

resource "aws_vpc" "data_tier" {
  cidr_block           = var.vpc_cidr_blocks.data_tier
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name          = "zt-${var.environment}-data-tier"
    TrustZone     = "data"
    Classification = "sensitive"
    Compliance    = "NIST-SC-7,SC-28"
  }
}

resource "aws_subnet" "data_private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.data_tier.id
  cidr_block        = cidrsubnet(var.vpc_cidr_blocks.data_tier, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name      = "zt-${var.environment}-data-private-${var.availability_zones[count.index]}"
    TrustZone = "data"
  }
}

# =============================================================================
# Management Plane VPC
# Trust Level: Critical — hypervisors, storage controllers, monitoring
# =============================================================================

resource "aws_vpc" "management_tier" {
  cidr_block           = var.vpc_cidr_blocks.management_tier
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name          = "zt-${var.environment}-management"
    TrustZone     = "management"
    Classification = "critical"
    Compliance    = "NIST-SC-7,AC-17"
  }
}

resource "aws_subnet" "mgmt_private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.management_tier.id
  cidr_block        = cidrsubnet(var.vpc_cidr_blocks.management_tier, 8, count.index)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name      = "zt-${var.environment}-mgmt-private-${var.availability_zones[count.index]}"
    TrustZone = "management"
  }
}

# =============================================================================
# Transit Gateway — Controlled Inter-VPC Communication
# Only explicitly defined routes are permitted (zero-trust principle)
# =============================================================================

resource "aws_ec2_transit_gateway" "zero_trust" {
  description                     = "Zero-trust transit gateway — explicit routes only"
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support               = "enable"

  tags = {
    Name       = "zt-${var.environment}-tgw"
    Compliance = "NIST-AC-4"
  }
}

# TGW attachments for each VPC
resource "aws_ec2_transit_gateway_vpc_attachment" "web" {
  subnet_ids         = aws_subnet.web_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  vpc_id             = aws_vpc.web_tier.id

  tags = { Name = "zt-${var.environment}-tgw-web" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "app" {
  subnet_ids         = aws_subnet.app_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  vpc_id             = aws_vpc.app_tier.id

  tags = { Name = "zt-${var.environment}-tgw-app" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "data" {
  subnet_ids         = aws_subnet.data_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  vpc_id             = aws_vpc.data_tier.id

  tags = { Name = "zt-${var.environment}-tgw-data" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "mgmt" {
  subnet_ids         = aws_subnet.mgmt_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  vpc_id             = aws_vpc.management_tier.id

  tags = { Name = "zt-${var.environment}-tgw-mgmt" }
}

# =============================================================================
# Transit Gateway Route Tables — Explicit Allow Only
# Each tier can only communicate with explicitly defined peers
# =============================================================================

resource "aws_ec2_transit_gateway_route_table" "web_routes" {
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  tags               = { Name = "zt-${var.environment}-web-routes" }
}

resource "aws_ec2_transit_gateway_route_table" "app_routes" {
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  tags               = { Name = "zt-${var.environment}-app-routes" }
}

resource "aws_ec2_transit_gateway_route_table" "data_routes" {
  transit_gateway_id = aws_ec2_transit_gateway.zero_trust.id
  tags               = { Name = "zt-${var.environment}-data-routes" }
}

# Web tier can only talk to App tier (not Data or Management)
resource "aws_ec2_transit_gateway_route" "web_to_app" {
  destination_cidr_block         = var.vpc_cidr_blocks.app_tier
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.web_routes.id
}

# App tier can talk to Web tier (responses) and Data tier
resource "aws_ec2_transit_gateway_route" "app_to_web" {
  destination_cidr_block         = var.vpc_cidr_blocks.web_tier
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.web.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.app_routes.id
}

resource "aws_ec2_transit_gateway_route" "app_to_data" {
  destination_cidr_block         = var.vpc_cidr_blocks.data_tier
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.data.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.app_routes.id
}

# Data tier can only respond to App tier — no direct web or management access
resource "aws_ec2_transit_gateway_route" "data_to_app" {
  destination_cidr_block         = var.vpc_cidr_blocks.app_tier
  transit_gateway_attachment_id  = aws_ec2_transit_gateway_vpc_attachment.app.id
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.data_routes.id
}

# NOTE: Web tier CANNOT reach Data tier directly — this is intentional.
# All data access must flow through the Application tier.

# =============================================================================
# Security Groups — Identity-Based, Not IP-Based
# Per ADR-001: Rules reference security group IDs, not CIDR blocks
# =============================================================================

# Web tier ALB security group
resource "aws_security_group" "web_alb" {
  name_prefix = "zt-${var.environment}-web-alb-"
  vpc_id      = aws_vpc.web_tier.id
  description = "ALB security group — accepts HTTPS from internet, forwards to web instances"

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # WAF/DDoS protection is upstream
  }

  egress {
    description     = "Forward to web instances only"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.web_instances.id]
  }

  tags = {
    Name       = "zt-${var.environment}-web-alb"
    TrustZone  = "web-dmz"
    Compliance = "NIST-SC-7"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Web tier instance security group
resource "aws_security_group" "web_instances" {
  name_prefix = "zt-${var.environment}-web-inst-"
  vpc_id      = aws_vpc.web_tier.id
  description = "Web instances — accepts from ALB only, connects to app tier"

  ingress {
    description     = "From ALB only (identity-based)"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.web_alb.id]
  }

  # No direct SSH — all management through SSM Session Manager
  # This eliminates the need for bastion hosts and SSH key management

  tags = {
    Name       = "zt-${var.environment}-web-instances"
    TrustZone  = "web-dmz"
    Compliance = "NIST-SC-7,AC-17"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# App tier security group
resource "aws_security_group" "app_services" {
  name_prefix = "zt-${var.environment}-app-svc-"
  vpc_id      = aws_vpc.app_tier.id
  description = "Application services — mTLS from web tier, connects to data tier"

  ingress {
    description = "mTLS from web tier via TGW"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_blocks.web_tier]  # Cross-VPC requires CIDR (TGW limitation)
  }

  ingress {
    description     = "Service mesh — east-west mTLS between app services"
    from_port       = 15443
    to_port         = 15443
    protocol        = "tcp"
    security_groups = []  # Self-referencing — added via separate rule
    self            = true
  }

  tags = {
    Name       = "zt-${var.environment}-app-services"
    TrustZone  = "application"
    Compliance = "NIST-SC-7,SC-8"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Data tier security group
resource "aws_security_group" "data_stores" {
  name_prefix = "zt-${var.environment}-data-"
  vpc_id      = aws_vpc.data_tier.id
  description = "Data stores — accepts from app tier ONLY, no direct web access"

  ingress {
    description = "PostgreSQL from app tier only"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_blocks.app_tier]
  }

  ingress {
    description = "Redis from app tier only"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr_blocks.app_tier]
  }

  # CRITICAL: No ingress from web tier — all data access flows through app tier
  # This is a core zero-trust principle: no direct path from low-trust to high-trust zones

  tags = {
    Name       = "zt-${var.environment}-data-stores"
    TrustZone  = "data"
    Compliance = "NIST-SC-7,SC-28"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# VPC Flow Logs — Comprehensive Visibility (NIST AU-2, SI-4)
# =============================================================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  for_each = {
    web  = aws_vpc.web_tier.id
    app  = aws_vpc.app_tier.id
    data = aws_vpc.data_tier.id
    mgmt = aws_vpc.management_tier.id
  }

  name              = "/zt/${var.environment}/flow-logs/${each.key}"
  retention_in_days = var.flow_log_retention_days

  tags = {
    Name       = "zt-${var.environment}-flow-logs-${each.key}"
    Compliance = "NIST-AU-9"
  }
}

resource "aws_flow_log" "all_vpcs" {
  for_each = {
    web  = aws_vpc.web_tier.id
    app  = aws_vpc.app_tier.id
    data = aws_vpc.data_tier.id
    mgmt = aws_vpc.management_tier.id
  }

  vpc_id                   = each.value
  traffic_type             = "ALL"  # Log accepts AND rejects (critical for threat detection)
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs[each.key].arn
  iam_role_arn             = aws_iam_role.flow_log_role.arn
  max_aggregation_interval = 60  # 1-minute granularity for near-real-time detection

  tags = {
    Name       = "zt-${var.environment}-flow-log-${each.key}"
    Compliance = "NIST-AU-2,SI-4"
  }
}

resource "aws_iam_role" "flow_log_role" {
  name = "zt-${var.environment}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "zt-${var.environment}-flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# =============================================================================
# Network ACLs — Coarse-Grained Backup to Security Groups
# Defense in depth: NACLs catch misconfigurations in security groups
# =============================================================================

resource "aws_network_acl" "data_tier" {
  vpc_id     = aws_vpc.data_tier.id
  subnet_ids = aws_subnet.data_private[*].id

  # Allow inbound from app tier only
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr_blocks.app_tier
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = var.vpc_cidr_blocks.app_tier
    from_port  = 6379
    to_port    = 6379
  }

  # Ephemeral ports for return traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = var.vpc_cidr_blocks.app_tier
    from_port  = 1024
    to_port    = 65535
  }

  # DENY ALL other inbound — defense in depth
  ingress {
    protocol   = "-1"
    rule_no    = 999
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow outbound to app tier only (responses)
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr_blocks.app_tier
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "-1"
    rule_no    = 999
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name       = "zt-${var.environment}-data-nacl"
    Compliance = "NIST-SC-7"
    Note       = "Defense-in-depth backup to security groups"
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "vpc_ids" {
  description = "VPC IDs for each trust zone"
  value = {
    web_tier  = aws_vpc.web_tier.id
    app_tier  = aws_vpc.app_tier.id
    data_tier = aws_vpc.data_tier.id
    mgmt_tier = aws_vpc.management_tier.id
  }
}

output "transit_gateway_id" {
  description = "Transit gateway ID for inter-VPC routing"
  value       = aws_ec2_transit_gateway.zero_trust.id
}

output "security_group_ids" {
  description = "Security group IDs for workload deployment"
  value = {
    web_alb       = aws_security_group.web_alb.id
    web_instances = aws_security_group.web_instances.id
    app_services  = aws_security_group.app_services.id
    data_stores   = aws_security_group.data_stores.id
  }
}
