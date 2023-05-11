//Data Sources

data "aws_vpc" "primary_vpc" {
  filter {
    name   = "tag:Name"
    values = ["${terraform.workspace}-application-vpc"]
  }
}


data "aws_subnet_ids" "private" {
  vpc_id = data.aws_vpc.primary_vpc.id

  tags = {
    "SubnetType" = "Private"
  }
}

data "aws_ecs_cluster" "primary_ecs_cluster" {
  cluster_name = "${terraform.workspace}-container-cluster"
}

data "aws_service_discovery_dns_namespace" "primary_sd_service" {
  name = "${terraform.workspace}.ccm"
  type = "DNS_PRIVATE"
}

data "aws_lb" "primary_public" {
  name = "${terraform.workspace}-ccm-pub-alb-1"
}

data "aws_lb_listener" "primary_public_listener" {
  load_balancer_arn = data.aws_lb.primary_public.arn
  port              = 443
}

data "aws_route53_zone" "primary_dns" {
  count        = terraform.workspace == "dev" || terraform.workspace == "test" || terraform.workspace == "preprod" ? 1 : 0
  name         = "${terraform.workspace}.crosscountrymortgage.com."
  private_zone = false
}

data "aws_route53_zone" "primary_dns_prod" {
  count        = terraform.workspace == "prod" ? 1 : 0
  name         = "production.crosscountrymortgage.com."
  private_zone = false
}

//mysql rds resources for wordpress site
module "ccm-wordpress-rds-sg" {
  source      = "terraform-aws-modules/security-group/aws"
  name        = "${terraform.workspace}-ccm-wordpress-rds-sg"
  description = "Security Group for ${terraform.workspace} wordpress rds"
  vpc_id      = module.primary-vpc.vpc_id

  #ingress
  ingress_with_cidr_blocks = [
    {
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      description = "MySQL Access"
      cidr_blocks = "192.168.0.0/32" //sg-0794bd4a20ee144c0
    }
  ]
  #egress
  egress_with_cidr_blocks = [
    {
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      description = "egress outbound"
      cidr_blocks = "192.168.0.0/16"
    }
  ]
  tags = {
    Name        = "${terraform.workspace}-wordpress-provision-rds-sg"
    Environment = terraform.workspace
    Cost        = "ccm-engineering"
    Description = "Security group for wordpress provisioning RDS"
    Terraform   = true
  }
}

resource "aws_db_instance" "ccmwordpressdb" {
  identifier            = "ccmwordpressdb"
  db_name               = "ccmwordpressdb"
  allocated_storage     = 30
  max_allocated_storage = 100
  engine                = "mysql"
  engine_version        = "8.0.28"
  instance_class        = var.db_instance_class[terraform.workspace]
  #This password is only used for the initial deployment. Change this immediately in the console under "modify"!  
  username                   = "testdbuser"
  password                   = "test123"
  auto_minor_version_upgrade = true
  backup_retention_period    = 5
  backup_window              = "10:00-12:00"
  maintenance_window         = "Sun:00:00-Sun:04:00"
  multi_az                   = true
  publicly_accessible        = var.db_accessibility[terraform.workspace]
  db_subnet_group_name       = var.db_subnet_group[terraform.workspace]
  final_snapshot_identifier  = "ccmwordpressdb-final-snapshot"
  skip_final_snapshot        = true
  apply_immediately          = true
  vpc_security_group_ids     = [module.ccm-wordpress-rds-sg.security_group_id]
  tags = {
    name        = "ccmwordpressdb-${terraform.workspace}"
    environment = terraform.workspace
    cost        = "ccm-engineering"
    description = "mysql database for wordpress."
    terraform   = true
  }
}

//CloudFront only supports certificates in us-east-1 region!
data "aws_acm_certificate" "primary_ssl" {
  provider = aws.aws-us-east-1
  domain   = terraform.workspace == "dev" || terraform.workspace == "test" || terraform.workspace == "preprod" ? "*.${terraform.workspace}.crosscountrymortgage.com" : "*.crosscountrymortgage.com"
  statuses = ["ISSUED"]
}

module "application_cloudfront" {
  source              = "terraform-aws-modules/cloudfront/aws"
  version             = "2.7.0"
  tags                = var.tags
  comment             = "CloudFront Distribution for ${var.application_public_endpoint}"
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "/"
  aliases             = terraform.workspace == "dev" || terraform.workspace == "test" || terraform.workspace == "preprod" ? ["${var.application_public_endpoint}.${terraform.workspace}.crosscountrymortgage.com"] : ["${var.application_public_endpoint}.crosscountrymortgage.com"]
  price_class         = "PriceClass_All"
  retain_on_delete    = false
  wait_for_deployment = false

  origin = {
    alb = {
      domain_name = data.aws_lb.primary_public.dns_name
      custom_origin_config = {
        /* http_port              = 80 */
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1", "TLSv1.1", "TLSv1.2"]
      }
    }
  }

  default_cache_behavior = {
    target_origin_id       = "alb"
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods = [
      "DELETE",
      "GET",
      "HEAD",
      "OPTIONS",
      "PATCH",
      "POST",
      "PUT",
    ]

    cached_methods = [
      "GET",
      "HEAD",
      "OPTIONS"
    ]
    use_forwarded_values = true
    forwarded_values = {
      headers = {
        header_behavior = "whitelist"
        items           = ["Host", "Referer", "Origin", "CloudFront-Forwarded-Proto"]
      }
      query_string = {
        forward = "all"
      }
      cookies = {
        forward = "whitelist"
        items   = ["comment_author_*", "comment_author_email_*", "comment_author_url_*", "wordpress_*", "wordpress_logged_in_*", "wordpress_test_cookie", "wp-settings-*"]
      }
    }
    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 31536000
  }
  ordered_cache_behavior = [
    {
      path_pattern           = "/wp-includes/*"
      target_origin_id       = "alb"
      compress               = true
      viewer_protocol_policy = "http and https"
      allowed_methods = [
        "GET",
        "HEAD",
        "OPTIONS",
      ]

      cached_methods = [
        "GET",
        "HEAD",
        "OPTIONS"
      ]
      use_forwarded_values = true
      forwarded_values = {
        headers = {
          header_behavior = "whitelist"
          items           = ["Access-Control-Request-Headers", "Access-Control-Request-Method", "Origin", "CloudFront-Forwarded-Proto"]
        }
        query_string = {
          forward = "none"
        }
        cookies = {
          forward = "none"
        }
      }
    },
    {
      path_pattern           = "/wp-content/*"
      target_origin_id       = "alb"
      compress               = true
      viewer_protocol_policy = "http and https"
      allowed_methods = [
        "GET",
        "HEAD",
        "OPTIONS",
      ]

      cached_methods = [
        "GET",
        "HEAD",
        "OPTIONS"
      ]
      use_forwarded_values = true
      forwarded_values = {
        headers = {
          header_behavior = "whitelist"
          items           = ["Access-Control-Request-Headers", "Access-Control-Request-Method", "Origin", "CloudFront-Forwarded-Proto"]
        }
        query_string = {
          forward = "none"
        }
        cookies = {
          forward = "none"
        }
      }
    },
    {
      path_pattern           = "/wp-admin/*"
      target_origin_id       = "alb"
      compress               = true
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods = [
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
      ]

      cached_methods = [
        "GET",
        "HEAD",
        "OPTIONS"
      ]
      use_forwarded_values = true
      forwarded_values = {
        headers = {
          header_behavior = "whitelist"
          items           = ["Host", "Referer", "Origin", "CloudFront-Forwarded-Proto"]
        }
        query_string = {
          forward = "all"
        }
        cookies = {
          forward = "whitelist"
          items   = ["comment_author_*", "comment_author_email_*", "comment_author_url_*", "wordpress_*", "wordpress_logged_in_*", "wordpress_test_cookie", "wp-settings-*"]
        }
      }
    },
    {
      path_pattern           = "/wp-login.php"
      target_origin_id       = "alb"
      compress               = true
      viewer_protocol_policy = "redirect-to-https"
      allowed_methods = [
        "DELETE",
        "GET",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "POST",
        "PUT",
      ]

      cached_methods = [
        "GET",
        "HEAD",
        "OPTIONS"
      ]
      use_forwarded_values = true
      forwarded_values = {
        headers = {
          header_behavior = "whitelist"
          items           = ["Host", "Referer", "Origin", "CloudFront-Forwarded-Proto"]
        }
        query_string = {
          forward = "all"
        }
        cookies = {
          forward = "whitelist"
          items   = ["comment_author_*", "comment_author_email_*", "comment_author_url_*", "wordpress_*", "wordpress_logged_in_*", "wordpress_test_cookie", "wp-settings-*"]
        }
      }
    }
  ]

  viewer_certificate = {
    acm_certificate_arn = data.aws_acm_certificate.primary_ssl.arn
    ssl_support_method  = "sni-only"
  }

  restrictions = {
    geo_restriction = "none"
  }
}

//Route53 Endpoint
resource "aws_route53_record" "application_endpoint_nonprod" {
  count   = terraform.workspace == "dev" || terraform.workspace == "test" ? 1 : 0
  zone_id = data.aws_route53_zone.primary_dns[count.index].zone_id
  name    = "${var.application_public_endpoint}.${terraform.workspace}.crosscountrymortgage.com"
  type    = "CNAME"
  ttl     = "60"
  records = [module.application_cloudfront.cloudfront_distribution_domain_name]
}

resource "aws_route53_record" "application_endpoint_prod" {
  count   = terraform.workspace == "prod" ? 1 : 0
  zone_id = data.aws_route53_zone.primary_dns_prod[count.index].zone_id
  name    = "${var.application_public_endpoint}.production.crosscountrymortgage.com"
  type    = "CNAME"
  ttl     = "60"
  records = [module.application_cloudfront.cloudfront_distribution_domain_name]
}

resource "aws_efs_file_system" "wordpress_efs" {
  creation_token   = "${terraform.workspace}-${var.application_public_endpoint}-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  encrypted        = "true"
  lifecycle_policy {
    transition_to_ia = "AFTER_7_DAYS"
  }
  tags = {
    Name        = "${terraform.workspace}-${var.application_public_endpoint}-efs"
    Environment = terraform.workspace
    Terraform   = "True"
    Cost        = "ccm-engineering"
    Description = "EFS for Wordpress app"
  }
}

module "ccm-wordpress-efs-sg" {
  source      = "terraform-aws-modules/security-group/aws"
  name        = "${terraform.workspace}-${var.application_public_endpoint}-efs-sg"
  description = "Security Group for ${terraform.workspace} EFS"
  vpc_id      = module.primary-vpc.vpc_id

  # ingress
  ingress_with_cidr_blocks = [
    {
      from_port   = 2049
      to_port     = 2049
      protocol    = "tcp"
      description = "vpc cider to access EFS"
      cidr_blocks = "192.168.0.0/16"
    },
    {
      from_port   = 2049
      to_port     = 2049
      protocol    = "tcp"
      description = "ECS to access EFS"
      cidr_blocks = "192.168.0.0/16" #sg-0794bd4a20ee144c0
    }
  ]

  # egress
  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 65535
      protocol    = "All"
      description = "egress outbound"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  tags = {
    Name        = "${terraform.workspace}-efs-sg"
    Environment = terraform.workspace
    Cost        = "ccm-engineering"
    Description = "Security group for Wordpress EFS"
    Terraform   = true
  }

}
resource "aws_efs_mount_target" "efsA" {
  file_system_id  = aws_efs_file_system.wordpress_efs.id
  subnet_id       = data.aws_subnet_ids.private.ids
  security_groups = ["${aws_security_group.wordpress-efs-sg.id}"]
}
resource "aws_efs_mount_target" "efsB" {
  file_system_id  = aws_efs_file_system.wordpress_efs.id
  subnet_id       = data.aws_subnet_ids.private.ids
  security_groups = ["${aws_security_group.wordpress-efs-sg.id}"]
}
resource "aws_efs_mount_target" "efsC" {
  file_system_id  = aws_efs_file_system.wordpress_efs.id
  subnet_id       = data.aws_subnet_ids.private.ids
  security_groups = ["${aws_security_group.wordpress-efs-sg.id}"]
}

//ECS FarGate 
resource "aws_cloudwatch_log_group" "main" {
  name              = "${terraform.workspace}-${var.container_service_name}"
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}
locals {
  log_multiline_pattern        = var.log_multiline_pattern != "" ? { "awslogs-multiline-pattern" = var.log_multiline_pattern } : null
  task_container_secrets       = length(var.task_container_secrets) > 0 ? { "secrets" = var.task_container_secrets } : null
  log_container_secrets        = length(var.log_container_secrets) > 0 ? { "secrets" = var.log_container_secrets } : null
  repository_credentials       = length(var.repository_credentials) > 0 ? { "repositoryCredentials" = { "credentialsParameter" = var.repository_credentials } } : null
  task_container_port_mappings = concat(var.task_container_port_mappings, [{ containerPort = var.task_container_port, hostPort = var.task_container_port, protocol = "tcp" }])
  task_container_environment   = [for k, v in var.task_container_environment : { name = k, value = v }]
  log_container_environment    = [for k, v in var.log_container_environment : { name = k, value = v }]

  log_configuration_options = merge({
    "awslogs-group"         = aws_cloudwatch_log_group.main.name
    "awslogs-region"        = data.aws_region.current.name
    "awslogs-stream-prefix" = "container"
  }, local.log_multiline_pattern)

  //Define log configuration options for coralogix
  log_configuration_options_coralogix = merge({
    "privatekey"    = var.coralogix_private_key
    "appname"       = var.coralogix_app_name
    "is_json"       = var.coralogix_is_json
    "@type"         = "coralogix"
    "subsystemname" = var.coralogix_subsystem_name
  }, local.log_multiline_pattern)


  container_definition = merge({
    "name"         = var.container_name != "" ? var.container_name : var.name_prefix
    "image"        = var.task_container_image,
    "essential"    = true
    "portMappings" = local.task_container_port_mappings
    "stopTimeout"  = var.stop_timeout
    "command"      = var.task_container_command
    "environment"  = local.task_container_environment
    "logConfiguration" = {
      "logDriver" = var.task_container_logging_provider != "cloudwatch" ? "awsfirelens" : "awslogs"
      "options"   = var.task_container_logging_provider != "cloudwatch" ? local.log_configuration_options_coralogix : local.log_configuration_options
    }
  }, local.task_container_secrets, local.repository_credentials)

  log_container_side_car = merge({
    "name"        = "log_router"
    "image"       = var.log_container_image
    "essential"   = true
    "environment" = local.log_container_environment
    "logConfiguration" = {
      "logDriver" = "awslogs"
      "options"   = local.log_configuration_options
    }
    "firelensConfiguration" = {
      "type" = "fluentd"
    }
  }, local.log_container_secrets, local.repository_credentials)
}
resource "aws_security_group" "ccm_wordpress_ecs_sg" {
  vpc_id      = var.vpc_id
  name        = "${var.name_prefix}-ccm-wordpress-ecs-sg"
  description = "Fargate service security group"
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-sg"
    },
  )
}

resource "aws_security_group_rule" "egress_service" {
  security_group_id = aws_security_group.ecs_service.id
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

resource "aws_security_group_rule" "ingress_service" {
  security_group_id = aws_security_group.ecs_service.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = var.task_container_port
  to_port           = var.task_container_port
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

resource "aws_ecs_task_definition" "ccm-wordpress-task-defination" {
  family                   = "${terraform.workspace}-${var.container_service_name}"
  execution_role_arn       = aws_iam_role.execution.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.task_definition_cpu
  memory                   = var.task_definition_memory
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = var.task_container_logging_provider != "cloudwatch" ? jsonencode([local.container_definition, local.log_container_side_car]) : jsonencode([local.container_definition])
}
resource "aws_ecs_service" "service" {
  depends_on                         = [null_resource.lb_exists]
  name                               = var.name_prefix
  cluster                            = var.cluster_id
  task_definition                    = aws_ecs_task_definition.task.arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  deployment_minimum_healthy_percent = var.deployment_minimum_healthy_percent
  deployment_maximum_percent         = var.deployment_maximum_percent
  health_check_grace_period_seconds  = var.lb_arn == "" ? null : var.health_check_grace_period_seconds
  wait_for_steady_state              = var.wait_for_steady_state

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_service.id]
    assign_public_ip = var.task_container_assign_public_ip
  }

  dynamic "load_balancer" {
    for_each = var.lb_arn == "" ? [] : [1]
    content {
      container_name   = var.container_name != "" ? var.container_name : var.name_prefix
      container_port   = var.task_container_port
      target_group_arn = aws_lb_target_group.task.arn
    }
  }

  deployment_controller {
    # The deployment controller type to use. Valid values: CODE_DEPLOY, ECS.
    type = var.deployment_controller_type
  }

  deployment_circuit_breaker {
    enable   = var.deployment_circuit_breaker.enable
    rollback = var.deployment_circuit_breaker.rollback
  }

  dynamic "service_registries" {
    for_each = var.service_registry_arn == "" ? [] : [1]
    content {
      registry_arn   = var.service_registry_arn
      container_port = var.with_service_discovery_srv_record ? var.task_container_port : null
      container_name = var.container_name != "" ? var.container_name : var.name_prefix
    }
  }
}
/* module "fargate-service" {
  source               = "git::https://github.com/CCM-Engineering/Infra-modules.git//ecs-fargate?ref=master"
  name_prefix          = "${terraform.workspace}-${var.container_service_name}"
  vpc_id               = data.aws_vpc.primary_vpc.id
  private_subnet_ids   = data.aws_subnet_ids.private.ids
  lb_arn               = data.aws_lb.primary_public.arn
  cluster_id           = data.aws_ecs_cluster.primary_ecs_cluster.arn
  task_container_image = var.container_image_tag
  desired_count        = var.application_instance_count[terraform.workspace]

  task_container_assign_public_ip = false

  task_container_port = var.application_port

  task_definition_cpu = var.application_cpu[terraform.workspace]

  task_definition_memory = var.application_memory[terraform.workspace]

  service_registry_arn              = resource.aws_service_discovery_service.application-sd.arn
  with_service_discovery_srv_record = false

  deployment_circuit_breaker = { "enable" : true, "rollback" : true }
  wait_for_steady_state      = true

  task_container_environment = var.application_environment_variables[terraform.workspace]
  task_container_secrets     = var.application_environment_secrets[terraform.workspace]



  //Logging provider configuration
  task_container_logging_provider = var.log_provider
  log_container_environment       = var.log_environment_variables[terraform.workspace]
  log_container_secrets           = var.log_environment_secrets[terraform.workspace]
  log_container_image             = var.log_container_image[terraform.workspace]
  coralogix_private_key           = var.coralogix_private_key
  coralogix_app_name              = "${terraform.workspace}-${var.container_service_name}"
  coralogix_is_json               = var.coralogix_is_json
  coralogix_subsystem_name        = var.coralogix_subsystem_name

  health_check = {
    port = "traffic-port"
    path = var.application_healthcheck_path
  }

  tags = {
    Environment = terraform.workspace
    Terraform   = "True"
    Cost        = "ccm-engineering"
    Description = "FarGate Application Deployment"
  }
} */

//ALB Listener Rule for the Application

resource "aws_lb_listener_rule" "primary_app_listener_rule_nonprod" {
  listener_arn = data.aws_lb_listener.primary_public_listener.arn
  count        = terraform.workspace == "dev" || terraform.workspace == "test" ? 1 : 0

  action {
    type             = "forward"
    target_group_arn = module.fargate-service.target_group_arn
  }


  condition {
    host_header {
      values = ["${var.application_public_endpoint}.${terraform.workspace}.crosscountrymortgage.com"]
    }
  }
}

resource "aws_lb_listener_rule" "primary_app_listener_rule_prod" {
  listener_arn = data.aws_lb_listener.primary_public_listener.arn
  count        = terraform.workspace == "prod" ? 1 : 0

  action {
    type             = "forward"
    target_group_arn = module.fargate-service.target_group_arn
  }


  condition {
    host_header {
      values = ["${var.application_public_endpoint}.crosscountrymortgage.com"]
    }
  }
}


resource "aws_service_discovery_service" "application-sd" {
  name = var.container_service_name

  dns_config {
    namespace_id = data.aws_service_discovery_dns_namespace.primary_sd_service.id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }
  tags = {
    Environment = terraform.workspace
    Terraform   = "True"
    Cost        = "ccm-engineering"
    Description = "FarGate Application Deployment"
  }
}
