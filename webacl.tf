provider "aws" {
  alias  = "virginia"
  region = "us-east-1"
}

resource "aws_wafv2_rule_group" "custom_rule_group_global" {
  count       = var.cloudfront_true ? 1 : 0
  provider    = aws.virginia
  name        = "${var.project}-cloudfront-rule-group-global"
  scope       = "CLOUDFRONT"
  capacity    = 50  # minimum capacity for empty rule group
  description = "Empty custom WAF rule group for CloudFront"

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-customRuleGroupGlobal"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_rule_group" "custom_rule_group_regional" {
  count       = var.application_true ? 1 : 0
  name        = "${var.project}-application-group-regional"
  scope       = "REGIONAL"
  capacity    = 50  # minimum capacity for empty rule group
  description = "Empty custom WAF rule group for Regional"

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-customRuleGroupRegional"
    sampled_requests_enabled   = true
  }
}

resource "time_sleep" "wait_for_rule_groups" {
  depends_on = [
    aws_wafv2_rule_group.custom_rule_group_global,
    aws_wafv2_rule_group.custom_rule_group_regional,
  ]
  create_duration = "120s"
}

resource "aws_wafv2_web_acl" "wafv2_web_acl" {
  count       = var.waf_enabled ? 1 : 0
  depends_on = [time_sleep.wait_for_rule_groups]
  name        = "${var.project}-${var.env}-${var.waf_attachment_type}-security"
  description = "Geo-Location blocking and Web Application Security firewall"
  scope       = var.web_acl_scope

  default_action {
    dynamic "allow" {
      for_each = var.waf_default_action == "allow" ? [""] : []
      content {}
    }

    dynamic "block" {
      for_each = var.waf_default_action == "block" ? [""] : []
      content {}
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
    metric_name                = "WAF-Main"
    sampled_requests_enabled   = var.sampled_requests_enabled
  }

  // Geo-Location block rules - with highest priority in order to be avaluated before any other rules
  rule {
    name     = "GEO-Blacklist-Country"
    priority = 0

    action {
      dynamic "allow" {
        for_each = var.waf_geo_location_block_enforce == "allow" ? [""] : []
        content {}
      }

      dynamic "block" {
        for_each = var.waf_geo_location_block_enforce == "block" ? [""] : []
        content {}
      }
    }

    statement {
      geo_match_statement {
        country_codes = var.country_codes_match
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
      metric_name                = "GEO-Blacklist-Country"
      sampled_requests_enabled   = var.sampled_requests_enabled
    }
  }


 # Custom WAF rules
dynamic "rule" {
  for_each = { for waf_rule in var.custom_waf_rules : waf_rule.name => waf_rule }

  content {
    name     = rule.value.name
    priority = rule.value.priority

    action {
      dynamic "block" {
        for_each = rule.value.action == "block" ? [1] : []
        content {}
      }

      dynamic "allow" {
        for_each = rule.value.action == "allow" ? [1] : []
        content {}
      }
    
      dynamic "count" {
        for_each = rule.value.action == "count" ? [1] : []
        content {}
      }
    }

statement {
  dynamic "and_statement" {
    for_each = length(rule.value.match_conditions) > 1 ? [1] : []
    content {
      dynamic "statement" {
        for_each = rule.value.match_conditions
        content {
          dynamic "size_constraint_statement" {
            for_each = statement.value.type == "BodySize" ? [1] : []
            content {
              comparison_operator = statement.value.operator
              size                = tonumber(statement.value.value)
              field_to_match {
                body {}
              }
              text_transformation {
                priority = 0
                type     = lookup(statement.value, "transform", "NONE")
              }
            }
          }

          # Add other dynamic statement types here if needed
        }
      }
    }
  }

  dynamic "size_constraint_statement" {
    for_each = length(rule.value.match_conditions) == 1 && rule.value.match_conditions[0].type == "BodySize" ? [1] : []
    content {
      comparison_operator = rule.value.match_conditions[0].operator
      size                = tonumber(rule.value.match_conditions[0].value)
      field_to_match {
        body {}
      }
      text_transformation {
        priority = 0
        type     = lookup(rule.value.match_conditions[0], "transform", "NONE")
      }
    }
  }

  # Add similar single-statement support for other match types if needed
}



    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = rule.value.name
      sampled_requests_enabled   = true
    }
  }
}

  dynamic "rule" {
    for_each = toset(var.aws_managed_waf_rule_groups)

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        #count {}
        dynamic "count" {
          for_each = rule.value.action == "count" ? [""] : []
          content {}
        }

        dynamic "none" {
          for_each = rule.value.action == "none" ? [""] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = [for rule_override in rule.value.rules_override_to_count : rule_override]

            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.sampled_requests_enabled
      }
    }
  }


# Custom managed rule groups
dynamic "rule" {
    for_each = { for r in local.effective_custom_managed_waf_rule_groups : r.name => r }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = rule.value.action == "count" ? [""] : []
          content {}
        }

        dynamic "none" {
          for_each = rule.value.action == "none" ? [""] : []
          content {}
        }
      }

      statement {
        rule_group_reference_statement {
          arn = rule.value.rule_group_arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
        metric_name                = rule.value.name
        sampled_requests_enabled   = var.sampled_requests_enabled
    }
  }
}

#Custom rule
  dynamic "rule" {
    for_each = var.custom_rule_group_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        # Dynamically select one action based on input
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      # The statement block expects you to pass a proper map structure
      statement = rule.value.statement

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }
}


  
  # TODO: add options to handle, those rules additionally, they require specific additional configuration that cannot be handled with the current dynamic block
  #// AWS account creation fraud prevention rule group
  #{
  #name     = "AWSManagedRulesACFPRuleSet"
  #priority = 11
  #}
  #// Account Takeover prevention
  #{
  #name     = "AWSManagedRulesATPRuleSet"
  #priority = 12
  #}
}
