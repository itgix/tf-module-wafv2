resource "aws_wafv2_web_acl" "wafv2_web_acl" {
  count       = var.waf_enabled ? 1 : 0
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


 dynamic "rule" {
  for_each = var.rules
  content {
    name     = lookup(rule.value, "name")
    priority = lookup(rule.value, "priority")
   
      action {
        allow {}
      }
    statement {
      size_constraint_statement  {
        comparison_operator = "GT"
        size                = 5242881

        text_transformation {
          priority = 1
          type     = "NONE"
        }
    }
  }
 
    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = rule.value.name
      sampled_requests_enabled   = false
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
