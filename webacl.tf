provider "aws" {
  alias  = "virginia"
  region = "us-east-1"
}

resource "aws_wafv2_rule_group" "custom_rule_group_global" {
  count       = var.waf_enabled && var.cloudfront_true ? 1 : 0
  provider    = aws.virginia
  name        = "${var.project}-${var.env}-${var.aws_region}-cloudfront-rule-group-global"
  scope       = "CLOUDFRONT"
  capacity    = 50 # minimum capacity for empty rule group
  description = "Custom WAF rule group for CloudFront"

  lifecycle {
    ignore_changes = [rule]
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-${var.env}-${var.aws_region}-customRuleGroupGlobal"
    sampled_requests_enabled   = true
  }

  dynamic "rule" {
    for_each = var.custom_waf_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
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
      statement {
        size_constraint_statement {
          comparison_operator = rule.value.comparison_operator
          size                = rule.value.size

          field_to_match {
            body {}
          }

          text_transformation {
            priority = 0
            type     = rule.value.transform
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }
}

resource "aws_wafv2_rule_group" "custom_rule_group_regional" {
  count       = var.waf_enabled && var.application_true ? 1 : 0
  name        = "${var.project}-${var.env}-${var.aws_region}-application-group-regional"
  scope       = "REGIONAL"
  capacity    = 50 # minimum capacity for empty rule group
  description = "Custom WAF rule group for Regional"

  lifecycle {
    ignore_changes = [rule]
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-${var.env}-${var.aws_region}-customRuleGroupRegional"
    sampled_requests_enabled   = true
  }

  dynamic "rule" {
    for_each = var.custom_waf_rules
    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
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

      statement {
        size_constraint_statement {
          comparison_operator = rule.value.comparison_operator
          size                = rule.value.size

          field_to_match {
            body {}
          }

          text_transformation {
            priority = 0
            type     = rule.value.transform
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }
}

#resource "time_sleep" "wait_for_rule_groups" {
#  depends_on = [
#    aws_wafv2_rule_group.custom_rule_group_global,
#    aws_wafv2_rule_group.custom_rule_group_regional,
#  ]
#  create_duration = "120s"
#}

resource "aws_wafv2_web_acl" "wafv2_web_acl" {
  count = var.waf_enabled ? 1 : 0
  #  depends_on = [time_sleep.wait_for_rule_groups]
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

  # Bot Control first (count) adds labels; then allow verified bots before geo allowlist/blocklist.
  # See https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control-example-allow-verified-bots.html
  dynamic "rule" {
    for_each = var.allow_aws_verified_bots_before_geo ? [1] : []
    content {
      name     = "AWS-BotControl-Labeling"
      priority = var.bot_control_labeling_priority

      override_action {
        count {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesBotControlRuleSet"
          vendor_name = "AWS"

          managed_rule_group_configs {
            aws_managed_rules_bot_control_rule_set {
              inspection_level = var.waf_bot_control_inspection_level
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
        metric_name                = "AWS-BotControl-Labeling"
        sampled_requests_enabled   = var.sampled_requests_enabled
      }
    }
  }

  dynamic "rule" {
    for_each = var.allow_aws_verified_bots_before_geo ? [1] : []
    content {
      name     = "Allow-AWS-Verified-Bots"
      priority = var.verified_bot_allow_priority

      action {
        allow {}
      }

      statement {
        or_statement {
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = "awswaf:managed:aws:bot-control:bot:verified"
            }
          }
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = "awswaf:managed:aws:bot-control:bot:user_triggered:verified"
            }
          }
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = "awswaf:managed:aws:bot-control:bot:developer_platform:verified"
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = var.web_acl_cloudwatch_enabled
        metric_name                = "Allow-AWS-Verified-Bots"
        sampled_requests_enabled   = var.sampled_requests_enabled
      }
    }
  }

  dynamic "rule" {
    for_each = var.geo_rule_enabled ? [1] : []
    content {
      name     = var.waf_geo_location_block_enforce == "block" ? "GEO-Blacklist-Country" : "GEO-Whitelist-Country"
      priority = var.geo_rule_priority

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
        metric_name                = var.waf_geo_location_block_enforce == "block" ? "GEO-Blacklist-Country" : "GEO-Whitelist-Country"
        sampled_requests_enabled   = var.sampled_requests_enabled
      }
    }
  }

  dynamic "rule" {
    for_each = { for g in local.aws_managed_waf_rule_groups_for_acl : "${g.name}-${g.priority}" => g }

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
            for_each = [for rule_override in try(rule.value.rules_override_to_count, []) : rule_override]

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
    for_each = { for r in local.effective_custom_managed_waf_rule_groups_for_acl : r.name => r }

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

  dynamic "rule" {
    for_each = { for r in local.rate_limit_rules_for_acl : r.name => r }

    content {
      name     = rule.value.name
      priority = rule.value.priority

      action {
        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }

        dynamic "captcha" {
          for_each = rule.value.action == "captcha" ? [1] : []
          content {}
        }
      }

      statement {
        rate_based_statement {
          limit                 = rule.value.limit
          aggregate_key_type    = rule.value.aggregate_key_type
          evaluation_window_sec = rule.value.evaluation_window_sec

          dynamic "forwarded_ip_config" {
            for_each = rule.value.forwarded_ip_config != null ? [rule.value.forwarded_ip_config] : []
            content {
              header_name       = forwarded_ip_config.value.header_name
              fallback_behavior = forwarded_ip_config.value.fallback_behavior
            }
          }

          dynamic "scope_down_statement" {
            for_each = rule.value.scope_down_byte_match != null ? [rule.value.scope_down_byte_match] : []
            content {
              byte_match_statement {
                search_string         = scope_down_statement.value.search_string
                positional_constraint = scope_down_statement.value.positional_constraint

                field_to_match {
                  uri_path {}
                }

                text_transformation {
                  priority = 0
                  type     = scope_down_statement.value.text_transformation
                }
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