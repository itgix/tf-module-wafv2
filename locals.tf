locals {
  default_custom_managed_rule_groups_cloudfront = [
    {
      name                    = "CustomManagedRuleSetGlobal"
      priority                = 1
      action                  = "none"
      rule_group_arn          = aws_wafv2_rule_group.custom_rule_group_global.arn
      rules_override_to_count = []
    }
  ]

  default_custom_managed_rule_groups_regional = [
    {
      name                    = "CustomManagedRuleSetRegional"
      priority                = 1
      action                  = "none"
      rule_group_arn          = aws_wafv2_rule_group.custom_rule_group_regional.arn
      rules_override_to_count = []
    }
  ]

  effective_custom_managed_waf_rule_groups = length(var.custom_managed_waf_rule_groups) > 0 ? var.custom_managed_waf_rule_groups : (
    var.web_acl_scope == "CLOUDFRONT" ?
      local.default_custom_managed_rule_groups_cloudfront :
      local.default_custom_managed_rule_groups_regional
  )
}
