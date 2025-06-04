locals {
  default_custom_managed_rule_groups = [
    {
      name                    = "CustomManagedRuleSet"
      priority                = 1
      action                  = "none"
      rule_group_arn          = aws_wafv2_rule_group.CustomManagedRuleSet.arn
      rules_override_to_count = []
    }
  ]
  effective_custom_managed_waf_rule_groups = length(var.custom_managed_waf_rule_groups) > 0 ? var.custom_managed_waf_rule_groups : local.default_custom_managed_rule_groups 
}