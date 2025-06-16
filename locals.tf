locals {
  default_custom_managed_rule_groups_cloudfront = (
    var.cloudfront_true && (try(length(aws_wafv2_rule_group.custom_rule_group_global), 0) > 0) ? [
      {
        name                    = "CustomManagedRuleSetGlobal"
        priority                = 1
        action                  = "none"
        rule_group_arn          = try(aws_wafv2_rule_group.custom_rule_group_global[0].arn, null)
        rules_override_to_count = []
      }
    ] : []
  )#

  default_custom_managed_rule_groups_regional = (
    var.application_true && (try(length(aws_wafv2_rule_group.custom_rule_group_regional), 0) > 0) ? [
      {
        name                    = "CustomManagedRuleSetRegional"
        priority                = 1
        action                  = "none"
        rule_group_arn          = try(aws_wafv2_rule_group.custom_rule_group_regional[0].arn, null)
        rules_override_to_count = []
      }
    ] : []
  )#

  filtered_custom_managed_rule_groups = [
    for r in var.custom_managed_waf_rule_groups : r
    if (
      (var.web_acl_scope == "CLOUDFRONT" && contains(r.rule_group_arn, ":global/")) ||
      (var.web_acl_scope == "REGIONAL" && contains(r.rule_group_arn, ":regional/"))
    )
  ]#

  effective_custom_managed_waf_rule_groups = (
    length(local.filtered_custom_managed_rule_groups) > 0 ?
    local.filtered_custom_managed_rule_groups :
    (
      var.web_acl_scope == "CLOUDFRONT" ?
      local.default_custom_managed_rule_groups_cloudfront :
      local.default_custom_managed_rule_groups_regional
    )
  )
}
