locals {
  # If label_match is populated but rule_type is omitted, optional() defaults rule_type to size_constraint and
  # Terraform would emit size_constraint_statement without size. Infer label_match when labels are present.
  custom_waf_rules_for_rule_group = [
    for r in var.custom_waf_rules : merge(r, {
      rule_type = length(coalesce(r.label_match, [])) > 0 ? "label_match" : coalesce(r.rule_type, "size_constraint")
    })
  ]

  aws_managed_waf_rule_groups_for_acl = var.aws_managed_waf_rule_groups

  effective_custom_managed_waf_rule_groups_for_acl = local.effective_custom_managed_waf_rule_groups

  rate_limit_rules_for_acl = var.rate_limit_rules

  filtered_custom_managed_rule_groups = [
    for r in var.custom_managed_waf_rule_groups : r
    if(
      (var.web_acl_scope == "CLOUDFRONT" && contains(r.rule_group_arn, ":global/")) ||
      (var.web_acl_scope == "REGIONAL" && contains(r.rule_group_arn, ":regional/"))
    )
  ] #

  # Optional attachment of the module-built rule group (set attach_module_custom_rule_group_to_web_acl = true).
  module_managed_web_acl_rule_group_refs = concat(
    (
      var.attach_module_custom_rule_group_to_web_acl &&
      length(var.custom_waf_rules) > 0 &&
      var.waf_enabled &&
      var.cloudfront_true &&
      var.web_acl_scope == "CLOUDFRONT" &&
      length(aws_wafv2_rule_group.custom_rule_group_global) > 0
      ) ? [
      {
        name                    = "CustomManagedRuleSetGlobal"
        priority                = var.module_custom_rule_group_web_acl_priority
        action                  = "none"
        rule_group_arn          = one(aws_wafv2_rule_group.custom_rule_group_global[*].arn)
        rules_override_to_count = []
      }
    ] : [],
    (
      var.attach_module_custom_rule_group_to_web_acl &&
      length(var.custom_waf_rules) > 0 &&
      var.waf_enabled &&
      var.application_true &&
      var.web_acl_scope == "REGIONAL" &&
      length(aws_wafv2_rule_group.custom_rule_group_regional) > 0
      ) ? [
      {
        name                    = "CustomManagedRuleSetRegional"
        priority                = var.module_custom_rule_group_web_acl_priority
        action                  = "none"
        rule_group_arn          = one(aws_wafv2_rule_group.custom_rule_group_regional[*].arn)
        rules_override_to_count = []
      }
    ] : []
  )

  effective_custom_managed_waf_rule_groups = concat(
    local.filtered_custom_managed_rule_groups,
    local.module_managed_web_acl_rule_group_refs
  )
}
