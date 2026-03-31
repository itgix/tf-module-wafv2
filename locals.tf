locals {
  aws_managed_waf_rule_groups_for_acl = var.aws_managed_waf_rule_groups

  effective_custom_managed_waf_rule_groups_for_acl = [
    for r in var.custom_managed_waf_rule_groups : r
    if(
      (var.web_acl_scope == "CLOUDFRONT" && contains(r.rule_group_arn, ":global/")) ||
      (var.web_acl_scope == "REGIONAL" && contains(r.rule_group_arn, ":regional/"))
    )
  ]

  rate_limit_rules_for_acl = var.rate_limit_rules
}
