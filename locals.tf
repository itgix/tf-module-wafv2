locals {
  aws_managed_waf_rule_groups_for_acl = var.aws_managed_waf_rule_groups

  effective_custom_managed_waf_rule_groups_for_acl = [
    for r in var.custom_managed_waf_rule_groups : r
    if(
      (var.web_acl_scope == "CLOUDFRONT" && contains(r.rule_group_arn, ":global/")) ||
      (var.web_acl_scope == "REGIONAL" && contains(r.rule_group_arn, ":regional/"))
    )
  ]

  # Includes rate limits via statement.rate_based_statement (there is no separate rate_limit_rules input).
  custom_rules_for_acl = var.custom_rules

  ip_whitelist_active = var.waf_enabled && (length(var.ip_whitelist_prefixes) > 0 || length(var.ip_whitelist_ipv6_prefixes) > 0)
  ip_whitelist_v4_only = local.ip_whitelist_active && length(var.ip_whitelist_prefixes) > 0 && length(var.ip_whitelist_ipv6_prefixes) == 0
  ip_whitelist_v6_only = local.ip_whitelist_active && length(var.ip_whitelist_ipv6_prefixes) > 0 && length(var.ip_whitelist_prefixes) == 0
  ip_whitelist_both    = local.ip_whitelist_active && length(var.ip_whitelist_prefixes) > 0 && length(var.ip_whitelist_ipv6_prefixes) > 0
}
