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

  ip_prefix_rule_is_v4_only = {
    for r in var.ip_prefix_rules : r.name => (
      length(var.ip_prefix_sets[r.ip_set_key].ipv4_prefixes) > 0 &&
      length(var.ip_prefix_sets[r.ip_set_key].ipv6_prefixes) == 0
    )
  }
  ip_prefix_rule_is_v6_only = {
    for r in var.ip_prefix_rules : r.name => (
      length(var.ip_prefix_sets[r.ip_set_key].ipv6_prefixes) > 0 &&
      length(var.ip_prefix_sets[r.ip_set_key].ipv4_prefixes) == 0
    )
  }
  ip_prefix_rule_is_both_families = {
    for r in var.ip_prefix_rules : r.name => (
      length(var.ip_prefix_sets[r.ip_set_key].ipv4_prefixes) > 0 &&
      length(var.ip_prefix_sets[r.ip_set_key].ipv6_prefixes) > 0
    )
  }
}
