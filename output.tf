output "webacl_arn" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].arn : null
}

output "webacl_id" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].id : null
}

output "effective_custom_managed_waf_rule_groups" {
  value = local.effective_custom_managed_waf_rule_groups
}
