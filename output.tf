output "webacl_arn" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].arn : null
}

#output "webacl_id" {
#  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].id : null
#}

#output "custom_rule_group_arns" {
#  value = var.cloudfront_true || var.application_true ? [
#    for rg in local.effective_custom_managed_waf_rule_groups :
#    rg.rule_group_arn
#    if rg.rule_group_arn != null
#  ] : []
#}

#output "debug_rule_group_count" {
#  value = var.cloudfront_true ? 1 : 0
#}