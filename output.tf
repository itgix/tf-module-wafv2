output "webacl_arn" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].arn : null
}

output "webacl_id" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].id : null
}

output "ip_whitelist_ipv4_ip_set_arn" {
  value       = try(aws_wafv2_ip_set.whitelist_ipv4[0].arn, null)
  description = "ARN of the IPv4 IP set when ip_whitelist_prefixes is non-empty; otherwise null."
}

output "ip_whitelist_ipv6_ip_set_arn" {
  value       = try(aws_wafv2_ip_set.whitelist_ipv6[0].arn, null)
  description = "ARN of the IPv6 IP set when ip_whitelist_ipv6_prefixes is non-empty; otherwise null."
}
