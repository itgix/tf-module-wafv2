output "webacl_arn" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].arn : null
}

output "webacl_id" {
  value = length(aws_wafv2_web_acl.wafv2_web_acl) > 0 ? aws_wafv2_web_acl.wafv2_web_acl[0].id : null
}

output "ip_prefix_ipv4_set_arns" {
  value       = { for k, s in aws_wafv2_ip_set.prefix_ipv4 : k => s.arn }
  description = "Map of ip_prefix_sets keys to IPv4 IP set ARNs (only keys with IPv4 prefixes)."
}

output "ip_prefix_ipv6_set_arns" {
  value       = { for k, s in aws_wafv2_ip_set.prefix_ipv6 : k => s.arn }
  description = "Map of ip_prefix_sets keys to IPv6 IP set ARNs (only keys with IPv6 prefixes)."
}
