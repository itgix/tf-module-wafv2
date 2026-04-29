resource "aws_wafv2_ip_set" "prefix_ipv4" {
  for_each = var.waf_enabled ? {
    for k, v in var.ip_prefix_sets : k => v
    if length(coalesce(v.ipv4_prefixes, [])) > 0
  } : {}

  name               = "${var.project}-${var.env}-${each.key}-ipv4"
  description        = coalesce(each.value.description, "IPv4 prefixes (${each.key}) for ${var.project}-${var.env}")
  scope              = var.web_acl_scope
  ip_address_version = "IPV4"
  addresses          = each.value.ipv4_prefixes
}

resource "aws_wafv2_ip_set" "prefix_ipv6" {
  for_each = var.waf_enabled ? {
    for k, v in var.ip_prefix_sets : k => v
    if length(coalesce(v.ipv6_prefixes, [])) > 0
  } : {}

  name               = "${var.project}-${var.env}-${each.key}-ipv6"
  description        = coalesce(each.value.description, "IPv6 prefixes (${each.key}) for ${var.project}-${var.env}")
  scope              = var.web_acl_scope
  ip_address_version = "IPV6"
  addresses          = each.value.ipv6_prefixes
}
