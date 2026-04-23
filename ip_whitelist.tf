resource "aws_wafv2_ip_set" "whitelist_ipv4" {
  count = local.ip_whitelist_active && length(var.ip_whitelist_prefixes) > 0 ? 1 : 0

  name               = "${var.project}-${var.env}-ip-whitelist-ipv4"
  description        = "IPv4 allowlist for ${var.project}-${var.env}"
  scope              = var.web_acl_scope
  ip_address_version = "IPV4"
  addresses          = var.ip_whitelist_prefixes
}

resource "aws_wafv2_ip_set" "whitelist_ipv6" {
  count = local.ip_whitelist_active && length(var.ip_whitelist_ipv6_prefixes) > 0 ? 1 : 0

  name               = "${var.project}-${var.env}-ip-whitelist-ipv6"
  description        = "IPv6 allowlist for ${var.project}-${var.env}"
  scope              = var.web_acl_scope
  ip_address_version = "IPV6"
  addresses          = var.ip_whitelist_ipv6_prefixes
}
