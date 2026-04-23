variable "pid" {}
variable "project" {
  type        = string
  description = "Project name"
}

variable "env" {
  type        = string
  description = "Environment name"
}

variable "aws_region" {
  type        = string
  description = "aws region"
}

variable "waf_attachment_type" {
  type        = string
  description = "Type of resource where WAF will be attached, supported values - alb, api-gateway, cloudfront"
}

variable "waf_enabled" {
  type        = bool
  description = "If WAF WebACL should be created"
}

variable "web_acl_scope" {
  type        = string
  description = "Scope of the AWS WAF Web ACL - REGIONAL for API Gateway/ALB and CLOUDFRONT for cloudfront"
}

variable "web_acl_cloudwatch_enabled" {
  type        = bool
  description = "A boolean indicating whether the associated resource sends metrics to CloudWatch"
  default     = true
}

variable "sampled_requests_enabled" {
  type        = bool
  description = "A boolean indicating whether AWS WAF should store a sampling of the web requests that match the rules"
  default     = true
}

variable "aws_waf_logging_enabled" {
  type        = bool
  description = "A boolean indicating whether AWS WAF should store its logs into cloudwatch log group"
  default     = true
}

variable "waf_log_retention_days" {
  type        = number
  description = "Number of days to keep WAF logs in cloudwatch log group"
  default     = 365
}

variable "waf_default_action" {
  type        = string
  default     = "allow"
  description = "allow or block - default action of WAF when a request hasn't matched any rules"
}

variable "aws_managed_waf_rule_groups" {
  type    = any
  default = []
}

variable "custom_managed_waf_rule_groups" {
  description = "Rule groups to attach on the Web ACL by ARN. ARNs must match the Web ACL scope (global for CLOUDFRONT, regional for REGIONAL)."
  type = list(object({
    name                    = string
    priority                = number
    action                  = string
    rule_group_arn          = string
    rules_override_to_count = list(string)
  }))
  default = []
}

variable "custom_rules" {
  description = <<-EOT
    List of custom WAF rules with full statement support. Each rule is a map with keys:
      - name      (string)  Rule name
      - priority  (number)  Rule priority (must be unique across all rules in the Web ACL)
      - action    (string)  "allow", "block", "count", "captcha", or "challenge"
      - statement (map)     Statement tree matching the Terraform aws_wafv2_web_acl rule statement schema.
                            Supports: byte_match_statement, geo_match_statement, ip_set_reference_statement,
                            label_match_statement, regex_match_statement, regex_pattern_set_reference_statement,
                            size_constraint_statement, sqli_match_statement, xss_match_statement,
                            rate_based_statement, and_statement, or_statement, not_statement.
                            Geo allow/block lists: use geo_match_statement (see examples).
                            Logical statements (and/or/not) support up to 2 levels of nesting.
    Rate limiting: use statement.rate_based_statement (examples/custom-rules.tfvars).
    Use type = any (not list(any)) in root/wrapper modules: list(any) still requires every
    element to share the same type; different statement shapes need a top-level any.
  EOT
  type        = any
  default     = []
}

variable "ip_whitelist_prefixes" {
  type        = list(string)
  default     = []
  description = "IPv4 CIDR prefixes to allow before other rules. Creates an WAFv2 IP set and an allow rule. Example: [\"10.0.0.0/8\", \"203.0.113.0/32\"]. Leave empty to disable."
}

variable "ip_whitelist_ipv6_prefixes" {
  type        = list(string)
  default     = []
  description = "IPv6 CIDR prefixes to allow (separate WAF IP set; use together with or separate from ip_whitelist_prefixes)."
}

variable "ip_whitelist_rule_priority" {
  type        = number
  default     = 0
  description = "Priority of the allow rule for ip_whitelist_prefixes / ip_whitelist_ipv6_prefixes. Lower numbers are evaluated first; use 0 so trusted clients skip managed rules when matched."
}

variable "ip_whitelist_forwarded_ip_config" {
  type = object({
    header_name       = string
    fallback_behavior = string
    position          = string
  })
  default     = null
  description = "Optional. When the client IP is in a header (e.g. behind CloudFront/ALB), set this to use that header in the whitelist rule (same as ip_set_forwarded_ip_config on the IP set reference)."
}
