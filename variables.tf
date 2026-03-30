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

variable "country_codes_match" {
  type        = list(string)
  description = "Country codes to enforce WAF rules on - example US, CA, etc - https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html"
  default     = ["CU", "IR", "SY", "KP", "RU"] # default list of sanctioned contries
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

variable "waf_geo_location_block_enforce" {
  type        = string
  default     = "block"
  description = "allow or block - action to take on geo location list of countries"
}

variable "geo_rule_enabled" {
  type        = bool
  default     = true
  description = "Whether to include the geo-match rule in the Web ACL. Disable when geo blocking is not needed."
}

variable "geo_rule_priority" {
  type        = number
  default     = 0
  description = "Priority for the geo-match rule. Adjust to control evaluation order relative to other rules."
}

variable "aws_managed_waf_rule_groups" {
  type = list(any)
  default = [
    // Baseline rule groups
    {
      name     = "AWSManagedRulesAdminProtectionRuleSet"
      priority = 2
      action   = "none"
    },
    {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 3
      action   = "none"
    },
    {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 4
      action   = "none"
    },
    // Use-case specific rule groups
    {
      name     = "AWSManagedRulesLinuxRuleSet"
      priority = 5
      action   = "none"
    },
    {
      name     = "AWSManagedRulesSQLiRuleSet"
      priority = 6
      action   = "none"
    }
    #{
    #name     = "AWSManagedRulesUnixRuleSet"
    #priority = 7
    #action   = "none"
    #},
    #{
    #name     = "AWSManagedRulesPHPRuleSet"
    #priority = 8
    #action   = "none"
    #},
    #{
    #name     = "AWSManagedRulesWordPressRuleSet"
    #priority = 9
    #action   = "none"
    #},
    #// IP Reputation Rule groups 
    #{
    #name     = "AWSManagedRulesAmazonIpReputationList"
    #priority = 10
    #action   = "none"
    #},
    #{
    #name     = "AWSManagedRulesAnonymousIpList"
    #priority = 11
    #action   = "none"
    #},
    #// Bot control rule group
    #{
    #name     = "AWSManagedRulesBotControlRuleSet"
    #priority = 12
    #action   = "none"
    #}
  ]
}

variable "custom_waf_rules" {
  description = <<-EOT
    Rules evaluated inside the module-managed rule group (regional and/or CloudFront).
    rule_type "size_constraint" (default) — body size limits; set comparison_operator and size.
    rule_type "label_match" — match on WAF labels. Set label_match to one or more { key, scope } entries.
    One entry becomes a single label_match_statement; two or more are combined with OR (or_statement).
    Supply any label keys your stack uses (e.g. Bot Control labels after a count-mode rule on the Web ACL).
  EOT
  type = list(object({
    name                = string
    priority            = number
    action              = string # "allow", "block", or "count"
    rule_type           = optional(string, "size_constraint")
    comparison_operator = optional(string)
    size                = optional(number)
    transform           = optional(string, "NONE")
    label_match = optional(list(object({
      scope = optional(string, "LABEL")
      key   = string
    })))
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.custom_waf_rules :
      contains(["size_constraint", "label_match"], coalesce(r.rule_type, "size_constraint"))
    ])
    error_message = "custom_waf_rules[*].rule_type must be size_constraint or label_match."
  }

  validation {
    condition = alltrue([
      for r in var.custom_waf_rules :
      length(coalesce(r.label_match, [])) > 0 ? true : (
        coalesce(r.rule_type, "size_constraint") != "size_constraint" ? true : (
          try(r.comparison_operator, null) != null && try(r.size, null) != null
        )
      )
    ])
    error_message = "custom_waf_rules: size_constraint rules require comparison_operator and size (or set label_match for label_match rules)."
  }

  validation {
    condition = alltrue([
      for r in var.custom_waf_rules :
      (
        coalesce(r.rule_type, "size_constraint") != "label_match" &&
        length(coalesce(r.label_match, [])) == 0
      ) ? true : length(coalesce(r.label_match, [])) >= 1
    ])
    error_message = "custom_waf_rules: label_match rules require at least one label_match entry (key, optional scope)."
  }
}

variable "custom_managed_waf_rule_groups" {
  description = "Rule groups to attach on the Web ACL by ARN (in addition to any module-managed attachment). Use attach_module_custom_rule_group_to_web_acl to also reference the rule group this module builds from custom_waf_rules."
  type = list(object({
    name                    = string
    priority                = number
    action                  = string
    rule_group_arn          = string
    rules_override_to_count = list(string)
  }))
  default = []
}

variable "attach_module_custom_rule_group_to_web_acl" {
  type        = bool
  default     = true
  description = "When true, adds CustomManagedRuleSetGlobal / CustomManagedRuleSetRegional on the Web ACL when the module creates that rule group (custom_waf_rules non-empty). When false, [] custom_managed_waf_rule_groups means no such rule — only entries in custom_managed_waf_rule_groups are attached."
}

variable "module_custom_rule_group_web_acl_priority" {
  type        = number
  default     = 1
  description = "Web ACL priority for the module-managed rule group when attach_module_custom_rule_group_to_web_acl is true."
}

variable "rate_limit_rules" {
  description = "List of rate-based rules to add to the WAF Web ACL. Each rule tracks request rates and triggers the specified action when the limit is exceeded within the evaluation window."
  type = list(object({
    name                  = string
    priority              = number
    action                = string                 # "block", "count", or "captcha"
    limit                 = number                 # max requests per evaluation window (min 100)
    aggregate_key_type    = optional(string, "IP") # "IP", "FORWARDED_IP", or "CONSTANT"
    evaluation_window_sec = optional(number, 300)  # 60, 120, 300, or 600
    forwarded_ip_config = optional(object({
      header_name       = string
      fallback_behavior = string # "MATCH" or "NO_MATCH"
    }))
    scope_down_byte_match = optional(object({
      search_string         = string
      positional_constraint = string # "EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS"
      text_transformation   = optional(string, "NONE")
    }))
  }))
  default = []
}

variable "cloudfront_true" {
  type        = bool
  default     = false
  description = "When true, allows the CloudFront-scoped module rule group; it is only created if custom_waf_rules is non-empty."
}

variable "application_true" {
  type        = bool
  default     = false
  description = "When true, allows the Regional module rule group; it is only created if custom_waf_rules is non-empty."
}
