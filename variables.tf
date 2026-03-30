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

variable "allow_aws_verified_bots_before_geo" {
  type        = bool
  default     = false
  description = <<-EOT
    When true, evaluates AWS Bot Control in count mode first (priority 0), then allows requests labeled as AWS verified bots (priority 1),
    then your geo rule (priority 2). Use with a geo allowlist (e.g. CA, BG) and default_action block so crawlers such as Googlebot are not blocked by geography.
    Removes AWSManagedRulesBotControlRuleSet from aws_managed_waf_rule_groups if present to avoid attaching the same managed group twice.
    Shifts aws_managed_waf_rule_groups and custom_managed_waf_rule_groups priorities by +2.
  EOT
}

variable "waf_bot_control_inspection_level" {
  type        = string
  default     = "COMMON"
  description = "Inspection level for the Bot Control managed rule group when allow_aws_verified_bots_before_geo is true. Use COMMON (lower cost) or TARGETED."

  validation {
    condition     = contains(["COMMON", "TARGETED"], var.waf_bot_control_inspection_level)
    error_message = "waf_bot_control_inspection_level must be COMMON or TARGETED."
  }
}

variable "rules" {
  description = "List of WAF rules."
  type        = any
  default     = []
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
  description = "List of custom WAF rules to include in the rule group"
  type = list(object({
    name                = string
    priority            = number
    action              = string # "allow", "block", or "count"
    comparison_operator = string # e.g. "GT"
    size                = number # e.g. 15728640 (15MB)
    transform           = optional(string, "NONE")
  }))
  default = []
}

variable "custom_managed_waf_rule_groups" {
  type = list(object({
    name                    = string
    priority                = number
    action                  = string
    rule_group_arn          = string
    rules_override_to_count = list(string)
  }))
  default = []
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
  description = "Whether to create the CloudFront scoped WAF rule group"
}

variable "application_true" {
  type        = bool
  default     = false
  description = "Whether to create the Regional scoped WAF rule group"
}
