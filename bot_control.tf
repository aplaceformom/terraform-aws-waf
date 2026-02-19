locals {
  bot_control_label_enforcement_rules = var.bot_control_label_enforcement == null ? [] : flatten([
    for domain, cfg in var.bot_control_label_enforcement.domains : [
      for label in distinct(concat(var.bot_control_label_enforcement.base_blocked_labels, try(cfg.additional_blocked_labels, []))) : {
        domain = lower(domain)
        label  = label
      }
    ]
  ])
}

resource "aws_wafv2_rule_group" "bot_control_label_enforcement" {
  count = local.enabled && var.bot_control_label_enforcement != null ? 1 : 0

  name        = "${module.this.id}-${var.bot_control_label_enforcement.name}"
  description = "Label-based Bot Control enforcement"
  scope       = var.scope
  capacity    = var.bot_control_label_enforcement.capacity
  tags        = module.this.tags

  visibility_config {
    cloudwatch_metrics_enabled = lookup(try(var.bot_control_label_enforcement.visibility_config, {}), "cloudwatch_metrics_enabled", true)
    metric_name                = lookup(try(var.bot_control_label_enforcement.visibility_config, {}), "metric_name", "${var.bot_control_label_enforcement.name}-group")
    sampled_requests_enabled   = lookup(try(var.bot_control_label_enforcement.visibility_config, {}), "sampled_requests_enabled", true)
  }

  dynamic "rule" {
    for_each = {
      for idx, item in local.bot_control_label_enforcement_rules :
      idx => item
    }

    content {
      name     = format("botctrl-%03d-%s", rule.key, substr(md5("${rule.value.domain}-${rule.value.label}"), 0, 10))
      priority = rule.key

      action {
        block {}
      }

      statement {
        and_statement {
          statement {
            label_match_statement {
              scope = "LABEL"
              key   = rule.value.label
            }
          }
          statement {
            byte_match_statement {
              positional_constraint = "ENDS_WITH"
              search_string         = rule.value.domain

              field_to_match {
                single_header {
                  name = "host"
                }
              }

              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = format("%s-%03d", substr(var.bot_control_label_enforcement.name, 0, 110), rule.key)
        sampled_requests_enabled   = true
      }
    }
  }
}
