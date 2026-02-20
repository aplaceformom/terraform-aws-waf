locals {
  bot_control_label_enforcement_rules = var.bot_control_label_enforcement == null ? [] : [
    for domain, cfg in var.bot_control_label_enforcement.domains : {
      domain      = lower(domain)
      domain_slug = replace(lower(domain), "/[^a-z0-9-]/", "-")
      labels      = distinct(concat(var.bot_control_label_enforcement.base_blocked_labels, try(cfg.additional_blocked_labels, [])))
    }
  ]
}

resource "aws_wafv2_rule_group" "bot_control_label_enforcement" {
  count = local.enabled && var.bot_control_label_enforcement != null ? 1 : 0

  name        = "${module.this.id}-${var.bot_control_label_enforcement.name}"
  description = "Label-based Bot Control enforcement"
  scope       = var.scope
  capacity    = var.bot_control_label_enforcement.capacity
  tags        = module.this.tags

  visibility_config {
    cloudwatch_metrics_enabled = lookup(coalesce(try(var.bot_control_label_enforcement.visibility_config, null), {}), "cloudwatch_metrics_enabled", true)
    metric_name                = lookup(coalesce(try(var.bot_control_label_enforcement.visibility_config, null), {}), "metric_name", "${var.bot_control_label_enforcement.name}-group")
    sampled_requests_enabled   = lookup(coalesce(try(var.bot_control_label_enforcement.visibility_config, null), {}), "sampled_requests_enabled", true)
  }

  dynamic "rule" {
    for_each = {
      for idx, item in local.bot_control_label_enforcement_rules :
      idx => item
    }

    content {
      name     = substr(format("botctrl-block-%03d-%s", rule.key, rule.value.domain_slug), 0, 128)
      priority = rule.key

      action {
        block {}
      }

      statement {
        and_statement {
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
          statement {
            or_statement {
              dynamic "statement" {
                for_each = rule.value.labels
                content {
                  label_match_statement {
                    scope = "LABEL"
                    key   = statement.value
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = substr(format("%s-block-%s", var.bot_control_label_enforcement.name, rule.value.domain_slug), 0, 128)
        sampled_requests_enabled   = true
      }
    }
  }
}
