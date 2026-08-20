package zero_trust.rag

# Reference implementation for OPA/Rego.
# Production requirements:
# 1. Counters must be stored in an external trusted atomic state store.
# 2. The agent must not have write access to policy, counters, attestation state, or policy-version state.
# 3. Parent/child permissions must be resolved by a trusted authorization service.
# 4. Destination domain/region controls require authoritative classification data.

default allow := false

required_context := {"agent_id", "session_id", "task_id", "root_agent_id", "policy_version"}

missing_context contains key if {
  key := required_context[_]
  not object.get(input.context, key, false)
}

session_ok if {
  input.agent.session_expiry_ns > time.now_ns()
}

policy_version_ok if {
  input.context.policy_version == data.policy.current_version
}

attestation_ok if {
  input.agent.criticality in {"low", "medium"}
}

attestation_ok if {
  input.agent.criticality in {"high", "critical"}
  input.agent.attestation.status == "verified"
  input.agent.attestation.image_digest == data.policy.allowed_images[input.agent.agent_id]
  input.agent.attestation.verified_at_ns + data.policy.attestation_max_age_ns > time.now_ns()
}

metadata_scope_ok if {
  input.request.metadata.project_id == input.task.project_id
  input.request.metadata.owner_id == input.task.owner_id
  input.request.metadata.tenant_id == input.task.tenant_id
}

allowed_data_classes := object.get(data.policy.agents[input.agent.agent_id], "allowed_data_classes", [])
requested_data_classes := object.get(input.request, "data_classes", [])

data_classes_ok if {
  every class in requested_data_classes {
    class in allowed_data_classes
  }
}

request_limits_ok if {
  input.request.top_k <= data.policy.rag.max_top_k
  input.request.requested_tokens <= data.policy.rag.max_tokens_per_request
}

task_budget_ok if {
  input.usage.task_consumed_tokens + input.request.requested_tokens <= data.policy.rag.max_tokens_per_task
}

tree_budget_ok if {
  input.usage.tree_consumed_tokens + input.request.requested_tokens <= data.policy.rag.max_tokens_per_agent_tree
}

request_rate_ok if {
  input.usage.requests_last_minute < data.policy.rag.max_requests_per_minute
}

# Export control. Apply when the request causes data to leave the trusted retrieval boundary.
destination_ok if {
  not input.request.export
}

destination_ok if {
  input.request.export
  input.request.destination_domain in data.policy.export.allowed_domains
  input.request.destination_region in data.policy.export.allowed_regions
  input.request.export_bytes <= data.policy.export.max_bytes_per_task - input.usage.task_exported_bytes
}

# Child permissions must be a subset of the parent delegation scope.
parent_scope_ok if {
  not input.context.parent_agent_id
}

parent_scope_ok if {
  input.context.parent_agent_id
  every tool in input.request.requested_tools {
    tool in input.delegation.parent_allowed_tools
  }
  every class in requested_data_classes {
    class in input.delegation.parent_allowed_data_classes
  }
  input.request.requested_tokens <= input.delegation.parent_remaining_token_budget
}

allow if {
  count(missing_context) == 0
  session_ok
  policy_version_ok
  attestation_ok
  metadata_scope_ok
  data_classes_ok
  request_limits_ok
  task_budget_ok
  tree_budget_ok
  request_rate_ok
  destination_ok
  parent_scope_ok
}

deny_reasons contains "missing_context" if count(missing_context) > 0
deny_reasons contains "session_expired" if not session_ok
deny_reasons contains "policy_version_mismatch" if not policy_version_ok
deny_reasons contains "attestation_failed" if not attestation_ok
deny_reasons contains "metadata_scope_violation" if not metadata_scope_ok
deny_reasons contains "data_class_violation" if not data_classes_ok
deny_reasons contains "request_limit_exceeded" if not request_limits_ok
deny_reasons contains "task_budget_exceeded" if not task_budget_ok
deny_reasons contains "agent_tree_budget_exceeded" if not tree_budget_ok
deny_reasons contains "request_rate_exceeded" if not request_rate_ok
deny_reasons contains "destination_not_allowed" if not destination_ok
deny_reasons contains "parent_scope_exceeded" if not parent_scope_ok

response := {
  "allow": allow,
  "deny_reasons": sort([r | r := deny_reasons[_]]),
  "policy_version": data.policy.current_version,
  "decision_time_ns": time.now_ns(),
}
