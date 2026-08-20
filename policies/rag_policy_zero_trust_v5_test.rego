package zero_trust.rag_test

import data.zero_trust.rag

base_policy := {
  "policy": {
    "current_version": "v5.0",
    "attestation_max_age_ns": 900000000000,
    "allowed_images": {"rag-agent": "sha256:approved"},
    "agents": {"rag-agent": {"allowed_data_classes": ["internal", "confidential"]}},
    "rag": {
      "max_top_k": 10,
      "max_tokens_per_request": 2000,
      "max_tokens_per_task": 10000,
      "max_tokens_per_agent_tree": 20000,
      "max_requests_per_minute": 20
    },
    "export": {
      "allowed_domains": ["approved.example"],
      "allowed_regions": ["EU"],
      "max_bytes_per_task": 1048576
    }
  }
}

base_input := {
  "agent": {
    "agent_id": "rag-agent",
    "criticality": "critical",
    "session_expiry_ns": 9999999999999999999,
    "attestation": {
      "status": "verified",
      "image_digest": "sha256:approved",
      "verified_at_ns": 9999999000000000000
    }
  },
  "context": {
    "agent_id": "rag-agent",
    "session_id": "s-1",
    "task_id": "t-1",
    "root_agent_id": "rag-agent",
    "policy_version": "v5.0"
  },
  "task": {"project_id": "p1", "owner_id": "u1", "tenant_id": "tenant-a"},
  "request": {
    "metadata": {"project_id": "p1", "owner_id": "u1", "tenant_id": "tenant-a"},
    "data_classes": ["internal"],
    "top_k": 5,
    "requested_tokens": 1000,
    "requests_last_minute": 1,
    "requested_tools": ["vector.search"],
    "export": false
  },
  "usage": {
    "task_consumed_tokens": 1000,
    "tree_consumed_tokens": 2000,
    "requests_last_minute": 1,
    "task_exported_bytes": 0
  },
  "delegation": {
    "parent_allowed_tools": ["vector.search"],
    "parent_allowed_data_classes": ["internal"],
    "parent_remaining_token_budget": 5000
  }
}

test_allow_valid_request if {
  rag.allow with input as base_input with data as base_policy
}

test_deny_expired_session if {
  i := object.union(base_input, {"agent": object.union(base_input.agent, {"session_expiry_ns": 1})})
  not rag.allow with input as i with data as base_policy
  "session_expired" in rag.deny_reasons with input as i with data as base_policy
}

test_deny_bad_attestation if {
  a := object.union(base_input.agent.attestation, {"image_digest": "sha256:evil"})
  i := object.union(base_input, {"agent": object.union(base_input.agent, {"attestation": a})})
  not rag.allow with input as i with data as base_policy
  "attestation_failed" in rag.deny_reasons with input as i with data as base_policy
}

test_deny_tree_budget if {
  u := object.union(base_input.usage, {"tree_consumed_tokens": 19500})
  i := object.union(base_input, {"usage": u})
  not rag.allow with input as i with data as base_policy
  "agent_tree_budget_exceeded" in rag.deny_reasons with input as i with data as base_policy
}

test_deny_wrong_region if {
  r := object.union(base_input.request, {
    "export": true,
    "destination_domain": "approved.example",
    "destination_region": "APAC",
    "export_bytes": 100
  })
  i := object.union(base_input, {"request": r})
  not rag.allow with input as i with data as base_policy
  "destination_not_allowed" in rag.deny_reasons with input as i with data as base_policy
}

test_deny_child_scope_escalation if {
  c := object.union(base_input.context, {"parent_agent_id": "parent-1"})
  r := object.union(base_input.request, {"requested_tools": ["vector.search", "admin.export"]})
  i := object.union(base_input, {"context": c, "request": r})
  not rag.allow with input as i with data as base_policy
  "parent_scope_exceeded" in rag.deny_reasons with input as i with data as base_policy
}
