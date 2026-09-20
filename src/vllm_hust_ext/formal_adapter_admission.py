"""Code-reviewed producer admission for formal-real adapters."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

FORMAL_ADAPTER_REGISTRY_SCHEMA = "ecpa-formal-adapter-registry/v2"
FORMAL_ADAPTER_ADMISSION_SCHEMA = "ecpa-formal-adapter-admission/v1"

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_FIELDS = {
    "schema",
    "repository",
    "repository_id",
    "node_id",
    "default_branch",
    "pull_request",
    "reviewed_head",
    "reviewed_tree",
    "base",
    "state",
    "merge_commit",
    "human_line_review",
    "commands_reviewed",
    "activation_path_reviewed",
    "observer_independence_reviewed",
    "observed_at",
}


def validate_formal_adapter_admission(value: Any) -> dict[str, Any]:
    """Reject adapters whose producer and real activation path are not reviewed."""
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("formal adapter producer admission fields are incomplete")
    if value["schema"] != FORMAL_ADAPTER_ADMISSION_SCHEMA:
        raise ValueError("formal adapter producer admission schema is unsupported")
    if (
        not isinstance(value["repository"], str)
        or _REPOSITORY.fullmatch(value["repository"]) is None
        or not isinstance(value["repository_id"], int)
        or isinstance(value["repository_id"], bool)
        or value["repository_id"] <= 0
        or not isinstance(value["node_id"], str)
        or not value["node_id"]
        or value["node_id"].strip() != value["node_id"]
        or not isinstance(value["default_branch"], str)
        or not value["default_branch"]
        or value["default_branch"].strip() != value["default_branch"]
        or not isinstance(value["pull_request"], int)
        or isinstance(value["pull_request"], bool)
        or value["pull_request"] <= 0
    ):
        raise ValueError("formal adapter producer identity is invalid")
    if any(
        not isinstance(value[field], str) or _GIT_SHA.fullmatch(value[field]) is None
        for field in ("reviewed_head", "reviewed_tree", "base", "merge_commit")
    ):
        raise ValueError("formal adapter producer Git identity is invalid")
    if value["state"] != "merged" or any(
        value[field] is not True
        for field in (
            "human_line_review",
            "commands_reviewed",
            "activation_path_reviewed",
            "observer_independence_reviewed",
        )
    ):
        raise ValueError("formal adapter producer is not merge-admissible")
    observed_at = value["observed_at"]
    if (
        not isinstance(observed_at, str)
        or not observed_at
        or observed_at.strip() != observed_at
    ):
        raise ValueError("formal adapter producer observation time is invalid")
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("formal adapter producer observation time is invalid") from exc
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("formal adapter producer observation time lacks a timezone")
    return dict(value)
