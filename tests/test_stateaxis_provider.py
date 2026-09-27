from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vllm_hust_ext.manifest import parse_manifest
from vllm_hust_ext.providers import provider_for
from vllm_hust_ext.providers.stateaxis import StateAxisProvider


def stateaxis_manifest(digest: str, *, status: str = "import_only", qualified: bool = False):
    return parse_manifest({
        "schema_version": "0.2-experimental",
        "extension_id": "org.stateaxis.test-mod",
        "extension_version": "0.1.0",
        "kind": "scheduler_policy",
        "host": {"provider": "stateaxis", "name": "stateaxis", "version_range": ">=0.3.0.dev23,<0.4", "api_range": ">=1,<2"},
        "runtime": {"type": "python", "process_scope": "stateaxis_processes", "isolation": "trusted_in_process"},
        "lifecycle_owner": "host",
        "protocols": [],
        "implementation": [{"type": "python_module", "module": "stateaxis_mod", "object": "descriptor", "status": status}],
        "requires_services": [],
        "activation": {"additional_config": {"stateaxis_mod": {"mod_id": "stateaxis.test-mod", "version": "0.1.0", "manifest_sha256": digest, "performance_qualified": qualified}}},
    })


def test_stateaxis_is_a_builtin_provider() -> None:
    assert isinstance(provider_for("stateaxis", include_external=False), StateAxisProvider)


def test_descriptor_only_candidate_is_plannable_but_not_activatable() -> None:
    manifest = stateaxis_manifest("0" * 64)
    plan = StateAxisProvider().plan(manifest, {}, enabled=True)
    assert plan.actions[0].operation == "inspect_only"
    assert plan.actions[0].details["enabled"] is False
    assert any("descriptor-only" in warning for warning in plan.warnings)
    assert any("no performance qualification" in warning for warning in plan.warnings)


def test_check_verifies_research_manifest_digest_but_keeps_candidate_unconfigured(tmp_path: Path) -> None:
    research_manifest = tmp_path / "mod.json"
    research_manifest.write_text(json.dumps({"mod_id": "stateaxis.test-mod"}) + "\n")
    digest = hashlib.sha256(research_manifest.read_bytes()).hexdigest()
    manifest = stateaxis_manifest(digest)
    check = StateAxisProvider().check(manifest, {"host_version": "0.3.0.dev23", "research_manifest_path": str(research_manifest)})
    assert check.compatible is True
    assert check.configured is False
    assert check.degraded is True
    assert any("digest verified" in item for item in check.evidence)


def test_check_rejects_manifest_digest_mismatch(tmp_path: Path) -> None:
    research_manifest = tmp_path / "mod.json"
    research_manifest.write_text("{}\n")
    check = StateAxisProvider().check(stateaxis_manifest("0" * 64), {"host_version": "0.3.0.dev23", "research_manifest_path": str(research_manifest)})
    assert check.compatible is False
    assert any("digest mismatch" in item for item in check.evidence)
