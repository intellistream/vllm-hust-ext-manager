from __future__ import annotations

import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from vllm_hust_ext.runtime_evidence import (
    _start_identity,
    launch_environment,
    record_event,
    runtime_effective_evidence,
)


def _bundle() -> SimpleNamespace:
    carrier = SimpleNamespace(
        type="python_entry_point",
        attributes={"group": "vllm.general_plugins", "name": "example"},
    )
    manifest = SimpleNamespace(bundle_version="1.0", implementation=(carrier,))
    return SimpleNamespace(
        bundle_id="org.example.extension",
        manifest=manifest,
        manifest_path=Path("/example/manifest.json"),
    )


def _event(pid: int | None = None) -> dict[str, object]:
    process_id = pid if pid is not None else os.getpid()
    return {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "event-1",
        "event": "effective",
        "observation_kind": "runtime_effective",
        "entry_point": {
            "group": "vllm.general_plugins",
            "name": "example",
            "value": "example:register",
        },
        "process": {
            "host": socket.gethostname(),
            "pid": process_id,
            "start_identity": _start_identity(process_id)
            or f"pid:{process_id}:start_ticks:0",
        },
        "plan_id": "plan-1",
        "launch_id": "launch-1",
        "binding_status": "bound",
    }


def test_live_runtime_observer_event_is_effective_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    evidence = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("VLLM_HUST_EXT_EVIDENCE_PATH", str(evidence))

    record_event(_event())

    result = runtime_effective_evidence(_bundle())
    assert result is not None
    assert "launch_id=launch-1" in result
    assert f"pid={os.getpid()}" in result


def test_dead_process_event_is_not_runtime_effective(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VLLM_HUST_EXT_EVIDENCE_PATH", str(tmp_path / "evidence.jsonl"))
    record_event(_event(2**30))

    assert runtime_effective_evidence(_bundle()) is None


def test_sink_rejects_unbound_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("VLLM_HUST_EXT_EVIDENCE_PATH", str(tmp_path / "evidence.jsonl"))
    event = _event()
    event["binding_status"] = "unbound"

    with pytest.raises(ValueError, match="unbound"):
        record_event(event)


def test_launch_environment_is_fresh_and_manager_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = launch_environment((_bundle(),))
    assert environment["VLLM_ECPA_EVIDENCE_STRICT"] == "1"
    assert environment["VLLM_ECPA_PLAN_ID"]
    assert environment["VLLM_ECPA_LAUNCH_ID"]

    monkeypatch.setenv("VLLM_ECPA_LAUNCH_ID", "caller-owned")
    with pytest.raises(ValueError, match="owns runtime evidence"):
        launch_environment((_bundle(),))
