from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_PATH = ROOT / "experiments/false_effective/vllm_host_adapter_preflight.py"


def load_preflight():
    spec = importlib.util.spec_from_file_location(
        "vllm_adapter_preflight", PREFLIGHT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_producer_sources(root: Path, *, valid_bindings: bool = True) -> None:
    files = {
        "vllm/plugins/evidence.py": "VALUE = 1\n",
        "vllm/v1/core/sched/preemption.py": "VALUE = 2\n",
        "vllm/v1/engine/core.py": (
            "class EngineCoreProc:\n"
            "    def run_engine_core(self, dp_rank):\n"
            '        bind_process_identity("engine-core-scheduler", dp_rank)\n'
            if valid_bindings
            else "VALUE = 3\n"
        ),
        "vllm/v1/executor/multiproc_executor.py": "class WorkerProc:\n"
        "    def worker_main(self):\n"
        "        worker_ordinal = 0\n"
        '        bind_process_identity("worker", worker_ordinal)\n',
    }
    for relative, contents in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)


def initialize_checkout(root: Path) -> tuple[str, str]:
    write_producer_sources(root)
    commands = (
        ("init",),
        ("config", "user.email", "test@example.com"),
        ("config", "user.name", "Test"),
        (
            "remote",
            "add",
            "origin",
            "https://github.com/vLLM-HUST/vllm-hust.git",
        ),
        ("add", "."),
        ("commit", "-m", "fixture"),
    )
    for command in commands:
        subprocess.run(
            ("git", "-C", str(root), *command),
            check=True,
            capture_output=True,
        )
    commit = subprocess.check_output(
        ("git", "-C", str(root), "rev-parse", "HEAD"), text=True
    ).strip()
    tree = subprocess.check_output(
        ("git", "-C", str(root), "rev-parse", "HEAD^{tree}"), text=True
    ).strip()
    return commit, tree


def test_checkout_binds_identity_tree_blobs_and_cleanliness(tmp_path: Path) -> None:
    preflight = load_preflight()
    commit, tree = initialize_checkout(tmp_path)

    blobs = preflight.verify_checkout(tmp_path, commit, tree)
    assert set(blobs) == set(preflight.PRODUCER_PATHS)
    assert all(len(value) == 40 for value in blobs.values())
    preflight.verify_native_bindings(tmp_path)

    (tmp_path / "vllm/plugins/evidence.py").write_text("VALUE = 4\n")
    with pytest.raises(preflight.PreflightError, match="worktree changed"):
        preflight.materialize_producer_snapshot(tmp_path, tmp_path / "snapshot", blobs)
    with pytest.raises(preflight.PreflightError, match="clean"):
        preflight.verify_checkout(tmp_path, commit, tree)


def test_checkout_rejects_wrong_origin_and_missing_native_binding(
    tmp_path: Path,
) -> None:
    preflight = load_preflight()
    commit, tree = initialize_checkout(tmp_path)
    subprocess.run(
        ("git", "-C", str(tmp_path), "remote", "set-url", "origin", "evil/repo"),
        check=True,
    )
    with pytest.raises(preflight.PreflightError, match="canonical repository"):
        preflight.verify_checkout(tmp_path, commit, tree)

    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "remote",
            "set-url",
            "origin",
            "https://github.com/vLLM-HUST/vllm-hust.git",
        ),
        check=True,
    )
    write_producer_sources(tmp_path, valid_bindings=False)
    with pytest.raises(preflight.PreflightError, match="EngineCore"):
        preflight.verify_native_bindings(tmp_path)


def _start_identity() -> str:
    raw = Path("/proc/self/stat").read_text()
    start_ticks = raw[raw.rfind(")") + 1 :].split()[19]
    return f"pid:{os.getpid()}:start_ticks:{start_ticks}"


def _event(
    *,
    event: str,
    observation_kind: str,
    occurrence_id: int | str,
    controller: str,
    detail: str,
) -> dict:
    process = {
        "host": "adapter-preflight-host",
        "role": "engine-core-scheduler",
        "ordinal": 0,
        "pid": os.getpid(),
        "start_identity": _start_identity(),
        "process_epoch": 7,
        "assignment_source": "host",
    }
    invocation = occurrence_id if isinstance(occurrence_id, int) else None
    dispatch = None
    if invocation is not None:
        dispatch_material = json.dumps(
            [
                process["host"],
                process["start_identity"],
                process["process_epoch"],
                os.environ["VLLM_ECPA_PLAN_ID"],
                os.environ["VLLM_ECPA_LAUNCH_ID"],
                controller,
                occurrence_id,
            ],
            separators=(",", ":"),
        ).encode()
        dispatch = hashlib.sha256(dispatch_material).hexdigest()
    value = {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "pending",
        "event": event,
        "observation_kind": observation_kind,
        "entry_point": {
            "group": "vllm.preemption_policy",
            "name": "tests.SelectFirstPolicy",
            "value": "tests.SelectFirstPolicy",
        },
        "process": process,
        "observed_at_ns": 1_800_000_000_000_000_000 + (invocation or 0),
        "delivery_attempt": 1 if invocation is None else 2,
        "plan_id": os.environ["VLLM_ECPA_PLAN_ID"],
        "launch_id": os.environ["VLLM_ECPA_LAUNCH_ID"],
        "binding_status": "bound",
        "occurrence_id": occurrence_id,
        "controller_instance_id": controller,
        "invocation_seq": invocation,
        "dispatch_id": dispatch,
        "plugin_id": None,
        "artifact_digest": None,
        "identity_status": "launch-bound",
        "detail": detail,
    }
    entry = value["entry_point"]
    material = json.dumps(
        [
            process["host"],
            process["pid"],
            process["start_identity"],
            process["process_epoch"],
            process["role"],
            process["ordinal"],
            entry["group"],
            entry["name"],
            entry["value"],
            value["event"],
            value["detail"],
            occurrence_id,
            value["plan_id"],
            value["launch_id"],
            observation_kind,
            controller,
            value["delivery_attempt"],
            value["observed_at_ns"],
            process["assignment_source"],
        ],
        separators=(",", ":"),
    ).encode()
    value["event_id"] = hashlib.sha256(material).hexdigest()
    return value


def test_preflight_output_is_nonformal_and_schema_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preflight = load_preflight()
    from vllm_hust_ext.host_event_sink import append_event

    class Evidence:
        @staticmethod
        def bind_process_identity(role, ordinal):
            assert (role, ordinal) == ("engine-core-scheduler", 0)

    class Candidate:
        def __init__(self, request_id, *_args):
            self.request_id = request_id

    class Context:
        def __init__(self, candidates, *_args):
            self.candidates = candidates

    class Controller:
        def __init__(self, _config):
            self.stats = SimpleNamespace(policy_name="tests.SelectFirstPolicy")
            append_event(
                _event(
                    event="resolved",
                    observation_kind="scheduler_resolution",
                    occurrence_id="controller:controller-1",
                    controller="controller-1",
                    detail="engine-core.scheduler:protocol-validated",
                )
            )

        def select_victim(self, context):
            append_event(
                _event(
                    event="invoked",
                    observation_kind="scheduler_dispatch",
                    occurrence_id=1,
                    controller="controller-1",
                    detail="engine-core.scheduler:selected",
                )
            )
            return context.candidates[0].request_id

    producer = SimpleNamespace(
        PreemptionCandidate=Candidate,
        PreemptionContext=Context,
        PreemptionPolicyController=Controller,
    )

    @contextlib.contextmanager
    def modules(_checkout):
        yield Evidence, producer

    monkeypatch.setattr(
        preflight,
        "verify_checkout",
        lambda *_args: {p: "a" * 40 for p in preflight.PRODUCER_PATHS},
    )
    monkeypatch.setattr(preflight, "materialize_producer_snapshot", lambda *_args: None)
    monkeypatch.setattr(preflight, "verify_native_bindings", lambda *_args: None)
    monkeypatch.setattr(preflight, "_producer_modules", modules)
    monkeypatch.setattr(
        preflight,
        "_git",
        lambda _checkout, *_args: "https://github.com/vLLM-HUST/vllm-hust.git",
    )
    result = preflight.run_preflight(
        tmp_path,
        expected_commit="b" * 40,
        expected_tree="c" * 40,
    )

    schema = json.loads(
        (
            ROOT / "experiments/false_effective/vllm-host-adapter-preflight.schema.json"
        ).read_text()
    )
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(result)
    assert result["formal_real_result"] is False
    assert result["observed_path"]["events"] == [
        "scheduler_resolution",
        "scheduler_dispatch",
    ]
