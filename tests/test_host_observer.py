import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.host_evidence import EntryPointBinding
from vllm_hust_ext.host_observer import (
    HostObservationError,
    observe_bound_invocations,
    parse_linux_start_ticks,
    read_linux_process_identity,
)

PLUGIN = PluginIdentity("org.vllm-hust", "demo", "1", "a" * 64)
OBLIGATION = EvidenceObligation("worker-invoked", "worker", "invoked", (0,))
PLAN = Plan(
    (PLUGIN,),
    HostCompatibility("vllm-hust", "0.28", "vllm", "1"),
    (),
    (OBLIGATION,),
    PredecessorSnapshot(0, None, {}),
)
BINDING = EntryPointBinding(
    "vllm.general_plugins",
    "demo",
    "demo.plugin:register",
    PLUGIN.id,
    OBLIGATION.obligation_id,
)


def event_id(value: dict) -> str:
    process = value["process"]
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
            value["occurrence_id"],
            value["plan_id"],
            value["launch_id"],
            value["observation_kind"],
            value["controller_instance_id"],
            value["delivery_attempt"],
            value["observed_at_ns"],
            process["assignment_source"],
        ],
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(material).hexdigest()


def host_event(
    *,
    pid: int = os.getpid(),
    epoch: int = 7,
    launch_id: str = "launch:one",
    assignment_source: str = "host",
    plan: Plan = PLAN,
    role: str = "worker",
    name: str = BINDING.name,
    value: str = BINDING.value,
) -> bytes:
    identity = read_linux_process_identity(
        pid,
        f"pid:{pid}:start_ticks:{parse_linux_start_ticks(Path(f'/proc/{pid}/stat').read_bytes())}",
    )
    payload = {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "pending",
        "event": "invoked",
        "observation_kind": "loader_lifecycle",
        "entry_point": {
            "group": BINDING.group,
            "name": name,
            "value": value,
        },
        "process": {
            "host": "host-a",
            "role": role,
            "ordinal": 0,
            "pid": pid,
            "start_identity": identity["start_identity"],
            "process_epoch": epoch,
            "assignment_source": assignment_source,
        },
        "observed_at_ns": 1_800_000_000_000_000_000 + pid,
        "delivery_attempt": 1,
        "plan_id": plan.plan_id,
        "launch_id": launch_id,
        "binding_status": "bound",
        "occurrence_id": None,
        "controller_instance_id": None,
        "invocation_seq": None,
        "dispatch_id": None,
        "plugin_id": None,
        "artifact_digest": None,
        "identity_status": "launch-bound",
        "detail": None,
    }
    payload["event_id"] = event_id(payload)
    return json.dumps(payload, separators=(",", ":")).encode()


def scheduler_event(*, controller_instance: str) -> bytes:
    payload = json.loads(host_event())
    payload.update(
        {
            "observation_kind": "scheduler_dispatch",
            "occurrence_id": 1,
            "controller_instance_id": controller_instance,
            "invocation_seq": 1,
            "detail": "engine-core.scheduler:selected",
        }
    )
    process = payload["process"]
    material = json.dumps(
        [
            process["host"],
            process["start_identity"],
            process["process_epoch"],
            payload["plan_id"],
            payload["launch_id"],
            controller_instance,
            1,
        ],
        separators=(",", ":"),
    ).encode()
    payload["dispatch_id"] = hashlib.sha256(material).hexdigest()
    payload["event_id"] = event_id(payload)
    return json.dumps(payload, separators=(",", ":")).encode()


def write_journal(root: Path, *records: bytes) -> None:
    root.mkdir(mode=0o700)
    path = root / "host.jsonl"
    path.write_bytes(b"".join(record + b"\n" for record in records))
    path.chmod(0o600)


def observe(root: Path, *, epoch: int = 7) -> dict:
    metadata = root.stat()
    return observe_bound_invocations(
        root,
        expected_directory_identity=(metadata.st_dev, metadata.st_ino),
        plan=PLAN,
        launch_id="launch:one",
        controller_instance="controller:one",
        bindings=(BINDING,),
        required_processes=[
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": epoch,
            }
        ],
        local_host="host-a",
    )


def test_observer_binds_exact_journal_bytes_and_live_process(tmp_path):
    root = tmp_path / "journal"
    raw = host_event()
    write_journal(root, raw)

    result = observe(root)

    observed = result["obligations"][OBLIGATION.obligation_id]
    assert observed["plugin_invoked"] is True
    assert observed["coverage"] == 1.0
    assert result["complete_coverage"] is True
    assert result["effect_process_identities"][0]["pid"] == os.getpid()
    assert observed["controller_binding"] == {"source": None, "value": None}
    evidence = observed["effect_records"][0]
    assert base64.b64decode(evidence["raw_base64"]) == raw
    assert evidence["raw_sha256"] == "sha256:" + hashlib.sha256(raw).hexdigest()


def test_stale_epoch_remains_auditable_but_cannot_cover_target(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, host_event(epoch=6))

    result = observe(root)

    observed = result["obligations"][OBLIGATION.obligation_id]
    assert observed["plugin_invoked"] is False
    assert observed["coverage"] == 0.0
    assert observed["effect_records"] == []
    assert len(observed["stale_effect_records"]) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"123 (worker pool (0)) S " + b"1 " * 18 + b"424242 0 0\n",
        b"123 (worker) S " + b"1 " * 18 + b"777 0 0\n",
    ],
)
def test_proc_stat_parser_handles_spaces_and_parentheses(raw):
    assert parse_linux_start_ticks(raw) in {424242, 777}


@pytest.mark.parametrize(
    ("record", "message"),
    [
        (host_event(launch_id="launch:other"), "cross-launch"),
        (host_event(assignment_source="environment"), "cross-launch"),
    ],
)
def test_observer_rejects_cross_launch_or_non_host_identity(tmp_path, record, message):
    root = tmp_path / "journal"
    write_journal(root, record)
    with pytest.raises(HostObservationError, match=message):
        observe(root)


def test_other_entry_point_cannot_satisfy_binding(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, host_event(name="other", value="other.module:register"))

    result = observe(root)

    observed = result["obligations"][OBLIGATION.obligation_id]
    assert observed["coverage"] == 0.0
    assert observed["effect_records"] == []
    assert len(result["other_records"]) == 1


def test_plan_wide_snapshot_reports_each_obligation_separately(tmp_path):
    engine_obligation = EvidenceObligation(
        "engine-invoked", "engine_core", "invoked", (0,)
    )
    plan = Plan(
        (PLUGIN,),
        PLAN.host,
        (),
        (engine_obligation, OBLIGATION),
        PLAN.predecessor,
    )
    engine_binding = EntryPointBinding(
        BINDING.group,
        "engine-demo",
        "demo.plugin:register_engine",
        PLUGIN.id,
        engine_obligation.obligation_id,
    )
    root = tmp_path / "journal"
    write_journal(
        root,
        host_event(
            plan=plan,
            role="engine_core",
            name=engine_binding.name,
            value=engine_binding.value,
        ),
    )
    metadata = root.stat()

    result = observe_bound_invocations(
        root,
        expected_directory_identity=(metadata.st_dev, metadata.st_ino),
        plan=plan,
        launch_id="launch:one",
        controller_instance="controller:one",
        bindings=(engine_binding, BINDING),
        required_processes=[
            {
                "host": "host-a",
                "role": "engine_core",
                "ordinal": 0,
                "process_epoch": 7,
            },
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 7,
            },
        ],
        local_host="host-a",
    )

    assert result["obligations"][OBLIGATION.obligation_id]["coverage"] == 0.0
    assert result["obligations"][engine_obligation.obligation_id]["coverage"] == 1.0
    assert result["complete_coverage"] is False
    assert result["other_records"] == []


def test_scheduler_effect_must_match_manager_controller(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, scheduler_event(controller_instance="controller:other"))

    with pytest.raises(HostObservationError, match="controller identity"):
        observe(root)


def test_scheduler_effect_binds_controller_from_host_event(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, scheduler_event(controller_instance="controller:one"))

    result = observe(root)

    assert result["obligations"][OBLIGATION.obligation_id]["controller_binding"] == {
        "source": "scheduler_dispatch",
        "value": "controller:one",
    }


def test_loader_effect_does_not_claim_caller_controller(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, host_event())
    metadata = root.stat()

    result = observe_bound_invocations(
        root,
        expected_directory_identity=(metadata.st_dev, metadata.st_ino),
        plan=PLAN,
        launch_id="launch:one",
        controller_instance="controller:wrong",
        bindings=(BINDING,),
        required_processes=[
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 7,
            }
        ],
        local_host="host-a",
    )

    assert result["obligations"][OBLIGATION.obligation_id]["controller_binding"] == {
        "source": None,
        "value": None,
    }


def test_pid_reuse_or_fabricated_start_identity_is_rejected():
    pid = os.getpid()
    with pytest.raises(HostObservationError, match="start identity"):
        read_linux_process_identity(pid, f"pid:{pid}:start_ticks:1")


def test_replaced_journal_directory_identity_is_rejected(tmp_path):
    root = tmp_path / "journal"
    write_journal(root, host_event())
    metadata = root.stat()

    with pytest.raises(HostObservationError, match="directory identity changed"):
        observe_bound_invocations(
            root,
            expected_directory_identity=(metadata.st_dev, metadata.st_ino + 1),
            plan=PLAN,
            launch_id="launch:one",
            controller_instance="controller:one",
            bindings=(BINDING,),
            required_processes=[
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                }
            ],
            local_host="host-a",
        )


def test_one_logical_slot_cannot_use_two_live_processes(tmp_path):
    children = [
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        for _ in range(2)
    ]
    try:
        root = tmp_path / "journal"
        write_journal(root, *(host_event(pid=child.pid) for child in children))
        with pytest.raises(HostObservationError, match="multiple live identities"):
            observe(root)
    finally:
        for child in children:
            child.terminate()
        for child in children:
            child.wait()


def test_one_linux_identity_cannot_cover_two_plan_obligations(tmp_path):
    engine_obligation = EvidenceObligation(
        "engine-invoked", "engine_core", "invoked", (0,)
    )
    plan = Plan(
        (PLUGIN,),
        PLAN.host,
        (),
        (engine_obligation, OBLIGATION),
        PLAN.predecessor,
    )
    engine_binding = EntryPointBinding(
        BINDING.group,
        "engine-demo",
        "demo.plugin:register_engine",
        PLUGIN.id,
        engine_obligation.obligation_id,
    )
    root = tmp_path / "journal"
    write_journal(
        root,
        host_event(
            plan=plan,
            role="engine_core",
            name=engine_binding.name,
            value=engine_binding.value,
        ),
        host_event(plan=plan),
    )
    metadata = root.stat()

    with pytest.raises(HostObservationError, match="multiple target slots"):
        observe_bound_invocations(
            root,
            expected_directory_identity=(metadata.st_dev, metadata.st_ino),
            plan=plan,
            launch_id="launch:one",
            controller_instance="controller:one",
            bindings=(engine_binding, BINDING),
            required_processes=[
                {
                    "host": "host-a",
                    "role": "engine_core",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
            ],
            local_host="host-a",
        )


def test_exec_cannot_make_one_linux_identity_cover_two_roles(tmp_path, monkeypatch):
    engine_obligation = EvidenceObligation(
        "engine-invoked", "engine_core", "invoked", (0,)
    )
    plan = Plan(
        (PLUGIN,),
        PLAN.host,
        (),
        (engine_obligation, OBLIGATION),
        PLAN.predecessor,
    )
    engine_binding = EntryPointBinding(
        BINDING.group,
        "engine-demo",
        "demo.plugin:register_engine",
        PLUGIN.id,
        engine_obligation.obligation_id,
    )
    root = tmp_path / "journal"
    write_journal(
        root,
        host_event(
            plan=plan,
            role="engine_core",
            name=engine_binding.name,
            value=engine_binding.value,
        ),
        host_event(plan=plan),
    )
    metadata = root.stat()
    calls = 0

    def changing_argv(pid, expected_start_identity):
        nonlocal calls
        calls += 1
        return {
            "pid": pid,
            "start_ticks": 424242,
            "start_identity": expected_start_identity,
            "argv": [f"program-after-exec-{calls}"],
        }

    monkeypatch.setattr(
        "vllm_hust_ext.host_observer.read_linux_process_identity", changing_argv
    )

    with pytest.raises(HostObservationError, match="multiple target slots"):
        observe_bound_invocations(
            root,
            expected_directory_identity=(metadata.st_dev, metadata.st_ino),
            plan=plan,
            launch_id="launch:one",
            controller_instance="controller:one",
            bindings=(engine_binding, BINDING),
            required_processes=[
                {
                    "host": "host-a",
                    "role": "engine_core",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
                {
                    "host": "host-a",
                    "role": "worker",
                    "ordinal": 0,
                    "process_epoch": 7,
                },
            ],
            local_host="host-a",
        )
