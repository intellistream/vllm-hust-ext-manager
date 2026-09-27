import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from vllm_hust_ext.process_supervisor import supervise


def _proc_is_live(pid: int) -> bool:
    try:
        state = (
            Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1][0]
        )
    except FileNotFoundError:
        return False
    return state != "Z"


def test_supervisor_preserves_normal_exit_code() -> None:
    previous_handler = signal.getsignal(signal.SIGTERM)
    result = supervise(
        [sys.executable, "-c", "raise SystemExit(23)"],
        env=os.environ,
        shutdown_grace_seconds=0.1,
    )

    assert result == 23
    assert signal.getsignal(signal.SIGTERM) == previous_handler


def test_supervisor_rejects_negative_grace_period() -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        supervise(
            [sys.executable, "-c", "raise SystemExit(0)"],
            env=os.environ,
            shutdown_grace_seconds=-1,
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_supervisor_removes_descendant_after_parent_exits(tmp_path: Path) -> None:
    worker_pid_path = tmp_path / "orphan.pid"
    child_code = """
import signal
import subprocess
import sys

worker = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
])
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    stream.write(str(worker.pid))
"""

    result = supervise(
        [sys.executable, "-c", child_code, str(worker_pid_path)],
        env=os.environ,
        shutdown_grace_seconds=0.2,
    )

    assert result == 0
    worker_pid = int(worker_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 1
    while _proc_is_live(worker_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _proc_is_live(worker_pid)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_supervisor_escalates_and_removes_stubborn_descendants(
    tmp_path: Path,
) -> None:
    worker_pid_path = tmp_path / "worker.pid"
    child_code = """
import os
import signal
import subprocess
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
worker = subprocess.Popen([
    sys.executable,
    "-c",
    "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
])
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    stream.write(str(worker.pid))
while True:
    time.sleep(1)
"""

    def interrupt_when_ready() -> None:
        deadline = time.monotonic() + 5
        while not worker_pid_path.exists():
            if time.monotonic() >= deadline:
                return
            time.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)

    interrupter = threading.Thread(target=interrupt_when_ready)
    interrupter.start()
    started_at = time.monotonic()
    result = supervise(
        [sys.executable, "-c", child_code, str(worker_pid_path)],
        env=os.environ,
        shutdown_grace_seconds=0.2,
    )
    interrupter.join(timeout=1)

    assert result == 128 + signal.SIGTERM
    assert time.monotonic() - started_at < 3
    worker_pid = int(worker_pid_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 1
    while _proc_is_live(worker_pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not _proc_is_live(worker_pid)


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group contract")
def test_second_signal_escalates_without_waiting_for_grace(tmp_path: Path) -> None:
    ready_path = tmp_path / "ready"
    child_code = """
import signal
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
open(sys.argv[1], "w", encoding="utf-8").close()
while True:
    time.sleep(1)
"""

    def interrupt_twice() -> None:
        deadline = time.monotonic() + 5
        while not ready_path.exists():
            if time.monotonic() >= deadline:
                return
            time.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(0.05)
        os.kill(os.getpid(), signal.SIGTERM)

    interrupter = threading.Thread(target=interrupt_twice)
    interrupter.start()
    started_at = time.monotonic()
    result = supervise(
        [sys.executable, "-c", child_code, str(ready_path)],
        env=os.environ,
        shutdown_grace_seconds=5,
    )
    interrupter.join(timeout=1)

    assert result == 128 + signal.SIGTERM
    assert time.monotonic() - started_at < 2
