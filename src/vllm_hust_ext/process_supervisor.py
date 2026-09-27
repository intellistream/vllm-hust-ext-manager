"""Signal-safe supervision for commands launched by the Manager."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from types import FrameType

DEFAULT_SHUTDOWN_GRACE_SECONDS = 10.0
_POLL_SECONDS = 0.05
_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)


def _managed_signals() -> tuple[signal.Signals, ...]:
    names = ("SIGTERM", "SIGINT", "SIGHUP")
    return tuple(getattr(signal, name) for name in names if hasattr(signal, name))


def _signal_launch_tree(process: subprocess.Popen[object], signum: int) -> None:
    """Signal the launch tree without ever signalling the Manager itself."""

    if os.name == "posix":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signum)
        return
    if signum == _KILL_SIGNAL:
        process.kill()
    else:
        process.terminate()


def _launch_tree_exists(process: subprocess.Popen[object]) -> bool:
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_launch_tree(process: subprocess.Popen[object], deadline: float) -> bool:
    while _launch_tree_exists(process):
        if time.monotonic() >= deadline:
            return False
        time.sleep(_POLL_SECONDS)
    return True


def _cleanup_survivors(process: subprocess.Popen[object], deadline: float) -> None:
    """Stop descendants that outlive the direct child."""

    if not _launch_tree_exists(process):
        return
    _signal_launch_tree(process, signal.SIGTERM)
    if _wait_for_launch_tree(process, deadline):
        return
    _signal_launch_tree(process, _KILL_SIGNAL)


def supervise(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    shutdown_grace_seconds: float = DEFAULT_SHUTDOWN_GRACE_SECONDS,
) -> int:
    """Run a command and own the lifetime of the process tree it creates.

    On POSIX the child becomes a new session leader. Signals received by the
    Manager are forwarded to that launch group; a second signal or expiration
    of the grace period escalates to SIGKILL. The direct child is always reaped,
    and surviving descendants are terminated before the Manager returns.
    """

    if shutdown_grace_seconds < 0:
        raise ValueError("shutdown grace period must not be negative")

    child: subprocess.Popen[object] | None = None
    received: list[int] = []
    signal_started_at: list[float] = []
    previous_handlers: dict[signal.Signals, object] = {}

    def forward(signum: int, _frame: FrameType | None) -> None:
        first_signal = not received
        received.append(signum)
        if first_signal:
            signal_started_at.append(time.monotonic())
        if child is not None:
            forwarded = _KILL_SIGNAL if len(received) > 1 else signum
            _signal_launch_tree(child, forwarded)

    managed_signals = _managed_signals()
    for managed_signal in managed_signals:
        previous_handlers[managed_signal] = signal.getsignal(managed_signal)
        signal.signal(managed_signal, forward)

    try:
        popen_options: dict[str, object] = {"env": dict(env)}
        if os.name == "posix":
            popen_options["start_new_session"] = True
        child = subprocess.Popen(command, **popen_options)
        if received:
            _signal_launch_tree(child, received[0])

        escalated = False
        while True:
            try:
                return_code = child.wait(timeout=_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                if (
                    received
                    and not escalated
                    and time.monotonic() - signal_started_at[0]
                    >= shutdown_grace_seconds
                ):
                    _signal_launch_tree(child, _KILL_SIGNAL)
                    escalated = True

        cleanup_deadline = (
            signal_started_at[0] + shutdown_grace_seconds
            if received
            else time.monotonic() + shutdown_grace_seconds
        )
        _cleanup_survivors(child, cleanup_deadline)
        if received:
            return 128 + received[0]
        return return_code
    finally:
        if child is not None and child.poll() is None:
            _signal_launch_tree(child, _KILL_SIGNAL)
            child.wait()
        for managed_signal, previous_handler in previous_handlers.items():
            signal.signal(managed_signal, previous_handler)
