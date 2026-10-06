#!/usr/bin/env python3
"""Run an isolated Mooncake Store REST put/get/remove acceptance probe.

The operator owns the temporary Mooncake processes.  This script deliberately
does not use ``remove_all`` and removes only the unique key it creates.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


def request(
    method: str,
    url: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 2.0,
) -> tuple[int, bytes]:
    headers = {"Content-Type": content_type} if content_type else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_for_http(url: str, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"store service exited early with {process.returncode}")
        try:
            status, _body = request("GET", url)
            if status in {200, 404}:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"store service did not become reachable at {url}")


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def tail(path: Path, limit: int = 12000) -> str:
    if not path.exists():
        return ""
    return path.read_text(errors="replace")[-limit:]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--master-port", type=int, default=25051)
    parser.add_argument("--metadata-port", type=int, default=28081)
    parser.add_argument("--rest-port", type=int, default=28082)
    parser.add_argument("--metrics-port", type=int, default=29003)
    parser.add_argument("--transfer-port", type=int, default=15091)
    parser.add_argument("--lease-ttl-ms", type=int, default=1000)
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    args = parser.parse_args()

    master_binary = args.bin_dir / "mooncake_master"
    service_binary = args.bin_dir / "mc_store_rest_server"
    if not master_binary.exists() or not service_binary.exists():
        raise FileNotFoundError("Mooncake console scripts are missing from --bin-dir")

    master: subprocess.Popen[bytes] | None = None
    service: subprocess.Popen[bytes] | None = None
    with tempfile.TemporaryDirectory(prefix="vllmhust-mooncake-store-") as temp_name:
        temp = Path(temp_name)
        config_path = temp / "config.json"
        master_log_path = temp / "master.log"
        service_log_path = temp / "service.log"
        config_path.write_text(
            json.dumps(
                {
                    "local_hostname": f"127.0.0.1:{args.transfer_port}",
                    "metadata_server": (
                        f"http://127.0.0.1:{args.metadata_port}/metadata"
                    ),
                    "global_segment_size": 64 * 1024 * 1024,
                    "local_buffer_size": 16 * 1024 * 1024,
                    "protocol": "tcp",
                    "device_name": "",
                    "master_server_address": f"127.0.0.1:{args.master_port}",
                    "enable_ssd_offload": False,
                    "tenant_id": "vllmhust-probe",
                }
            )
        )

        try:
            with (
                master_log_path.open("wb") as master_log,
                service_log_path.open("wb") as service_log,
            ):
                master = subprocess.Popen(
                    [
                        os.fspath(master_binary),
                        f"--rpc_port={args.master_port}",
                        "--enable_http_metadata_server=true",
                        "--http_metadata_server_host=127.0.0.1",
                        f"--http_metadata_server_port={args.metadata_port}",
                        f"--metrics_port={args.metrics_port}",
                        "--enable_metric_reporting=false",
                        f"--default_kv_lease_ttl={args.lease_ttl_ms}",
                        "--logtostderr=true",
                    ],
                    stdout=master_log,
                    stderr=subprocess.STDOUT,
                )
                time.sleep(1)
                if master.poll() is not None:
                    raise RuntimeError(f"master exited early with {master.returncode}")

                service = subprocess.Popen(
                    [
                        os.fspath(service_binary),
                        "--config",
                        os.fspath(config_path),
                        "--port",
                        str(args.rest_port),
                        "--max-wait-time",
                        str(args.startup_timeout),
                    ],
                    stdout=service_log,
                    stderr=subprocess.STDOUT,
                )
                base_url = f"http://127.0.0.1:{args.rest_port}"
                wait_for_http(
                    f"{base_url}/api/exist/__vllmhust_readiness__",
                    service,
                    args.startup_timeout,
                )

                key = f"vllmhust-probe-{uuid.uuid4().hex}"
                value = f"mooncake-store-roundtrip-{uuid.uuid4().hex}"
                payload = json.dumps({"key": key, "value": value}).encode()
                put_status, put_body = request(
                    "PUT",
                    f"{base_url}/api/put",
                    body=payload,
                    content_type="application/json",
                )
                exist_status, exist_body = request("GET", f"{base_url}/api/exist/{key}")
                get_status, get_body = request("GET", f"{base_url}/api/get/{key}")
                # A read renews Mooncake's hard lease.  The REST remove endpoint
                # intentionally does not expose force deletion, so honor the
                # configured lease instead of bypassing Store ownership rules.
                time.sleep(args.lease_ttl_ms / 1000 + 0.25)
                remove_status, remove_body = request(
                    "DELETE", f"{base_url}/api/remove/{key}"
                )
                missing_status, _missing_body = request(
                    "GET", f"{base_url}/api/get/{key}"
                )

                result = {
                    "key": key,
                    "bytes": len(value.encode()),
                    "put_status": put_status,
                    "put_response": put_body.decode(errors="replace"),
                    "exist_status": exist_status,
                    "exists": json.loads(exist_body).get("exists"),
                    "get_status": get_status,
                    "value_matches": get_body == value.encode(),
                    "remove_status": remove_status,
                    "remove_response": remove_body.decode(errors="replace"),
                    "missing_after_remove_status": missing_status,
                }
                print(json.dumps(result, indent=2, sort_keys=True))
                passed = (
                    put_status == 200
                    and exist_status == 200
                    and result["exists"] is True
                    and get_status == 200
                    and result["value_matches"] is True
                    and remove_status == 200
                    and missing_status == 404
                )
                if not passed:
                    raise RuntimeError("Mooncake Store REST round trip failed")
        except Exception:
            print("--- mooncake master log ---", file=sys.stderr)
            print(tail(master_log_path), file=sys.stderr)
            print("--- mooncake store service log ---", file=sys.stderr)
            print(tail(service_log_path), file=sys.stderr)
            raise
        finally:
            stop_process(service)
            stop_process(master)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
