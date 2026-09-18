import sqlite3

import pytest

from vllm_hust_ext.durable_coordinator import SQLiteActivationStore

LEGACY_COLUMNS = (
    "nonce,plan_id,launch_id,process_key,role,ordinal,epoch,obligation_id,event,"
    "issued_at,expires_at,artifact_id,authority,manager_epoch,valid"
)


def create_legacy(path, partial=False):
    connection = sqlite3.connect(path)
    suffix = ", issuer TEXT NOT NULL DEFAULT ''" if partial else ""
    connection.execute(
        "CREATE TABLE evidence ("
        "nonce TEXT PRIMARY KEY, plan_id TEXT, launch_id TEXT, process_key TEXT,"
        "role TEXT, ordinal INTEGER, epoch INTEGER, obligation_id TEXT, event TEXT,"
        "issued_at INTEGER, expires_at INTEGER, artifact_id TEXT, authority TEXT,"
        f"manager_epoch INTEGER, valid INTEGER{suffix})"
    )
    connection.execute(
        f"INSERT INTO evidence ({LEGACY_COLUMNS}) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            "legacy-nonce",
            "legacy-plan",
            "legacy-launch",
            "host/worker/0/start/1",
            "worker",
            0,
            1,
            "loaded",
            "loaded",
            10,
            20,
            "legacy-artifact",
            "host-runtime",
            3,
            1,
        ),
    )
    connection.commit()
    connection.close()


@pytest.mark.parametrize("partial", [False, True])
def test_legacy_evidence_migration_is_idempotent_and_preserves_rows(tmp_path, partial):
    path = tmp_path / f"legacy-{partial}.db"
    create_legacy(path, partial)

    store = SQLiteActivationStore(path)
    columns = {
        row[1] for row in store.connection.execute("PRAGMA table_info(evidence)")
    }
    assert {
        "issuer",
        "kid",
        "observed_at",
        "evidence_digest",
        "artifact_digest",
    } <= columns
    row = store.connection.execute(
        "SELECT nonce,plan_id,issued_at,expires_at,valid,issuer,kid,observed_at,"
        "evidence_digest,artifact_digest FROM evidence"
    ).fetchone()
    assert tuple(row) == (
        "legacy-nonce",
        "legacy-plan",
        10,
        20,
        1,
        "",
        "",
        0,
        "",
        "",
    )
    assert store.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    store.close()

    reopened = SQLiteActivationStore(path)
    assert (
        reopened.connection.execute("SELECT count(*) FROM evidence").fetchone()[0] == 1
    )
    assert reopened.connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    reopened.boot()
    assert reopened.connection.execute("SELECT valid FROM evidence").fetchone()[0] == 0
    assert tuple(
        reopened.connection.execute(
            "SELECT nonce,plan_id,issued_at,expires_at FROM evidence"
        ).fetchone()
    ) == ("legacy-nonce", "legacy-plan", 10, 20)
    reopened.close()
