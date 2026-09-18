import sqlite3

from vllm_hust_ext.durable_coordinator import SQLiteActivationStore


def test_legacy_evidence_table_is_additively_migrated(tmp_path):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE evidence ("
        "nonce TEXT PRIMARY KEY, plan_id TEXT, launch_id TEXT, process_key TEXT,"
        "role TEXT, ordinal INTEGER, epoch INTEGER, obligation_id TEXT, event TEXT,"
        "issued_at INTEGER, expires_at INTEGER, artifact_id TEXT, authority TEXT,"
        "manager_epoch INTEGER, valid INTEGER)"
    )
    connection.commit()
    connection.close()

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
    store.close()
