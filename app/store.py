"""SQLite 读写：批次快照、运行清单、隔离行、键值状态。

只放数据访问，不放判定；调用方拿到的是普通字典。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

from app import config

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    schema_id      TEXT PRIMARY KEY,
    version_label  TEXT NOT NULL,
    source_path    TEXT NOT NULL,
    source_sha256  TEXT NOT NULL,
    encoding       TEXT NOT NULL,
    bom            INTEGER NOT NULL,
    field_count    INTEGER NOT NULL,
    blocked_count  INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    batch_key      TEXT NOT NULL UNIQUE,
    old_schema_id  TEXT NOT NULL,
    new_schema_id  TEXT NOT NULL,
    version_seq    INTEGER NOT NULL,
    input_sha256   TEXT NOT NULL,
    ruleset        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to   TEXT,
    summary_json   TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    schema_id     TEXT NOT NULL,
    line          INTEGER,
    table_name    TEXT,
    column_name   TEXT,
    reason        TEXT NOT NULL,
    blocking      INTEGER NOT NULL,
    detail        TEXT,
    raw           TEXT
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retire_jobs (
    job_id          TEXT PRIMARY KEY,
    run_id          TEXT NOT NULL,
    batch_key       TEXT NOT NULL,
    status          TEXT NOT NULL,
    phase           TEXT NOT NULL,
    input_sha256    TEXT NOT NULL,
    digests_json    TEXT NOT NULL,
    paths_json      TEXT NOT NULL,
    run_ids_json    TEXT NOT NULL,
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    certificate_json TEXT,
    error           TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retire_evidence (
    evidence_id  TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL,
    run_id       TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    frozen_at    TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS retire_steps (
    job_id  TEXT NOT NULL,
    step    TEXT NOT NULL,
    target  TEXT NOT NULL,
    done_at TEXT NOT NULL,
    PRIMARY KEY (job_id, step, target)
);
CREATE TABLE IF NOT EXISTS destroyed_inputs (
    digest       TEXT PRIMARY KEY,
    job_id       TEXT NOT NULL,
    destroyed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_schema ON quarantine(schema_id);
CREATE INDEX IF NOT EXISTS idx_retire_jobs_run ON retire_jobs(run_id);
CREATE INDEX IF NOT EXISTS idx_retire_jobs_batch ON retire_jobs(batch_key);
"""


def db_path() -> Path:
    raw = os.environ.get("LINEAGEGUARD_DB", "").strip()
    path = Path(raw) if raw else config.DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)


def reset() -> None:
    """测试与重建用：清空全部业务表。"""
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)
        for table in ("snapshots", "runs", "quarantine", "kv",
                      "retire_jobs", "retire_evidence", "retire_steps",
                      "destroyed_inputs"):
            conn.execute(f"DELETE FROM {table}")


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value):
    if not value:
        return None
    return json.loads(value)


# ---------- 快照 ----------

def save_snapshot(snapshot: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO snapshots (schema_id, version_label, source_path, source_sha256,
                   encoding, bom, field_count, blocked_count, created_at, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(schema_id) DO UPDATE SET
                   version_label=excluded.version_label,
                   source_path=excluded.source_path,
                   source_sha256=excluded.source_sha256,
                   encoding=excluded.encoding,
                   bom=excluded.bom,
                   field_count=excluded.field_count,
                   blocked_count=excluded.blocked_count,
                   created_at=excluded.created_at,
                   payload_json=excluded.payload_json""",
            (
                snapshot["schema_id"], snapshot["version_label"], snapshot["source_path"],
                snapshot["source_sha256"], snapshot["encoding"], int(bool(snapshot["bom"])),
                int(snapshot["field_count"]), int(snapshot["blocked_count"]),
                snapshot["created_at"], _dumps(snapshot),
            ),
        )


def load_snapshot(schema_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM snapshots WHERE schema_id=?", (schema_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def find_snapshots_by_sha(source_sha256: str) -> list[dict]:
    """按输入内容摘要找持久化副本；同一文件可能采信成多份快照。"""
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT payload_json FROM snapshots WHERE source_sha256=? ORDER BY schema_id",
            (source_sha256,),
        ).fetchall()
    return [_loads(row["payload_json"]) for row in rows]


def list_snapshots(limit: int = 20) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT schema_id, version_label, source_path, source_sha256, encoding, bom,
                      field_count, blocked_count, created_at
               FROM snapshots ORDER BY created_at DESC, schema_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_quarantine(schema_id: str, rows: list[dict]) -> None:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM quarantine WHERE schema_id=?", (schema_id,))
        conn.executemany(
            """INSERT INTO quarantine (schema_id, line, table_name, column_name, reason,
                   blocking, detail, raw) VALUES (?,?,?,?,?,?,?,?)""",
            [
                (
                    schema_id, int(row.get("line") or 0), row.get("table") or "",
                    row.get("column") or "", row["reason"], int(bool(row.get("blocking"))),
                    row.get("detail") or "", row.get("raw") or "",
                )
                for row in rows
            ],
        )


def list_quarantine(schema_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT line, table_name, column_name, reason, blocking, detail, raw
               FROM quarantine WHERE schema_id=? ORDER BY line, reason""",
            (schema_id,),
        ).fetchall()
    return [
        {
            "line": row["line"],
            "table": row["table_name"],
            "column": row["column_name"],
            "reason": row["reason"],
            "blocking": bool(row["blocking"]),
            "detail": row["detail"],
            "raw": row["raw"],
        }
        for row in rows
    ]


# ---------- 运行清单 ----------

def save_run(run: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id, version_seq,
                   input_sha256, ruleset, created_at, effective_from, effective_to,
                   summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["run_id"], run["batch_key"], run["old_schema_id"], run["new_schema_id"],
                int(run["version_seq"]), run["input_sha256"], run["ruleset"],
                run["created_at"], run["effective_from"], run["effective_to"],
                _dumps(run["summary"]), _dumps(run),
            ),
        )


def find_run_by_key(batch_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE batch_key=?", (batch_key,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def run_by_id(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def latest_run() -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs ORDER BY version_seq DESC LIMIT 1"
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_runs(limit: int = 30) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT summary_json FROM runs ORDER BY version_seq DESC, run_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_loads(row["summary_json"]) for row in rows]


def count_runs() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    return int(row["n"])


def next_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"]) + 1


def current_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"])


def list_windows() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT run_id, effective_from, effective_to FROM runs ORDER BY version_seq"
        ).fetchall()
    return [dict(row) for row in rows]


# ---------- 键值 ----------

def set_kv(key: str, value) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO kv (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, _dumps(value)),
        )


def get_kv(key: str, default=None):
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return _loads(row["v"]) if row else default


# ---------- 销毁：运行清单改写与并发守卫 ----------

def list_run_payloads() -> list[dict]:
    """全量批次原文载体，级联查找共用输入的批次时用。"""
    with _LOCK, _connect() as conn:
        rows = conn.execute("SELECT payload_json FROM runs ORDER BY version_seq").fetchall()
    return [_loads(row["payload_json"]) for row in rows]


def update_run_payload(run: dict) -> None:
    """按 run_id 重写批次载荷与摘要；只覆盖内容，不改身份列。"""
    with _LOCK, _connect() as conn:
        conn.execute(
            "UPDATE runs SET summary_json=?, payload_json=? WHERE run_id=?",
            (_dumps(run.get("summary") or {}), _dumps(run), run["run_id"]),
        )


def update_snapshot_payload(snapshot: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            "UPDATE snapshots SET payload_json=? WHERE schema_id=?",
            (_dumps(snapshot), snapshot["schema_id"]),
        )


def scrub_quarantine_raw(schema_id: str) -> None:
    """隔离区原文列清空，行结构与原因码保留。"""
    with _LOCK, _connect() as conn:
        conn.execute("UPDATE quarantine SET raw='' WHERE schema_id=?", (schema_id,))


def save_run_if_clean(run: dict) -> dict | None:
    """检查与写入同锁：批次涉销毁或输入已登记销毁时不写，返回冲突描述。"""
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT job_id, status FROM retire_jobs WHERE batch_key=?",
            (run["batch_key"],),
        ).fetchone()
        if row:
            return {"reason": "RUN_RETIRED", "job_id": row["job_id"],
                    "status": row["status"]}
        for role, digest in sorted((run.get("digests") or {}).items()):
            hit = conn.execute(
                "SELECT job_id FROM destroyed_inputs WHERE digest=?", (digest,)
            ).fetchone()
            if hit:
                return {"reason": "INPUT_DESTROYED", "role": role,
                        "digest": digest, "job_id": hit["job_id"]}
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id, version_seq,
                   input_sha256, ruleset, created_at, effective_from, effective_to,
                   summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["run_id"], run["batch_key"], run["old_schema_id"], run["new_schema_id"],
                int(run["version_seq"]), run["input_sha256"], run["ruleset"],
                run["created_at"], run["effective_from"], run["effective_to"],
                _dumps(run["summary"]), _dumps(run),
            ),
        )
    return None


# ---------- 销毁：任务、证据、步骤、已销毁输入 ----------

def create_retire_job(job: dict) -> bool:
    """登记销毁任务；同 job_id 已存在时不重复登记，返回 False。"""
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO retire_jobs
                   (job_id, run_id, batch_key, status, phase, input_sha256,
                    digests_json, paths_json, run_ids_json, evidence_json,
                    certificate_json, error, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                job["job_id"], job["run_id"], job["batch_key"], job["status"],
                job["phase"], job["input_sha256"], _dumps(job["digests"]),
                _dumps(job["paths"]), _dumps(job["run_ids"]),
                _dumps(job.get("evidence") or {}), job.get("certificate_json"),
                job.get("error"), job["created_at"], job["updated_at"],
            ),
        )
    return cursor.rowcount > 0


def _retire_job_view(row) -> dict:
    return {
        "job_id": row["job_id"],
        "run_id": row["run_id"],
        "batch_key": row["batch_key"],
        "status": row["status"],
        "phase": row["phase"],
        "input_sha256": row["input_sha256"],
        "digests": _loads(row["digests_json"]) or {},
        "paths": _loads(row["paths_json"]) or {},
        "run_ids": _loads(row["run_ids_json"]) or [],
        "evidence": _loads(row["evidence_json"]) or {},
        "certificate": _loads(row["certificate_json"]),
        "error": row["error"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def get_retire_job(job_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM retire_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
    return _retire_job_view(row) if row else None


def find_retire_job_by_batch(batch_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM retire_jobs WHERE batch_key=? ORDER BY created_at DESC LIMIT 1",
            (batch_key,),
        ).fetchone()
    return _retire_job_view(row) if row else None


def find_retire_job_by_run(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        rows = conn.execute("SELECT * FROM retire_jobs").fetchall()
    for row in rows:
        view = _retire_job_view(row)
        if run_id in view["run_ids"]:
            return view
    return None


def list_retire_jobs(limit: int = 30) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM retire_jobs ORDER BY created_at DESC, job_id LIMIT ?", (limit,)
        ).fetchall()
    return [_retire_job_view(row) for row in rows]


def update_retire_job(job_id: str, **fields) -> None:
    """只更新允许的列；certificate 传 dict 时在这里序列化。"""
    allowed = {"status", "phase", "error", "updated_at"}
    sets: list[str] = []
    values: list = []
    for key, value in fields.items():
        if key in allowed:
            sets.append(f"{key}=?")
            values.append(value)
        elif key == "certificate":
            sets.append("certificate_json=?")
            values.append(_dumps(value))
        elif key == "evidence":
            sets.append("evidence_json=?")
            values.append(_dumps(value))
    if not sets:
        return
    values.append(job_id)
    with _LOCK, _connect() as conn:
        conn.execute(f"UPDATE retire_jobs SET {', '.join(sets)} WHERE job_id=?", values)


def save_retire_evidence(evidence: dict) -> None:
    """冻结列级证据；同 evidence_id 重试不重复登记。"""
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO retire_evidence
                   (evidence_id, job_id, run_id, sha256, frozen_at, payload_json)
               VALUES (?,?,?,?,?,?)""",
            (
                evidence["evidence_id"], evidence["job_id"], evidence["run_id"],
                evidence["sha256"], evidence["frozen_at"], _dumps(evidence["payload"]),
            ),
        )


def get_retire_evidence(evidence_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT * FROM retire_evidence WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "evidence_id": row["evidence_id"],
        "job_id": row["job_id"],
        "run_id": row["run_id"],
        "sha256": row["sha256"],
        "frozen_at": row["frozen_at"],
        "payload": _loads(row["payload_json"]),
    }


def retire_evidence_for_job(job_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT evidence_id, run_id, sha256, frozen_at FROM retire_evidence"
            " WHERE job_id=? ORDER BY run_id",
            (job_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def retire_step_done(job_id: str, step: str, target: str, done_at: str) -> None:
    """步骤完成登记；主键去重，断点重跑同一目标不重复记账。"""
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO retire_steps (job_id, step, target, done_at)"
            " VALUES (?,?,?,?)",
            (job_id, step, target, done_at),
        )


def list_retire_steps(job_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT step, target, done_at FROM retire_steps"
            " WHERE job_id=? ORDER BY done_at, step, target",
            (job_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def register_destroyed(digest: str, job_id: str, destroyed_at: str) -> None:
    """输入内容登记销毁；按内容摘要去重，换名重导也落同一个键。"""
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO destroyed_inputs (digest, job_id, destroyed_at)"
            " VALUES (?,?,?)",
            (digest, job_id, destroyed_at),
        )


def destroyed_digests() -> set[str]:
    with _LOCK, _connect() as conn:
        rows = conn.execute("SELECT digest FROM destroyed_inputs").fetchall()
    return {row["digest"] for row in rows}


def list_destroyed_inputs() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT digest, job_id, destroyed_at FROM destroyed_inputs ORDER BY destroyed_at"
        ).fetchall()
    return [dict(row) for row in rows]
