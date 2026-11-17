"""列级证据：从批次载荷里抽出迁移争议核查所需的全部结构化事实。

证据只保留列级信息（字段、类型、引用列、影响路径、判定与账目）；
SQL 原文与隔离行原文一律不进证据，敏感常量随原文一起销毁。
"""

from __future__ import annotations

import hashlib
import json

# 证据里允许出现的消费者字段；sql 是原文，明确排除
_CONSUMER_KEYS = ("name", "kind", "refs", "aliases", "unresolved", "upstream", "downstream")
# 隔离行里允许出现的字段；raw 是原文行，明确排除
_QUARANTINE_KEYS = ("line", "table", "column", "reason", "blocking", "detail", "side")


def evidence_id_for(run_id: str) -> str:
    """证据身份只由批次决定：重试与跨任务恢复都落到同一行，不重复登记。"""
    return "ev-" + hashlib.sha256(f"evidence:{run_id}".encode("utf-8")).hexdigest()[:12]


def _consumers(run: dict) -> list[dict]:
    refs = run.get("refs") or {}
    return [
        {key: consumer.get(key) for key in _CONSUMER_KEYS}
        for consumer in (refs.get("consumers") or [])
    ]


def _quarantine(run: dict) -> list[dict]:
    return [
        {key: row.get(key) for key in _QUARANTINE_KEYS}
        for row in (run.get("quarantine") or [])
    ]


def build_payload(run: dict) -> dict:
    """冻结内容：影响路径（变更列 → 引用 → 受影响节点）与列级账目。"""
    return {
        "run_id": run["run_id"],
        "batch_key": run["batch_key"],
        "ruleset": run.get("ruleset"),
        "created_at": run.get("created_at"),
        "window": run.get("window") or {},
        "version_labels": {
            "old": run.get("version_label_old"),
            "new": run.get("version_label_new"),
        },
        "input_sha256": run.get("input_sha256"),
        "input_digests": run.get("digests") or {},
        "input_names": run.get("input_names") or {},
        "fields_old": run.get("fields_old") or [],
        "fields_new": run.get("fields_new") or [],
        "diff": run.get("diff") or [],
        "buckets": run.get("buckets") or {},
        "verdicts": run.get("verdicts") or [],
        "mapping": run.get("mapping") or {},
        "consumers": _consumers(run),
        "resolution": run.get("resolution") or {},
        "impact": run.get("impact") or {},
        "ledger": run.get("ledger") or {},
        "quarantine": _quarantine(run),
        "warnings": run.get("warnings") or [],
    }


def sha256_payload(payload: dict) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build(run: dict, job_id: str, frozen_at: str) -> dict:
    payload = build_payload(run)
    return {
        "evidence_id": evidence_id_for(run["run_id"]),
        "job_id": job_id,
        "run_id": run["run_id"],
        "sha256": sha256_payload(payload),
        "frozen_at": frozen_at,
        "payload": payload,
    }
