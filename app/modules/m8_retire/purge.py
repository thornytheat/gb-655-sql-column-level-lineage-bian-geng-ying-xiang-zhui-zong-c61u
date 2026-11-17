"""原文净化：把批次与快照载荷里的原文抹成不可回读的形状。

纯函数，返回新字典；落库由编排层负责。抹除后结构保留，
页面与对账接口照常工作，只是再也读不到原文。
"""

from __future__ import annotations

import copy

from app.modules.m6_batches import history

# 原文落点：消费者 SQL、隔离行原文、快照诊断原文
_QUARANTINE_KEYS = ("quarantine", "quarantine_old", "quarantine_new")


def scrub_run(run: dict, job_id: str, at: str) -> dict:
    """抹掉批次载荷里的 SQL 原文与隔离行原文，打上销毁标记。"""
    out = copy.deepcopy(run)
    refs = out.get("refs") or {}
    for consumer in refs.get("consumers") or []:
        consumer["sql"] = None
        consumer["sql_retired"] = True
    for key in _QUARANTINE_KEYS:
        for row in out.get(key) or []:
            row["raw"] = None
    out["retired"] = {"job_id": job_id, "at": at, "reason": "RETIRE_COMPLETED"}
    out["summary"] = history.summary_of(out)
    return out


def scrub_snapshot(snapshot: dict) -> dict:
    """抹掉快照诊断里的原文行，列级结构保留。"""
    out = copy.deepcopy(snapshot)
    for row in out.get("diagnostics") or []:
        row["raw"] = None
    return out
