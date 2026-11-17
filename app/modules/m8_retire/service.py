"""销毁编排：冻结证据 → 清除原文 → 出具凭据，断点可恢复。

顺序约定：
1. 先把共用输入的批次闭包找出来，登记全部输入摘要（待销毁），
   从此刻起并发跑批与换名重导都会被拒；
2. 逐批次冻结列级证据，证据落库后才进入清除阶段；
3. 清除覆盖批次载荷、快照副本、隔离区原文与输入文件；
4. 凭据在所有清除步骤完成后生成。

每个动作幂等、每步先查后做：中断后重新发起，从第一个未完成的步骤继续，
已登记的步骤与证据不会重复记账。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from app import config, errors, store
from app.modules.m8_retire import certificate, evidence, purge

PHASES = ("register", "freeze", "purge", "certify")


def _now() -> str:
    return config.now_utc().isoformat()


def _job_id_for(batch_key: str) -> str:
    return "rt-" + hashlib.sha256(f"retire:{batch_key}".encode("utf-8")).hexdigest()[:12]


def _cascade(root: dict) -> list[dict]:
    """共用输入（按内容摘要）的批次传递闭包，含根批次本身。"""
    seed = set((root.get("digests") or {}).values())
    picked: dict[str, dict] = {}
    changed = True
    while changed:
        changed = False
        for run in store.list_run_payloads():
            run_id = run["run_id"]
            if run_id in picked:
                continue
            digests = set((run.get("digests") or {}).values())
            if digests & seed:
                picked[run_id] = run
                seed |= digests
                changed = True
    return [picked[key] for key in sorted(picked, key=lambda k: picked[k]["version_seq"])]


def _load_runs(run_ids: list[str]) -> list[dict]:
    return [run for run in (store.run_by_id(run_id) for run_id in run_ids) if run]


def _done_steps(job_id: str) -> set[tuple[str, str]]:
    return {(row["step"], row["target"]) for row in store.list_retire_steps(job_id)}


def _step(job_id: str, done: set[tuple[str, str]], step: str, target: str, action) -> None:
    """已完成的步骤直接跳过；动作先执行再登记，动作本身幂等。"""
    if (step, target) in done:
        return
    action()
    at = _now()
    store.retire_step_done(job_id, step, target, at)
    done.add((step, target))


def _input_files(job: dict) -> list[tuple[str, str]]:
    """任务覆盖的 (文件名, 内容摘要)，按名字去重排序。"""
    seen: dict[str, str] = {}
    for run_id in job["run_ids"]:
        names = (job["paths"] or {}).get(run_id) or {}
        digests = (job["digests"] or {}).get(run_id) or {}
        for role, name in names.items():
            if name:
                seen.setdefault(str(name), str(digests.get(role) or ""))
    return sorted(seen.items())


def _delete_input(name: str) -> None:
    """删除样例目录内的输入文件；越界名字直接拒绝，已缺失视为成功。"""
    root = config.SAMPLE_DIR.resolve()
    path = (root / name).resolve()
    if root not in path.parents:
        raise errors.BadInput("输入文件路径越出样例目录", detail={"file": name})
    path.unlink(missing_ok=True)


def _register(job: dict, done: set[tuple[str, str]]) -> None:
    """登记待销毁输入摘要：登记一刻起，跑批与采信都拒绝这些内容。"""
    store.update_retire_job(job["job_id"], phase="register", updated_at=_now())
    for run_id in job["run_ids"]:
        for digest in sorted(set(((job["digests"] or {}).get(run_id) or {}).values())):
            _step(job["job_id"], done, "register_digest", digest,
                  lambda d=digest: store.register_destroyed(d, job["job_id"], _now()))


def _freeze(job: dict, runs: list[dict], done: set[tuple[str, str]]) -> None:
    """列级证据先冻结，证据落库是清除原文的前置条件。"""
    store.update_retire_job(job["job_id"], phase="freeze", updated_at=_now())
    for run in runs:
        _step(job["job_id"], done, "freeze_evidence", run["run_id"],
              lambda r=run: store.save_retire_evidence(
                  evidence.build(r, job["job_id"], _now())))
    mapping = {run_id: evidence.evidence_id_for(run_id) for run_id in job["run_ids"]}
    store.update_retire_job(job["job_id"], evidence=mapping, updated_at=_now())


def _purge(job: dict, runs: list[dict], done: set[tuple[str, str]]) -> None:
    """清除原文：批次载荷、快照副本、隔离区、输入文件，一个都不落。"""
    store.update_retire_job(job["job_id"], phase="purge", updated_at=_now())
    at = _now()
    for run in runs:
        _step(job["job_id"], done, "purge_run_payload", run["run_id"],
              lambda r=run: store.update_run_payload(
                  purge.scrub_run(r, job["job_id"], at)))
    digests = {
        digest
        for run_id in job["run_ids"]
        for digest in (((job["digests"] or {}).get(run_id) or {}).values())
    }
    for digest in sorted(digests):
        for snapshot in store.find_snapshots_by_sha(digest):
            schema_id = snapshot["schema_id"]
            _step(job["job_id"], done, "purge_snapshot", schema_id,
                  lambda s=snapshot: store.update_snapshot_payload(
                      purge.scrub_snapshot(s)))
            _step(job["job_id"], done, "purge_quarantine", schema_id,
                  lambda sid=schema_id: store.scrub_quarantine_raw(sid))
    for name, _digest in _input_files(job):
        _step(job["job_id"], done, "purge_input_file", name,
              lambda n=name: _delete_input(n))


def _certify(job: dict, done: set[tuple[str, str]]) -> None:
    store.update_retire_job(job["job_id"], phase="certify", updated_at=_now())

    def _issue() -> None:
        fresh = store.get_retire_job(job["job_id"]) or job
        evidence_rows = store.retire_evidence_for_job(job["job_id"])
        destroyed = [row for row in store.list_destroyed_inputs()
                     if row["job_id"] == job["job_id"]]
        cert = certificate.build(fresh, evidence_rows, store.list_retire_steps(job["job_id"]),
                                 destroyed, _now())
        store.update_retire_job(job["job_id"], certificate=cert, status="done",
                                phase="done", updated_at=_now())

    _step(job["job_id"], done, "certify", job["job_id"], _issue)
    store.update_retire_job(job["job_id"], status="done", phase="done", updated_at=_now())


def retire(run_id: str | None = None) -> dict:
    """发起或恢复销毁；已完成任务直接回读，不重复登记。"""
    run = store.run_by_id(run_id) if run_id else store.latest_run()
    if run is None:
        raise errors.NotFound("没有可销毁的批次", detail={"run_id": run_id})
    job = store.find_retire_job_by_run(run["run_id"])
    if job is not None and job["status"] == "done":
        return status_view(job["job_id"])
    if job is None:
        runs = _cascade(run)
        job = {
            "job_id": _job_id_for(run["batch_key"]),
            "run_id": run["run_id"],
            "batch_key": run["batch_key"],
            "status": "running",
            "phase": "register",
            "input_sha256": run.get("input_sha256") or "",
            "digests": {item["run_id"]: item.get("digests") or {} for item in runs},
            "paths": {item["run_id"]: item.get("input_names") or {} for item in runs},
            "run_ids": [item["run_id"] for item in runs],
            "evidence": {},
            "created_at": _now(),
            "updated_at": _now(),
        }
        store.create_retire_job(job)
    else:
        runs = _load_runs(job["run_ids"])
    done = _done_steps(job["job_id"])
    try:
        _register(job, done)
        _freeze(job, runs, done)
        _purge(job, runs, done)
        _certify(job, done)
    except Exception as exc:
        store.update_retire_job(job["job_id"], status="failed",
                                error=f"{type(exc).__name__}: {exc}", updated_at=_now())
        raise
    return status_view(job["job_id"])


def _verify_paths(job: dict, steps: list[dict]) -> dict:
    """核对清理路径与原批次登记路径：一致才算清理闭环。"""
    expected = sorted({
        str(name)
        for names in (job["paths"] or {}).values()
        for name in (names or {}).values()
        if name
    })
    purged = sorted({row["target"] for row in steps if row["step"] == "purge_input_file"})
    return {
        "paths_match": set(purged) == set(expected),
        "expected_paths": expected,
        "purged_paths": purged,
        "pending": [name for name in expected if name not in purged],
        "unexpected": [name for name in purged if name not in expected],
    }


def status_view(job_id: str) -> dict:
    job = store.get_retire_job(job_id)
    if job is None:
        raise errors.NotFound("销毁任务不存在", detail={"job_id": job_id})
    steps = store.list_retire_steps(job_id)
    frozen = {row["target"] for row in steps if row["step"] == "freeze_evidence"}
    purged = {row["target"] for row in steps if row["step"] == "purge_run_payload"}
    evidence_rows = []
    for run_id in job["run_ids"]:
        row = store.get_retire_evidence(evidence.evidence_id_for(run_id))
        if row is not None:
            evidence_rows.append({
                "run_id": run_id,
                "evidence_id": row["evidence_id"],
                "sha256": row["sha256"],
                "frozen_at": row["frozen_at"],
            })
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "phase": job["phase"],
        "run_ids": job["run_ids"],
        "paths": job["paths"],
        "digests": job["digests"],
        "progress": {
            "steps_done": len(steps),
            "runs_total": len(job["run_ids"]),
            "runs_frozen": len(frozen),
            "runs_purged": len(purged),
        },
        "steps": steps,
        "verify": _verify_paths(job, steps),
        "evidence": evidence_rows,
        "destroyed_inputs": [row for row in store.list_destroyed_inputs()
                             if row["job_id"] == job_id],
        "original_readable": job["status"] != "done",
        "certificate": job["certificate"],
        "certificate_valid": certificate.verify(job["certificate"])
        if job["certificate"] else None,
        "error": job["error"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
    }


def listing() -> list[dict]:
    return store.list_retire_jobs()


def evidence_view(job_id: str, run_id: str) -> dict:
    job = store.get_retire_job(job_id)
    if job is None:
        raise errors.NotFound("销毁任务不存在", detail={"job_id": job_id})
    if run_id not in job["run_ids"]:
        raise errors.NotFound("批次不在该销毁任务内",
                              detail={"job_id": job_id, "run_id": run_id})
    row = store.get_retire_evidence(evidence.evidence_id_for(run_id))
    if row is None:
        raise errors.NotFound("证据尚未冻结",
                              detail={"job_id": job_id, "run_id": run_id})
    return row


def guard_batch(key: str, digests: dict) -> None:
    """跑批前置守卫：待销毁/已销毁内容拒绝复用与重写。"""
    retired = store.find_retire_job_by_batch(key)
    if retired is not None:
        raise errors.Conflict(
            "批次原文已销毁，拒绝重新写入",
            detail={"reason": "RUN_RETIRED", "job_id": retired["job_id"],
                    "run_id": retired["run_id"]},
        )
    gone = sorted(store.destroyed_digests() & set((digests or {}).values()))
    if gone:
        raise errors.Conflict(
            "输入内容已登记销毁，换名重导也不复活原文",
            detail={"reason": "INPUT_DESTROYED", "digests": gone},
        )


def guard_intake(sha256: str, name: str) -> None:
    """采信前置守卫：已销毁内容换名再导也在这里拦下。"""
    if sha256 in store.destroyed_digests():
        raise errors.Conflict(
            "输入内容已登记销毁，拒绝重新采信",
            detail={"reason": "INPUT_DESTROYED", "file": name, "digest": sha256},
        )
