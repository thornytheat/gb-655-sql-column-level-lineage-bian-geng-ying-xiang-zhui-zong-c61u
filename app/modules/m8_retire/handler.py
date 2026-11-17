"""M8 入口：销毁发起/恢复、进度回读、列级证据查询。"""

from __future__ import annotations

from fastapi import APIRouter

from app import errors
from app.modules.m8_retire import service

router = APIRouter()

ALLOWED_KEYS = {"run_id"}


@router.post("/api/retire")
def retire_api(payload: dict | None = None):
    """发起销毁；同一批次重复调用返回同一任务，中断后调用即恢复。"""
    body = payload or {}
    unknown = set(body) - ALLOWED_KEYS
    if unknown:
        raise errors.BadInput("出现未知参数", detail={"keys": sorted(unknown)})
    run_id = body.get("run_id")
    if run_id is not None and not isinstance(run_id, str):
        raise errors.BadInput("run_id 必须是字符串", detail={"field": "run_id"})
    return service.retire(run_id=run_id)


@router.get("/api/retire")
def retire_jobs_api():
    return {"jobs": service.listing()}


@router.get("/api/retire/{job_id}")
def retire_status_api(job_id: str):
    """清理进度回读：步骤、路径核对、证据与凭据。"""
    return service.status_view(job_id)


@router.get("/api/retire/{job_id}/evidence/{run_id}")
def retire_evidence_api(job_id: str, run_id: str):
    """冻结的列级证据：迁移争议核查影响路径用，不含原文。"""
    return service.evidence_view(job_id, run_id)
