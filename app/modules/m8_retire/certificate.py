"""销毁凭据：证明哪些原文在何时被销毁、证据冻结在哪。

凭据自身可校验：fingerprint 是对凭据正文（不含 fingerprint）的摘要，
任何字段被改动都会失配。凭据不含原文，可长期留存。
"""

from __future__ import annotations

import hashlib
import json

from app import config

SCOPES = ("run_payload", "snapshot_payload", "quarantine_raw", "input_file")
STATEMENT = "原文已不可回读"


def certificate_id_for(job_id: str) -> str:
    return "rc-" + hashlib.sha256(f"certificate:{job_id}".encode("utf-8")).hexdigest()[:12]


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build(job: dict, evidence_rows: list[dict], steps: list[dict],
          destroyed: list[dict], completed_at: str) -> dict:
    inputs = []
    for run_id in job["run_ids"]:
        names = (job["paths"] or {}).get(run_id) or {}
        digests = (job["digests"] or {}).get(run_id) or {}
        for role in sorted(digests):
            inputs.append({
                "run_id": run_id,
                "role": role,
                "name": (names.get(role) or ""),
                "sha256": digests[role],
            })
    cert = {
        "certificate_id": certificate_id_for(job["job_id"]),
        "job_id": job["job_id"],
        "run_ids": list(job["run_ids"]),
        "statement": STATEMENT,
        "scopes": list(SCOPES),
        "inputs": inputs,
        "evidence": [
            {"run_id": row["run_id"], "evidence_id": row["evidence_id"],
             "sha256": row["sha256"], "frozen_at": row["frozen_at"]}
            for row in evidence_rows
        ],
        "destroyed_inputs": [
            {"digest": row["digest"], "destroyed_at": row["destroyed_at"]}
            for row in destroyed
        ],
        "steps": [
            {"step": row["step"], "target": row["target"], "done_at": row["done_at"]}
            for row in steps
        ],
        "window_semantics": config.WINDOW_SEMANTICS,
        "completed_at": completed_at,
    }
    cert["fingerprint"] = hashlib.sha256(_canonical(cert).encode("utf-8")).hexdigest()
    return cert


def verify(certificate: dict) -> bool:
    """重算指纹核对凭据；缺 fingerprint 视为无效。"""
    fingerprint = certificate.get("fingerprint")
    if not fingerprint:
        return False
    body = {key: value for key, value in certificate.items() if key != "fingerprint"}
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest() == fingerprint
