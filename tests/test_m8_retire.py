"""M8 销毁：证据冻结、原文清除、断点恢复、重跑与换名重导拦截。

夹具自建一套含敏感常量的输入文件（唯一名，跑批后即销毁），
不与种子批次共享任何输入，避免级联误伤默认样例。
"""

from __future__ import annotations

import json
import uuid

import pytest

from app import config, errors, store
from app.modules.m6_batches import service as batch_service
from app.modules.m8_retire import certificate, evidence, purge, service

SENSITIVE_PHONE = "13800001111"
SENSITIVE_ID = "110101199003077777"
SENSITIVE_LINE = "broken_row 手机号13800001111"

DDL_OLD = f"""-- m8 销毁测试旧版 v2099_01
CREATE TABLE m8_order (
  `order_id`     BIGINT        NOT NULL,  -- fid=9101
  `order_no`     VARCHAR(64)   NOT NULL,  -- fid=9102
  `order_amt`    DECIMAL(20,4) NOT NULL,  -- fid=9103
  `buyer_phone`  VARCHAR(32)   NOT NULL,  -- fid=9104
  {SENSITIVE_LINE}
);
"""

DDL_NEW = """-- m8 销毁测试新版 v2099_03
CREATE TABLE m8_order (
  `order_id`     BIGINT        NOT NULL,  -- fid=9101
  `order_code`   VARCHAR(64)   NOT NULL,  -- fid=9102
  `order_amt`    DECIMAL(20,4) NOT NULL,  -- fid=9103
  `buyer_phone`  VARCHAR(32)   NULL       -- fid=9104
);
"""

DDL_OLD_B = """-- m8 销毁测试共用输入旧版 v2099_01
CREATE TABLE m8_refund (
  `refund_id`    BIGINT        NOT NULL,  -- fid=9201
  `order_no`     VARCHAR(64)   NOT NULL,  -- fid=9202
  `refund_amt`   DECIMAL(18,4) NULL       -- fid=9203
);
"""

DDL_NEW_B = """-- m8 销毁测试共用输入新版 v2099_03
CREATE TABLE m8_refund (
  `refund_id`    BIGINT        NOT NULL,  -- fid=9201
  `order_code`   VARCHAR(64)   NOT NULL,  -- fid=9202
  `refund_amt`   DECIMAL(18,4) NULL       -- fid=9203
);
"""


def _refs_payload() -> dict:
    return {
        "registered_at": "2099-01-15T00:00:00Z",
        "consumers": [
            {
                "name": "dw.m8_order_daily",
                "kind": "view",
                "sql": "select o.order_id, o.order_no from m8_order o "
                       f"where o.buyer_phone = '{SENSITIVE_PHONE}'",
                "upstream": [],
                "downstream": ["dw.m8_settle"],
            },
            {
                "name": "dw.m8_settle",
                "kind": "task",
                "sql": "select o.order_id, o.order_amt from m8_order o "
                       f"where o.order_no = '{SENSITIVE_ID}'",
                "upstream": ["dw.m8_order_daily"],
                "downstream": [],
            },
        ],
    }


def _write(name: str, text: str):
    path = config.SAMPLE_DIR / name
    path.write_text(text, encoding="utf-8")
    return path


def _blob(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


@pytest.fixture()
def sensitive_batch(client):
    """跑起一个含敏感常量的批次；用例结束清理可能残留的输入文件。"""
    token = uuid.uuid4().hex[:8]
    names = {
        "old": f"m8old_v2099_01_{token}.sql",
        "new": f"m8new_v2099_03_{token}.sql",
        "refs": f"m8refs_{token}.json",
    }
    seeded = store.latest_run()
    paths = [
        _write(names["old"], DDL_OLD),
        _write(names["new"], DDL_NEW),
        _write(names["refs"], json.dumps(_refs_payload(), ensure_ascii=False)),
    ]
    run = batch_service.execute(
        old_file=names["old"], new_file=names["new"], refs_file=names["refs"],
        base_file=None,
    )
    try:
        yield {
            "run": run,
            "names": names,
            "paths": paths,
            "refs_text": json.dumps(_refs_payload(), ensure_ascii=False),
            "seeded_run_id": seeded["run_id"],
        }
    finally:
        for path in paths:
            path.unlink(missing_ok=True)


def test_retire_purges_originals_and_keeps_column_evidence(client, sensitive_batch):
    run = sensitive_batch["run"]
    run_id = run["run_id"]
    # 销毁前：原文（含敏感常量）确实持久化在批次与快照副本里
    assert SENSITIVE_PHONE in _blob(store.run_by_id(run_id))
    snapshot_before = store.load_snapshot(run["old_schema_id"])
    assert SENSITIVE_PHONE in _blob(snapshot_before)
    quarantine_before = store.list_quarantine(run["old_schema_id"])
    assert any(SENSITIVE_PHONE in (row["raw"] or "") for row in quarantine_before)

    response = client.post("/api/retire", json={"run_id": run_id})
    assert response.status_code == 200
    view = response.json()
    assert view["status"] == "done"
    assert view["original_readable"] is False
    assert view["run_ids"] == [run_id]

    # 销毁凭据：内容自洽，声明原文已不可回读
    cert = view["certificate"]
    assert cert["statement"] == "原文已不可回读"
    assert view["certificate_valid"] is True
    assert certificate.verify(cert) is True
    assert {row["role"] for row in cert["inputs"]} == {"old", "new", "refs"}

    # 批次载荷：SQL 原文抹除，结构保留，打销毁标记
    after = store.run_by_id(run_id)
    assert SENSITIVE_PHONE not in _blob(after)
    assert SENSITIVE_ID not in _blob(after)
    consumers = after["refs"]["consumers"]
    assert all(item["sql"] is None and item["sql_retired"] for item in consumers)
    assert after["retired"]["job_id"] == view["job_id"]
    assert after["summary"]["retired"] is True

    # 持久化副本：快照诊断与隔离区的原文行一并清空
    snapshot_after = store.load_snapshot(run["old_schema_id"])
    assert SENSITIVE_PHONE not in _blob(snapshot_after)
    assert all(row["raw"] is None for row in snapshot_after["diagnostics"])
    quarantine_after = store.list_quarantine(run["old_schema_id"])
    assert quarantine_after and all(row["raw"] == "" for row in quarantine_after)

    # 输入文件已删除
    for path in sensitive_batch["paths"]:
        assert not path.exists()

    # 列级证据：影响路径可核查，但不含任何原文
    ev = client.get(f"/api/retire/{view['job_id']}/evidence/{run_id}")
    assert ev.status_code == 200
    payload = ev.json()["payload"]
    blob = _blob(payload)
    assert SENSITIVE_PHONE not in blob
    assert SENSITIVE_ID not in blob
    assert "m8_order.order_id" in blob  # 列级引用保留
    assert all("sql" not in item for item in payload["consumers"])
    assert payload["consumers"][0]["refs"]  # 引用列清单在
    assert payload["impact"]["summary"]["consumers"] == 2  # 影响路径在
    assert payload["diff"]  # 列级变更在
    assert "LINE_MALFORMED" in {row["reason"] for row in payload["quarantine"]}
    assert all("raw" not in row for row in payload["quarantine"])

    # 种子批次与本次销毁无共用输入，原文不受影响
    seeded = store.run_by_id(sensitive_batch["seeded_run_id"])
    assert "select" in _blob(seeded["refs"]["consumers"])


def test_retire_idempotent_no_duplicate_registration(client, sensitive_batch):
    run_id = sensitive_batch["run"]["run_id"]
    first = client.post("/api/retire", json={"run_id": run_id}).json()
    steps_once = store.list_retire_steps(first["job_id"])
    destroyed_once = store.list_destroyed_inputs()

    again = client.post("/api/retire", json={"run_id": run_id})
    assert again.status_code == 200
    second = again.json()
    assert second["job_id"] == first["job_id"]
    assert second["status"] == "done"
    # 重试不重复登记：步骤、证据、销毁登记一行不多
    assert store.list_retire_steps(first["job_id"]) == steps_once
    assert store.list_destroyed_inputs() == destroyed_once
    assert len(store.retire_evidence_for_job(first["job_id"])) == 1


def test_retire_resume_after_interruption(client, sensitive_batch, monkeypatch):
    run_id = sensitive_batch["run"]["run_id"]
    calls = {"purge": 0}
    real_update = store.update_run_payload

    def _boom(run):
        calls["purge"] += 1
        raise RuntimeError("模拟清理中断")

    monkeypatch.setattr(store, "update_run_payload", _boom)
    with pytest.raises(RuntimeError):
        service.retire(run_id)
    job = store.find_retire_job_by_run(run_id)
    assert job["status"] == "failed"
    assert job["phase"] == "purge"
    # 证据已冻结，清除尚未完成
    assert len(store.retire_evidence_for_job(job["job_id"])) == 1
    assert calls["purge"] == 1

    # 注意不能用 monkeypatch.undo()：会把 client 夹具的库路径设置一并撤销
    monkeypatch.setattr(store, "update_run_payload", real_update)
    view = service.retire(run_id)
    assert view["status"] == "done"
    # 断点恢复不重复记账：冻结与登记步骤各一次
    steps = store.list_retire_steps(job["job_id"])
    kinds = [row["step"] for row in steps]
    assert kinds.count("freeze_evidence") == 1
    assert kinds.count("purge_run_payload") == 1
    assert kinds.count("certify") == 1
    assert len(store.retire_evidence_for_job(job["job_id"])) == 1


def test_pending_destruction_rejects_concurrent_rerun(client, sensitive_batch, monkeypatch):
    """清理中途（待销毁状态）发起的同输入跑批必须被拒。"""
    run = sensitive_batch["run"]
    names = sensitive_batch["names"]
    real_update = store.update_run_payload
    monkeypatch.setattr(store, "update_run_payload",
                        lambda _run: (_ for _ in ()).throw(RuntimeError("中断")))
    with pytest.raises(RuntimeError):
        service.retire(run["run_id"])
    # 恢复真实写库；undo() 会连 client 夹具的库路径一起撤销，不能用
    monkeypatch.setattr(store, "update_run_payload", real_update)

    # 输入文件还在（purge 未完成），但批次已登记销毁：跑批与采信都拒
    response = client.post("/api/runs", json={
        "old_file": names["old"], "new_file": names["new"],
        "refs_file": names["refs"], "base_file": "",
    })
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "INPUT_DESTROYED"
    with pytest.raises(errors.Conflict):
        batch_service.execute(old_file=names["old"], new_file=names["new"],
                              refs_file=names["refs"], base_file=None)
    # 恢复清理，收尾成功
    assert service.retire(run["run_id"])["status"] == "done"


def test_rerun_and_renamed_reimport_never_revive(client, sensitive_batch):
    run = sensitive_batch["run"]
    names = sensitive_batch["names"]
    view = client.post("/api/retire", json={"run_id": run["run_id"]}).json()
    assert view["status"] == "done"

    # 同名恢复文件再跑：内容已登记销毁，409
    for path, text in (
        (sensitive_batch["paths"][0], DDL_OLD),
        (sensitive_batch["paths"][1], DDL_NEW),
        (sensitive_batch["paths"][2], sensitive_batch["refs_text"]),
    ):
        _write(path.name, text)
    exact = client.post("/api/runs", json={
        "old_file": names["old"], "new_file": names["new"],
        "refs_file": names["refs"], "base_file": "",
    })
    assert exact.status_code == 409
    assert exact.json()["detail"]["reason"] == "INPUT_DESTROYED"

    # 同内容换名重导：跑批拒、采信也拒
    token = uuid.uuid4().hex[:8]
    renamed = _write(f"m8refs_renamed_{token}.json", sensitive_batch["refs_text"])
    try:
        via_run = client.post("/api/runs", json={
            "old_file": names["old"], "new_file": names["new"],
            "refs_file": renamed.name, "base_file": "",
        })
        assert via_run.status_code == 409
        assert via_run.json()["detail"]["reason"] == "INPUT_DESTROYED"
        via_import = client.post("/api/schemas/import", json={"files": [renamed.name]})
        assert via_import.status_code == 409
        assert via_import.json()["detail"]["reason"] == "INPUT_DESTROYED"
    finally:
        renamed.unlink(missing_ok=True)

    # 原文依旧不可回读
    assert SENSITIVE_PHONE not in _blob(store.run_by_id(run["run_id"]))


def test_shared_input_cascade_purges_related_batches(client, sensitive_batch):
    token = uuid.uuid4().hex[:8]
    names = sensitive_batch["names"]
    extra = [
        _write(f"m8oldB_v2099_01_{token}.sql", DDL_OLD_B),
        _write(f"m8newB_v2099_03_{token}.sql", DDL_NEW_B),
    ]
    try:
        run_b = batch_service.execute(
            old_file=extra[0].name, new_file=extra[1].name,
            refs_file=names["refs"], base_file=None,
        )
        assert run_b["run_id"] != sensitive_batch["run"]["run_id"]

        view = client.post(
            "/api/retire", json={"run_id": sensitive_batch["run"]["run_id"]}
        ).json()
        # 共用 refs 输入的关联批次一并处理
        assert set(view["run_ids"]) == {sensitive_batch["run"]["run_id"], run_b["run_id"]}
        assert view["status"] == "done"
        after_b = store.run_by_id(run_b["run_id"])
        assert all(item["sql"] is None for item in after_b["refs"]["consumers"])
        assert len(view["evidence"]) == 2
        # 两个批次的输入路径都在清理清单里
        expected = set(view["verify"]["expected_paths"])
        assert expected == set(names.values()) | {path.name for path in extra}
        assert view["verify"]["paths_match"] is True
        for path in extra:
            assert not path.exists()
    finally:
        for path in extra:
            path.unlink(missing_ok=True)


def test_progress_readback_and_path_verification(client, sensitive_batch):
    run = sensitive_batch["run"]
    names = sensitive_batch["names"]
    created = client.post("/api/retire", json={"run_id": run["run_id"]}).json()
    job_id = created["job_id"]

    view = client.get(f"/api/retire/{job_id}")
    assert view.status_code == 200
    body = view.json()
    assert body["progress"]["runs_total"] == 1
    assert body["progress"]["runs_frozen"] == 1
    assert body["progress"]["runs_purged"] == 1
    # 清理路径与原批次登记路径一致，无遗漏无越界
    verify = body["verify"]
    assert verify["paths_match"] is True
    assert verify["pending"] == []
    assert verify["unexpected"] == []
    assert set(verify["expected_paths"]) == set(names.values())
    assert sorted(verify["purged_paths"]) == sorted(names.values())
    steps = {(row["step"], row["target"]) for row in body["steps"]}
    for name in names.values():
        assert ("purge_input_file", name) in steps
    assert ("freeze_evidence", run["run_id"]) in steps
    # 每个输入内容都有销毁登记
    destroyed = {row["digest"] for row in body["destroyed_inputs"]}
    assert destroyed == set(run["digests"].values())

    listing = client.get("/api/retire").json()
    assert any(job["job_id"] == job_id for job in listing["jobs"])

    missing = client.get("/api/retire/rt-000000000000")
    assert missing.status_code == 404


def test_guard_batch_unit_and_certificate_tamper(client, sensitive_batch):
    run = sensitive_batch["run"]
    view = client.post("/api/retire", json={"run_id": run["run_id"]}).json()
    # 批次级守卫：同一批次键直接判 RUN_RETIRED
    with pytest.raises(errors.Conflict) as caught:
        service.guard_batch(run["batch_key"], {})
    assert caught.value.detail["reason"] == "RUN_RETIRED"
    # 输入级守卫：任一已销毁摘要即拒
    with pytest.raises(errors.Conflict) as caught:
        service.guard_batch("0" * 64, {"refs": run["digests"]["refs"]})
    assert caught.value.detail["reason"] == "INPUT_DESTROYED"
    # 凭据篡改失配
    cert = dict(view["certificate"])
    cert["statement"] = "原文仍可回读"
    assert certificate.verify(cert) is False


def test_retire_rejects_bad_input_and_empty_store(client, empty_client):
    # 未知参数 400
    bad = client.post("/api/retire", json={"batch": "x"})
    assert bad.status_code == 400
    # 空库没有批次可销毁 404
    missing = empty_client.post("/api/retire", json={})
    assert missing.status_code == 404
    assert empty_client.get("/api/retire").json()["jobs"] == []


def test_evidence_id_stable_and_scrub_is_pure(client, sensitive_batch):
    run = sensitive_batch["run"]
    first = evidence.build(run, "rt-test", "2026-11-17T00:00:00+00:00")
    second = evidence.build(run, "rt-test", "2026-11-17T00:00:00+00:00")
    assert first["evidence_id"] == second["evidence_id"]
    assert first["sha256"] == second["sha256"]
    # 净化不改原对象，返回新字典
    scrubbed = purge.scrub_run(run, "rt-test", "2026-11-17T00:00:00+00:00")
    assert scrubbed is not run
    assert SENSITIVE_PHONE in _blob(run["refs"]["consumers"])
    assert SENSITIVE_PHONE not in _blob(scrubbed["refs"]["consumers"])
