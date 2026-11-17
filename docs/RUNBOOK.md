# 运行手册 lineageguard

## 1 启动

```bash
docker compose up -d --build
curl -s localhost:18214/api/health
```

宿主端口 `18214`，容器内 `8000`。启动时如果库是空的，服务会自动把 `sample_data/` 里的样例跑一遍，页面打开即有数据。

## 2 截图与验收命令

```bash
docker compose config --quiet
docker compose exec -T app python -m pytest -q
```

## 3 主流程

1. 打开 `http://localhost:18214/`，看规格单的字段清单与采信诊断。
2. `/types` 比较两个类型写法，看读者 / 写者两向结论。
3. `/mapping` 看旧名到新名、别名 SQL、冲突项。
4. `/impact` 看受影响节点、环、断链、单边登记。
5. `/batches` 点「跑一次」，再点「陈旧提交」验证 409。
6. `/spec` 导出迁移单与三份账目 CSV。

## 4 重建数据库

```bash
docker compose down -v
docker compose up -d --build
```

命名卷 `lineageguard-data` 挂着 `/data/lineageguard.sqlite`。删卷即清空批次、快照与隔离区。

## 5 接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/health` | 服务与库状态、当前批次号 |
| POST | `/api/schemas/import` | 采信样例文件，返回快照摘要与诊断 |
| GET | `/api/schemas/quarantine` | 隔离区 JSON |
| GET | `/api/schemas/quarantine.csv` | 隔离区 CSV |
| GET | `/api/types` | 类型格与别名表 |
| POST | `/api/types/compare` | 两个类型写法比较 |
| POST | `/api/compat` | 一对版本的两向判定 |
| GET | `/api/mapping` | 映射表、别名、冲突 |
| GET | `/api/impact` | 影响面、环、断链 |
| POST | `/api/runs` | 跑批次，可带基线版本号与生效区间 |
| GET | `/api/batches` | 批次历史 |
| GET | `/api/reconcile` | 四账对账 |
| GET | `/api/export/spec.md` | 迁移单 Markdown |
| GET | `/api/export/fields.csv` | 字段账 CSV |
| GET | `/api/export/refs.csv` | 引用账 CSV |
| GET | `/api/export/ledger.csv` | 账目 CSV |
| GET | `/api/export/manifest.json` | 运行清单 |
| POST | `/api/retire` | 销毁批次原文；同一批次重复调用返回同一任务，中断后调用即恢复 |
| GET | `/api/retire` | 销毁任务列表 |
| GET | `/api/retire/{job_id}` | 清理进度回读：步骤台账、路径核对、证据与凭据 |
| GET | `/api/retire/{job_id}/evidence/{run_id}` | 冻结的列级证据（不含原文），迁移争议核查影响路径用 |

## 5.1 销毁语义

- 顺序：登记待销毁摘要 → 冻结列级证据 → 清除原文（批次载荷、快照副本、隔离区、输入文件）→ 出具凭据。证据未冻结不清除。
- 共用同一输入内容（按 SHA-256）的批次进入同一销毁任务，一并冻结、一并清除。
- 输入内容摘要一经登记，跑批（`POST /api/runs`）与采信（`POST /api/schemas/import`）一律 409，换文件名重导同样拦截。
- 凭据 `fingerprint` 可对凭据正文（不含 fingerprint 字段）重算 SHA-256 校验；`verify.paths_match=true` 表示清理路径与原批次登记路径一致。

## 6 失败处置

| 现象 | 原因 | 处置 |
|---|---|---|
| 409 `VERSION_STALE` | 提交带的基线序号落后 | 去掉 `base_version_seq` 或填当前序号 |
| 409 `RUN_RETIRED` | 批次原文已销毁或销毁中 | 不可重跑；用 `GET /api/retire/{job_id}` 查凭据与证据 |
| 409 `INPUT_DESTROYED` | 输入内容已登记销毁（含换名重导） | 不可复活原文；核查销毁任务与凭据 |
| 400 `WINDOW_INVERTED` | 生效区间起点不早于终点 | 检查 `effective_from` / `effective_to` |
| 400 `BAD_INPUT` | 文件名、参数或 JSON 结构不对 | 看返回的 `detail` |
| 404 `NOT_FOUND` | 还没跑过批次 | 先在 `/batches` 点「跑一次」 |

## 7 端口与并发

本服务固定 18214。同时起多个栈时改 `docker-compose.yml` 的端口映射与 `lineageguard-data` 卷名，避免与本机其他项目抢端口、串数据。
