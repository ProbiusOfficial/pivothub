# 第 3 轮计划（PLAN-ROUND3）— 合并落地 · 契约同步 · 代理编排闭环

> 目标：把「上一轮 AI 写的后端」与「本包最新前端」合并落地，补齐实测契约缺口，
> 并把代理编排从「只生成命令文本」推进到「真实建立 + 可验证 + 可销毁」。
> 权威顺序见 `docs/ASSUMPTIONS.md` A-19；本轮已落地的实现取舍见 A-20。

---

## 1. 落地决策（任务 A-1）

**选择：在工作区根目录铺开**（`pivothub-backend/` 子目录方案被否决）。

理由：

| 约束 | 根目录铺开 | 子目录方案 |
|---|---|---|
| `python -m pivothub` 一条命令可启动 | ✅ 直接满足（包在根，`config.ROOT_DIR` = 根） | 需 `cd pivothub-backend` 或设 PYTHONPATH |
| `config.DATA_DIR` = `<ROOT>/data`、`DB_PATH` = `<ROOT>/pivothub.db` | ✅ 与既有路径一致 | 需改 config 或复制 data/ |
| 前端 `index.html` / `assets/` 与后端同根 | ✅ 静态服务器指向根即可同时服务前端与 API | 需两处路径 |
| 既有 `docs/` `tests/` `scripts/` `tools/` 路径引用 | ✅ 零改动 | 需批量改引用 |

**旧前端处置**：`_audit\supershell`（及 `other\supershell.7z`）中的 `index.html` 与
`assets/` **未被使用**；根目录的 `index.html` / `assets/**` 保持交付基线不变
（逐文件 MD5 对账见 `docs/FRONTEND-SYNC-ROUND3.md`）。

落地后的目录（只列本轮相关）：

```
supershell/
├─ index.html                 # 前端基线（未改动）
├─ assets/                    # 前端基线（css/mock.js/topology.js 未改动；api.js/store.js/proxy.js 数据流接线）
├─ pivothub/                  # 后端包（根目录，python -m pivothub 直接可跑）
│  ├─ adapters/               # base(生命周期) / chisel(三种链路) / registry
│  ├─ api/                    # projects state / hosts / shells / links / attack / creds / flags / timeline / export
│  ├─ models/  schemas/       # SQLAlchemy 2.x + Pydantic v2（字段名对齐 mock.js）
│  ├─ service/                # timeline(segments) / relay(中继推导) / probe(出网探测) / tty / export / statlib
│  ├─ session/                # 会话抽象层（http_shell / local / registry）
│  └─ ws/                     # WebSocket 广播
├─ data/                      # meta.json / seed_project.json / commands / tty_fixes / payloads
├─ tests/                     # pytest（含本轮新增：契约 / 三种链路 / 中继推导 / 攻击机配置 / 出网探测）
├─ scripts/lab/miniweb/       # 零依赖「真实执行」联调靶（stdlib，真实子进程 + 真实文件系统）
├─ tools/                     # chisel.exe / chisel_linux
└─ docs/                      # 本轮新增 PLAN-ROUND3 / FRONTEND-SYNC-ROUND3 / evidence-round3.json
```

---

## 2. 任务分解与验收映射

| 任务 | 交付物 | 验收方式 |
|---|---|---|
| A 落地 + 对账 | 根目录后端 + `docs/FRONTEND-SYNC-ROUND3.md` | 基线 pytest 全绿；前端逐文件 MD5 对账 |
| B-1 `state.attack` | `GET/PUT /api/attack`、`StateOut.attack`、`data/meta.json` | `_work/contract_check.py`：attack 四字段 + PUT 回填 + 本机节点同步 |
| B-2 segments 新拓扑 | `service/timeline.segments_of` + `data/seed_project.json` | 四段顺序/配色/层级逐条等于 `mock.js SEGMENTS` |
| B-3 `ifaces` | `HostOut.ifaces` / `HostIn.ifaces` / DB JSON 列 | 入口机 `192.168.100.2 / 10.85.101.3`、L2 `10.85.101.4 / 172.56.102.4` |
| B-4 链路新字段 | `LinkOut/LinkIn/ProxyLink` 9 字段 + `localSocks` 语义 | 字段齐备；`localSocks` 非 `127.0.0.1` |
| B-5 新建项目攻击端 IP | `POST /api/projects` 取 `attack.ip` | 新项目仅 1 台主机且 IP = attack.ip |
| B-6 启动崩溃 | `config.init_console()` UTF-8 重配 | GBK(936) 控制台下 `python -m pivothub` 无 UnicodeEncodeError |
| C-A 攻击机可配置 | `PUT /api/attack` 全链路生效 | 改 IP 后 `/state`、本机节点、生成命令、`localSocks` 同步 |
| C-B 三种链路真实建立 | `adapters/chisel.py` 生命周期 + `POST /api/links/deploy` | pid 存活 + 端口连通 + 隧道内读到目标服务 banner |
| C-B relay 多级中继 | `service/relay.py` 推导 + 三步编排 | `relayAddr` = 上层跳板在本层网段的 IP（取自 ifaces） |
| C-C 出网探测真实执行 | `service/probe.py` + `POST /api/shells/{id}/probe` | 四探针真实命令/真实回显/结论 + 时间线事件 |
| C-D 前端接线 | `api.js` PUT、`store.js` saveAttack/deployLink/relayPlan/probeShell、`proxy.js` 三处接线 | 11 视图 0 错误；mock 回退不白屏 |

### Adapter 统一生命周期（硬约束 3）

```
generate_config → start(攻击机 chisel server) → upload(客户端二进制分块)
→ execute(靶机后台拉起) → wait_callback(本机入口端口可连) → verify(隧道内读目标 banner)
→ register_link(逐层 pid 落库) → health_check(进程 + 端口) → destroy(逐层清理)
```

路由层零 `subprocess`（`grep -rn "subprocess" pivothub/api/` 应为 0）；
命令执行/文件读写一律经 `pivothub/session/**` 抽象层。

---

## 3. 验收命令（复跑）

```powershell
$env:PYTHONIOENCODING="utf-8"          # 仅 pytest 需要；python -m pivothub 不需要

# 1) 启动（GBK 控制台直接可用）
python -m pivothub --no-open           # 仅监听 127.0.0.1:8000

# 2) 全量测试
python -m pytest tests/ -q -p no:warnings

# 3) 契约核对（无 chisel 依赖，独立临时库）
python _work/contract_check.py         # 期望 27/27 PASS

# 4) 三种链路 + 中继 + 销毁无孤儿（真实 chisel）
python -m pytest tests/test_link_deploy.py -q -p no:warnings

# 5) 路由层无 subprocess
grep -rn "subprocess" pivothub/api/    # 期望 0 处
```

---

## 4. 风险与已知边界（诚实标注）

| 风险/边界 | 现状与处置 |
|---|---|
| 本机无 Docker/Linux 靶机 | 用 `scripts/lab/miniweb`（stdlib、真实子进程/文件系统）做真实执行验证；Linux PTY 固化成功路径标注「待环境」 |
| Windows 防火墙首连拦截 | 新端口首次监听会被拦截，chisel 客户端自动重试可接通（默认等 45s）；彻底消除需管理员加规则（见 VERIFY） |
| chisel 二进制被 Defender 隔离 | 已记入 PROGRESS 教训；`tools/` 双端二进制须保留 |
| 目标侧 `%TEMP%` 不展开 | `remoteDir` 由调用方传绝对路径（`_remote_dir()`） |
| **同机多会话并发跑 chisel 用例** | 会话级清理改为「只清理本会话启动的 pid + 本会话暂存目录命中的进程」，禁止按映像名全量 taskkill（否则会话互杀导致 wait_callback 假失败） |
| 浏览器验收 | 使用 Chrome Headless + CDP（`.verify/*.js`）；本机 Chrome 路径见环境说明 |

---

## 5. 每轮收尾要求

1. 跑第 3 节全部命令，把「命令 + 输出摘要」写入 `docs/PROGRESS.md` 当轮条目；
2. `docs/FRONTEND-SYNC-ROUND3.md` 与 `docs/PROGRESS.md` 每轮更新；
3. 失败必须返回真实阶段与原因（不伪造成功），前端据此降级半自动档。
