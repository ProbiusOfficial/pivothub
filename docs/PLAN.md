# PivotHub（链透中枢）后端实现计划

> 依据：PRD v1.0 > README §6 契约 > `assets/js/mock.js` 字段 > 原型现有实现。
> 技术栈锁定：Python 3.10+ / FastAPI + Uvicorn + WebSocket / SQLAlchemy 2.x + SQLite / Pydantic v2 / pytest + httpx / Playwright(e2e)。前端保持 Vue 3 CDN 原型零构建。
> 面板仅监听 `127.0.0.1:8000`（与原型侧栏「后端 127.0.0.1:8000」硬编码一致），无需认证。

---

## 1. 总体思路

1. **数据契约零适配**：后端所有 JSON 序列化字段名与 mock.js 完全一致（含 `lastBeat`『刚刚/N 秒前』、`time`『HH:MM』、`kind`『密码/NTLM 哈希』、`status`『alive/error/stopped』、`direction`『反向/正向』等中文枚举值）。DB 内部存规范形式（ISO 时间戳等），序列化层统一渲染为契约字符串。
2. **一次拉全量 + WS 增量**：`GET /api/projects/{id}/state` 返回 store.init() 所需的全部键（project/projects/segments/hosts/shells/links/creds/flags/timeline/probes/tools/commands/injectTips/ttyFixes/shellTypes/encoders/credKinds/layers/stageNames/fileTree/scanSample），前端一次替换数据源；`/ws` 按 README §6.2 事件推送增量（shell.beat / shell.output / shell.tty / probe.result / link.state / link.created / host.found / cred.found / timeline.push / ws.online）。
3. **会话抽象层**：`pivothub/session/`。路由层只依赖 `Session` 接口（exec / list_dir / read_file / write_file / test / close）。实现：`local.py`（本机 subprocess，供适配器与本地联调靶标用）、`http_shell.py`（HTTP 一句话马协议驱动，MS2）。**任何 subprocess 不出现在 api/ 路由函数内。**
4. **适配器模式**：`pivothub/adapters/base.py` 定义 `generate_config → deploy → start → wait_callback → register_link → health_check → destroy` 生命周期。一期真实实现 frp / chisel / Neo-reGeorg；nps / EW / Stowaway / Venom / ligolo-ng 为占位 Adapter（接口齐全，`available=False`）。
5. **插件化数据**：`data/commands/*.json`（命令速查）、`data/payloads/*.json`（马模板/写马姿势）、`data/tty_fixes/*.json`（终端固化技法库）、`data/meta.json`（枚举目录与静态基线）、`data/seed_project.json`（三层内网演示项目，与 mock.js 场景一致）。
6. **前端最小侵入**：仅新增 `assets/js/api.js`，改 `store.js` 各动作的数据来源（先 API、失败回退 mock）；`index.html` 只新增一行 `<script src="assets/js/api.js">`；`topology.js` 仅加两行纯数据流代码（拖拽位置上报 + 恢复，详见 ASSUMPTIONS.md）。
7. **持久化与恢复**：SQLite 单文件 `pivothub.db`；启动时若无项目则播种演示项目；重启后从 DB 完整恢复，代理进程状态自动核对（有 pid 的链路核验进程存活，失联标记 error，可一键重拉）。

## 2. 目录树（交付态）

```
supershell/
├─ index.html / assets/ / README.md        # 原型（assets/js/api.js 新增，store.js 改数据源）
├─ requirements.txt
├─ run.py                                  # 等价 python -m pivothub
├─ pivothub.db                             # SQLite（运行时生成）
├─ pivothub/
│  ├─ __init__.py  __main__.py             # 入口：横幅（合规声明）+ 打印面板 URL
│  ├─ config.py                            # 端口/路径/DB/超时配置
│  ├─ db.py                                # engine/session/Base/init_db+seed
│  ├─ models/                              # SQLAlchemy 2.x（Project/Host/Shell/ProxyLink/Credential/Flag/TimelineEvent）
│  ├─ schemas/                             # Pydantic v2（字段名=mock.js）
│  ├─ api/                                 # 路由：projects/hosts/shells/links/creds/flags/timeline/export/meta
│  ├─ service/                             # 业务：timeline/statlib/probe/tty/credreuse/deploy/export/files
│  ├─ session/                             # 会话抽象：base/registry/local/http_shell(MS2)
│  ├─ adapters/                            # base + frp/chisel/neoregeorg(真实) + nps/ew/stowaway/venom/ligolong(占位)
│  └─ ws/                                  # manager（连接管理+广播）+ events
├─ data/
│  ├─ meta.json                            # segments/tools/probes 基线/枚举目录/scanSample/fileTree 初始树
│  ├─ seed_project.json                    # 演示项目数据（与 mock.js 三层内网场景一致）
│  ├─ commands/*.json                      # 6 类命令速查（信息收集/Linux提权/Windows提权/域渗透/横向/维持）
│  ├─ payloads/*.json                      # 马模板 + 写马姿势
│  └─ tty_fixes/{linux,windows}.json       # 13 条固化技法
├─ scripts/
│  ├─ e2e_smoke.py  e2e_flagship.py        # Playwright 端到端
│  └─ lab/                                 # Docker 靶场：reverse-tcp / http-only / multi-nic 三场景
├─ tests/                                  # pytest：模型CRUD/出网探测解析/TTY判定/生命周期状态机/导出快照/凭据复用
└─ docs/  PLAN.md  PROGRESS.md  ASSUMPTIONS.md  ARCHITECTURE.md  VERIFY.md
```

## 3. 里程碑排期（按 PRD MS1–MS6，每步自验后写 PROGRESS.md）

| 里程碑 | 交付 | 验收 |
|---|---|---|
| MS1（本轮） | 骨架：模型+状态聚合+WS+StaticFiles+前端切真实接口（mock 回退） | 11 视图真实接口驱动，控制台 0 错误 0 警告 |
| MS2 | session 层 + Shell 登记/测试/执行/文件管理 + M1-8 终端固化全套（真实 tty 解析/PTY 判定/技法库/stty raw 收尾/落库） | 对真实 WebShell（scripts/lab）完成 检测→固化→收尾，Shell.stable 落库 |
| MS3 | frp/chisel/Neo-reGeorg Adapter + 出网探测真实执行 + 半自动档 + 回连监听 + ProxyLink 自动登记 + Socks 映射表 | 拓扑自动画出第一条真实代理链 |
| MS4 | 其余 5 Adapter 占位补全 + 多级串联（继承上层 Socks 入口）+ proxychains/msf 生成 + 健康检查与断链重拉 | 两级链路串联跑通 |
| MS5 | 凭据复用推荐服务化 + 自动档（识别 OS/架构→上传→执行→失败降级半自动）+ 健康看板实时推送 | 自动档失败降级路径可演示 |
| MS6 | Flag/笔记/计时看板 + 命令速查 + MD/HTML/JSON 服务端导出 + 项目打包 + requirements/发布说明 | 三格式导出快照测试通过，README 更新 |

## 4. MS1 详细设计

### 4.1 数据模型（SQLAlchemy 2.x，`pivothub/models/`）

```
Project       id(str pk)  name  start_at(str)  duration_sec(int)  note  created_at
Host          id pk  project_id fk  ip  hostname  os  layer  segment  privilege
              owned(bool)  ports(JSON)  services(JSON)  note  discovery
              is_local(bool)  pos_x(float?)  pos_y(float?)        # 拓扑拖拽持久化
Shell         id pk  project_id  host_id fk  type  url  pass  encoder
              alive(bool)  latency(int)  last_beat_at(dt?)  hostname  privilege  stable(bool)
ProxyLink     id pk  project_id  tool  direction  from_host_id  to_host_id
              local_socks  target_segment  status  latency  traffic  conf
              created_by  note  pid(int?)  created_at                  # pid 供重启后状态核对
Credential    id pk  project_id  host_id  username  secret  kind  services(JSON)
              reuse(bool)  source  created_at
Flag          id pk  project_id  host_id  stage  value  submitted(bool)  created_at
TimelineEvent id pk  project_id  ts(dt)  kind  title  host_id?  detail  cmd  markdown
```

序列化契约（schemas 层）：`Shell.lastBeat`←`last_beat_at` 相对时间串（断线时『N 分钟前（断线）』）；`TimelineEvent.time`/`Credential.time`←ts 的 `HH:MM`；`segments[].count` 按主机实时聚合；`stats.flagsTotal` 前端写死 6，后端 seed 保持 5 条 Flag + 阶段配额一致即可（不额外传）。

### 4.2 REST（MS1 全部落库实现；MS2/MS3 项返回 501 待接）

MS1 即实现：`GET /api/projects`、`GET /api/projects/{id}/state`、`POST /api/hosts`、`POST /api/hosts/import`、`PATCH /api/hosts/{id}/position`、`POST /api/shells`、`POST /api/shells/{id}/test`、`DELETE /api/shells/{id}`、`POST /api/creds`、`POST /api/flags`、`POST /api/timeline/notes`、`POST /api/links/{id}/check|restart`、`DELETE /api/links/{id}`、`GET /api/export?format=md|html|json`、`GET /api/meta`。
占位（501 + 明确 reason）：`shells/{id}/exec|tty/*|files/*|probe`、`POST /api/links`（真实部署 MS3）。所有写操作产生 `timeline.push` WS 事件，与 mock 行为一致。

### 4.3 WebSocket（`pivothub/ws/manager.py`）

`/ws`：连接注册（按 projectId 归组）→ `ws.online`；广播器 `broadcast(type, **payload)`。MS1 接入：写操作后 timeline.push、link 状态变化 link.state、链路创建 link.created；周期心跳（10s）对 alive Shell 推 shell.beat（真实 HEAD 请求测延迟）。

### 4.4 静态挂载与启动

`app = FastAPI()` → `/api` 路由 + `/ws` → `StaticFiles(directory=项目根, html=True)` 挂 `/`（index.html + assets 原样服务）。`python -m pivothub`：打印合规横幅 + `面板地址 http://127.0.0.1:8000`，`uvicorn.run(app, host="127.0.0.1", port=8000)`。

### 4.5 前端接入（唯一允许改动面）

- 新增 `assets/js/api.js`：REST 封装 + WS 连接（指数退避重试）+ 事件分发到 `PivotStore.handleWsEvent`。
- `store.js`：`init()` 改为异步——先 API 全量，失败回退 MOCK；各动作函数改为『API 成功→用服务端返回实体；网络失败→原 mock 逻辑』；新增 `handleWsEvent`/`saveNodePos`。
- `index.html` 仅加一行 api.js 引用；`topology.js` 仅加拖拽位置上报/恢复两行（详见 ASSUMPTIONS.md）。

### 4.6 MS1 验证

1. `python -m pivothub` 启动，`curl http://127.0.0.1:8000/api/projects` 返回 seed 项目。
2. Chrome headless + CDP（复用 .verify 思路）：逐个切换 11 视图，收集 console error/warning，要求 0/0；断言 `PivotStore.state.hosts` 来自 API（修改 DB 后刷新可见）。
3. `pytest tests/ -q`（MS1 先落 conftest + 模型 CRUD + state 聚合 + 导出快照 3 组测试）。
4. 重启服务，数据仍在（SQLite 持久化验证）。

## 5. 风险与对策

| 风险 | 对策 |
|---|---|
| Windows 无 pty 模块，MS2 TTY 固化依赖真实 Linux 靶机回显 | MS2 起 Docker 靶场（scripts/lab）提供真实 Linux WebShell；Windows 技法按 PowerShell 会话编排 |
| frp/chisel 等二进制不可得 | Adapter 支持本地已有二进制路径配置 + lab 内用 chisel（单文件易备）；缺失时 Adapter 明确报错不假装成功 |
| 前端部分动作散落在视图文件（proxy.js deploy 等） | 以 store.js 新增动作承接，视图最小改动逐条记录 ASSUMPTIONS.md |
| Chrome/Playwright 不可用 | MS1 用现成 CDP 脚本；e2e 交付前安装 Playwright + chromium |
