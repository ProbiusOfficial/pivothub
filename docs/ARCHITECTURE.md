# PivotHub 后端架构（ARCHITECTURE）

> 对应 PRD §3.2 架构分层。前端原型零构建（Vue 3 CDN），由后端 StaticFiles 原样托管。

```
┌────────────────────────────────────────────────────────────┐
│ 浏览器面板（127.0.0.1:8000，StaticFiles 托管原型）           │
│   assets/js/api.js ── REST(/api/*) + WS(/ws)                │
│   assets/js/store.js ── API 优先，失败回退 MOCK（永不白屏）  │
├────────────────────────────────────────────────────────────┤
│ API 层 pivothub/api/        （路由只做参数校验与编排，       │
│   projects/hosts/shells/     不出现 subprocess）             │
│   links/creds/flags/timeline/export                         │
├────────────────────────────────────────────────────────────┤
│ 服务层 pivothub/service/                                    │
│   timeline.py 自动事件+WS广播   statlib.py 看板统计          │
│   export.py 三格式导出          probe.py 出网探测(MS3)       │
│   tty.py 终端固化(MS2)          credreuse.py 复用推荐(MS5)   │
│   deploy.py 部署编排(MS3)                                    │
├────────────────────────────────────────────────────────────┤
│ 会话抽象层 pivothub/session/（所有命令执行/文件读写的唯一出口）│
│   base.py Session 接口: test/exec/list_dir/read_file/       │
│                         write_file/close                    │
│   local.py 本地进程驱动（供联调/靶场）                        │
│   http_shell.py WebShell 协议驱动(MS2，冰蝎/哥斯拉留扩展点)   │
├────────────────────────────────────────────────────────────┤
│ 适配器层 pivothub/adapters/（统一生命周期，MS3 起启用）       │
│   generate_config → deploy → start → wait_callback          │
│   → register_link → health_check → destroy                  │
│   frp / chisel / Neo-reGeorg（一期真实实现）                 │
│   nps / EW / Stowaway / Venom / ligolo-ng（占位，接口齐全）   │
├────────────────────────────────────────────────────────────┤
│ 持久层 SQLAlchemy 2.x + SQLite（pivothub.db，WAL）           │
│   Project/Host/Shell/ProxyLink/Credential/Flag/TimelineEvent│
│   data/ 插件：commands/*.json payloads/*.json               │
│               tty_fixes/*.json meta.json seed_project.json  │
└────────────────────────────────────────────────────────────┘
```

## 1. 数据契约

- 所有出参字段名与 `assets/js/mock.js` 一致（`Shell.lastBeat`『刚刚/N 秒前（断线）』、`TimelineEvent.time`『HH:MM』、中文枚举原样）。
- DB 存规范形式（ISO datetime / JSON 列表），`pivothub/schemas/` 负责渲染为契约字符串。
- `GET /api/projects/{id}/state` 一次返回前端 `init()` 所需全部键（与 MOCK 顶层同构）。
- `POST /api/shells` 的请求体字段 `pass`（Python 侧 `pass_`，Pydantic alias 处理）。

## 2. 实时通道（/ws）

事件类型与 README §6.2 一致：`shell.beat / shell.output / shell.tty / probe.result / link.state / link.created / host.found / cred.found / timeline.push / ws.online`。
`ws/manager.py` 提供 `manager.push(type, **payload)` 线程安全入口：服务层写库后统一推送；后台线程（MS3 适配器回连监听）通过 `note_loop` 记录的主事件循环投递。
前端 `api.js` 自动重连（指数退避 ≤10s），`store.handleWsEvent` 按 type 增量更新 reactive 状态。

## 3. 状态恢复（可靠性要求）

- 服务启动 `init_db()`：建表；空库时播种演示项目（data/seed_project.json）。
- `ProxyLink.pid` 记录本机子进程号；健康检查用 `util.proc_alive` 真实核验，失联标 `error`，可一键重拉（MS3 起 Adapter 真实重拉进程）。
- 重启后面板刷新即从 SQLite 全量恢复；拓扑拖拽位置存 `hosts.pos_x/pos_y`。

## 4. 插件化数据

| 目录 | 内容 | 消费方 |
|---|---|---|
| data/commands/*.json | 命令速查（6 分类） | /state → 命令速查视图 |
| data/payloads/*.json | 写马姿势（马模板 MS2 扩展） | /state → 马生成器 |
| data/tty_fixes/*.json | 终端固化技法（Linux/Windows） | /state → 终端固化面板（MS2 执行引擎） |
| data/meta.json | 枚举目录/工具表/探针基线/文件树初值 | /state |
| data/seed_project.json | 演示项目（与 mock.js 场景一致） | 首启播种 |

`scripts/export_mock_to_data.mjs` 可在 mock.js 变更后重新导出，保持「mock.js 是数据模型唯一权威」。

## 5. 合规边界

- 仅监听 127.0.0.1（config 断言强制）；无认证（本地单机工具）。
- 不内置任何针对真实目标的 exploit；命令库/技法库均为通用运维与官方工具参数编排。
- README 与启动横幅双处声明「仅限 CTF / 授权靶场 / 教学」。
