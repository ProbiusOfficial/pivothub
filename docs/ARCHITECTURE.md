# PivotHub 后端架构（ARCHITECTURE）

> 对应 PRD §3.2 架构分层。前端零构建（Vue 3 本地化 + ECharts 5），由后端 StaticFiles 原样托管。
> 数据一律来自后端，前端**没有 mock 回退**（`assets/js/mock.js` 已于第 4 轮移除）。

```
┌────────────────────────────────────────────────────────────┐
│ 浏览器面板（127.0.0.1:8000，StaticFiles 托管前端）           │
│   assets/js/api.js ── REST(/api/*) + WS(/ws)                │
│   assets/js/store.js ── 数据全部来自后端（无 mock 回退）     │
├────────────────────────────────────────────────────────────┤
│ API 层 pivothub/api/        （路由只做参数校验与编排，       │
│   projects/hosts/shells/     不出现 subprocess）             │
│   links/creds/flags/timeline/export/recon/stage/tools/attack│
├────────────────────────────────────────────────────────────┤
│ 服务层 pivothub/service/                                    │
│   timeline.py 自动事件+WS广播   statlib.py 看板统计          │
│   export.py 三格式导出          probe.py 出网探测            │
│   tty.py 终端固化               relay.py 链路编排/多级中继   │
│   recon.py 资产探测(含 fscan)   filestage.py 上传暂存        │
├────────────────────────────────────────────────────────────┤
│ 会话抽象层 pivothub/session/（所有命令执行/文件读写的唯一出口）│
│   base.py Session 接口: test/exec/list_dir/read_file/       │
│                         write_file/close                    │
│   local.py 本地进程驱动（供联调/靶场）                        │
│   http_shell.py WebShell 协议驱动（冰蝎/哥斯拉留扩展点）      │
│   reverse.py 反弹通道（原始 PTY 直连） registry.py 会话注册   │
├────────────────────────────────────────────────────────────┤
│ 适配器层 pivothub/adapters/（统一生命周期）                   │
│   generate_config → deploy → start → wait_callback          │
│   → register_link → health_check → destroy                  │
│   chisel（已接入真实实现）                                    │
│   frp / nps / Neo-reGeorg / EW / Stowaway / Venom /         │
│   ligolo-ng（占位，status=offline，接口齐全）                 │
├────────────────────────────────────────────────────────────┤
│ 持久层 SQLAlchemy 2.x + SQLite（pivothub.db，WAL）           │
│   Project/Host/Shell/ProxyLink/Credential/Flag/TimelineEvent│
│   data/ 插件：commands/*.json payloads/*.json               │
│               tty_fixes/*.json meta.json seed_project.json  │
└────────────────────────────────────────────────────────────┘
```

## 1. 数据契约

- **`pivothub/schemas/` 是字段名与枚举值的唯一权威**（`ShellOut.lastBeat`『刚刚/N 秒前（断线）』、`TimelineOut.time`『HH:MM』、中文枚举原样）；前端消费侧见 `assets/js/store.js`。
- DB 存规范形式（ISO datetime / JSON 列表），`pivothub/schemas/` 负责渲染为契约字符串。
- `GET /api/projects/{id}/state` 一次返回前端 `init()` 所需全部键（项目 / 攻击机 / 资产 / 会话 / 链路 / 凭据 / Flag / 时间线 + 静态目录）。
- `POST /api/shells` 的请求体字段 `pass`（Python 侧 `pass_`，Pydantic alias 处理）。
- 项目级隔离：除攻击机网络（`Project.settings.attack`）外，所有实体表都带 `project_id`；
  `DELETE /api/projects/{id}` 级联清理该项目全部数据，且至少保留一个项目。

## 2. 实时通道（/ws）

后端实际推送的事件（`manager.push`）：

| 事件 | 载荷 | 触发 |
|---|---|---|
| `shell.beat` | shellId / alive / latency / lastBeat | 心跳 |
| `shell.output` | shellId / kind(`out`\|`raw`) / line | 命令回显、反弹通道原始输出、扫描日志镜像 |
| `shell.tty` | shellId / mode / hasPty / term | 终端固化状态变化 |
| `shell.created` | shell | 登记 / 反弹回连自动登记 |
| `probe.result` | hostId / probe / ok / ms / evidence / cmd | 出网探测逐探针 |
| `recon.scan` | jobId / shellId / status / kind / line / seq | 资产扫描流式日志 |
| `attack.updated` | attack | 攻击机网络变更 |
| `tools.updated` | tools[] | 项目级代理工具启用集变更 |
| `link.state` | linkId / status / latency / traffic | 链路健康 |
| `link.created` | link | 链路登记 / 部署成功 |
| `link.removed` | linkId / projectId | 链路记录删除 |
| `host.found` | host | 资产登记 / 扫描导入 |
| `host.removed` | hostId / projectId / shellIds | 资产移除（级联） |
| `timeline.push` | event | 时间线新增 |
| `project.removed` | projectId | 项目删除 |
| `ws.online` | online | 前端本地标记连接状态 |

`ws/manager.py` 提供 `manager.push(type, **payload)` 线程安全入口：服务层写库后统一推送；
后台线程（Adapter 回连监听）通过 `note_loop` 记录的主事件循环投递。
前端 `api.js` 自动重连（指数退避 ≤10s），`store.handleWsEvent` 按 type 增量更新 reactive 状态。

## 3. 状态恢复（可靠性要求）

- 服务启动 `init_db()`：建表；空库时播种演示项目（`data/seed_project.json`，非空库不覆盖）。
- `ProxyLink.pid` 记录本机子进程号；健康检查用 `util.proc_alive` 真实核验，失联标 `error`，可一键重拉。
- 重启后面板刷新即从 SQLite 全量恢复；拓扑拖拽位置存 `hosts.pos_x/pos_y`。

## 4. 插件化数据

| 目录 | 内容 | 消费方 |
|---|---|---|
| data/commands/*.json | 命令速查（6 分类） | /state → 命令速查视图 |
| data/payloads/*.json | 写马姿势 | /state → 马生成器 |
| data/tty_fixes/*.json | 终端固化技法（Linux/Windows） | /state → 终端固化面板 |
| data/meta.json | 枚举目录/工具表/探针基线/文件树初值 | /state |
| data/seed_project.json | 演示项目（三层内网场景） | 首启播种 |

## 5. 合规边界

- 仅监听 127.0.0.1（config 断言强制）；无认证（本地单机工具）。
- 不内置任何针对真实目标的 exploit；命令库/技法库均为通用运维与官方工具参数编排。
- README 与启动横幅双处声明「仅限 CTF / 授权靶场 / 教学」。
