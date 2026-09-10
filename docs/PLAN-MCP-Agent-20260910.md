# 计划：顶栏 MCP 服务 + Agent 会话

- 日期：2026-09-10
- 状态：**待确认开工**
- 范围：PivotHub 面板新增「MCP 服务」（对外暴露）与「Agent 会话」（面板内置 AI 对话），入口均在顶栏

---

## 0. 一句话目标

让 PivotHub 从「人操作的面板」变成「人 + AI 都能操作的作战中枢」：

- **对外**：面板自身作为 **MCP Server**，外部 AI 客户端（Claude Desktop / Cursor / 自研 Agent）可查询并操作面板；
- **对内**：面板内置 **Agent 会话**，用同一张 MCP 工具表驱动面板干活（自举），模型可切换自定义端点或官方 API。

---

## 1. 已确认决策（用户拍板）

| 项 | 决定 |
|---|---|
| MCP 定位 | **面板对外提供 MCP**（Server 侧） |
| MCP 实现 | **官方 `mcp` Python SDK**（`>=2.2,<3`，锁大版本） |
| 模型接入 | **双端点可配**：自定义端点优先，官方 API 兜底 |
| Agent 权限 | **全权限自动执行**（不逐步确认） |
| 顶栏位置 | 「WS 已连接」与「全局设置」之间插两个控件 |

---

## 2. 实测证据（已跑，非假设）

| 端点 | 模型清单 | 工具调用 |
|---|---|---|
| `http://192.168.3.33:1234/v1`（自定义 / LM Studio） | `qwen3.8-flash-next-131b-a6b`、`qwen3.6-35b-a3b`、`qwen3.8-27b`、`text-embedding-nomic-embed-text-v1.5` | ✅ `finish_reason=tool_calls` → `list_hosts {}` |
| `https://api.deepseek.com/v1`（官方） | `deepseek-flash`、`deepseek-v4-pro` | ✅ `finish_reason=tool_calls` → `list_hosts {}` |

`mcp` SDK 环境事实（本机 venv 实测）：

- 已装版本 **2.2.0**
- 高层 API：`mcp.server.MCPServer`（即 1.x 的 `FastMCP` 在 2.x 的改名）
  - `@server.tool()` 注册工具
  - `server.run(transport='stdio'|'sse'|'streamable-http')`
  - `server.streamable_http_app(...) -> Starlette`（**可直接 mount 进现有 FastAPI**）
- ⚠️ 2.x **不存在** `mcp.server.fastmcp`（迁移时不要按 1.x 文档写）
- 传递依赖：`httpx2`、`sse-starlette`、`jsonschema`、`pyjwt`、`opentelemetry-api`、`python-multipart`、`pywin32`、`mcp-types`

---

## 3. 架构

```
外部 AI 客户端 ──MCP(stdio / streamable-http)──┐
                                              ├─→ pivothub/mcp/tools.py（工具注册表）
面板内 Agent 会话 ──LLM /chat/completions─────┘        │
        └── 工具调用与外部客户端走同一张表 ────────────┘
                                                       ↓
                                        pivothub/service/*（既有业务层，不重写）
                                                       ↓
                                        pivothub/session/*（唯一命令执行出口）
```

**硬约束（沿用项目既有规矩）**：

- `subprocess` 只出现在 `adapters/` 与 `session/` 层 —— MCP 工具层**只能**调 `service/*`，不许自己碰进程
- MCP 端点**只监听 127.0.0.1**（`config.py` 已有断言）
- 面板作为 MCP Server 是**暴露能力**，不是新增攻击面：所有动作仍走既有会话层

---

## 4. MCP 服务设计

### 4.1 传输与端点

| 传输 | 用途 | 落地 |
|---|---|---|
| **streamable-http** | 远程/同机客户端（Claude Code、Cursor、自研） | `app.mount("/mcp", server.streamable_http_app())` |
| **stdio** | Claude Desktop 等「命令+参数」型客户端 | 新增 `pivothub/mcp/stdio.py`，入口 `python -m pivothub.mcp.stdio` |

### 4.2 鉴权

- HTTP：`Authorization: Bearer <token>` 中间件；token 由面板生成（随机 32 hex），可在顶栏芯片里**复制 / 轮换**
- stdio：进程级信任（本机同用户），不额外鉴权
- Token 存储：**DB `Project.settings["mcp"]["token"]`**（`*.db` 已 gitignore），不落源码

### 4.3 工具表（复用既有 service，全覆盖 + 危险等级）

**只读类（`danger: none`）**

| 工具 | 映射 |
|---|---|
| `get_project_state` | `build_state()`（主机/会话/链路/Flag/时间线一次性） |
| `list_hosts` / `list_shells` / `list_links` | state 派生 |
| `list_credentials` / `list_flags` | state 派生 |
| `get_timeline` | 时间线（分页） |
| `get_attack_config` | 攻击机网络配置 |
| `list_tools` / `list_stages` | 工具启用集 / 阶段名 |

**动作类（`danger: low`）**

| 工具 | 映射 |
|---|---|
| `shell_probe` | `POST /shells/{id}/probe`（出网四探针） |
| `shell_probe_callback` | `POST /shells/{id}/probe/callback`（回连端口矩阵，A4） |
| `scan_clues` | `POST /clues/scan`（A2） |
| `fingerprint_scan` / `discover_dirs` | A9 / A10 |
| `recon_env` | `POST /recon/env` |
| `test_shell` / `heartbeat_all` | 连通性 / 存活 |
| `list_files` / `read_file` | 会话层文件 IO |

**动作类（`danger: high`，全自动执行但记审计）**

| 工具 | 映射 |
|---|---|
| `exec_command` | `POST /shells/{id}/exec` |
| `deploy_link` | `POST /links/deploy`（chisel / frp / Neo-reGeorg） |
| `destroy_link` | 销毁链路（逐层清理进程） |
| `recon_scan` | `POST /recon/scan/stream` |
| `add_ssh_session` | `POST /shells/ssh`（A7） |
| `escalate_shell` | 提权包装器 |
| `add_host` / `add_cred` / `add_flag` / `patch_flag` | 资产登记 |

> 每个工具的 `description` 都写清"会真实执行什么"，便于模型自我约束；`danger` 等级用于面板提示与审计标记，不阻断。

---

## 5. Agent 会话设计

### 5.1 内核

- LLM 客户端：OpenAI 兼容 `/chat/completions`（curl 实测双端点均支持 tool calling）
- 循环：`user → LLM → (tool_calls)* → 执行 → 回填 tool 结果 → LLM → … → 文本`，上限轮数 + 超时保护
- 会话持久化：新建 `AgentSession` / `AgentMessage` 表（`pivothub/models/`）或复用 `Project.settings`（见 §7 待确认）
- 流式：走既有 WS（`manager.push("agent.delta" / "agent.tool" / "agent.done")`）

### 5.2 UI（顶栏「Agent 会话」）

- 右侧**抽屉**（不占主视图，可边看拓扑边对话）
- 消息流：用户/助手气泡 + **tool call 折叠卡片**（工具名、参数、结果摘要、耗时、状态）
- 顶部一段常驻：当前模型（端点/模型名）+「⚠ 自动执行中」指示 + 急停按钮

### 5.3 权限（按你的决定：全权限自动执行）

**全部工具直接执行，不逐步确认。** 我额外加四道不打断流程的兜底：

1. 顶栏常驻 **「⚠ 自动执行中」** 指示（醒目、不可忽视）
2. **所有工具调用全量写入操作时间线**（可审计、可复盘）
3. **一键急停**：立刻中止当前循环并切断后续工具调用
4. **危险命令黑名单**：`rm -rf /`、`mkfs`、`dd of=/dev/`、`:(){ :|:& };:` 等**命中即阻断**并回显原因（其余全自动）

> 保留开关：配置里可切「逐步确认」模式，默认按你的要求关闭。

---

## 6. 任务清单

### A 档（本轮）

| 编号 | 任务 | 交付 |
|---|---|---|
| **A1** | MCP 服务骨架 | `pivothub/mcp/server.py`（MCPServer 实例 + `/mcp` mount）、`pivothub/mcp/stdio.py`、Token 中间件 |
| **A2** | 工具注册表 | `pivothub/mcp/tools.py`（§4.3 全表 + JSON-Schema + danger 标注） |
| **A3** | MCP 管理 API | `get/put /api/mcp`（开关、端点、token 轮换）、`GET /api/mcp/tools`、`GET /api/mcp/logs` |
| **A4** | Agent 内核 | `pivothub/agent/client.py`（双端点 LLM 客户端）、`pivothub/agent/runner.py`（工具循环）、`api/agent.py` |
| **A5** | 顶栏两个入口 | 「MCP 服务」芯片+弹窗、Agent 抽屉（`assets/js/views/agent.js` + `assets/js/mcp.js`） |
| **A6** | 配置与密钥 | `Project.settings["llm"]`（端点/模型/Key/备用端点），`PIVOTHUB_LLM_KEY` 环境变量覆盖，MOCK 兜底 |
| **A7** | 安全兜底 | 自动执行指示、审计时间线、急停、危险命令黑名单 |

### B 档（后续）

- B1 MCP `resources` / `prompts`（不只 tools）
- B2 多轮记忆 + 上下文压缩 + 「攻击路径规划」模式
- B3 Agent 与拓扑联动（高亮正在操作的节点）
- B4 反向模式：面板作为 MCP **客户端**消费外部 MCP

---

## 7. 待确认

1. **会话持久化方式**：新建表（干净、可查询）vs 复用 `Project.settings`（零迁移）—— 我倾向**新建表**，会走一份 `db.py` 迁移
2. **默认模型**：Agent 默认走哪个？我倾向**自定义端点 `qwen3.8-flash-next-131b-a6b`**（本地、快、不花钱），官方 `deepseek-flash` 作一键切换
3. **stdio 入口是否本轮做**：Claude Desktop 用户需要它；如果只服务 Cursor/Claude Code 可缓做

---

## 8. 验收标准

1. 外部 JSON-RPC 调通 `initialize` → `tools/list` → `tools/call`，**返回真实面板数据**（不是桩）
2. 面板内 Agent 跑通闭环：*列出主机 → 对某主机出网探测 → 给出结论*
3. 新增 `tests/test_mcp.py`（协议握手 / 工具表 / 鉴权 401 / 危险命令阻断）、`tests/test_agent.py`（工具循环 / MOCK 模式 / 急停）
4. **全量回归保持绿**（跑前必须先停 `python run.py`——踩过坑）

---

## 9. 风险与对策

| 风险 | 对策 |
|---|---|
| MCP SDK 大版本破坏性变更（1.x→2.x 已发生 FastMCP→MCPServer 改名） | `requirements.txt` 锁 `mcp>=2.2,<3`；工具层与 SDK 解耦（工具表是纯 dict + 可调用） |
| 依赖体积膨胀（`mcp` 拖 8 个包） | 仅在启用 MCP 时导入（延迟 import），未启用不影响启动 |
| 全自动执行下模型幻觉造成破坏 | 危险命令黑名单 + 全量审计 + 急停；文档明确风险 |
| LLM 端点不可达 / Key 失效 | 明确 MOCK 模式（打标"未接模型"），绝不伪造结果 |
| 密钥泄漏 | 只存 DB（已 gitignore）+ 环境变量覆盖；日志打码；不写入源码与文档 |
