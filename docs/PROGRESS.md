# 推进日志（PROGRESS）

> 每轮记录：完成项 / 验证证据 / 下一轮计划 / 未决问题。按轮倒序追加。

---

## 第 6 轮（2026-09-09，用户反馈驱动）：终端输入修复 + 反弹 Shell 引导 + 攻击机全局设置

### A. 修掉「虚拟终端敲不进字」（真实 bug，浏览器实测复现）

**根因**：`index.html` 终端输入框同时写了 `ref="termInput"`（模板 ref）与 `v-model="termInput"`
（setup 返回的 writable computed）——**名字撞车**。Vue 重渲染时把 DOM 元素写回该绑定 → 触发
computed setter → `typeof el !== 'string'` 被强制置空 → 刚敲的字符立刻被清掉。

**证据**：给 `termState.input` 挂 setter 探针，敲入 `hello` 后 800ms 内被置空 3 次，调用栈均为
`vue.global.prod.js → shell.js:53 computed _setter`；DOM 值恒为空。

**修复**：模板 ref 改名 `termInputEl`，`focusTerm()` 改用它聚焦。浏览器实测：
`whoami` → 回显 `tomcat9`（JSP 靶机真实回显）；`↑` 历史与 Tab 补全正常。

### B. 反弹 Shell 引导流程（后端能力已有，前端补入口）

- 终端面板头部新增「反弹 Shell」按钮（HTTP 马会话可见，反弹会话隐藏）。
- 弹窗三步：① 攻击机监听（真实 socket，默认取全局设置里的攻击机 IP）→ ② 反弹载荷按平台选择
  （Linux bash / python3 / nc、Windows PowerShell，**均后台执行**，避免 WebShell 的 exec 等命令结束）→
  一键「发送到当前伪终端」→ ③ 回连后自动登记为面板会话（`kind=reverse`）并切到该会话终端。
- 步骤日志实时显示（监听 / 回连 / 登记），失败诚实报错。

**端到端实测（真实靶机）**：JSP 马（10.8.0.6，Debian/tomcat9）→ 监听 `10.8.0.12:4444` → bash 载荷回连
→ 自动登记 `s-zqo1p`（`reverse://10.8.0.6:52854`，228ms）→ 终端执行 `id; hostname; uname -m`
得 `uid=1000(tomcat9)` / `archive-web` / `x86_64`，提示符变为 `tomcat9@archive-web:/usr/local/tomcat$`。

### C. 攻击机全局设置 + 拓扑

- 顶栏新增「全局设置」：攻击机 IP / 网卡 / 网段 / 备注；「检测本机 IP」调 `GET /api/netinfo`
  自动填本机地址（过滤回环与 169.254.*，私网优先）；「同步到所有项目」逐项目 `PUT /api/attack`。
- 拓扑新增**反弹会话边**（目标 → 攻击机，蓝色虚线，tooltip 显示会话 / 延迟 / 状态）。
- 反弹会话的终端不再提示「WebShell 伪终端」，改为「反弹会话（原始通道）已建立」。

### D. 顺带修复

- 静态资源改 **no-store**（`NoCacheStaticFiles`）：面板是「改完刷新即看」的本地工具，JS/CSS 缓存
  曾导致「明明改了还是旧行为」（本轮排查终端 bug 时再次踩到）。

### 验证证据

| 项 | 命令 / 操作 | 结果 |
|---|---|---|
| 反弹接口测试 | `pytest tests/test_reverse_api.py -q` | **4 passed**（netinfo / 监听→回连→登记 / 未回连诚实失败 / 非法 bind 诚实失败） |
| 全量回归 | `pytest tests/ -q -p no:warnings` | **82 passed**（+4） |
| 全局设置 E2E | 顶栏 → 全局设置 → 检测本机 IP → 保存 | 填入 `10.8.0.12`，`/state.attack` 与攻击机节点同步 |
| 反弹 E2E | 终端 → 反弹 Shell → 开始监听 → 发送到伪终端 | 真实回连并登记；终端 `id` 回显 `uid=1000(tomcat9)`；0 控制台错误 |
| 拓扑 | 网络拓扑视图 | 边 `rev-s-zqo1p`：`h-xoedv → h-attacker`，蓝色虚线「反弹 Shell」 |

### 未决问题

- `kind=reverse` 会话的平台判定固定 `linux`（`ReverseShellChannel.platform`）：Windows 靶机反弹的
  载荷/命令适配待按回显识别平台后再分派；
- 面板重启后历史反弹会话会被标记断线（`_reset_reverse_shells`），监听端口不自动恢复，需重新开监听。

### 第 6 轮增补（2026-09-09，用户反馈：机器休眠后反弹 Shell 掉线）

用户实测环境：休眠后本机 IP 从 `10.8.0.12` 变成 `10.8.0.14`，旧监听仍占着端口。

| 问题 | 修复 |
|---|---|
| 「监听失败：该地址端口已在监听」 | `ReverseShellService.open()` 对同地址端口的**未回连**监听自动替换（返回 `replaced=true`）；已有回连的通道拒绝替换并提示先关闭 |
| 端口被已取走的通道长期占用 | `take()` 取走通道后关闭监听 socket 并清除回连标记 → 端口立即释放 |
| 「WinError 10049 地址无效」看不懂 | `listen` 先校验 bind 是否为本机当前地址，不是则返回 `stage=bind` + 本机地址列表；`start()` 对 10049/10048 追加可操作提示 |
| 没有释放监听的手段 | 新增 `DELETE /api/shells/reverse/listeners/{id}` 与 `DELETE .../listeners`（前端「关闭 / 清理全部监听」） |
| 反弹会话仍显示「伪终端」 | 终端徽标新增「交互通道（反弹）」（`modeBadge`）；打开反弹会话时自动跑一次真实交互能力检测 |
| 反弹 Shell 入口藏在弹窗里 | 升级为**独立视图「反弹 Shell」**（执行组）：半自动档 / 全自动档、监听列表（含关闭）、反弹会话列表（打开终端）、步骤日志 |
| 检测失败误报「后端不可用」 | `detectTty` 按 `reason` 归因（通道断开 → 明确提示重新监听 / 探活） |

**实测（休眠后真实环境）**：新模块提示 `10.8.0.12 已不在本机地址列表` → 一键换 `10.8.0.14` → 开监听 →
全自动档自动下发载荷 → 真实回连并登记 `s-eh7vv`（`reverse://10.8.0.6:51388`，240ms）；同端口重开
返回 `replaced=true`；失效地址返回「本机当前没有地址 10.8.0.12 …」+ 本机地址列表。

`pytest tests/test_reverse_api.py` → **6 passed**；全量 **84 passed**。

---

## 第 5 轮（2026-09-09，用户指令驱动）：MS4 收口 —— 代理工具只保留 chisel + 「代理工具设置」

### 完成项

1. **工具目录加 `status`**（`data/meta.json → tools[]`）：`chisel=online`，其余 7 款
   （frp / nps / Neo-reGeorg / EW / Stowaway / Venom / ligolo-ng）= `offline`。
2. **项目级启用集**：`Project.settings["tools"].enabled`（默认 = 全部 online 工具）；
   `GET/PUT /api/tools`（`PUT` 只接受 online 工具，offline / 未知 → **422** 并说明原因）；
   `/state.tools` 每项带 `status` + `enabled`；WS 新增 `tools.updated` 广播。
3. **前端「代理工具设置」弹窗**（代理编排台右上角）：两列工具卡片 + 自绘开关，online 可勾选、
   offline 显示「下线」且开关禁用；「隧道工具」下拉只渲染已启用项；未启用任何工具时下拉显示占位提示、
   「生成命令 / 一键部署」按钮禁用。
4. **探测推荐回退**：出网探测结论 / `applyRecommend` 命中未启用工具时回退到第一个已启用工具并 toast 说明。
5. **文档**：`docs/ASSUMPTIONS.md` A-22（可见性决策与理由）；`README.md` §6 契约（`/api/tools`、
   `tools.updated`、`Tool` 模型、MS4 范围）与 §9 已知边界（原文仍是「Mock 原型」旧描述，已按当前实现改写）。

### 验证证据

| 验证 | 命令 / 操作 | 结果 |
|---|---|---|
| 新增接口测试 | `python -m pytest tests/test_tools_api.py -q` | **4 passed**（默认仅 chisel / offline 422 / 项目级隔离 / 时间线留痕） |
| 全量回归 | `python -m pytest tests/ -q -p no:warnings` | **78 passed**（6:29，+4） |
| 浏览器：下拉只显示 chisel | 内置浏览器 · 代理编排台 | 「隧道工具」只有 `chisel — 单文件、易上传、HTTP 承载`；设置按钮徽标 `1` |
| 浏览器：设置弹窗 | 同上 → 代理工具设置 | 8 张卡片；chisel `is-on` + 开关可用；7 款 `is-off` + 开关 `disabled`；摘要「已启用 1 / 8」 |
| 浏览器：保存链路 | 关掉 chisel → 保存 | 下拉变占位项、徽标 `0`、控制台 0 错误；重新启用后恢复 `chisel` |
| 浏览器：交互回归 | 点卡片开关 → 取消 | 卡片态 `is-on → is-ready`、摘要 `0 / 8`，取消不落库 |

### 未决问题

- **MS4 的 8 款 Adapter 仍只完成 chisel**：本轮交付的是「可见性诚实收敛」，未新增 Adapter；
- 下线工具当前**不可启用**（刻意设计，见 A-22）：后续接入某款工具时把它的 `status` 改为 `online`
  并在 `adapters/registry.py` 注册即可，前端无需再改。

### 第 5 轮增补（2026-09-09，用户指令）：凭据 / 口令全明文，不再打码

| 改动 | 位置 |
|---|---|
| Shell 管理「密码」列明文（原 `••••`） | `index.html` |
| 凭据库「凭据」列明文 + 去掉「显示 / 隐藏」按钮 | `index.html` |
| Flag 墙 Flag 值明文 + 去掉「显示 / 隐藏」按钮 | `index.html`、`views/flag.js`（删 `mask()`） |
| 拓扑侧栏凭据列表明文（原 `c.secretMask` 未定义、渲染为空——顺带修掉） | `index.html` |
| 导出预览 Markdown 凭据明文 | `store.js buildMarkdown()` |
| 导出预览 JSON 明文（原 `pass/secret: '***'`） | `views/export.js` |
| 服务端导出 MD / JSON 明文（原脱敏） | `service/export.py` |
| 导出选项文案「敏感信息脱敏」→「明文」 | `index.html` |

验证：`tests/test_export_snapshot.py` **4 passed**（断言改为明文：md 含 `root123`、json
`pass`/`secret` 非 `***`）；浏览器注入内存数据核验 Shell / 凭据 / Flag 三处均渲染明文且无
「显示 / 隐藏」按钮、控制台 0 错误；全量 pytest **78 passed**。决策记录见 `ASSUMPTIONS.md` A-23。

---

## 第 4 轮（2026-09-09，用户指令驱动）：彻底移除 Mock 回退 + 真题 ④ 实战

### A. 彻底去 Mock（用户明确授权的前端改动）

| 改动 | 位置 | 说明 |
|---|---|---|
| 不再加载 `mock.js` | `index.html` | 删除 `<script src="assets/js/mock.js">`（文件保留在仓库，但无任何引用） |
| 删除全部 mock 回退函数 | `assets/js/store.js` | 14 个 `mock*` 函数（testShell/detectTty/applyTtyFix/runTtyFinish/execCommand/refreshFileEntries/testLink/restartLink/stopLink/addHost/importScan/addCred/addFlag/addNote）整体移除；1381 → 1092 行 |
| 状态不再以假数据初始化 | `store.js` | `project/projects/segments/attack/hosts/shells/links/creds/flags/timeline/commands/injectTips/ttyFixes/files` 全部改为空值，只由 `/state` 填充 |
| 静态目录改读后端 | `store.js` + 6 个视图 | 新增 `state.probes/tools/shellTypes/encoders/credKinds/layers/stageNames/scanSample` 并由 `applyState` 回填；`asset.js/cred.js/dashboard.js/flag.js/proxy.js/shell.js` 的 `MOCK.*` 全部改 `S.state.*` |
| 失败显式反馈 | `store.js` | 新增 `failApi()`；命令/链路/主机/凭据/Flag/笔记等动作在后端不可用时**报错**而不是造假数据；终端里红字 + 原因 |
| 视图内的假动画/假结果移除 | `shell.js`（文件读取/写入/上传）、`cred.js`（横向「成功」随机数）、`generator.js`（写马「成功」随机数） | 只走真实接口，失败即报错 |
| 文案 | `index.html` | 底栏 `MOCK` → `未连接`；「打包项目（Mock）」→「打包项目」 |

验证：`hasMock=false`、`apiMode=true`、`layers/stageNames/tools/probes` 均由后端下发（4/4/8/4）；
11 视图 **错误 0 / 警告 0**；`python -m pytest tests/ -q -p no:warnings` → **74 passed**。

### B. 真题 ④ 回声 · 遗忘的部署（详见 `docs/CTF-ECHO-04.md`）

- 独立项目 `proj-10h9m`（演示项目 `proj-1` 未污染）；攻击机 `10.8.0.12`。
- 链路：CVE-2017-12615 PUT 写 JSP 马 → `/dev/tcp` 反弹（新增会话层 `reverse` 驱动）→
  `/etc/passwd` 666 追加 UID=0 账户 + `script` 造 PTY + `/io` 喂密码 → `uid=0(root)` →
  `db.properties` 弱口令读内网库。
- **3/3 flag**：`flag{t4-6b2f19d3-…}` / `flag{t4-d4c803f9-…}` / `flag{t4-a91d57e2-…}`，已入 Flag 墙 + 时间线复盘。
- 新增能力：`pivothub/session/reverse.py`（监听/通道/交互读写）、
  `/api/shells/reverse/{listen,listeners,register}`、`POST /api/shells/{id}/io`、
  `Shell.kind` 字段（含 DB 自动迁移）、`?project=<id>` 深链。
- 面板重启后历史反弹会话自动标记断线（`app._reset_reverse_shells`），避免「绿点但敲不进命令」。

---

## 第 3 轮（2026-09-09）：落地 + 契约同步 + 代理编排闭环 —— 🚧 进行中

### 落地决策

后端**铺开在工作区根目录**（`pivothub/` `data/` `tests/` `scripts/` `tools/`），
不建 `pivothub-backend/` 子目录；理由与目录树见 `docs/PLAN-ROUND3.md` §1。
根目录 `index.html` / `assets/**` 保持交付基线，`_audit\supershell` 旧前端未被使用。

### 本轮完成项

1. **对账（任务 A）**：`docs/FRONTEND-SYNC-ROUND3.md` —— 逐文件 MD5 对账交付基线 zip：
   `index.html`(80,603) / `assets/js/mock.js`(30,930) / `topology.js` / `css/**` / `vendor/**`
   **字节级一致**；第 3 轮仅改 3 个 JS 数据流文件（`api.js` +3、`store.js` +61、
   `views/proxy.js` +97/−19），无 UI 结构/样式改动；旧前端（index.html 72,381 / proxy.js 17,768）
   已彻底替换。
2. **契约同步（任务 B）实测核对**：新增 `_work/contract_check.py`（无 chisel 依赖、独立临时库）
   逐条核对 27 项 → **27/27 PASS**（详见下表）。
3. **修复契约缺口（B-2）**：`service.timeline.segments_of` 原先跳过 `is_local` 主机 →
   `/state.segments` 只有 L1/L2/L3 三段，缺 `192.0.2.0/24(VPN,#00e5a0)`。
   已改为攻击端网段单列 `layer="VPN"`（主机自身 layer 仍为 `LOCAL`，与 mock 一致），
   顺序/配色按 `data/meta.json`；`tests/test_state_api.py` 改为逐条断言 mock.js 的四段契约
   （原 `test_segments_aggregated_without_local` 锁定了错误行为，随 `ASSUMPTIONS A-5 → A-20` 修正）。
4. **测试隔离修复（避免会话互杀）**：`tests/test_link_deploy.py` 原会话夹具按
   `IMAGENAME eq chisel.exe` **全机** taskkill，同机并发会话会互相杀掉对方的隧道服务端，
   导致 `wait_callback` 阶段假失败（`服务端进程退出`）。已改为只清理
   ①本会话真实启动过的 pid（从 deploy 响应逐层记录）②命令行命中本会话专属暂存目录的 chisel 进程。
5. **文档**：新增 `docs/PLAN-ROUND3.md`、`docs/FRONTEND-SYNC-ROUND3.md`；
   `docs/ASSUMPTIONS.md` 补 A-19（第 3 轮权威顺序）与 A-20（segments 含 VPN，修正 A-5）；
   `README.md` §6 契约同步（新增 `/api/attack`、`/api/links/deploy`、`/api/links/relay-plan`、
   `/api/links/{id}/verify` 与 `attack.updated` WS 事件；模型补 `Attack/Segment`、`Host.ifaces`、
   `ProxyLink` 全字段与 `localSocks` 新语义）；`docs/VERIFY.md` 第 5/6/6b/6c/8 条由「🔜 MS3」
   改为可复跑命令 + 通过记录。
6. **部署链路两处健壮性修复**（`pivothub/adapters/chisel.py`、`pivothub/api/links.py`）：
   - `_spawn_background(marker=...)`：目标侧进程定位改用本次部署唯一的 `--auth` 令牌
     （原先用 `"client"` 子串，同机存在历史/其他会话的 chisel client 时会认错 pid，
     导致销毁结束错误进程、留下孤儿）；
   - `DeployIn.bindHost` 原先在部署路径**完全未被使用**（服务端写死 `0.0.0.0`）；
     现按 `bind_host or lhost` 绑定攻击机侧 chisel 服务端，缺省取用户配置的攻击机地址。
7. **清理**：删除早期调试残留 `scripts/lab/wwwroot/%TEMP%\.pivothub\chisel.exe`
   （`%TEMP%` 未展开写进联调靶根目录的产物）。
8. **portfwd 验证真实化（不伪造成功）**：全量复跑暴露 `test_deploy_failure_reports_real_stage`
   ——目标服务端口关闭时部署仍返回成功。根因：`verify_tunnel(portfwd)` 只检查「本机入口端口可连」，
   而 chisel 的反向监听对失败的目标拨号同样会接受连接（本机侧看不到差异）。
   现改为**先在跳板机侧实测目标服务**（Windows `TcpClient.Connect` / POSIX `/dev/tcp`，
   真实回显判定 `TCP OPEN`/`TCP CLOSED`），不可达则诚实返回 `stage=verify` +
   「目标服务不可达：跳板机连接 <host>:<port> 失败（原因）」并回滚进程；
   `POST /api/links/{id}/verify` 同样在可用会话下做该实测。

### 验证证据（本轮已跑）

| 验证 | 命令 | 结果 |
|---|---|---|
| 启动横幅（GBK 控制台 936，未设 PYTHONIOENCODING） | `chcp` + `python -c "import pivothub.config as c; c.init_console(); print(c.BANNER)"` | **BANNER-OK**，无 UnicodeEncodeError |
| 契约核对 27 项 | `python _work/contract_check.py` | **27/27 PASS** |
| state/export 接口测试 | `python -m pytest tests/test_state_api.py tests/test_export_snapshot.py -q -p no:warnings` | **20 passed**（含新 segments 契约） |
| 链路纯逻辑测试 | `python -m pytest tests/test_link_deploy.py -q -k "generate_config or relay_plan or next_segment"` | **4 passed** |
| 全量测试（修复后复跑） | `python -m pytest tests/ -q -p no:warnings` | **74 passed**（6:34，与另一会话的 pytest 并发运行亦通过） |
| 三种链路 + 三层中继 + 无孤儿（独立证据） | `python _work/evidence_mine.py`（→ `_work/evidence-independent.json`） | socks/portfwd/relay 全部 `ok=true`，逐层 pid 全部 `killed=true`，`leftover_from_links=[]`、四个端口全部关闭 |

### 三种链路 / 三层中继 / 无孤儿：独立证据（`_work/evidence-independent.json`）

| 链路 | 结果 | 逐层 pid | 隧道内实测 |
|---|---|---|---|
| socks | `ok=true` | server 72776 · target 76484（销毁后均 `killed=true`） | 经本机 Socks5 入口读到目标服务（banner `(connected, no banner)`，目标为 miniweb 靶） |
| portfwd | `ok=true` | server 69608 · target 80844（销毁后均 `killed=true`） | 直连 `localPort` 读到 **`HTTP/1.0 200 OK`**（真实目标服务回显） |
| relay（三层） | `ok=true` | server 79192 · relay 69100 · target 72392（销毁后均 `killed=true`） | 经三层链路读到目标服务；`relay-plan` 推导 `relayAddr=10.85.101.210`（上层跳板在 L2 网段的 `ifaces` 地址）、`targetSegment=172.56.102.0/24`、三步命令 `server -p 65151 --reverse` → `client 192.0.2.10:65151 65151:65151` → `client 10.85.101.210:65151 R:0.0.0.0:65153:socks` |
| 攻击机配置 | `PUT /api/attack` | — | `192.0.2.10 → 10.0.17.88`，`/state.attack` 同步 |
| 出网探测 | `ok=true` | — | 四探针真实执行（ICMP ok / DNS fail / HTTP `HTTP 200` / TCP `TCP OPEN`）→ 「可反向 TCP / HTTP 出网」 |
| 销毁后无孤儿 | — | — | `leftover_from_links=[]`；`ports_closed` 四个端口全 `true`（`chisel_pids_now` 仅剩另一并发会话的 2 个进程，非本链路） |

### 浏览器验收（独立实例 8000 + 独立临时库，Chrome Headless + CDP）

| 验收 | 命令 | 结果 |
|---|---|---|
| 后端一条命令启动 + 仅监听回环 | `PIVOTHUB_PORT=8000 python -m pivothub --no-open` → `Get-NetTCPConnection -LocalPort 8000 -State Listen` | `127.0.0.1:8000`（无 0.0.0.0）；`/api/health` 200 |
| 11 视图 0 错误 0 警告 | `PH_URL=http://127.0.0.1:8000/ node _work/verify/cdp-test.js` | **错误 (0) / 警告 (0)**；11 视图全部渲染（看板 133 节点 / 拓扑 canvas / Shell 表格 / 速查 16 面板…） |
| 代理编排台（三种链路/中继推导/攻击机设置） | `node _work/verify/proxy-test.js` | **错误 (0)**；链路类型三项齐全；选中 L2 双网卡机自动推导中继：`relayAddr=10.85.101.3:1331`、`targetSegment=172.56.102.0/24`、三步命令与后端 `relay-plan` 逐字一致；攻击机弹窗保存后 `attackIpNow=10.0.17.9` 且健康看板出口/命令同步；拓扑 `segments` 四段含 VPN |
| 「＋ 新建」→ 干净工作区 | `node _work/verify/newproject-test.js` | **NEWPROJECT-TEST: PASS**；`proj-1(10 主机) → 新项目(仅 1 台 isLocal 攻击端)`，`shells/links/creds/flags = 0`，新项目节点 IP = `attack.ip`，0 错误 0 警告 |
| 路由层零 subprocess | `grep -rn "subprocess\|Popen\|os.system" pivothub/api/` | 仅注释命中，**0 处真实调用** |


### 契约核对明细（`_work/contract_check.py`，27/27 PASS）

| 契约项 | 结果 |
|---|---|
| `state.attack` 四字段 `{ip,segment,iface,note}` | PASS |
| `segments` = 192.0.2.0/24(VPN,#00e5a0) / 192.168.100.0/24(L1,#3ba7ff) / 10.85.101.0/24(L2,#a97bff) / 172.56.102.0/24(L3,#ff8a3d)，顺序与配色同 mock.js | PASS（修复后） |
| `hosts[].ifaces`（入口机 192.168.100.2/10.85.101.3；L2 双网卡 10.85.101.4/172.56.102.4） | PASS |
| `LinkOut` 9 个新字段齐备；`linkType ∈ {socks,portfwd,relay}` | PASS |
| `localSocks` = 攻击机IP:端口（非 127.0.0.1） | PASS（`192.0.2.10:10006` 等） |
| `GET/PUT /api/attack`（含非法 IP 422 拒绝） | PASS |
| PUT 后 `/state.attack`、攻击端本机节点 ip/ifaces 同步 | PASS |
| 新建项目仅攻击端 1 台主机且 IP = `attack.ip`（非 127.0.0.1） | PASS |
| `relay-plan`：relayAddr=10.85.101.3（上层跳板在本层网段的 IP）、targetSegment=172.56.102.0/24、三步命令 | PASS |
| 无上游链路时诚实降级（`无需中继` + 原因） | PASS |
| `POST /api/shells/{id}/probe` 四探针真实执行 + verdict/recommend/alt/reason + 时间线 | PASS（HTTP 200 / TCP OPEN 真实证据） |

### 未决问题 / 已闭环（本轮）

1. ✅ **已闭环：同机第二个 agent 会话并发执行本任务**（`_work/evidence_run.py` + 另一个
   `python -m pivothub` 实例）导致全量 pytest 的 portfwd/relay 间歇失败（单跑通过、
   失败用例在两次运行间互换）。根因是**双方都按映像名全量 taskkill chisel**：
   - 测试侧已修（只清理本会话启动的 pid + 本会话暂存目录命中的进程）；
   - 目标侧进程定位改用本次部署唯一的 `--auth` 令牌（不再用 `"client"` 子串）。
   复跑结果：**74 passed**（与对方 pytest 并发运行仍通过）；独立证据
   `_work/evidence-independent.json` 三条链路全绿、无孤儿。
   ⚠ 遗留提示：`_work/evidence_run.py`（另一个会话的脚本）仍含「全机 chisel 清理」，
   并发时会影响对方的隧道；本轮的独立证据脚本 `_work/evidence_mine.py` 已去掉该步骤。
2. ✅ 三种链路 + 三层中继证据已完成（见上「独立证据」表）：pid 存活、端口连通、
   隧道内读到目标服务（portfwd 读到 `HTTP/1.0 200 OK`）、`relayAddr` 推导正确、销毁无孤儿。
3. ✅ 浏览器验收已完成（见上「浏览器验收」表）；**mock 回退档**另有 1 条浏览器级 404 日志
   （`GET /api/projects/proj-1/state` 在纯静态服务下必然 404，属浏览器网络层日志，
   JS 无法抑制）；该档 11 视图仍全部渲染、交互可用、不白屏，符合「后端不可用前端仍可跑」。
4. ⏳ 待环境（不阻塞）：Linux 靶机上的「终端固化成功路径」与 Docker 三场景靶场复跑
   （本机无 Docker/WSL/PHP，见 ASSUMPTIONS A-16）；真实内网靶机的多级中继（跨主机三段）
   目前用同机 miniweb + 真实 chisel 双端等价验证。

### 第 3 轮 · 第二份独立证据（并行会话复核，2026-09-09 06:0x）

> 同一任务的另一会话在无干扰时段独立复跑，产物 `docs/evidence-round3.json`
> （脚本 `_work/evidence_run.py`），与上表结论互相印证。

| 项 | 结果 |
|---|---|
| 攻击机配置 | `PUT /api/attack`：`192.0.2.10 → 10.0.17.88`，`/state.attack` 同步为 `10.0.17.88` |
| socks | `ok=true`，pid `[73100, 75836]`，销毁后均 `killed=true`，本机入口端口已关闭；隧道内 Socks5 读到目标服务 |
| portfwd | `ok=true`，pid `[77120, 78328]`，销毁均 `killed=true`；直连 `localPort` 读到 **`HTTP/1.0 200 OK`** |
| relay（三层） | `ok=true`，pid `[73572(server), 68332(relay), 76148(target)]`，销毁均 `killed=true`；`relay-plan` 推导 `relayAddr=10.85.101.210`、`targetSegment=172.56.102.0/24`、三步命令 `server -p 63892 --reverse` → `client 192.0.2.10:63892 63892:63892` → `client 10.85.101.210:63892 R:0.0.0.0:63894:socks` |
| 出网探测 | `ok=true`，四探针真实执行：ICMP `ok`（真实 ping 回显）/ DNS `fail`（真实 nslookup 超时）/ HTTP `ok`（`HTTP 200`）/ TCP `ok`（`TCP OPEN`）→ 结论「可反向 TCP / HTTP 出网」、推荐 `chisel`，事件入时间线 |
| 销毁后无孤儿 | `tasklist` 复核 `chisel_pids_now=[]`、`leftover_from_links=[]`、四个端口 `ports_closed` 全 `true` |
| 浏览器（本会话独立实例 8777 + 真实后端） | `cdp-test` 11 视图 **错误 0 / 警告 0**；`proxy-test` 错误 0（三种链路类型、中继推导、攻击机弹窗 `PUT /api/attack` 生效）；`modal-test`/`tty-test`/`inject-test` 错误 0；`layout-test` 错误 0（脚本选择器 `.term-row` 已按当前 DOM 改为 `.term-col` 并加空值防护，非产品缺陷） |
| 全量测试 | `python -m pytest tests/ -q -p no:warnings` → **74 passed** |
| 独立实例浏览器复核（8031 + 独立临时库 `_work/verify-isolated.db`） | `node _work/verify-isolated.js http://127.0.0.1:8031/` → **ISOLATED-VERIFY: PASS**：`apiMode=true`、11 视图标题全对、`PUT /api/attack`（192.0.2.10→10.0.17.123）服务端/本机节点/ifaces 同步、`segments` 四段含 VPN、链路字段齐备（`linkType/localSocks/listenPort/localPort/relayAddr/hops`）、错误 0 警告 0 |
| 防火墙影响核查（用户提问驱动） | `python _work/fw_summary.py`（数据 `_work/fw_rules_all.json`） | chisel 入站规则 52 条：`tools\chisel.exe` **Allow**（port=Any / Private,Public / remote=Any）；`%TEMP%\.pivothub-*` 临时副本 22 Allow + **30 Block**；全部验收流量走回环 → **本轮结论不受影响**（详见 ASSUMPTIONS A-21） |


---

## 第 2 轮增补 3（2026-09-09）：「一键部署并登记」接真实流程（用户反馈驱动）

### 完成项

1. **自动档真实化**（用户在代理编排台点「一键部署并登记」暴露了 Mock 流程：出口写死
   `h-attacker` 显示「—」，且登记的是假链路）：
   - 新增 `pivothub/adapters/`（chisel Adapter：服务端子进程 → 客户端二进制分块上传 →
     靶机 setsid 后台执行 → 轮询本机 socks 端口等回连 → 回滚保护）；
   - 会话层新增二进制安全上传：`write_file_b64`（PHP FILE_APPEND / JSP）+
     JSP 原始字节上传器（PUT 流式落盘 JSP，octet-stream 裸体分块，绕开表单体积与
     Linux 128KB 单参数限制）——9.3MB 客户端经 Webshell 上传实测成功；
   - `POST /api/links/deploy`：自动档部署端点（失败返回真实阶段与原因并降级半自动）；
   - `POST /api/links` 登记校验 pid 真实存活（拒绝假隧道）；proxy.js 自动档接真实端点，
     失败/后端不可用才回退 Mock 演示。
2. **实战验证**：面板路径真实部署 socks 10803（首次回连被 Windows 防火墙拦截 46s，
   客户端自动重试接通）→ 穿隧道读到 db01 MySQL 握手 → 链路登记 p-p8jil（出口=攻击端）。
3. 假链路清理；`tools/` 目录落位双端二进制（PID 12996 的 1081 手工链与 9308 的自动链并存，
   均可从面板「销毁」真实结束进程）。

### 验证证据

pytest **57 passed**（+4：链路登记 pid 校验/广播、lhost 选取、端口探测）；e2e 0 错误 PASS；
重启后 SQLite 完整恢复（3 主机/2 链路/3 Flag）。

### 已知边界（并入 MS3）

- 防火墙首连延迟：新路径的 chisel.exe 首次监听会触发 Windows 防火墙拦截，客户端自动重试
  可接通（当前默认等待 45s；以管理员运行一次 `netsh advfirewall firewall add rule ...`
  可消除延迟，命令见 VERIFY）；
- chisel 之外的工具（frp/Neo-reGeorg）Adapter 与断链自动重拉随后续里程碑。

---

## 第 2 轮增补 2（2026-09-09）：真实代理链贯通（MS3 核心提前落地，用户驱动）

### 完成项

1. **`POST /api/links` 真实登记接口**：承接「隧道已真实建立」的链路登记（拒绝登记 pid 不存在的
   假隧道）；健康检查核验本机进程真实存活；销毁真实结束进程；登记即入统一 Socks 映射表、
   拓扑画出有向边、WS `link.created/link.state` 推送。
2. **真实代理链打通**（靶机④ 边界机 ↔ 攻击端）：
   - chisel 1.10.1 双端（服务端 Windows 绑 10.8.0.11:8443 --reverse --auth；
     客户端经面板 exec 上传（暂存 HTTP → 靶机 curl 取二进制，md5 双向校验一致）并
     `setsid nohup` 拉起反向 socks）；
   - 回连成功（67ms），本机 socks 入口 127.0.0.1:1081 → 经隧道真实读到 db01:3306 MySQL 握手包；
   - 链路登记 p-c7yp7：archive-web → kali-attacker，覆盖网段 172.33.0.0/24，pid 落库可核对。
3. **内网资产上拓扑**：靶机侧真实 ping 扫描 172.33.0.0/24（存活 .1 网桥/.10 自身/.20 db01）→
   importScan 登记.db01（L2 · MySQL 5.7.44 · 复用边界机配置口令）；边界机权限更新 root。
4. **教训入库**：Windows Defender 会隔离 chisel 双端二进制（用户关闭实时防护后解决）；
   curl 断点续传跨 GitHub 重定向会拼接出内容污染的 gzip（须 sha256/size 双校验，官方
   checksums 文件名实为 release API 的 assets digest）。

### 验证证据

| 验证 | 结果 |
|---|---|
| socks 隧道端到端 | `curl --socks5-hostname 127.0.0.1:1081 telnet://172.33.0.20:3306` 收到 MySQL 5.7.44 握手 |
| pytest | **53 passed** |
| e2e | 0 错误 0 警告 PASS |
| 新项目状态 | 3 主机 / 1 存活链路 / 3 Flag / 2 凭据 / 23 时间线事件 |

### 待办（并入 MS3）

- chisel/frp/Neo-reGeorg Adapter 封装（当前为面板半自动驱动：上传→执行→回连→登记手工完成）；
- Adapter 自动上传二进制（write_file_b64 二进制安全上传，替代暂存 HTTP）；
- 断链自动重拉（进程退出监控）。

---

## 第 2 轮增补（2026-09-09）：真实靶机实战 + 多项目隔离（用户反馈驱动）

### 完成项

1. **「新建项目」入口**（用户反馈：无法新建项目、CTF 数据混入演示项目）：
   - 后端 `POST /api/projects`（新项目=干净工作区，仅攻击端本机节点）；
   - **多项目作用域改造**：全部实体写入路由（hosts/hosts.import/shells/creds/flags/timeline.notes/events）
     接受 `projectId`（缺省回退演示项目），实体级操作（exec/tty/files/link 运维/位置持久化）按实体自身
     归属校验——跨项目操作 Shell 不再 404，事件落在实体所在项目；
   - 前端顶栏「＋ 新建」按钮（用户显式批准的 UI 增补，见 ASSUMPTIONS A-17）+ store `createProject()`
     （prompt 命名 → 创建 → 自动切换并整包刷新）；applyState 修复项目切换时残留的 Shell 选中态。
2. **真实 CTF 实战验证**（授权靶场训练题「④ 回声 · 遗忘的部署」）：
   - CVE-2017-12615 PUT 尾斜杠写 JSP 马（与 PivotHub JSP 驱动同协议）→ 面板登记真实存活（165ms）；
   - 面板虚拟终端真实执行：双网卡发现（172.32.0.10/172.33.0.10）、WEB-INF/db.properties 读出内网库
     凭据 archive/REDACTED（db01=172.33.0.20）、/etc/passwd 666 提权（openssl -1 hash 追加 UID=0
     用户 + script 转 pty 过 su）→ uid=0(root)；
   - 3 个 Flag 全部拿下并入库新项目 Flag 墙（应用层 / 提权后 / 内网库 secret_vault），战报笔记入时间线；
   - JDBC 查询马（复用 Tomcat 自带 mysql-connector）打通内网库，验证「配置弱口令→内网」训练点。
3. **数据独立**：CTF 主机/Shell/时间线事件迁入新项目「回声 · 遗忘的部署（④）」，演示项目还原干净。

### 验证证据

| 验证 | 结果 |
|---|---|
| pytest（含 test_projects.py 项目隔离） | **53 passed** |
| Playwright「＋新建」按钮 | 创建→自动切换→仅攻击端节点，0 控制台错误 PASS |
| e2e 回归 | apiMode=True / 0 错误 0 警告 PASS |
| 隔离验证 | 演示项目 hosts=10（纯净种子）；新项目 hosts=2 / flags=3 |

### 下一轮计划（MS3 代理闭环）

frp/chisel/Neo-reGeorg 三 Adapter + 出网探测真实执行 + 半自动档 + 回连监听 + ProxyLink 自动登记 +
统一 Socks 映射表；验收=拓扑自动画出第一条真实代理链（可用本题边界机 ↔ 攻击端做真实链路验证）。

---

## 第 2 轮（2026-09-09）：MS2 会话抽象层 + Shell 闭环 + 终端固化 —— ✅ 完成

### 本轮完成项

1. **会话抽象层落地**（`pivothub/session/`，任务书硬约束 3）：
   - `base.py`：`SessionBase` 统一接口（test/exec/list_dir/read_file/write_file/close + pty_probe），
     `ExecResult/FileEntry` 契约数据类；
   - `http_shell.py`：HTTP 一句话马驱动（PHP=密码字段 eval / JSP=cmd 参数 / ASPX=pass 参数 / ASP=VBS 尽力而为），
     自定义 AES 马诚实报不支持；全部回显以 `[[PIVOTHUB_EOF]]` 标记校验；
   - `local.py` 本机驱动；`registry.py` Shell 记录 → 驱动路由（冰蝎/哥斯拉二期扩展点）。
   - 路由层零 subprocess（grep 可验证）。
2. **Shell 闭环真实化**（`api/shells.py`）：
   - 登记：真实协议探针测活 + 延迟落库 + autoCollect 信息回传（id/uname 解析入库，M1-5 子集）；
   - `/exec`：真实命令执行（M1-3），死靶探活快失败（6s 内），返回结构化结果；
   - `/files` 四端点（M1-4）：真实列目录（dir/size/mtime，人类可读 size）/ 读 / 写 / 上传（base64）；
   - `/test` `/heartbeat`：逐会话真实探针；断线诚实标记。
3. **终端固化 M1-8 全套真实实现**（`service/tty.py`，P0）：
   - 检测：真实执行 `tty` / `echo $TERM` / `stty size` / `which python3 python script socat nc` 并解析真实回显；
   - PTY 判定：目标侧真实拉起 PTY（python pty.spawn → script 备选），在其内执行
     `tty; echo TERM=$TERM; stty size; id`，依据 pts/TERM≠dumb/行列 三要素判定（不随机不硬编码）；
   - 技法库：data/tty_fixes 插件（13 条），reverse 类（socat/nc/win-ps）诚实标注随 MS3 回连监听启用；
   - 收尾：真实执行 `stty sane` + `stty rows/cols`（窗口尺寸同步）并回读 `stty size` 验证；
   - `Shell.stable` 落库 + `shell.tty` WS 广播 + 时间线事件。
4. **前端接线**：store 新增 `readFile/writeFile/uploadFile`（真实文件读写/上传）+ `host.update/shell.created` WS 事件；
   shell.js 三个纯数据流钩子（openFile/saveFile/upload，仅 apiMode 生效，详见 ASSUMPTIONS A-13）；
   检测/固化/收尾的 timeline 事件改由服务端统一入库（避免重复）。
5. **Docker 靶场**（`scripts/lab/`）：3 场景 compose（可反向 TCP / 仅 HTTP / 双网卡多级）+
   真实一句话马（shell.php/cmd.jsp）+ php:8.2-apache 镜像（内置 python3/script/socat/nc）；
   另有零依赖本地靶 `miniweb`（同一 POST 协议、真实子进程/真实文件系统执行）。
6. **测试**：新增 `test_session_protocol.py`（10 项，真实 HTTP+子进程+文件系统）、
   `test_tty_judge.py`（8 项，真实回显样本）、`test_shell_api.py`（9 项，面板 API→会话层→真实靶全链路）。

### 验证证据（最近一次通过：2026-09-09）

| 验证 | 命令 | 结果 |
|---|---|---|
| 全部测试 | `PY -m pytest tests/ -q -p no:warnings` | **50 passed**（含会话协议/TTY 判定/exec API） |
| 11 视图 0 错误 | `PY scripts/e2e_ms1_console.py` | apiMode=True / WS 在线 / **0 错误 0 警告 PASS** |
| 路由层无 subprocess | `grep -rn "subprocess" pivothub/api/` | 0 处（仅 session/ 与 util/ 内） |
| 真实执行链路 | `pytest tests/test_shell_api.py` | 登记→探活→exec→文件读写→上传→TTY 检测 全链路真实通过 |
| 死靶快失败 | s-1（不可达靶）detect/upgrade/finish | 6s 内诚实返回结构化失败，不再逐条等超时 |

### 浏览器可检查的真实链路（miniweb 已随服务启动）

面板 → Shell 管理 → 添加连接：
URL `http://127.0.0.1:8787/shell.php` · 密码 `cmd` · 类型 `PHP 一句话马` · 勾选自动回传
→ 登记即真实探活；虚拟终端执行命令（真实子进程回显）；文件面板浏览/编辑/上传（真实文件系统）；
终端固化弹窗 → 交互能力检测（真实探测）。**注意**：本机为 Windows，无 Linux pty，
固化技法会诚实判定失败（不伪造成功）；完整「检测→固化→收尾→stable 落库」成功路径
需 Linux 靶机（`scripts/lab` 场景 1 容器，Docker 可用时一键复跑）。

### 未决问题

- 本机无 Docker/WSL/PHP（第 1 轮遇阻）：Linux 靶机的固化成功路径暂以
  「单测（真实回显样本）+ 容器内复跑命令」交付；Docker 可用后 `docker compose up -d --build` 即可闭环。
- socat/nc/PowerShell 反向固化技法 + 面板终端桥接：随 MS3 回连监听一起实现。

---

## 第 1 轮（2026-09-08）：PLAN + MS1 骨架 —— ✅ 完成

### 本轮完成项

1. **通读五份权威资料**（README / PRD / mock.js / store.js / topology.js + views/*），
   输出 `docs/PLAN.md`（总体思路 / 目录树 / MS1–MS6 排期 / MS1 详细设计 / 风险）。
2. **后端骨架**（`pivothub/` 包）：
   - `models/`：SQLAlchemy 2.7 模型（Project/Host/Shell/ProxyLink/Credential/Flag/TimelineEvent），
     Host 带 `pos_x/pos_y`（拓扑拖拽持久化）、ProxyLink 带 `pid`（重启后进程状态核对）；
   - `schemas/`：Pydantic v2 出参，字段名与 mock.js 完全一致（含 `pass` 别名、
     `lastBeat`『刚刚/N 秒前（断线）』、`time`『HH:MM』、中文枚举）；
   - `api/`：projects/state 聚合、hosts（登记/导入去重/位置 PATCH）、shells（登记/真实连通性测试/心跳/删除）、
     links（check 进程核验/restart/destroy）、creds/flags/timeline（含客户端事件入库）、export 三格式；
     MS2/MS3 能力（exec/tty/files/probe/POST links）返回 `200 + pivothubFallback` 标记；
   - `ws/`：连接管理 + 线程安全广播（timeline.push/link.state/link.created/host.found/shell.beat/ws.online）；
   - `service/`：timeline（自动事件+广播+segments 聚合）、statlib、export（MD/HTML/JSON，凭据与口令脱敏）；
   - `db.py`：WAL SQLite、空库自动播种演示项目；`util.py` 跨平台进程存活核验；
   - `__main__.py`：合规横幅 + 打印面板 URL，`uvicorn` 仅绑 127.0.0.1:8000（config 断言强制）。
3. **插件化数据**（`data/`，由 `scripts/export_mock_to_data.mjs` 从 mock.js 权威导出）：
   `meta.json`、`seed_project.json`、`commands/*.json`（6 分类）、`tty_fixes/{linux,windows}.json`（13 条）、
   `payloads/inject-tips.json`。
4. **前端切真实接口**：新增 `assets/js/api.js`（REST + WS 指数退避重连）；
   `store.js` 全部动作改为「API 优先、失败回退 mock」，新增 `applyState/handleWsEvent/saveNodePos/refreshState`；
   `index.html` 仅新增一行 api.js 引用 + CDN 本地化两行（离线可用）；`topology.js` 仅加拖拽上报与
   位置恢复两处数据流代码（详见 docs/ASSUMPTIONS.md A-2/A-3）。
5. **测试与验收**：pytest 22 项全绿；Playwright e2e `scripts/e2e_ms1_console.py` PASS；
   重启恢复验证 PASS。README 更新真实启动方式/接口清单/已知边界；
   docs 新增 ARCHITECTURE.md / ASSUMPTIONS.md / VERIFY.md。
6. 环境适配：Playwright Chromium 走 127.0.0.1:7897 代理安装；Vue/ECharts 本地化
  （`assets/vendor/`，解决 CDN 不可达导致面板无法加载的问题）。

### 验证证据（最近一次通过：2026-09-08）

| 验证 | 命令 | 结果 |
|---|---|---|
| 单元/接口测试 | `PY -m pytest tests/ -q -p no:warnings` | **22 passed** |
| 一条命令启动 | `PY -m pivothub --no-open` | 横幅 + `http://127.0.0.1:8000/`，health 200 |
| 11 视图真实接口 | `PY scripts/e2e_ms1_console.py` | apiMode=True，wsOnline=True，**0 错误 0 警告**，E2E-MS1-CONSOLE: PASS |
| 导出三格式 | `pytest tests/test_export_snapshot.py` + curl | md/json/html 200，敏感字段脱敏断言通过 |
| 重启恢复 | 写入标记数据 → 重启 → 回读 | 主机/拖拽位置/新增数据完整恢复，RESTART-RECOVERY: PASS |

### 下一轮计划（MS2：Shell 闭环 + 终端固化 M1-8）

1. `session/` 会话抽象层落地：`base.py` Session 接口 + `http_shell.py` PHP/JSP/ASPX 一句话马驱动
   （exec/list_dir/read_file/write_file/test 全走接口，路由零 subprocess）；
2. `/api/shells/{id}/exec` 真实执行（shell.output WS 推送）、`files/*` 真实目录浏览/读写；
3. M1-8 终端固化：`service/tty.py` 真实解析 `tty` / `echo $TERM` / `stty size` / 工具探测回显 →
   PTY 判定（isatty + TERM 非 dumb）→ 技法执行（data/tty_fixes 插件）→ `stty raw -echo` 收尾 +
   `stty rows/cols` 同步 → `Shell.stable` 落库 + `shell.tty` WS 推送；
4. `scripts/lab` Docker 靶场第一场景（可反向 TCP 出网）+ 马/代理二进制准备；
5. pytest 补：TTY 判定解析器、会话层协议；e2e 补：固化全流程。

### 未决问题（不阻塞，持续跟进）

- 本机无 Docker Desktop 时 `scripts/lab` 靶场如何验证 → 若连续 3 轮受阻，按规则记录 blocked_reason；
- frp/chisel 二进制获取（走代理下载或 lab 内置源）→ MS3 处理；
- Windows 下真实 PTY 判定依赖 Linux 靶机回显，Windows 会话按 PowerShell 会话编排（MS2 设计）。
