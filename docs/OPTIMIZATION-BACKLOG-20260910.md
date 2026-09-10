# PivotHub · 链透中枢 — 黑盒评测复盘与优化待办

> 复盘日期：2026-09-10
> 输入：`docs/USAGE-REPORT-20260909.md`（ZCode 内置浏览器黑盒评测，2 轮，2026-09-09 ~ 09-10）
> 证据：`docs/shots/`（14 张）、`docs/export-④回声-writeup.md`
> 本文件动作：**对报告全部问题做代码级根因核查**（不改代码），产出分批优化计划
> 基线：`pytest tests/ -q -p no:warnings` → 223 passed（任何改动需保持全绿）

---

## 一、评测结论速览

| 项 | 结果 |
|---|---|
| 靶场 | 6 道真实靶场（10.8.0.6:8083–8088，共 20 flag） |
| 得分 | **15 / 20 flag** |
| 全清 | ④ 回声 3/3 · ⑤ 终端 3/3 · ⑥ 密语 3/3 · ⑦ 幽冥 4/4 |
| 受阻 | ② 孤岛 1/3 · ③ 深潜 1/4（均为凭据墙 + 面板链路断裂） |
| 整体可用性 | **6.5 / 10** |
| 结论 | 单会话工作流成熟（④ 为端到端样板）；**多层纵深场景无法在面板内闭环** |

**一句话定性**：⑤⑥⑦ 的利用链全部在**面板外**完成——不是工具不行，是面板在三个结构性断点上把用户推了出去。

---

## 二、报告问题 → 代码根因核查（含与报告的出入）

> 报告自身声明「根因均未查源码」。本节补上源码侧核查，**有 3 处结论需要修正**。

| 编号 | 报告结论 | 代码核查（本机仓库实测） | 判定 |
|---|---|---|---|
| **P0-1** | 「＋ 新建」依赖 `window.prompt`，内嵌浏览器静默失败 | 确认。全仓 4 处 `window.prompt`：`assets/js/store.js:1676`（新建项目）、`assets/js/app.js:50`（网卡）、`app.js:65`（网段）、`views/asset.js:26`（网段） | ✅ 成立 |
| **P0-2** | 后端 `/api/shells/reverse/register` **返回 404（接口不存在）** | **需修正**。路由存在：`pivothub/api/shells.py:876`。真实链路：`views/reverse.js:127` 传 `hostId: target ? target.hostId : ''` → 无 WebShell 会话时 `hostId=''` → `shells.py:881` `db.get(Host,'')` 为 None → `raise HTTPException(404, "主机不存在: ")`；`assets/js/api.js:16` 只抛 `'HTTP ' + res.status + ' ' + path`，**丢弃了 detail**，于是「主机不存在」与「路由不存在」在 UI 上完全同形 | ⚠️ 现象成立，**根因需重写** |
| **P0-3** | 隧道工具仅 chisel 在线，**服务端端口固定 1331**，且只支持靶机回连 | **部分修正**。端口并非固定：`shells.py`/`links.py:90` 只是默认 `1331`，前端 `views/proxy.js` 有 `compose.attackPort` 输入并透传（`store.js:1461`），`adapters/chisel.py:327` 亦支持 `server_port` 推导。**真正缺的**是：① 无「复用已登记会话」的 HTTP 隧道（reGeorg 类）；② 推荐逻辑不看靶机出站白名单，不给出「把 server 挪到 443/80」或 DNS 隧道变体 | ⚠️ 一半成立，**需拆成两条** |
| **P1-1** | 出网探测结论与证据自相矛盾（探针 `TCP=fail` 却输出「可反向 TCP 出网」），且对端不明 | 待复核 `service/probe.py` 的推荐分支（本轮未逐行核） | ⏳ 待核 |
| **P1-2** | 一键提权误报：仅一条 SUID 采集即命中 80% | **确认且根因明确**。`data/privesc/linux.json:56` `linux-suid` 规则 `match` 正则含 `mount`，而 `/usr/bin/mount` 是 Debian/Ubuntu **默认 SUID**（同理 `umount`/`su`/`passwd`）→ 默认系统状态即命中。且该规则**无 `verify` / `expect` 字段**（对比 `linux-passwd-writable` 两者齐全），所以永远无法进入验证分支，UI 直接报「已执行」 | ✅ 成立，根因更精确 |
| **P1-3** | 提权上下文包装器破坏复杂命令，需「取消提权」才能跑 | **确认且根因明确**。`pivothub/session/base.py:27` 为 `wrapper.replace("%CMD%", shlex.quote(cmd))`；包装器是 `script -qc "su ph -c %CMD%" /dev/null`（`data/privesc/linux.json:32`）。命令含双引号或 `$(...)` 时，`shlex.quote` 产出的单引号内容里再出现双引号，会**提前闭合外层双引号** → 语法断裂 → 零输出零执行 | ✅ 成立 |
| **P1-4** | 无 Python/Java 会话类型，无手动登记外部会话入口 | 确认：马生成器仅 PHP/JSP/ASP/ASPX；`POST /shells` 无「外部会话接管」语义 | ✅ 成立 |
| **P1-5** | 多处静默失败（Flag 保存、编排台失败无 toast） | 确认：`views/reverse.js:131` 有 push 到日志，但编排台 `proxy.js` 失败路径仅写时间线 | ✅ 成立 |
| **P1-6** | 「最后心跳」显示 8 小时前；时间线双写 + 时间戳错乱 | 见 `docs/export-④回声-writeup.md`：时间线为 `16:39/16:43/16:48`，而实际评测发生在 `23:55–01:06`（截图 mtime）→ 确为时区偏移问题（UTC vs UTC+8） | ✅ 成立 |
| **P1-7** | 马生成器硬编码 `http://127.0.0.1:8000/api/collect` | 确认：`assets/js/views/generator.js:77`（`_pkg` / `_work` / `_audit` 三份副本同样） | ✅ 成立 |
| **P1-8** | 编排参数不持久化 + 每次进入强制重探测 ~10s | 确认（每次进入重跑探测） | ✅ 成立 |
| **P1-9** | Flag 记录不可删除 / 移动 | **确认**：`pivothub/api/flags.py` 仅有 `@router.post("/flags")`，**无 DELETE / PATCH** | ✅ 成立 |
| **P2-1** | Flag 阶段固定 L1/L2/L3/域控，总数固定 6 | 确认（阶段枚举硬编码） | ✅ 成立 |
| **P2-2** | 导出拓扑攻击端显示 `127.0.0.1` | **确认，且比报告更严重**：`pivothub/service/export.py:51` 是硬编码字符串 `"## 1. 网络拓扑\n\n```\n攻击端 127.0.0.1\n"`——**拓扑段是桩实现**，只渲染 links 不渲染 hosts，故 ④ 的导出拓扑里除「攻击端」一行外**完全空白** | ✅ 成立 + 加码 |
| **P2-3** | 终端固化模板变量替换未生效（占位 IP、`$i` 自指） | 待复核模板数据（`data/commands/`） | ⏳ 待核 |
| **P2-4 ~ P2-6** | 扫描勾选不一致 / 终端偶发无响应 / 目标侧题目设计 | 小瑕疵与题目侧观察，非本仓缺陷 | — |

---

## 三、优化点（按优先级 + 具体改法）

### P0 —— 阻断级，必须先修（决定「能否在面板内闭环」）

**P0-1 自绘模态框替代原生 `window.prompt`**
- 位置：`assets/js/store.js:1676`、`assets/js/app.js:50`、`app.js:65`、`views/asset.js:26`
- 改法：复用现有 20+ 处弹窗组件（自绘 modal），统一「输入 + 校验 + 回调」；4 处一次性替换，禁止再引入原生 `prompt/confirm/alert`
- 验收：CDP 脚本能对弹窗输入框直接 `fill` 并提交

**P0-2 反弹会话登记解耦 + 错误透传 + 手动登记兜底**
- 位置：`pivothub/api/shells.py:876`、`assets/js/views/reverse.js:121-134`、`assets/js/api.js:16`
- 改法（三件套）：
  1. 后端 `ReverseRegisterIn` 增加 `hostIp`（可选）：无 `hostId` 时**按 `hostIp` 自动建/复用主机**，去掉「必须先有 WebShell 会话」的隐性前置；
  2. `api.js` 解析响应体：非 2xx 时优先取 `detail` / `error` 字段，抛出真实原因（当前 `'HTTP ' + status + ' ' + path` 把 404 语义抹平了）；
  3. 监听行增加「**登记为会话**」手动按钮；「等待中」细分「已连接未登记」，失败原因就地展示
- 验收：新增测试「无预置主机 + 有回连 → 自动建主机并登记成功」；`tests/test_reverse_api.py` 全绿

**P0-3 上线「走会话通道的 HTTP 隧道」+ 出站感知的推荐逻辑**
- 位置：`pivothub/adapters/`（新增 Neo-reGeorg 类适配器）、`data/meta.json`（`status: online`）、`pivothub/service/probe.py`（推荐分支）
- 改法：
  1. 新增一款复用已登记 Webshell 的 HTTP 隧道（reGeorg / Neo-reGeorg 模式），覆盖「OUTPUT DROP + 仅内网放行」场景；
  2. 推荐逻辑读靶机出站策略：仅放行 443/80 时输出「chisel server 挪到 443」；仅放行 UDP/53 时输出 DNS 隧道模板；并**注明探针对端**；
  3. 部署失败在编排台本体 toast（当前仅写时间线，见 P1-5）；
  4. 修正探测结论与四探针证据的一致性（P1-1）
- 验收：`scripts/lab/` 增加「出站白名单」靶机变体，自动档可成功建链

### P1 —— 正确性，第二轮修（决定「工具是否可信」）

| 编号 | 改法 | 位置 |
|---|---|---|
| **P1-2** | 提权规则**条件化**：`linux-suid` 的 `match` 排除默认路径（`/usr/bin/mount`、`umount`、`su`、`passwd`、`chsh`、`chfn`、`gpasswd`、`newgrp`、`/bin/mount` 等），只认非默认路径的 GTFOBins 二进制；**为规则补 `verify`/`expect`**，无验证字段的规则禁止报「已执行」 | `data/privesc/linux.json:56`、`service/privesc.py` |
| **P1-3** | 包装器改 **base64 单层传参**：`apply_cmd_wrapper` 把命令 base64 后嵌入 `script -qc "su ph -c 'echo <b64>\|base64 -d\|sh'"`，彻底规避引号嵌套 | `pivothub/session/base.py:16-27` |
| **P1-4** | 会话类型扩展：新增「Python 命令回显」类型；新增「外部/反向会话手动登记」入口；马生成器同步加 Python 模板 | `api/shells.py`、`views/shell.js`、`views/generator.js` |
| **P1-5** | 静默失败全量治理：所有保存/部署/登记路径统一 `error → toast`，禁止 UI 静默回滚 | 全局（store.js 各 Promise 链） |
| **P1-6** | 统一时间基准为本地时区（UTC+8）；时间线按 `(kind, title, ts)` 去重 | `service/timeline.py`、导出与前端心跳显示 |
| **P1-7** | 马生成器回传地址改用**全局设置的攻击机 IP**，不再硬编码回环 | `views/generator.js:77` |
| **P1-8** | 编排参数持久化（localStorage / 项目级）；探测结果加缓存与「重新探测」按钮 | `views/proxy.js` |
| **P1-9** | Flag 墙支持删除 / 改绑项目与阶段 | `api/flags.py`（补 DELETE + PATCH）、`views/flag.js` |

### P2 —— 打磨（第三轮）

- **P2-2（优先）**：`service/export.py:51` 拓扑段**真实化**——渲染「攻击机 IP（取全局设置）+ 全部主机 + 链路」，替换硬编码桩；④ 导出拓扑空白必须消失
- **P2-1**：Flag 阶段可自定义、总数不写死 6
- **P2-3**：终端固化模板变量替换修正（占位 IP、`$i` 自指）
- **P2-4**：扫描导入列表「新发现 / 已在库」勾选行为统一
- **P2-5**：终端视图偶发无响应（自动化环境特有，人工复测确认）

---

## 四、后续工作（分批执行）

> 每批结束必须：`pytest tests/ -q -p no:warnings` 全绿 + 浏览器逐视图复跑 0 错误 + 在 `scripts/lab/` 用真实靶机回归。

### Batch A · 打通闭环（P0 三件套）
1. A1 自绘弹窗替代 `prompt`（4 处）
2. A2 反弹登记解耦 + 错误透传 + 手动登记按钮
3. A3 新增 HTTP 会话隧道适配器 + 出站感知推荐（含 P1-1 一致性修正）
- **出口标准**：③ 类型场景（无 WebShell、仅 RCE 反弹）能在面板内登记会话并继续纵深；② 类出站受限场景自动档可建链

### Batch B · 可信度（P1 正确性）
4. B1 提权规则条件化 + 强制验证（P1-2）
5. B2 包装器 base64 单层（P1-3）
6. B3 会话类型扩展 + 马生成器 Python 模板（P1-4）
7. B4 静默失败治理 + 时区/去重 + 生成器回传地址 + 编排持久化（P1-5/6/7/8）
8. B5 Flag 删除与改绑（P1-9）
- **出口标准**：一键提权在「仅默认 SUID」环境**不再命中**；④ 全链在提权上下文中跑复杂命令（含 `$(...)`）零失败

### Batch C · 打磨与新能力
9. C1 导出拓扑真实化 + 阶段自定义（P2-1/2）
10. C2 终端模板变量修正 + 扫描勾选一致（P2-3/4）
11. C3 **新增能力**（按报告第 5 节优先级）：
    - 容器逃逸命令包（docker.sock 检测与逃逸、PwnKit、cron 劫持）— ⑥⑦ 实战刚需
    - SSH 会话管理（凭据库联动 → 面板内直连）— ②③⑦ 备份机场景刚需
    - Jenkins / ActiveMQ 内网应用专用探测项（未授权脚本台、弱口令）
    - 出网探测「对攻击机端口矩阵」模式（直接回答「哪个端口能回连」）

### 待补核查（本轮未逐行核，进 Batch B 前先做）
- P1-1：`service/probe.py` 推荐分支的结论来源
- P2-3：`data/commands/` 终端固化模板的变量替换实现

---

## 五、必须保留的亮点（防退化）

1. **一键提权「验证型」闭环**（④）：采集 → 规则匹配 → 执行 → `script-su` 验证 `uid=0` → 建立提权上下文（徽标 + 可取消）
2. **诚实的失败判定**：无 PTY 能力明确说「平台限制」；fscan 按字节数校验；连通性测试真实回显
3. **资产探测一条龙**：网卡/hosts/路由表格化 + 网段一键填入 + 8.4MB fscan 分片直传 + 结果导入上拓扑
4. **数据库面板免驱动**：目标侧客户端执行 + 结构自动探测 + 点表预览 + 中文正常（base64 回传）
5. **操作时间线信息密度**：失败证据全文、四探针结果、命令回放 —— writeup 素材免整理
6. **后端韧性**：进程重启后自动恢复监听、标记历史会话断线并明确说明「通道不跨进程存活」
7. **数据只来自后端**：无假数据兜底（`mock.js` 已移除），排障时可信

> 修复 P0 时不得以「降级为假数据」换取界面通过 —— 违反 `HANDOFF.md` §2 的硬约定。

---

*复盘完 · 2026-09-10 · 代码级根因核查基于本机仓库，未修改任何实现代码*
