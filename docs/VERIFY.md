# 验证手册（VERIFY）

> 每条完成标准给出可复跑命令与最近一次通过记录。每轮里程碑推进后更新「最近通过」。
> 环境：Windows / Python 3.13 / Node 22。`PY` 指 Python 3.10+ 解释器（本机为
> `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`）。

## 0. 一键复跑（全部）

```bash
cd /d/supershell   # 项目根（即本文件上级目录）
PY -m pytest tests/ -q -p no:warnings                 # 后端测试
PY -m pivothub --no-open &                            # 启动服务（等 3s）
PY scripts/e2e_ms1_console.py                         # 浏览器端到端验收
```

## 1. python -m pivothub 一条命令启动成功，仅监听 127.0.0.1，打印面板 URL

```bash
PY -m pivothub --no-open
# 期望输出：合规横幅 + “面板地址：http://127.0.0.1:8000/” + “数据库：...\pivothub.db”
curl -s http://127.0.0.1:8000/api/health
# 期望：{"ok":true,"name":"PivotHub","version":"0.1.0"}
# 仅监听回环：netstat -ano | findstr :8000 应只看到 127.0.0.1:8000
```
- 最近通过：2026-09-08 MS1（服务启动、health 200、绑定 127.0.0.1）。

## 2. 12 个视图全部真实接口驱动，浏览器控制台 0 错误 0 警告

```bash
PY scripts/e2e_ms1_console.py
# 期望：数据源检查 apiMode=True / wsOnline=True / hosts=10 / commands=16 / ttyFixes=13
#       控制台错误 0 个 / 警告 0 个
#       E2E-MS1-CONSOLE: PASS
```
- 最近通过：2026-09-08 MS1（Playwright Chromium 151，11 视图 + 终端交互，0/0）。

## 3. 拓扑图节点/边来自 SQLite，拖拽位置持久化

```bash
PY -m pytest tests/test_state_api.py -q -p no:warnings
# 覆盖：state 顶层键与 mock.js 同构 / hosts、links 契约字段 / segments 聚合 /
#       position 持久化与回读 / hosts.import 去重
PY - <<'EOF'
import json, urllib.request
def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request('http://127.0.0.1:8000' + path, data=data, method=method,
                               headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(r) as resp:
        return json.loads(resp.read())
print(req('PATCH', '/api/hosts/h-l2-01/position', {'x': 555.5, 'y': 333.25}))
d = req('GET', '/api/projects/proj-1/state')
h = next(x for x in d['hosts'] if x['id'] == 'h-l2-01')
assert (h['posX'], h['posY']) == (555.5, 333.25)
print('POSITION-PERSIST: PASS')
EOF
```
- 最近通过：2026-09-08 MS1（pytest 22 项 + PATCH/回读 + 浏览器拖拽上报）。

## 4. 终端固化真实可用：tty 检测、PTY 判定、技法执行、stty raw 收尾、状态落库（MS2）

```bash
# 判定逻辑（真实回显样本单测）
PY -m pytest tests/test_tty_judge.py -q -p no:warnings
# 会话协议 + API 全链路（miniweb 真实执行靶：登记→检测→技法→收尾）
PY -m pytest tests/test_session_protocol.py tests/test_shell_api.py -q -p no:warnings
# Linux 靶机完整闭环（检测→固化→收尾→stable 落库）——需 Docker：
cd scripts/lab && docker compose up -d --build
# 面板登记 http://127.0.0.1:8801/shell.php (密码 pivothub) → 检测 → Python PTY → 收尾
```
- 最近通过：2026-09-09 MS2（判定/协议/链路 27 项通过；Linux 成功路径待 Docker 环境，
  本机 Windows 靶按设计诚实判定失败）。

## 5. 出网探测真实执行并输出推荐；半自动档配置正确；自动档含失败降级（R3 已交付）

```bash
# 真实执行四类探针（经会话抽象层在目标侧执行 ICMP/DNS/HTTP/TCP 并解析真实回显）
PY -m pytest tests/test_attack_and_probe.py -q -p no:warnings
# 契约核对脚本（无 chisel 依赖，独立临时库）：probe 项会打到本机 miniweb 靶
PY _work/contract_check.py                     # 期望：27/27 PASS
# 手工复跑（起 miniweb 靶 + 面板 8000）：
PY scripts/lab/miniweb/miniweb.py --port 8787 --pwd cmd --dir scripts/lab/wwwroot
curl -s -X POST http://127.0.0.1:8000/api/shells/s-1/probe \
  -H "Content-Type: application/json" \
  -d '{"httpUrl":"http://127.0.0.1:8787/","tcpHost":"127.0.0.1","tcpPort":8787,"dnsName":"localhost"}'
# 期望：ok=true + verdict/recommend/alt/reason + probes[4]（含真实 cmd 与 evidence）+ 时间线事件
```
- 最近通过：2026-09-09 R3（`_work/contract_check.py` probe 项 HTTP=ok / TCP=ok，证据 `TCP OPEN`；
  结论「可反向 TCP / HTTP 出网」+ 推荐 chisel；结论入时间线）。

## 6. 三种链路类型 + 三层中继真实跑通，销毁后无孤儿进程（R3 已交付）

```bash
# 三种链路（socks / portfwd / relay）+ 中继推导 + 失败阶段诚实回报（真实 chisel 双端）
PY -m pytest tests/test_link_deploy.py -q -p no:warnings
# 端到端证据脚本（真实后端 + 两个 miniweb 靶，逐条打印 pid/端口/banner/销毁核对）
PY -m pivothub --no-open &            # 8000
PY _work/evidence_run.py              # 结果写入 docs/evidence-round3.json
# 销毁后无孤儿：tasklist /FI "IMAGENAME eq chisel.exe"
```
- 验收要点：`linkType ∈ {socks,portfwd,relay}`；portfwd 直连 `localPort` 读到目标服务回显；
  relay 三步 pid 全部落库（`server` / `relay` / `target`）；`relayAddr` = 上一层跳板在「本层网段」
  里的 IP（取自 `ifaces`，非主 IP）；`targetSegment` = 本层双网卡机第二块网卡段；销毁后逐层 pid 不存在。
- 最近通过：见 `docs/evidence-round3.json` 与 `docs/PROGRESS.md` 第 3 轮条目（含并发会话干扰说明）。
- ⚠ 注意：同机并发跑 chisel 用例会互相影响；`tests/test_link_deploy.py` 的清理只作用于本会话
  启动的进程（`_SESSION_PIDS` / `_SESSION_DIRS`），不得改回按映像名全量 `taskkill`。

## 6b. 攻击机网络可配置，改 IP 后所有命令/链路地址同步（R3 已交付）

```bash
PY -m pytest tests/test_attack_and_probe.py::test_attack_get_put_roundtrip \
              tests/test_attack_and_probe.py::test_attack_scoped_per_project -q -p no:warnings
PY _work/contract_check.py    # 「任务 C-A」段落：PUT 回填 / state 同步 / 本机节点同步 / 非法 IP 422
```
- 最近通过：2026-09-09 R3（`PUT /api/attack` → `/state.attack`、攻击端节点 `ip` 与 `ifaces[0].ip`
  同步；前端代理编排台弹窗保存后 `attackIpNow` 更新且健康看板/命令同步，0 控制台错误）。

## 6c. 「＋ 新建」创建项目后自动切换为干净工作区（R3 已交付）

```bash
PY -m pytest tests/test_projects.py -q -p no:warnings        # 新项目=仅攻击端节点，IP 取 attack.ip
node _work/verify/newproject-test.js                          # 浏览器侧：点击 ＋ 新建 → 自动切换
```
- 最近通过：2026-09-09 R3（`NEWPROJECT-TEST: PASS`：主机 10 → 1 台 isLocal、shells/links/creds/flags=0、
  新节点 IP = `attack.ip`，0 错误 0 警告）。

## 6d. 完成标准一键复核（R3 已交付）

```bash
PY -m pivothub --no-open &                 # 8777（或任意空闲端口）
PY _work/acceptance_check.py http://127.0.0.1:8777
# 期望：17 PASS / 0 FAIL（state 契约 / attack 读写 / 新建项目 / 中继推导 / 探测诚实失败）
node _work/verify-isolated.js http://127.0.0.1:8777   # 独立实例浏览器复核
# 期望：ISOLATED-VERIFY: PASS（11 视图标题 + apiMode + attack PUT + 链路字段 + 错误0/警告0）
```
- 最近通过：2026-09-09 R3（`17 PASS / 0 FAIL`；`ISOLATED-VERIFY: PASS`）。

## 8. pytest 全绿；e2e 全绿（随里程碑累积）

```bash
PY -m pytest tests/ -q -p no:warnings     # 期望：N passed
PY scripts/e2e_ms1_console.py             # 期望：PASS
```
- 最近通过：2026-09-09 MS2（**50 passed**；E2E-MS1-CONSOLE: PASS，0 错误 0 警告）。

## 7. 凭据复用推荐、Flag 墙、时间线、三格式导出均由真实数据生成

```bash
# 凭据/Flag/时间线：页面操作落 SQLite 并回读（pytest 覆盖）
PY -m pytest tests/test_state_api.py -q -p no:warnings
# 三格式导出快照（结构、真实数据、明文断言）
PY -m pytest tests/test_export_snapshot.py -q -p no:warnings
curl -s "http://127.0.0.1:8000/api/export?format=md" | head -8
```
- 最近通过：2026-09-08 MS1（导出 md 4029B / json 17KB / html 4.7KB，明文断言通过）。

## 8. pytest 全绿；e2e 全绿（随里程碑累积）

```bash
PY -m pytest tests/ -q -p no:warnings     # 期望：N passed
PY scripts/e2e_ms1_console.py             # 期望：PASS
```
- 最近通过：2026-09-09 MS2（**50 passed**；E2E-MS1-CONSOLE: PASS，0 错误 0 警告）。

## 9. 重启服务后项目状态从 SQLite 完整恢复

```bash
# 1) 写入标记数据（见第 3 条脚本）→ 2) Ctrl+C 停服务 → 3) PY -m pivothub --no-open → 4) 回读：
PY - <<'EOF'
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8000/api/projects/proj-1/state') as r:
    d = json.loads(r.read())
h = next(x for x in d['hosts'] if x['id'] == 'h-l2-01')
print('位置恢复:', h['posX'], h['posY'], '| 主机数:', len(d['hosts']))
EOF
```
- 最近通过：2026-09-08 MS1（重启后主机 11 台、拖拽位置 555.5/333.25、新增主机均恢复）。

## 10. docs/VERIFY.md 每条完成标准可复跑

本文件即索引；随里程碑推进逐条补充「最近通过」记录。

## 11. README 合规声明与真实启动说明

README §1 方式 A（后端一体化启动）+ §10 合规声明；启动横幅（pivothub/config.py BANNER）
双处声明「仅限 CTF / 授权靶场 / 教学」。
- 最近通过：2026-09-08 MS1。
