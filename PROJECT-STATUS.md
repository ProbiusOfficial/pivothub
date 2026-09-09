# PivotHub · 链透中枢 — 项目状态（PROJECT STATUS）

> 更新时间：2026-09-09
> 形态：**前端原型 + FastAPI 后端（全栈）**——数据落 SQLite，命令执行 / 文件读写 / 出网探测 / 终端固化
> 全部走真实会话层，后端不可用时前端显式报错，**不用假数据兜底**（`assets/js/mock.js` 已于第 4 轮移除）。
> 后端回归：`pytest tests/ -q -p no:warnings` → **134 passed**（2026-09-09 本机实测）。
> 前端回归：`.verify/` 12 视图 0 错误 0 警告（`README.md` §8 记录，本轮未复跑）。

---

## 1. 一句话状态

PRD 的 M1–M6 主体已实现并跑通：WebShell 会话管理、虚拟终端与终端固化（M1-8）、反弹 Shell 引导、
出网探测与 chisel 链路编排、资产 / 凭据 / Flag / 时间线、三格式复盘导出。
未完成的是 PRD 二期（冰蝎 / 哥斯拉、提权 exp 匹配）、7 款占位 Adapter，以及 M6-3 打包导出。

---

## 2. 分层实现（详见 `docs/ARCHITECTURE.md`）

| 层 | 位置 | 现状 |
|---|---|---|
| 前端 | `index.html` + `assets/` | Vue 3（CDN）+ ECharts 5，零构建；12 个导航视图 + `views/reverse.js` 反弹引导视图 |
| API | `pivothub/api/` | FastAPI，**57 个端点**：projects / hosts / shells / links / creds / flags / timeline / export / recon / stage / tools / attack / netinfo |
| 服务层 | `pivothub/service/` | 出网探测、终端固化、文件暂存双通道、链路编排、资产探测、统计、导出、时间线 |
| 会话层 | `pivothub/session/` | 命令执行与文件读写的**唯一出口**：HTTP 马 / 本地进程 / 反弹通道 |
| 适配器 | `pivothub/adapters/` | **仅 chisel 已接入**；frp / nps / Neo-reGeorg / EW / Stowaway / Venom / ligolo-ng 为占位（`data/meta.json` 标 `offline`，面板不可启用） |
| 持久层 | `pivothub/models/` + SQLite | SQLAlchemy 2.x，`pivothub.db`（WAL）；库被清空后按 `data/seed_project.json` 重新播种 |

---

## 3. 真实执行 / 尚未实现

**真实执行**（后端不可用即报错）：

- Shell 命令执行；文件浏览 / 读 / 写 / 下载 / 上传（HTTP 拉取 + 分片直传双通道，按字节数校验）；
- 反弹 Shell：攻击机侧真实 socket 监听 → 载荷回连 → 自动登记为 `kind=reverse` 会话；
- 终端固化 M1-8：交互能力检测 → 技法执行 → `stty raw` 收尾（三态标记）；
- 出网探测四探针（ICMP / DNS / HTTP / TCP）+ 隧道推荐；
- chisel 链路部署，多级中继三层串联与逐层进程清理；
- 资产探测：内置 fscan v2.2.1（`tools/fscan_linux` / `fscan.exe`）上传目标执行 + 结果导入；
- 复盘导出 MD / HTML / JSON；操作时间线自动事件 + Markdown 笔记。

**尚未实现**（详见 `README.md` §9 与 `docs/PROGRESS.md` 各轮「未决问题」）：

- 代理工具仅 chisel 可用，其余 7 款下线不可启用（MS4 范围，`docs/ASSUMPTIONS.md` A-22）；
- 断链自动重拉；
- M1-7 冰蝎 / 哥斯拉协议、M5-2 提权 exp 智能匹配（PRD 二期）；
- M6-3 项目导入 / 导出打包：界面就绪，后端接口未实现；
- 反弹会话平台判定固定 `linux`；面板重启后监听不自动恢复、历史反弹会话标记断线；
- Windows 靶机终端固化诚实判定失败（无 Linux pty），完整成功路径需 `scripts/lab` 的 Linux 靶机。

---

## 4. 验证证据

| 项 | 命令 / 来源 | 结果 |
|---|---|---|
| 后端全量回归 | `pytest tests/ -q -p no:warnings` | **134 passed**（398s，2026-09-09 本机实测） |
| 前端 12 视图 | `node .verify/cdp-test.js`（需 8777 静态服务） | 0 错误 0 警告（`README.md` §8） |
| 端到端 | `.verify/deep-test.js` · `tty-test.js` · `proxy-test.js` 等 8 个脚本 | 见 `README.md` §8 |
| 仓库规模 | `PACKAGE-MANIFEST.md` | 200 文件 / 约 42.2 MB |

---

## 5. 启动

```bash
pip install -r requirements.txt
python run.py            # 等价 python -m pivothub，监听 127.0.0.1:8000
```

浏览器打开 http://127.0.0.1:8000/ —— 后端直接托管前端。
面板强制仅监听回环（`pivothub/config.py` 有断言，合规硬约束）。

---

## 6. 文档索引

| 文档 | 内容 |
|---|---|
| `README.md` | 使用说明、PRD 对照、REST / WS 契约、已验证情况、已知边界 |
| `多层内网渗透辅助工具-产品设计文档.md` | PRD v1.0 |
| `docs/ARCHITECTURE.md` | 后端分层与数据契约 |
| `docs/PROGRESS.md` | 逐轮推进日志（倒序）+ 每轮未决问题 |
| `docs/ASSUMPTIONS.md` | 设计假设与取舍（A-xx 编号） |
| `docs/VERIFY.md` | 验证方法 |
| `docs/PROXY_GUIDE.md` | 代理编排指南 |
| `HANDOFF.md` | 交接说明（接续开发从这里开始） |
