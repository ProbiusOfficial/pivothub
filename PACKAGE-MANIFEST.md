# 仓库清单（REPOSITORY MANIFEST）

> 更新时间：2026-09-10
> 跟踪文件：**230 个 / 约 113.5 MB**（`git ls-files` + `docs/screenshots/` 实测）
> 说明：本文件由早期「前端交付包清单（48 文件 / 3.8 MB，含已删除的 `mock.js`）」更新而来；
> 已随仓库清理移除过时的自动化测试脚本与旧截图（`.verify/` 等，见 git 历史）。
> 不再逐文件列 SHA256 —— git 本身即内容寻址（`git ls-files -s`、`git hash-object <file>`），
> 手工维护的哈希清单会随下一次提交立即过期。

---

## 1. 目录构成

| 目录 | 文件数 | 大小 | 说明 |
|---|---:|---:|---|
| `pivothub/` | 77 | 0.5 MB | 后端包：`api/`(20) · `models/`(9) · `schemas/`(12) · `service/`(12) · `session/`(7) · `adapters/`(5) · `ws/`(2) + `app.py` / `config.py` / `db.py` / `util.py` / `localinfo.py` |
| `assets/` | 27 | 1.5 MB | 前端：`css/`(3) · `js/`(22，含 17 个 views) · `vendor/`(2：Vue 3 + ECharts 本地化) |
| `docs/` | 47 | 6.5 MB | 架构 / 计划 / 进展 / 验证文档 + `screenshots/`(17 张界面截图) + `shots/`(靶场验证证据) |
| `tests/` | 27 | 0.2 MB | pytest 用例（当前 **223 passed**，2026-09-10 实测） |
| `scripts/` | 10 | < 0.1 MB | 靶场 Compose（`lab/`）· Windows 防火墙放行脚本 |
| `data/` | 15 | < 0.1 MB | 命令库、payload 模板、终端固化技法、提权规则、插件清单、种子项目 |
| `tools/` | 18 | 104.5 MB | chisel / frp / fscan 二进制与 Neo-reGeorg 模板（Adapter 部署与内网扫描用） |
| 根目录 | 9 | 0.2 MB | `index.html` · `README.md` · PRD · 三份交接文档 · `requirements.txt` · `run.py` · `.gitignore` |

---

## 2. 未入库内容（见 `.gitignore`）

| 排除项 | 原因 |
|---|---|
| `pivothub.db` / `-shm` / `-wal` | 运行时 SQLite（WAL），由 `data/seed_project.json` 播种 |
| `__pycache__/`、`.pytest_cache/` | 缓存 |
| `_work/`、`_audit/`、`_pkg/`、`other/` | 本地工作副本 / 审计快照 / 打包产物（各含一份完整重复代码） |
| `other/*.7z`、`pivothub-frontend-baseline-*.zip` | 归档文件 |
| `%TEMP%/` | 环境变量展开错误产生的空目录 |
| `.run/` | Adapter 运行时产物（frps/frpc 配置含随机 token） |
| `data/stage/` | 文件暂存 HTTP 服务目录（运行时临时文件） |
| `.workbuddy/` | 本地 Agent 记忆 / 工作区数据（非源码） |
| `/data/plugins/*/` | 插件市场安装内容（运行时数据） |

---

## 3. 大文件

`tools/` 下的二进制均远低于 GitHub 100 MB 单文件上限：

| 文件 | 大小 | 用途 |
|---|---:|---|
| `tools/frps.exe` / `frps_linux` | 19.1 / 18.7 MB | frp 服务端（攻击机） |
| `tools/frpc.exe` / `frpc_linux` | 15.3 / 14.9 MB | frp 客户端（目标侧） |
| `tools/chisel.exe` / `chisel_linux` | 9.8 / 9.4 MB | chisel 服务端 / 客户端 |
| `tools/fscan.exe` / `fscan_linux` | 8.8 / 8.5 MB | fscan v2.2.1（资产探测内置扫描器） |

`fscan` 二进制的 sha256 与官方 release `checksums.txt` 一致（见 `README.md` §9）。
