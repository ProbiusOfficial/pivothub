# 仓库清单（REPOSITORY MANIFEST）

> 更新时间：2026-09-09
> 跟踪文件：**200 个 / 约 42.2 MB**（`git ls-files` 实测）
> 说明：本文件由早期「前端交付包清单（48 文件 / 3.8 MB，含已删除的 `mock.js`）」更新为当前全栈仓库清单。
> 不再逐文件列 SHA256 —— git 本身即内容寻址（`git ls-files -s`、`git hash-object <file>`），
> 手工维护的哈希清单会随下一次提交立即过期。

---

## 1. 目录构成

| 目录 | 文件数 | 大小 | 说明 |
|---|---:|---:|---|
| `pivothub/` | 62 | 0.3 MB | 后端包：`api/`(14) · `models/`(8) · `schemas/`(12) · `service/`(9) · `session/`(6) · `adapters/`(4) · `ws/`(2) + `app.py` / `config.py` / `db.py` / `util.py` / `localinfo.py` |
| `assets/` | 24 | 1.4 MB | 前端：`css/`(3) · `js/`(19，含 13 个 views) · `vendor/`(2：Vue 3 + ECharts 本地化) |
| `docs/` | 23 | 2.3 MB | 9 篇文档 + `evidence-round3.json` + `screenshots/`(13 张界面截图) |
| `.verify/` | 39 | 5.4 MB | 8 个 CDP 自动化脚本 + 31 张验证截图 |
| `tests/` | 16 | 0.1 MB | pytest 用例（当前 134 passed） |
| `scripts/` | 12 | < 0.1 MB | 靶场 Compose、联调 / 防火墙脚本 |
| `data/` | 11 | < 0.1 MB | 命令库、payload 模板、终端固化技法、种子项目 |
| `tools/` | 4 | 34.7 MB | chisel / fscan 二进制（Adapter 部署与内网扫描用） |
| 根目录 | 9 | 0.2 MB | `index.html` · `README.md` · PRD · 三份交接文档 · `requirements.txt` · `run.py` · `.gitignore` |

---

## 2. 未入库内容（见 `.gitignore`）

| 排除项 | 原因 |
|---|---|
| `pivothub.db` / `-shm` / `-wal` | 运行时 SQLite（WAL），由 `data/seed_project.json` 播种 |
| `__pycache__/`、`.pytest_cache/` | 缓存 |
| `_work/`、`_audit/`、`_pkg/` | 本地工作副本 / 审计快照 / 打包产物（各含一份完整重复代码） |
| `other/*.7z`、`pivothub-frontend-baseline-*.zip` | 归档文件 |
| `%TEMP%/` | 环境变量展开错误产生的空目录 |

---

## 3. 大文件

最大文件为 `tools/` 下的 4 个二进制（8.4–9.7 MB），均远低于 GitHub 100 MB 单文件上限：

| 文件 | 大小 | 用途 |
|---|---:|---|
| `tools/chisel.exe` | 9.3 MB | chisel 服务端（Windows 攻击机） |
| `tools/chisel_linux` | 8.9 MB | chisel 客户端（Linux 目标） |
| `tools/fscan.exe` | 8.4 MB | fscan v2.2.1（Windows 目标内网扫描） |
| `tools/fscan_linux` | 8.1 MB | fscan v2.2.1（Linux 目标内网扫描） |

`fscan` 二进制的 sha256 与官方 release `checksums.txt` 一致（见 `README.md` §9）。
