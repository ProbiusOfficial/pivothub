# 交接说明（HANDOFF）— 接续开发从这里开始

> 更新时间：2026-09-10
> 本仓库是 **前端原型 + FastAPI 后端的全栈基线**（早期「纯前端交付包」版本已作废）。
> 后端回归 `pytest tests/ -q -p no:warnings` → **223 passed**（2026-09-10 实测）；接口契约已在代码中落地，不再有「待补字段」清单。

---

## 1. 先看什么

| 顺序 | 文件 | 作用 |
|---|---|---|
| 1 | `README.md` | 使用说明 + PRD 对照 + REST / WS 契约 + 已知边界 |
| 2 | `docs/ARCHITECTURE.md` | 分层架构与数据契约 |
| 3 | `docs/PROGRESS.md` | 已完成轮次与每轮「未决问题」（倒序，最新在最上） |
| 4 | `docs/ASSUMPTIONS.md` | 设计假设（A-xx 编号，改动前先读） |
| 5 | `PROJECT-STATUS.md` | 当前状态速览 |

---

## 2. 关键约定（勿退化）

- **数据来源只有后端**：`assets/js/mock.js` 已在第 4 轮移除（见 `docs/PROGRESS.md`）。后端不可用时前端显式报错，不允许恢复假数据兜底。
- **唯一权威契约在后端 schemas**：`pivothub/schemas/`。其中 `HostOut` 含 `ifaces`，`LinkOut` 含
  `linkType` / `listenPort` / `remoteBind` / `relayAddr` / `hops`，`StateOut` 顶层含 `attack` / `segments`。
  前端消费侧在 `assets/js/store.js`，视图层不改数据来源。
- **命令执行与文件读写只走 `pivothub/session/`**：API 层不出现 `subprocess`。
- **面板仅监听 `127.0.0.1`**：`pivothub/config.py` 有断言，属合规硬约束，不要放宽。
- **前端回归**：改动后在浏览器逐视图复跑（重点：拓扑拖拽 / 终端固化 / 链路部署 / 探测弹窗 / 导出），控制台保持 0 错误；
  后端以 `pytest tests/ -q -p no:warnings` 全绿为准入门槛。早期 `.verify/` CDP 脚本已随仓库清理移除，需要时可从 git 历史取回。
- **凭据 / 口令 / Flag 明文显示是有意设计**（`docs/ASSUMPTIONS.md` A-23）：面板仅面向本机授权场景；
  对外分享 Writeup / 导出 JSON 前请自行删减敏感信息。

---

## 3. 早期交接文档中的「待补契约」已全部落地

上一版 `HANDOFF.md` 列的差异清单，在本次基线中均已实现：

| 早期缺口 | 现状 |
|---|---|
| `state` 顶层 `attack` + `GET/PUT /api/attack` | `pivothub/schemas/state.py`、`pivothub/api/attack.py` |
| `HostOut.ifaces` 双网卡信息 | `pivothub/schemas/host.py`（多级中继推导依赖） |
| `LinkOut.linkType` / `hops` / `relayAddr` 等链路参数 | `pivothub/schemas/link.py`，三种链路类型齐全 |
| `POST /api/shells/{id}/probe` 真实探测 | `pivothub/service/probe.py`，四探针真实执行 |
| `POST /api/links/deploy` 仅单跳 socks、写死 127.0.0.1 | `pivothub/service/relay.py`，支持多级中继与逐层清理 |
| `localSocks` 语义为「攻击机 IP:端口」 | 已按此实现，攻击机地址由全局设置统一提供 |

---

## 4. 下一步（按优先级）

1. **接入其余 7 款 Adapter**（frp / nps / Neo-reGeorg / EW / Stowaway / Venom / ligolo-ng）：
   在 `pivothub/adapters/registry.py` 注册，并把 `data/meta.json` 中对应 `status` 改为 `online`，
   前端无需改动（`docs/ASSUMPTIONS.md` A-22）。
2. **断链自动重拉**（`README.md` §9 列为未实现）。
3. **M6-3 项目导入 / 导出打包**：前端按钮就绪，后端接口待实现。
4. **反弹会话**：平台识别（`uname -s` 回显）与监听持久化 / 自动恢复已落地；仅剩「历史会话重启后标记断线」——
   通道是进程内 socket，属预期行为（监听已自动恢复，靶机重连即可再登记）。
5. **PRD 二期**：M1-7 冰蝎 / 哥斯拉协议。

---

## 5. 开发与验证

```bash
pip install -r requirements.txt
pytest tests/ -q -p no:warnings        # 223 passed
python run.py                          # 127.0.0.1:8000，后端托管前端
```

前端回归（人工，浏览器逐视图）：

打开 `http://127.0.0.1:8000/`，逐视图点击并观察控制台 0 错误；
重点复跑拓扑拖拽、终端固化、链路部署、探测弹窗、复盘导出。

靶场：`scripts/lab/`（Docker Compose，含 JSP / PHP 马与 Linux 靶机）。

---

## 6. 合规

本工具仅用于 CTF 竞赛、授权靶场与教学演示，禁止对未授权真实目标使用。
面板仅监听 `127.0.0.1`；不内置任何针对真实目标的 exploit。
