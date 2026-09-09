# 交付说明（HANDOFF）— 以此包为基线继续开发

> 本包是 **前端原型 + 后端接入层** 的合并基线。
> 你（接续开发的 AI）请以本包为**唯一前端基线**，在此之上继续后端开发。

---

## 1. 这个包是什么

```
supershell/
├─ index.html                    # 前端骨架 + 全部 Vue 模板（含「＋ 新建」按钮）
├─ assets/
│  ├─ css/                       # theme / layout / components
│  ├─ vendor/                    # Vue 3 + ECharts 本地化（离线可用，勿删）
│  └─ js/
│     ├─ api.js                  # ★ 后端接入层（REST + WS 指数退避重连）
│     ├─ mock.js                 # ★ 数据模型唯一权威（三层内网 + 攻击机 + 双网卡）
│     ├─ store.js                # ★ API 优先 / 失败回退 mock（含全部业务动作）
│     ├─ topology.js             # 拓扑画布（含拖拽位置持久化上报）
│     ├─ icons.js  app.js  components/common.js
│     └─ views/                  # 11 个视图
├─ docs/screenshots/             # 界面截图
├─ .verify/                      # 8 个可复跑的 Chrome Headless 测试脚本
├─ PROJECT-STATUS.md             # 前端能力与已知边界
└─ 多层内网渗透辅助工具-产品设计文档.md   # PRD
```

**启动（纯前端）**：任意静态服务器指向本目录，例如 `python -m http.server 8777`。
后端未启动时自动走 Mock（面板永不白屏）；后端可用时自动切真实接口。

---

## 2. 与上一版后端的差异（务必先看）

上一版后端仓库里的前端是**旧快照**，本包已把它替换为最新前端，并保留了后端的 API 接入层：

| 项 | 上一版后端仓库 | 本包 |
|---|---|---|
| proxy.js | 17.7 KB（单跳 Socks） | **27.8 KB**（三种链路类型 + 多级中继 + 攻击机网络） |
| mock.js | 25.6 KB（旧网段） | **30.9 KB**（VPN 网段 + ifaces + attack） |
| index.html | 72.4 KB | **80.5 KB**（＋新建按钮已合入） |
| store.js | 60.4 KB（API 接入） | **60.4 KB（保留）** |
| api.js / vendor | 有 | **保留** |
| topology.js | 含拖拽上报 | **已合入** |
| shell.js | 含文件钩子 | **已合入** |
| 视图其余 | 旧版 | **最新版** |

**结论**：本包 = 最新前端 UI + 后端的 API 接入层 + ＋新建按钮。你之前实现的后端代码**无需重写**，
只需按新契约补字段与能力（见 HANDOFF §4 与任务提示词）。

---

## 3. 前端已实现的能力（不要退化）

11 个视图全部可用：阶段看板 / 网络拓扑 / Shell 管理（含终端固化弹窗）/ 马生成器 /
代理编排台 / 主机清单 / 凭据库 / Flag 墙 / 操作时间线 / 命令速查 / 复盘导出。

重点三块：

**① 代理编排台（本次重点）**
- 攻击机网络可配置（右上角按钮 → 弹窗：本机在靶场网络的 IP / 监听端口 / 网卡 / 网段）
- 三种链路类型：**Socks 代理 / 单端口转发 / 中继穿透（多级）**
- 多级中继自动推导：选中双网卡节点时自动切为 relay，并推导中继地址与目标网段
- 出网探测：跳板机下拉框右侧按钮 → 弹窗（四探针 + 结论 + 推荐 + 「使用推荐工具」）
- 分步命令卡片，每步可单独「发送到该节点终端」

**② 终端固化（PRD M1-8，P0）**
- 交互能力检测（tty / TERM / stty size / 工具探测）
- 13 条技法库（Linux 9 / Windows 4），插件化数据
- 一键执行固化 + `stty raw` 收尾 + 三态标记（伪终端 / 半交互 / 已固化）

**③ 写马姿势速查**
- 5 张卡片，`{URL}`/`{PARAM}`/`{PATH}`/`{FILE}`/`{IP}` 等变量按选中主机自动替换

---

## 4. 后端需要跟上的契约（实测差异）

本包的前端会消费以下字段，上一版后端**尚未提供**：

### 4.1 `/api/projects/{id}/state` 顶层

| 缺失 | 说明 |
|---|---|
| `attack` | `{ ip, segment, iface, note }` — 攻击机在靶场网络的地址（**不可再写 127.0.0.1**） |
| 新 `segments` | `192.0.2.0/24(VPN)` / `192.168.100.0/24` / `10.85.101.0/24` / `172.56.102.0/24` |

### 4.2 `HostOut`

| 缺失 | 说明 |
|---|---|
| `ifaces: [{iface, ip, segment}]` | 双网卡信息；拓扑 tooltip 与多级中继推导都依赖它 |

### 4.3 `LinkOut` / `ProxyLink`

| 缺失 | 说明 |
|---|---|
| `linkType` | `socks` / `portfwd` / `relay` — 看板类型徽标、拓扑边着色依赖 |
| `listenPort` / `remoteBind` / `localPort` | 链路参数 |
| `targetHost` / `targetPort` | 单端口转发目标 |
| `relayAddr` / `relayPort` | 多级中继入口 |
| `hops[]` | 分步命令回放 |

`localSocks` 语义改为 **`攻击机IP:端口`**（不再是 `127.0.0.1:端口`），字符串格式不变。

### 4.4 端点

| 端点 | 状态 |
|---|---|
| `GET/PUT /api/attack` | 需新增（攻击机网络读写） |
| `POST /api/shells/{id}/probe` | 需真实执行（出网探测） |
| `POST /api/links/deploy` | 已有，但只支持单跳 socks + 写死 127.0.0.1，需扩展 |

---

## 5. 已知边界（本包仍是 Mock 数据）

- 无后端时全部数据来自 `mock.js`，刷新即还原；
- 命令执行、文件读写、终端固化判定、代理拉起均为**流程演示**；
- 前端 `proxy.js` 的攻击机配置目前写入 `MOCK.attack`，接后端后应改为调 `PUT /api/attack`
  （或在 `applyState` 里从服务端 `attack` 回填）。

---

## 6. 复跑测试

```bash
# 起静态服务（8777）后
node .verify/cdp-test.js      # 11 视图 + 弹窗，断言 0 错误
node .verify/deep-test.js     # 探测/部署/终端/文件/导入/导出
node .verify/tty-test.js      # 终端固化全流程
node .verify/proxy-test.js    # 三种链路类型 / 多级中继 / 攻击机设置 / 探测弹窗
node .verify/inject-test.js   # 写马变量替换
node .verify/modal-test.js    # 固化弹窗
node .verify/layout-test.js   # 终端布局
node .verify/shots.js         # 重新生成 docs/screenshots
```

最近一次：**11 视图 0 错误 0 警告**，上述脚本全部通过。

---

## 7. 合规

本工具仅用于 CTF 竞赛、授权靶场与教学演示，禁止对未授权真实目标使用。
面板仅监听 `127.0.0.1`；不内置任何针对真实目标的 exploit。
