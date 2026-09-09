# PivotHub 交付包 · 当前状态与交接说明

> 打包时间：2026-09-09
> 包内容：前端 UI 原型（可交互，Mock 数据）+ PRD + README + 测试脚本 + 界面截图
> **本包不含任何后端代码**——后端尚未开始，或由其他 AI 在别处开发。

---

## 1. 这个包里有什么

```
supershell/
├─ index.html                              前端骨架 + 全部 Vue 模板（x-template）
├─ README.md                               使用说明 + 后端对接契约（REST/WS 清单）
├─ 多层内网渗透辅助工具-产品设计文档.md     PRD v1.0（含 M1-8 终端固化）
├─ assets/
│  ├─ css/  theme.css · layout.css · components.css
│  └─ js/
│     ├─ mock.js             Mock 数据（三层内网 + 终端固化技法库）
│     ├─ store.js            全局状态 + 全部业务动作（接后端只改这里）
│     ├─ topology.js         拓扑画布（ECharts Graph）
│     ├─ icons.js  app.js  components/common.js
│     └─ views/              dashboard · shell · generator · proxy · asset
│                            cred · flag · timeline · cheat · export
├─ docs/screenshots/         12 张界面截图
└─ .verify/                  8 个可复跑的 Chrome Headless + CDP 测试脚本
```

**技术栈**：Vue 3（CDN 全局构建）+ ECharts 5 + 原生 CSS，零构建、零 npm 依赖。
**启动**：`python -m http.server 8777` 后访问 http://127.0.0.1:8777/

---

## 2. 当前已实现（前端原型，全部可交互）

| 模块 | 状态 | 说明 |
|---|---|---|
| 阶段看板 | ✅ | 已控主机 / 层级深度 / Flag 进度 / 剩余时间 + 攻击路径链 |
| 网络拓扑 | ✅ | ECharts 有向图；3 种布局；链路按类型着色（Socks / 中继 / 端口转发 / 断开）；节点 tooltip 显示全部网卡 |
| Shell 管理 | ✅ | 连接登记 / 心跳 / 虚拟终端（历史、Tab 补全、复合命令）/ 文件管理 |
| 终端固化 M1-8 | ✅ | 交互能力检测 + 13 条技法库 + 一键固化 + stty raw 收尾 + 三态标记 |
| 马生成器 | ✅ | PHP/JSP/ASP/ASPX × 5 种混淆；写马姿势速查 5 张卡（变量自动替换） |
| 代理编排台 | ✅ | 攻击机网络配置（弹窗）；三种链路类型；多级中继自动推导；出网探测按钮+弹窗；分步命令可单发到对应节点 |
| 主机清单 | ✅ | 表格 / 筛选 / 登记 / 扫描结果导入 |
| 凭据库 | ✅ | 表格 + 复用推荐（按网段/域/服务打分） |
| Flag 收集墙 | ✅ | 卡片墙 + 进度环 + 阶段进度 + 一键复制 |
| 操作时间线 | ✅ | 自动事件 + 手动 Markdown 笔记 |
| 命令速查 | ✅ | 6 大类 16 条模板 + 变量替换 + 发送到终端 |
| 复盘导出 | ✅ | MD / HTML / JSON 三格式实时预览 + 下载 |

### Mock 场景（与真实渗透场景对齐）

| 层级 | 网段 | 主机 |
|---|---|---|
| VPN | `192.0.2.0/24` | 攻击机 `192.0.2.10`（tun0） |
| L1 | `192.168.100.0/24` | web-dmz-01 **双网卡** `192.168.100.2`/`10.85.101.3`、web-dmz-02、db-dmz |
| L2 | `10.85.101.0/24` | app-int-01 **双网卡** `10.85.101.4`/`172.56.102.4`、app-int-02、file-int |
| L3 | `172.56.102.0/24` | DC01、SRV-SQL、srv-ops |

5 条代理链路覆盖三种类型；7 条凭据、5 个 Flag、17 条时间线事件、13 条固化技法。

---

## 3. 测试脚本（可复跑）

先启动静态服务（8777），再执行：

| 脚本 | 覆盖 |
|---|---|
| `.verify/cdp-test.js` | 11 个视图渲染 + 弹窗 + 交互，断言控制台 0 错误 |
| `.verify/deep-test.js` | 出网探测 / 自动档部署 / 终端 / 文件管理 / 扫描导入 / 导出 |
| `.verify/tty-test.js` | 终端固化全流程（检测 → 固化 → 收尾） |
| `.verify/proxy-test.js` | 三种链路类型 / 多级中继推导 / 攻击机设置 / 探测弹窗 / 两栏平衡 |
| `.verify/inject-test.js` | 写马姿势变量替换完整性 |
| `.verify/modal-test.js` | 固化弹窗尺寸与流程 |
| `.verify/layout-test.js` | 终端布局与状态保持 |
| `.verify/shots.js` | 重新生成 docs/screenshots |

最近一次全量结果：**11 视图 0 错误 0 警告**，上述脚本全部通过。

---

## 4. 已知边界 / 未完成（后端部分）

前端是**流程与交互的真实还原**，但所有数据来自 `mock.js`，以下均为模拟：

1. **无后端**：无 FastAPI、无 SQLite、无 WebSocket；刷新页面即恢复初始 Mock。
2. **命令执行是模拟**：`store.js` 的 `execCommand()` 用内置响应模拟回显，未走真实 Shell。
3. **终端固化是演示**：PTY 判定、技法成功率是模拟值；接后端后需按真实 `tty` / `stty size` / `isatty` 回显判定，并同步 `stty rows/cols`。
4. **代理链路未真实拉起**：命令文本正确，但未启动 chisel/frp 子进程、未监听回连。
5. **文件上传/下载**为进度模拟，未真实落盘。
6. **写马「一键尝试」是随机结果**：不发送真实请求，成功也不会自动登记 Shell。
7. **未实现**：冰蝎/哥斯拉协议（PRD M1-7，二期）、提权 exp 智能匹配（M5-2，二期）。

**对接入口**：`assets/js/store.js` 是唯一需要替换数据来源的文件，视图层零改动；
接口清单见 `README.md` §6（REST 路径 + WebSocket 事件 + 数据模型）。

---

## 5. 给接续开发的提示

- **数据契约以 `assets/js/mock.js` 为准**（字段名/枚举/示例），`README.md` §6.3 是摘要。
- **不要改前端 UI 结构与样式**：原型已通过 8 个自动化测试验证，联调只允许新增 `assets/js/api.js` 并改 `store.js` 的数据来源，且保留 mock 回退。
- **代理编排的关键推导逻辑在 `assets/js/views/proxy.js`**：
  - `nextSegmentOf()`：双网卡主机取第二块网卡所在网段作为纵深目标；
  - `findUpstream()` / `relayAddr`：推导多级中继的入口地址（上一层跳板在**本层网段**里的 IP）。
  后端实现多级串联时应复刻这套判定，而不是让用户手填。
- **PRD 中 M1-8（终端固化）是 P0**，别当成可选增强。
