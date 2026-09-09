# 前端同步对账（FRONTEND-SYNC-ROUND3）

> 问题：把「上一轮 AI 写的后端」合并落地后，当前前端保留了什么、有没有冲突、
> 旧前端是否已彻底替换？
> 结论：**前端基线零结构改动、旧前端已彻底替换、契约冲突 1 处（segments）已修复**。

---

## 1. 结论摘要

| 项 | 结论 |
|---|---|
| 当前前端是否被旧前端覆盖 | ❌ 没有。`index.html` / `assets/**` 与交付基线逐文件 MD5 一致（除 3 个 JS 数据流文件） |
| UI 结构/样式是否改动 | ❌ 没有。`index.html`、`assets/css/**` 与交付基线 **字节级一致** |
| 数据模型权威是否改动 | ❌ 没有。`assets/js/mock.js` 与交付基线 **字节级一致** |
| 第 3 轮前端改动 | ✅ 仅 3 个文件、纯数据流接线：`api.js`(+3) / `store.js`(+61) / `views/proxy.js`(+97 −19) |
| 旧前端是否彻底替换 | ✅ 是。`_audit\supershell` 旧快照体积/hash 均不同，且未被任何入口引用 |
| 契约冲突 | 1 处已修复：`state.segments` 缺 VPN 段（见 §4） |

---

## 2. 逐文件对账（当前工作区 vs 交付基线）

基线来源：`pivothub-frontend-baseline-20260909.zip`（解包至 `%TEMP%\ph-zipcheck\supershell`），
用 MD5 逐文件比对。

```powershell
# 复跑：解包 + 逐文件 MD5 比对
& "C:\Program Files\7-Zip\7z.exe" x "pivothub-frontend-baseline-20260909.zip" "-o$env:TEMP\ph-zipcheck" -y
# 再对 index.html / assets/** 逐文件 Get-FileHash -Algorithm MD5 比对
```

| 文件 | zip 大小 | 当前大小 | 判定 |
|---|---|---|---|
| `index.html` | 80,603 | 80,603 | **IDENTICAL** |
| `assets/js/mock.js` | 30,930 | 30,930 | **IDENTICAL** |
| `assets/js/topology.js` | 12,465 | 12,465 | **IDENTICAL** |
| `assets/css/theme.css`（及 layout/components） | 3,736 | 3,736 | **IDENTICAL** |
| `assets/vendor/**`（vue / echarts 本地化） | — | — | **IDENTICAL** |
| `assets/js/api.js` | 2,581 | 2,745 | MODIFIED（+3 行） |
| `assets/js/store.js` | 60,412 | 63,979 | MODIFIED（+61 行） |
| `assets/js/views/proxy.js` | 27,767 | 31,909 | MODIFIED（+97 −19） |
| 其余 `assets/js/**`（app/icons/components/views/*.js） | — | — | **IDENTICAL** |

`git diff --no-index` 统计：

```
assets/js/api.js                  | 3 +++            1 hunk
assets/js/store.js                | 61 ++++++        4 hunks
assets/js/views/proxy.js          | 97 ++ / 19 --    6 hunks
```

---

## 3. 当前前端保留的后端改动（数据流接线，非 UI）

### 3.0 ⚠ 落地时的前端基线缺口（第 3 轮已修复，必读）

首次落地时工作区根目录的前端**并非交付基线**：`assets/js/api.js` 整个缺失，
`store.js`(39,866) / `topology.js`(11,807) / `views/shell.js`(9,048) 是旧版，
`assets/vendor/**` 缺失，`index.html` 仍引用 unpkg CDN（离线不可用、无 API 层）。
判定方法：与 `PACKAGE-MANIFEST.md` 的 SHA256 前 12 位逐文件比对。

已从 `pivothub-frontend-baseline-20260909.zip`（= `_pkg/supershell`，与清单哈希一致）
恢复以下文件，恢复后哈希与清单**逐条相同**：

| 文件 | 恢复前 | 恢复后 | 清单 SHA256(前12) |
|---|---|---|---|
| `index.html` | 78,681 B（CDN 引用） | 80,603 B | `59A53F12BBAF` ✅ |
| `assets/js/store.js` | 39,866 B（无 API 层） | 60,412 B | `4E57026C547B` ✅ |
| `assets/js/api.js` | **缺失** | 2,581 B | `DE80372CB36B` ✅ |
| `assets/js/topology.js` | 11,807 B | 12,465 B | `49CFE3B2F99A` ✅ |
| `assets/js/views/shell.js` | 9,048 B | 9,531 B | `A462ADF4A0D5` ✅ |
| `assets/vendor/vue.global.prod.js` | **缺失** | 146,843 B | `B50EEEFE35D4` ✅ |
| `assets/vendor/echarts.min.js` | **缺失** | 1,030,855 B | `E84270BD0CD5` ✅ |

其余 `assets/**`（`mock.js` 30,930 / `views/proxy.js` 27,767 / `css/**` / 其余视图）
落地时即与清单一致，未改动。**这是「前端基线」意义上的修复，不涉及任何 UI 结构/样式/文案。**

### 3.1 交付基线里本就已合入的（本轮未动，确认保留）

| 能力 | 位置 | 状态 |
|---|---|---|
| REST + WS 指数退避重连接入层 | `assets/js/api.js` | 保留（R3 仅新增 `put`） |
| API 优先 / 失败回退 mock 的 store 层 | `assets/js/store.js` | 保留 |
| 拓扑拖拽位置持久化上报/恢复 | `assets/js/topology.js` | 保留（未改动） |
| Shell 文件读/写/上传钩子 | `assets/js/views/shell.js` | 保留（未改动） |
| Vue / ECharts 本地化（离线可用） | `assets/vendor/**` | 保留（未改动） |
| 顶栏「＋ 新建」按钮 | `index.html` | 保留（未改动） |

### 3.2 第 3 轮新增接线

| 文件 | 新增 | 说明 |
|---|---|---|
| `api.js` | `PivotAPI.put()` | `PUT /api/attack` 需要；`GET/POST/PATCH/DELETE` 基线已有 |
| `store.js` | `state.attack` + `saveAttack()` | apiMode 下 `PUT /api/attack` 并整包回填；后端不可用仅本地生效（Mock 回退） |
| `store.js` | `deployLink()` | `POST /api/links/deploy`，携带 `linkType/bindAddr/localPort/targetHost/targetPort/relayAddr/relayPort/relayShellId`；失败返回真实 `stage/error` |
| `store.js` | `relayPlan()` | `GET /api/links/relay-plan`（服务端按同一规则复核中继推导） |
| `store.js` | `probeShell()` | `POST /api/shells/{id}/probe`（真实出网探测） |
| `store.js` | `applyState()` 增 `attack` 回填 | 服务端 `attack` 覆盖本地（原读 `MOCK.attack`） |
| `proxy.js` | 攻击机弹窗改调 `S.saveAttack()` | 不再直接写 `MOCK.attack`；服务端回填后 `refreshCmds()` |
| `proxy.js` | 出网探测接 `S.probeShell()` | 逐探针真实结果回填 `detect.probes`；无可用 Shell 时明确提示（不伪造） |
| `proxy.js` | 自动档部署接 `S.deployLink()` | 三种链路类型 + 中继会话参数；失败回退 Mock 演示 |

**未改动**：任何 DOM 结构、class、样式、模板文本；`MOCK.*` 常量（含 `SEGMENTS`/`ATTACK`/`HOSTS[].ifaces`）
保持字节级原样，继续作为后端不可用时的回退数据源。

---

## 4. 冲突清单与处置

| # | 冲突 | 权威依据 | 处置 |
|---|---|---|---|
| 1 | `state.segments` 只返回 L1/L2/L3 三段，缺 `192.0.2.0/24(VPN,#00e5a0)` | 任务 B-2 + `mock.js` `SEGMENTS`（4 条） | ✅ 已修：`service.timeline.segments_of` 不再跳过 `is_local`，攻击端网段单列 `layer="VPN"`；顺序按 `data/meta.json` `segmentColors`；`tests/test_state_api.py::test_segments_match_mock_topology` 逐条断言。原 `test_segments_aggregated_without_local` 锁定的旧行为（依据 `ASSUMPTIONS A-5`「mock 只有 3 段」）已随 A-5 修正为 A-20 |
| 2 | `localSocks` 旧语义 `127.0.0.1:端口` | HANDOFF §4.3 + 任务 B-4 | ✅ 后端已改为 `攻击机IP:端口`（字符串格式不变），前端零改名 |
| 3 | 后端曾写死 `127.0.0.1` 作为回连地址 | 任务 C-A | ✅ 一律取 `/api/attack` 配置；`pick_lhost()` 仅作默认建议 |
| 4 | 无 | — | 未发现其他字段名/枚举/结构冲突 |

---

## 5. 旧前端是否已彻底替换

| 项 | 旧快照 `_audit\supershell` | 当前工作区 | 判定 |
|---|---|---|---|
| `index.html` | 72,381 | 80,603 | 已替换（含「＋ 新建」） |
| `assets/js/mock.js` | 25,585 | 30,930 | 已替换（新网段 + ifaces + attack） |
| `assets/js/views/proxy.js` | 17,768 | 31,909 | 已替换（三种链路 + 多级中继 + 攻击机网络） |
| `assets/js/store.js` | 60,412 | 63,979 | 已替换（含 R3 接线） |
| `assets/js/api.js` | 2,581 | 2,745 | 已替换（含 `put`） |
| `assets/js/topology.js` | 11,620 | 12,465 | 已替换（拖拽上报） |

- `_audit\supershell\index.html` 与 `_audit\supershell\assets\` **未被复制到工作区**，也不被任何
  启动路径引用（`python -m pivothub` 从根目录读 `data/`；静态服务器指向根目录即服务当前前端）。
- 唯一残留：`scripts/lab/wwwroot/%TEMP%\.pivothub\chisel.exe`（早期调试时 `%TEMP%` 未展开写进
  联调靶根目录的产物），已清理，见 `docs/PROGRESS.md` 第 3 轮条目。

---

## 6. 复跑命令

```powershell
$env:PYTHONIOENCODING="utf-8"
python -m pytest tests/ -q -p no:warnings        # 全量
python _work/contract_check.py                   # 契约 27 项（无 chisel 依赖）
node .verify/cdp-test.js                         # 11 视图 0 错误（需先起前端静态服务）
node .verify/proxy-test.js                       # 三种链路/多级中继/攻击机设置/探测弹窗
```
