# 打包清单（PACKAGE MANIFEST）

> 生成时间：2026-09-09
> 文件数：48 · 总大小：约 3.8 MB
> 校验：SHA256 前 12 位

| 路径 | 大小 | SHA256(前12) |
|---|---|---|
| .verify/cdp-test.js | 7.4 KB | 7BB4517450D8 |
| .verify/deep-test.js | 10.1 KB | 23CCE9CD8A33 |
| .verify/inject-test.js | 6.9 KB | 483168188ABE |
| .verify/layout-test.js | 6.4 KB | D3B9255200F1 |
| .verify/modal-test.js | 7.2 KB | 68540B31C5DA |
| .verify/proxy-test.js | 12.5 KB | 5BBF25EDFB50 |
| .verify/shots.js | 4.3 KB | 8BB4484F4953 |
| .verify/tty-test.js | 8.7 KB | 6561DF6FBE93 |
| assets/css/components.css | 17.2 KB | B27E1D80EA68 |
| assets/css/layout.css | 21.1 KB | AEFDCC127282 |
| assets/css/theme.css | 3.6 KB | ED294C84AD8C |
| assets/js/api.js | 2.5 KB | DE80372CB36B |
| assets/js/app.js | 1.6 KB | E30EE012ABD0 |
| assets/js/components/common.js | 0.9 KB | 5802E83CF727 |
| assets/js/icons.js | 4.1 KB | 2D319F457667 |
| assets/js/mock.js | 30.2 KB | 72BC37685CDC |
| assets/js/store.js | 59.0 KB | 4E57026C547B |
| assets/js/topology.js | 12.2 KB | 49CFE3B2F99A |
| assets/js/views/asset.js | 2.9 KB | 6C2F172206E2 |
| assets/js/views/cheat.js | 2.7 KB | 3F0C0E73094F |
| assets/js/views/cred.js | 4.3 KB | C0E0F44B34C9 |
| assets/js/views/dashboard.js | 2.0 KB | E10B64DF85C3 |
| assets/js/views/export.js | 3.5 KB | C1FEB423E1AA |
| assets/js/views/flag.js | 1.8 KB | E281FF8A460B |
| assets/js/views/generator.js | 7.2 KB | 3A3FED93A877 |
| assets/js/views/proxy.js | 27.1 KB | 39EC5DD622BE |
| assets/js/views/shell.js | 9.3 KB | A462ADF4A0D5 |
| assets/js/views/timeline.js | 1.6 KB | 22143F02004D |
| assets/vendor/echarts.min.js | 1006.7 KB | E84270BD0CD5 |
| assets/vendor/vue.global.prod.js | 143.4 KB | B50EEEFE35D4 |
| docs/screenshots/00-启动合规声明.png | 160.1 KB | 7E92393268AB |
| docs/screenshots/01-阶段看板.png | 170.3 KB | B7BF3ACB26FC |
| docs/screenshots/02-网络拓扑.png | 227.0 KB | 3C0186BC488E |
| docs/screenshots/03-Shell管理.png | 176.5 KB | 48864A99A8BB |
| docs/screenshots/03b-终端固化弹窗.png | 232.2 KB | A11369B450DC |
| docs/screenshots/04-代理编排台.png | 196.4 KB | 90A45C2117C7 |
| docs/screenshots/05-马生成器.png | 176.8 KB | 63C97F9553F3 |
| docs/screenshots/06-主机清单.png | 179.6 KB | 2DC9A7504B93 |
| docs/screenshots/07-凭据库.png | 183.4 KB | B444F6290596 |
| docs/screenshots/08-Flag收集墙.png | 117.5 KB | B9C43ACD41E6 |
| docs/screenshots/09-操作时间线.png | 160.0 KB | D55364EA8D40 |
| docs/screenshots/10-命令速查.png | 158.9 KB | 71ADF4B51AF6 |
| docs/screenshots/11-复盘导出.png | 136.3 KB | 568F8F1BFDFB |
| HANDOFF.md | 6.2 KB | 4573BAACF75B |
| index.html | 78.7 KB | 59A53F12BBAF |
| PROJECT-STATUS.md | 6.0 KB | 60DAC0354F89 |
| README.md | 19.4 KB | 36FE8B8789BD |
| 多层内网渗透辅助工具-产品设计文档.md | 23.0 KB | 6C18EFBB8131 |

## 与上一版后端的合并说明

本包以前端为基线，已合入上一版后端的以下改动：

| 合入项 | 来源 | 说明 |
|---|---|---|
| `assets/js/api.js` | 后端 | REST + WS 客户端（指数退避重连） |
| `assets/vendor/*` | 后端 | Vue / ECharts 本地化，离线可用 |
| `store.js`（60 KB） | 后端 | API 优先 + mock 回退，含 `applyState/refreshState/handleWsEvent/readFile/writeFile/uploadFile/createProject/saveNodePos` |
| `index.html` 脚本引用 | 后端 | `api.js` + `vendor` 两行 |
| 「＋ 新建」按钮 | 后端 | 顶栏项目选择器旁，`@click="createProject"` |
| `topology.js` 拖拽上报 | 后端 | `S.saveNodePos()` + 服务端位置恢复 watch |
| `shell.js` 文件钩子 | 后端 | `openFile/saveFile/upload` 的 apiMode 分支 |

前端 UI 与逻辑以本包为权威；后端仓库中的旧版前端**已被本包取代**。
