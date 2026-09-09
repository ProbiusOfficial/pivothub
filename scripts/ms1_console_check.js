/* MS1 验收：后端(8000) 驱动下逐视图渲染，收集 console 错误/警告。
 * 用法：先启动 python -m pivothub，再 node scripts/ms1_console_check.mjs */
'use strict';
const fs = require('fs');
const { spawn } = require('child_process');
const path = require('path');

const BROWSERS = [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
  path.join(process.env.LOCALAPPDATA || '', 'Google\\Chrome\\Application\\chrome.exe'),
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
];
const CHROME = BROWSERS.find((p) => { try { return p && fs.existsSync(p); } catch (e) { return false; } });
if (!CHROME) { console.error('未找到 Chrome/Edge，无法运行浏览器验收'); process.exit(2); }
const PORT = 9337;
const URL = 'http://127.0.0.1:8000/';
const VIEWS = ['dashboard', 'topology', 'shell', 'generator', 'proxy', 'asset', 'cred', 'flag', 'timeline', 'cheat', 'export'];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getTargets() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch('http://127.0.0.1:' + PORT + '/json/list');
      const list = await res.json();
      const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch (e) { /* retry */ }
    await sleep(300);
  }
  throw new Error('无法连接 Chrome 调试端口');
}

(async () => {
  const userDir = path.join(process.env.TEMP || '.', 'ph-ms1-' + Date.now());
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1680,1050',
    '--user-data-dir=' + userDir, URL,
  ], { stdio: 'ignore' });

  try {
    const page = await getTargets();
    const ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((r) => (ws.onopen = r));

    let id = 0;
    const pending = new Map();
    const errors = [];
    const warnings = [];
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
        return;
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails;
        errors.push('[exception] ' + (d.exception && d.exception.description ? d.exception.description : d.text) + ' @' + (d.url || '') + ':' + (d.lineNumber || 0));
      }
      if (msg.method === 'Runtime.consoleAPICalled') {
        const text = msg.params.args.map((a) => a.value || a.description || a.type).join(' ');
        if (msg.params.type === 'error') errors.push('[console.error] ' + text);
        if (msg.params.type === 'warning') warnings.push('[console.warn] ' + text);
      }
      if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
        errors.push('[log] ' + msg.params.entry.text);
      }
    };
    const send = (method, params) => new Promise((resolve, reject) => {
      const mid = ++id;
      pending.set(mid, { resolve, reject });
      ws.send(JSON.stringify({ id: mid, method, params: params || {} }));
    });
    const evaluate = async (expr) => {
      const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + JSON.stringify(r.exceptionDetails.exception || {}));
      return r.result.value;
    };

    await send('Runtime.enable');
    await send('Page.enable');
    for (let i = 0; i < 40; i++) {
      const ok = await evaluate('!!(window.PivotStore && document.querySelector(".main"))').catch(() => false);
      if (ok) break;
      await sleep(400);
    }
    await evaluate('PivotStore.state.ui.disclaimerOpen = false; 1');
    await sleep(1500); // 等待 API 状态加载 + WS

    const report = await evaluate(`(() => {
      const S = PivotStore;
      return {
        apiMode: S.isApiMode ? S.isApiMode() : false,
        wsOnline: S.state.ws.online,
        hosts: S.state.hosts.length,
        shells: S.state.shells.length,
        links: S.state.links.length,
        creds: S.state.creds.length,
        flags: S.state.flags.length,
        timeline: S.state.timeline.length,
        commands: S.state.commands.length,
        ttyFixes: S.state.ttyFixes.length,
        firstHostIp: S.state.hosts[1] ? S.state.hosts[1].ip : null,
        firstShellLastBeat: S.state.shells[0] ? S.state.shells[0].lastBeat : null,
      };
    })()`);
    console.log('数据源检查:', JSON.stringify(report));

    for (const v of VIEWS) {
      await evaluate(`PivotStore.state.ui.view = '${v}'; 1`);
      await sleep(v === 'shell' ? 1200 : 700);
      if (v === 'shell') {
        await evaluate(`PivotStore.openTerminalById(PivotStore.state.shells[0].id); 1`).catch(() => {});
        await sleep(800);
        await evaluate(`PivotStore.execCommand('id'); 1`);
        await sleep(600);
      }
      if (v === 'topology') await sleep(600);
    }

    console.log('错误数:', errors.length, '| 警告数:', warnings.length);
    errors.slice(0, 20).forEach((e) => console.log('  E>', e));
    warnings.slice(0, 20).forEach((w) => console.log('  W>', w));

    const pass = errors.length === 0 && warnings.length === 0 && report.apiMode && report.hosts > 0;
    console.log(pass ? 'MS1-CONSOLE-CHECK: PASS' : 'MS1-CONSOLE-CHECK: FAIL');
    process.exitCode = pass ? 0 : 1;
    ws.close();
  } finally {
    child.kill();
  }
})();
