/* CDP 冒烟测试：逐视图渲染 + 控制台错误收集 + 截图 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9333;
const URL = process.env.PH_URL || 'http://127.0.0.1:8033/?project=proj-10h9m';
const OUT = path.join(__dirname);
const VIEWS = ['dashboard', 'topology', 'shell', 'reverse', 'generator', 'proxy', 'asset', 'cred', 'flag', 'timeline', 'cheat', 'export'];

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
  const userDir = path.join(process.env.TEMP || '.', 'ph-cdp-' + Date.now());
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1680,1050',
    '--user-data-dir=' + userDir, URL,
  ], { stdio: 'ignore' });

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
      errors.push('[exception] ' + (d.exception && d.exception.description ? d.exception.description : d.text) +
        ' @' + (d.url || '') + ':' + (d.lineNumber || 0));
    }
    if (msg.method === 'Runtime.consoleAPICalled') {
      const text = msg.params.args.map((a) => a.value || a.description || a.type).join(' ');
      if (msg.params.type === 'error') errors.push('[console.error] ' + text);
      else if (msg.params.type === 'warning') warnings.push('[console.warn] ' + text);
    }
    if (msg.method === 'Log.entryAdded') {
      const e = msg.params.entry;
      if (e.level === 'error') errors.push('[log] ' + e.text + ' ' + (e.url || ''));
      else if (e.level === 'warning') warnings.push('[log] ' + e.text);
    }
  };

  const send = (method, params) => new Promise((resolve, reject) => {
    const mid = ++id;
    pending.set(mid, { resolve, reject });
    ws.send(JSON.stringify({ id: mid, method, params: params || {} }));
  });

  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' :: ' + expr);
    return r.result.value;
  };

  await send('Runtime.enable');
  await send('Log.enable');
  await send('Page.enable');
  await sleep(3500);

  const report = [];
  const basic = await evaluate(`(() => ({
    vue: !!window.Vue, echarts: !!window.echarts, store: !!window.PivotStore,
    navCount: document.querySelectorAll('.nav-item').length,
    canvas: !!document.querySelector('canvas'),
    title: document.querySelector('.view-head h2') ? document.querySelector('.view-head h2').textContent : ''
  }))()`);
  report.push(['初始加载', JSON.stringify(basic)]);

  for (const v of VIEWS) {
    const before = errors.length;
    await evaluate(`PivotStore.goto('${v}'); 1`);
    await sleep(700);
    const info = await evaluate(`(() => {
      const main = document.querySelector('.main');
      return {
        view: PivotStore.state.ui.view,
        h2: document.querySelector('.view-head h2') ? document.querySelector('.view-head h2').textContent.trim() : '(无)',
        nodes: main ? main.querySelectorAll('*').length : 0,
        panels: main ? main.querySelectorAll('.panel').length : 0,
        tables: main ? main.querySelectorAll('table').length : 0,
        canvas: main ? main.querySelectorAll('canvas').length : 0
      };
    })()`);
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(OUT, 'view-' + v + '.png'), Buffer.from(shot.data, 'base64'));
    report.push([v, JSON.stringify(info) + (errors.length > before ? '  ⚠ 新增错误 ' + (errors.length - before) : '')]);
  }

  /* 交互测试 */
  const before2 = errors.length;
  const interact = await evaluate(`(() => {
    const out = [];
    /* 拓扑：点击节点 */
    PivotStore.goto('topology');
    PivotStore.selectHost('h-l2-01');
    out.push('选中主机=' + (PivotStore.selected.host ? PivotStore.selected.host.ip : 'null'));
    PivotStore.selectLink('p-1');
    out.push('选中链路=' + (PivotStore.selected.link ? PivotStore.selected.link.tool : 'null'));
    /* 终端 */
    PivotStore.openTerminalById('s-1');
    PivotStore.execCommand('id');
    PivotStore.execCommand('ls -la');
    PivotStore.execCommand('help');
    out.push('终端行数=' + PivotStore.termState.lines.length);
    /* 出网探测 + 自动档部署 */
    PivotStore.goto('proxy');
    out.push('链路数=' + PivotStore.state.links.length);
    /* 凭据推荐 / Flag / 导出 */
    PivotStore.goto('cred');
    PivotStore.goto('flag');
    PivotStore.goto('export');
    const md = PivotStore.buildMarkdown({ topo: true, timeline: true, creds: true, flags: true, placeholder: true, chain: true });
    out.push('Markdown长度=' + md.length);
    return out.join(' | ');
  })()`);
  report.push(['交互测试', interact + (errors.length > before2 ? '  ⚠ 错误 ' + (errors.length - before2) : '')]);
  await sleep(500);

  /* 弹窗测试 */
  const before3 = errors.length;
  await evaluate(`PivotStore.openModal('shell-add'); 1`);
  await sleep(400);
  await evaluate(`PivotStore.openModal('host-add'); 1`);
  await sleep(300);
  await evaluate(`PivotStore.openModal('cred-add', {data:{hostId:'h-l2-02'}}); 1`);
  await sleep(300);
  await evaluate(`PivotStore.openModal('flag-add'); 1`);
  await sleep(300);
  await evaluate(`PivotStore.openModal('note-add'); 1`);
  await sleep(300);
  await evaluate(`PivotStore.closeModal(); 1`);
  await sleep(300);
  report.push(['弹窗测试', errors.length > before3 ? '⚠ 新增错误 ' + (errors.length - before3) : '全部弹窗可打开/关闭']);

  /* 清理初始 disclaimer 弹窗后截一张干净图 */
  await evaluate(`PivotStore.state.ui.disclaimerOpen = false; PivotStore.goto('topology'); 1`);
  await sleep(900);
  const shot2 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'final-topology.png'), Buffer.from(shot2.data, 'base64'));

  console.log('===== 视图渲染 =====');
  report.forEach(([k, v]) => console.log(k.padEnd(12) + ' ' + v));
  console.log('\n===== 错误 (' + errors.length + ') =====');
  console.log(errors.length ? errors.join('\n') : '（无）');
  console.log('\n===== 警告 (' + warnings.length + ') =====');
  console.log(warnings.length ? warnings.slice(0, 12).join('\n') : '（无）');

  ws.close();
  child.kill();
  process.exit(errors.length ? 1 : 0);
})().catch((e) => {
  console.error('测试脚本失败:', e.message);
  process.exit(2);
});
