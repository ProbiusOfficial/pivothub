/* 终端布局与状态保持验证 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9351;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1760,1080',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-layout-' + Date.now()),
    'http://127.0.0.1:8777/',
  ], { stdio: 'ignore' });

  let page = null;
  for (let i = 0; i < 40 && !page; i++) {
    try {
      const l = await (await fetch('http://127.0.0.1:' + PORT + '/json/list')).json();
      page = l.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    } catch (e) { }
    if (!page) await sleep(300);
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0; const pending = new Map(); const errs = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); return; }
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
      errs.push(m.params.args.map((a) => a.value || a.description || '').join(' ').split('\n')[0]);
    }
  };
  const send = (method, params) => new Promise((res) => {
    const mid = ++id; pending.set(mid, res);
    ws.send(JSON.stringify({ id: mid, method, params: params || {} }));
  });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) {
      const d = r.exceptionDetails;
      throw new Error((d.exception && d.exception.description ? d.exception.description : d.text) +
        ' @expr:' + String(expr).slice(0, 60).replace(/\s+/g, ' '));
    }
    return r.result.value;
  };

  await send('Runtime.enable'); await send('Page.enable'); await send('Network.enable');
  await send('Network.setCacheDisabled', { cacheDisabled: true });
  for (let i = 0; i < 30; i++) {
    const c = await evaluate('!!(window.PivotStore && document.querySelector(".main"))');
    if (c) break;
    await sleep(400);
  }
  await evaluate('PivotStore.state.ui.disclaimerOpen = false; 1');
  await sleep(400);

  const out = [];

  /* 1. 布局：终端撑满 + hints 在最底部横跨整行 */
  const layout = await evaluate(`(async () => {
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 1800));
    const term = document.querySelector('.term');
    const row = document.querySelector('.term-col') || document.querySelector('.term-row');
    const hints = document.querySelector('.term-hints');
    const fix = document.querySelector('.tty-fix');
    const panel = document.querySelector('.terminal-panel');
    const main = document.querySelector('.main');
    if (!term || !row || !hints || !panel || !main) {
      return JSON.stringify({ error: 'missing dom', term: !!term, row: !!row, hints: !!hints,
        panel: !!panel, main: !!main, view: PivotStore.state.ui.view,
        selected: PivotStore.state.ui.selectedShellId, shells: PivotStore.state.shells.length });
    }
    const r = (el) => el ? el.getBoundingClientRect() : null;
    const t = r(term), rr = r(row), hh = r(hints), ff = r(fix), pp = r(panel), mm = r(main);
    return JSON.stringify({
      termH: t ? Math.round(t.height) : 0,
      rowH: rr ? Math.round(rr.height) : 0,
      fixH: ff ? Math.round(ff.height) : 0,
      hintsW: Math.round(hh.width),
      panelW: Math.round(pp.width),
      hintsBelowRow: Math.round(hh.top) >= Math.round(rr.bottom) - 2,
      hintsSpansPanel: Math.round(hh.width) >= Math.round(pp.width) - 30,
      hintsIsLast: panel.lastElementChild === hints,
      termFillsCol: Math.round(t.height) >= Math.round(rr.height) - 4,
      panelRight: Math.round(pp.right) + ' / main right=' + Math.round(mm.right)
    });
  })()`);
  out.push('布局: ' + layout);

  /* 2. 固化后再检测，状态不得降级 */
  const keep = await evaluate(`(async () => {
    const card = Array.from(document.querySelectorAll('.tty-card')).find(c => c.textContent.includes('Python PTY'));
    const btn = card && Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('执行并固化'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 1500));
    const ps1El = () => document.querySelector('.term-ps1');
    const afterFix = { mode: PivotStore.termState.mode, ps1: ps1El() ? ps1El().textContent.trim() : '(无终端)' };
    PivotStore.detectTty();
    await new Promise(r => setTimeout(r, 2600));
    const afterDetect = { mode: PivotStore.termState.mode, ps1: ps1El() ? ps1El().textContent.trim() : '(无终端)', capsTty: PivotStore.termState.caps.tty };
    return JSON.stringify({ afterFix, afterDetect, kept: afterFix.mode === afterDetect.mode && afterDetect.mode === 'full' });
  })()`);
  out.push('状态保持: ' + keep);

  /* 3. 切到已固化会话 s-1 应恢复已固化形态 */
  const resume = await evaluate(`(async () => {
    PivotStore.openTerminalById('s-2');
    await new Promise(r => setTimeout(r, 700));
    const other = PivotStore.termState.mode;
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 800));
    const ps1 = document.querySelector('.term-ps1');
    return JSON.stringify({ s2mode: other, s1mode: PivotStore.termState.mode,
      s1ps1: ps1 ? ps1.textContent.trim() : '(无终端)' });
  })()`);
  out.push('会话切换: ' + resume);

  /* 4. 截图（终端撑满 + hints 底部） */
  await evaluate(`(async () => {
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 900));
    PivotStore.execCommand('id');
    PivotStore.execCommand('uname -a');
    return 1;
  })()`);
  await sleep(1200);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'layout-term.png'), Buffer.from(shot.data, 'base64'));

  /* 5. 窄屏检查 */
  await send('Emulation.setDeviceMetricsOverride', { width: 1180, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(1200);
  const narrow = await evaluate(`(() => {
    const row = document.querySelector('.term-col') || document.querySelector('.term-row');
    const hints = document.querySelector('.term-hints');
    if (!row || !hints) return JSON.stringify({ error: 'missing dom', row: !!row, hints: !!hints });
    return JSON.stringify({
      rowDirection: getComputedStyle(row).flexDirection,
      hintsW: Math.round(hints.getBoundingClientRect().width),
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
    });
  })()`);
  out.push('窄屏 1180px: ' + narrow);
  await send('Emulation.clearDeviceMetricsOverride');

  console.log('===== 终端布局测试 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n错误 (' + errs.length + '): ' + (errs.length ? errs.join(' | ') : '无'));
  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
