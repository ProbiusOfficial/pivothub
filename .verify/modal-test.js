/* 终端固化弹窗 + 页面高度验证 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9352;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1760,1080',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-fixmodal-' + Date.now()),
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
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
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

  /* 1. 页面高度：终端下方不应超出视口 */
  const height = await evaluate(`(async () => {
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 1200));
    const main = document.querySelector('.main');
    const panel = document.querySelector('.terminal-panel');
    const hints = document.querySelector('.term-hints');
    const term = document.querySelector('.term');
    const r = (el) => el ? el.getBoundingClientRect() : null;
    const hh = r(hints), tt = r(term), pp = r(panel), mm = r(main);
    return JSON.stringify({
      viewportH: window.innerHeight,
      mainScrollH: main.scrollHeight, mainClientH: main.clientHeight,
      mainScrollable: main.scrollHeight - main.clientHeight,
      panelBottom: Math.round(pp.bottom),
      hintsBottom: Math.round(hh.bottom),
      hintsVisible: hh.bottom <= window.innerHeight + 1,
      termH: Math.round(tt.height),
      hintsBelowTerm: hh.top >= tt.bottom - 2,
      hintsInsidePanel: panel.contains(hints)
    });
  })()`);
  out.push('页面高度: ' + height);

  /* 2. 打开固化弹窗 */
  const modal = await evaluate(`(async () => {
    const btn = Array.from(document.querySelectorAll('.terminal-panel .panel-head .btn')).find(b => b.textContent.includes('终端固化'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 700));
    const m = document.querySelector('.modal-fix');
    const cards = document.querySelectorAll('.modal-fix .tty-card');
    const body = document.querySelector('.fix-body');
    const list = document.querySelector('.modal-fix .tty-list');
    const rr = (el) => el ? el.getBoundingClientRect() : null;
    return JSON.stringify({
      modalOpen: PivotStore.state.ui.modal,
      modalW: m ? Math.round(rr(m).width) : 0,
      modalH: m ? Math.round(rr(m).height) : 0,
      withinViewport: m ? rr(m).height <= window.innerHeight : false,
      cards: cards.length,
      cols: body ? getComputedStyle(body).gridTemplateColumns : '',
      listScrollable: list ? list.scrollHeight > list.clientHeight : false,
      genericModal: !!document.querySelector('.modal:not(.modal-fix):not(.modal-wide):not(.modal-narrow)')
    });
  })()`);
  out.push('固化弹窗: ' + modal);

  /* 3. 弹窗内执行检测 + 固化 */
  const flow = await evaluate(`(async () => {
    const detectBtn = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.includes('交互能力检测'));
    if (detectBtn) detectBtn.click();
    await new Promise(r => setTimeout(r, 2700));
    const stateAfterDetect = PivotStore.termState.mode;
    const card = Array.from(document.querySelectorAll('.modal-fix .tty-card')).find(c => c.textContent.includes('Python PTY'));
    const applyBtn = card && Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('执行并固化'));
    if (applyBtn) applyBtn.click();
    await new Promise(r => setTimeout(r, 1600));
    const footBtn = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.includes('stty raw'));
    return JSON.stringify({
      stateAfterDetect,
      stateAfterFix: PivotStore.termState.mode,
      modalBadge: document.querySelector('.modal-fix .modal-head .badge:last-child').textContent.trim(),
      appliedInModal: document.querySelectorAll('.modal-fix .tty-card.is-applied').length,
      finishBtnEnabled: footBtn ? !footBtn.disabled : null,
      termStillThere: !!document.querySelector('.term')
    });
  })()`);
  out.push('弹窗内流程: ' + flow);

  /* 4. 弹窗截图 */
  const shotModal = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'fix-modal.png'), Buffer.from(shotModal.data, 'base64'));

  /* 5. 关闭弹窗后终端仍在且无页面溢出 */
  const after = await evaluate(`(async () => {
    const close = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.trim() === '关闭');
    if (close) close.click();
    await new Promise(r => setTimeout(r, 500));
    const main = document.querySelector('.main');
    const hints = document.querySelector('.term-hints');
    return JSON.stringify({
      modalClosed: PivotStore.state.ui.modal === null,
      hintsVisible: hints.getBoundingClientRect().bottom <= window.innerHeight + 1,
      mainScrollable: main.scrollHeight - main.clientHeight,
      docOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth
    });
  })()`);
  out.push('关闭后: ' + after);
  await sleep(600);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'fix-after.png'), Buffer.from(shot.data, 'base64'));

  console.log('===== 固化弹窗与高度测试 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n错误 (' + errs.length + '): ' + (errs.length ? errs.join(' | ') : '无'));
  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
