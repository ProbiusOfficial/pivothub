/* 终端固化（TTY upgrade）功能测试 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9350;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1760,1080',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-tty-' + Date.now()),
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
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      errs.push('[exc] ' + ((d.exception && d.exception.description) || d.text).split('\n')[0]);
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

  /* 1. 打开固化弹窗，检查渲染 */
  const layout = await evaluate(`(async () => {
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 1100));
    PivotStore.state.ui.modal = 'tty-fix';
    await new Promise(r => setTimeout(r, 700));
    const fix = document.querySelector('.modal-fix');
    const cards = document.querySelectorAll('.modal-fix .tty-card');
    const term = document.querySelector('.term');
    return JSON.stringify({
      fixModal: fix ? Math.round(fix.getBoundingClientRect().width) + 'x' + Math.round(fix.getBoundingClientRect().height) : '无',
      cards: cards.length,
      termW: term ? Math.round(term.getBoundingClientRect().width) : 0,
      termH: term ? Math.round(term.getBoundingClientRect().height) : 0,
      headBadge: document.querySelector('.terminal-panel .panel-head .badge:last-child') ? document.querySelector('.terminal-panel .panel-head .badge:last-child').textContent.trim() : '无',
      stateText: document.querySelector('.tty-state-v') ? document.querySelector('.tty-state-v').textContent.trim() : '无',
      ps1: document.querySelector('.term-ps1') ? document.querySelector('.term-ps1').textContent.trim() : '无',
      tableCols: document.querySelectorAll('.view-shell thead th').length,
      stableCell: document.querySelector('.view-shell tbody tr td:nth-child(6)') ? document.querySelector('.view-shell tbody tr td:nth-child(6)').textContent.trim() : '无'
    });
  })()`);
  out.push('固化弹窗渲染: ' + layout);

  /* 2. 交互能力检测 */
  const detect = await evaluate(`(async () => {
    const btn = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.includes('交互能力检测'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 2600));
    return JSON.stringify({
      mode: PivotStore.termState.mode,
      modeLabel: PivotStore.termState.modeLabel,
      caps: PivotStore.termState.caps,
      lines: PivotStore.termState.lines.slice(-6).map(l => l.kind + ':' + l.html.slice(0, 46)),
      badge: document.querySelector('.tty-state') ? document.querySelector('.tty-state').className : ''
    });
  })()`);
  out.push('交互能力检测: ' + detect);

  /* 3. 应用 Python PTY 技法（可靠性 95%） */
  const apply = await evaluate(`(async () => {
    const card = Array.from(document.querySelectorAll('.modal-fix .tty-card')).find(c => c.textContent.includes('Python PTY'));
    const btn = card ? Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('执行并固化')) : null;
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 1400));
    return JSON.stringify({
      mode: PivotStore.termState.mode,
      modeLabel: PivotStore.termState.modeLabel,
      shellStable: (PivotStore.state.shells.find(s => s.id === 's-1') || {}).stable,
      applied: PivotStore.ttyAppliedList('s-1').map(x => x.name),
      appliedBadge: document.querySelectorAll('.modal-fix .tty-card.is-applied').length,
      ps1: document.querySelector('.term-ps1') ? document.querySelector('.term-ps1').textContent.trim() : '',
      last: PivotStore.termState.lines.slice(-3).map(l => l.kind + ':' + l.html.slice(0, 60))
    });
  })()`);
  out.push('应用 Python PTY: ' + apply);

  /* 4. 收尾 Ctrl+Z → stty raw */
  const finish = await evaluate(`(async () => {
    const btn = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.includes('stty raw'));
    const disabled = btn ? btn.disabled : 'no-btn';
    if (btn && !btn.disabled) btn.click();
    await new Promise(r => setTimeout(r, 1200));
    return JSON.stringify({
      btnDisabled: disabled,
      mode: PivotStore.termState.mode,
      capsTty: PivotStore.termState.caps.tty,
      lines: PivotStore.termState.lines.slice(-5).map(l => l.kind + ':' + l.html.slice(0, 55))
    });
  })()`);
  out.push('收尾 stty raw: ' + finish);

  /* 5. 事件是否入时间线 */
  const ev = await evaluate(`(() => {
    const hits = PivotStore.state.timeline.filter(e => /固化|检测/.test(e.title)).map(e => e.time + ' ' + e.title);
    return JSON.stringify(hits.slice(0, 4));
  })()`);
  out.push('时间线事件: ' + ev);

  /* 6. Windows 主机（ASPX 马）应显示 Windows 技法 */
  const win = await evaluate(`(async () => {
    PivotStore.openTerminalById('s-4');
    await new Promise(r => setTimeout(r, 1200));
    PivotStore.state.ui.modal = 'tty-fix';
    await new Promise(r => setTimeout(r, 700));
    const names = Array.from(document.querySelectorAll('.modal-fix .tty-card b')).map(b => b.textContent.trim());
    return JSON.stringify({
      platform: PivotStore.shellPlatform(PivotStore.state.shells.find(s => s.id === 's-4')),
      names,
      mode: PivotStore.termState.mode,
      firstLines: PivotStore.termState.lines.slice(0, 5).map(l => l.kind + ':' + l.html.slice(0, 50))
    });
  })()`);
  out.push('Windows 会话技法: ' + win);

  /* 7. 仅发送 / 复制 不报错 */
  const misc = await evaluate(`(async () => {
    const card = Array.from(document.querySelectorAll('.modal-fix .tty-card')).find(c => c.textContent.includes('ConPTY'));
    const send = card ? Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('仅发送')) : null;
    if (send) send.click();
    await new Promise(r => setTimeout(r, 700));
    return '发送后终端行数=' + PivotStore.termState.lines.length;
  })()`);
  out.push('仅发送按钮: ' + misc);

  /* 截图：固化弹窗 + 关闭后的终端 */
  const shotModal = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'tty-fix-modal.png'), Buffer.from(shotModal.data, 'base64'));
  await evaluate(`(async () => {
    PivotStore.state.ui.modal = null;
    PivotStore.openTerminalById('s-1');
    await new Promise(r => setTimeout(r, 1000));
    return 1;
  })()`);
  await sleep(900);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'tty-fix-shell.png'), Buffer.from(shot.data, 'base64'));

  console.log('===== 终端固化测试 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n===== 控制台错误 (' + errs.length + ') =====');
  console.log(errs.length ? errs.join('\n') : '（无）');
  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
