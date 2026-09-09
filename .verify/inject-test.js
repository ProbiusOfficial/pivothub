/* 写马姿势速查：变量替换验证 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9355;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1760,1080',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-inject-' + Date.now()),
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
  await evaluate('PivotStore.state.ui.disclaimerOpen = false; PivotStore.goto("generator"); 1');
  await sleep(1300);

  const out = [];

  /* 1. 卡片与变量徽标渲染 */
  const cards = await evaluate(`(() => {
    const list = Array.from(document.querySelectorAll('.inject-card'));
    return JSON.stringify(list.map(c => ({
      title: c.querySelector('.inject-head b').textContent.trim(),
      vars: Array.from(c.querySelectorAll('.inject-vars .badge')).map(b => b.textContent.trim()),
      code: c.querySelector('code').textContent.slice(0, 90).replace(/\\n/g, ' ⏎ '),
      host: c.querySelector('select').value
    })));
  })()`);
  out.push('卡片渲染: ' + cards);

  /* 2. 切换主机 → 变量真的变了 */
  const swap = await evaluate(`(async () => {
    const card = document.querySelectorAll('.inject-card')[0];
    const sel = card.querySelector('select');
    const before = card.querySelector('code').textContent;
    /* 切到 L3 域控 10.10.30.8 */
    sel.value = 'h-l3-01';
    sel.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 500));
    const after = card.querySelector('code').textContent;
    return JSON.stringify({
      changed: before !== after,
      beforeLine: before.split('\\n')[0],
      afterLine: after.split('\\n')[0],
      hasL3Ip: after.includes('10.10.30.8'),
      noBrace: !/\\{[A-Z]+\\}/.test(after),
      vars: Array.from(card.querySelectorAll('.inject-vars .badge')).map(b => b.textContent.trim())
    });
  })()`);
  out.push('切换主机替换: ' + swap);

  /* 3. 每张卡片都无残留占位符 */
  const allResolved = await evaluate(`(async () => {
    const res = [];
    for (const c of document.querySelectorAll('.inject-card')) {
      const sel = c.querySelector('select');
      for (const opt of Array.from(sel.options).slice(0, 4)) {
        sel.value = opt.value;
        sel.dispatchEvent(new Event('change'));
        await new Promise(r => setTimeout(r, 160));
        const txt = c.querySelector('code').textContent;
        const leftover = (txt.match(/\\{[A-Z]+\\}/g) || []);
        if (leftover.length) res.push(c.querySelector('.inject-head b').textContent.trim() + '@' + opt.textContent.trim() + ' → ' + leftover.join(','));
      }
    }
    return res.length ? res.join(' | ') : '全部占位符均已替换';
  })()`);
  out.push('占位符完整性: ' + allResolved);

  /* 4. 复制按钮拿到的是替换后的内容 */
  const copy = await evaluate(`(async () => {
    const card = document.querySelectorAll('.inject-card')[0];
    const sel = card.querySelector('select');
    sel.value = 'h-l1-01';
    sel.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 400));
    let captured = null;
    const orig = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = (t) => { captured = t; return Promise.resolve(); };
    const btn = Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('复制 payload'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 400));
    navigator.clipboard.writeText = orig;
    return JSON.stringify({
      copied: captured ? captured.slice(0, 80).replace(/\\n/g, ' ⏎ ') : '未捕获',
      hasTargetIp: captured ? captured.includes('192.168.100.10') : false,
      noBrace: captured ? !/\\{[A-Z]+\\}/.test(captured) : false
    });
  })()`);
  out.push('复制内容: ' + copy);

  /* 5. 一键尝试闭环（结果随机，检查两种分支都合理） */
  const inject = await evaluate(`(async () => {
    const before = PivotStore.state.timeline.length;
    const card = document.querySelectorAll('.inject-card')[0];
    const btn = Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('一键尝试'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 1500));
    const last = PivotStore.state.toasts[PivotStore.state.toasts.length - 1] || {};
    return JSON.stringify({
      lastToast: last.kind + ':' + last.msg,
      newEvents: PivotStore.state.timeline.length - before,
      lastEvent: PivotStore.state.timeline[0].title,
      consistent: (last.kind === 'ok') === (PivotStore.state.timeline.length - before === 1)
    });
  })()`);
  out.push('一键尝试: ' + inject);

  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'inject-tips.png'), Buffer.from(shot.data, 'base64'));

  console.log('===== 写马姿势速查测试 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n错误 (' + errs.length + '): ' + (errs.length ? errs.join(' | ') : '无'));
  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
