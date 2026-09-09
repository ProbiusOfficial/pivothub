/* 代理编排台重构验证：攻击机网段 / 三种链路类型 / 多级中继推导 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9362;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1760,1080',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-proxy-' + Date.now()),
    (process.env.PH_URL || 'http://127.0.0.1:8033/?project=proj-1'),
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
  await evaluate('PivotStore.state.ui.disclaimerOpen = false; PivotStore.goto("proxy"); 1');
  await sleep(1300);

  const out = [];

  /* 1. 攻击机网络 + 链路类型渲染 */
  const ui = await evaluate(`(() => {
    const attack = PivotStore.state.hosts.find(h => h.isLocal);
    return JSON.stringify({
      attackIp: attack.ip, attackSeg: attack.segment,
      linkTypes: Array.from(document.querySelectorAll('.linktype-card b')).map(b => b.textContent.trim()),
      attackBox: document.querySelector('.attack-box') ? document.querySelector('.attack-box').innerText.replace(/\\n+/g, ' | ').slice(0, 120) : '无',
      tableCols: Array.from(document.querySelectorAll('.view-proxy thead th')).map(t => t.textContent.trim())
    });
  })()`);
  out.push('UI 渲染: ' + ui);

  /* 2. 单跳 Socks：跳板选 L1-01 */
  const socks = await evaluate(`(async () => {
    const sel = document.querySelector('.view-proxy .form-stack select');
    sel.value = 'h-l1-01'; sel.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 500));
    const cards = Array.from(document.querySelectorAll('.linktype-card'));
    cards.find(c => c.textContent.includes('Socks')).click();
    await new Promise(r => setTimeout(r, 400));
    return JSON.stringify({
      selected: sel.options[sel.selectedIndex].textContent.trim().slice(0, 30),
      hops: Array.from(document.querySelectorAll('.hop-head')).map(h => h.innerText.replace(/\\n/g, ' ')),
      type: document.querySelector('.linktype-card.is-active b').textContent.trim()
    });
  })()`);
  out.push('单跳 Socks: ' + socks);

  /* 3. 单端口转发 */
  const fwd = await evaluate(`(async () => {
    Array.from(document.querySelectorAll('.linktype-card')).find(c => c.textContent.includes('单端口转发')).click();
    await new Promise(r => setTimeout(r, 500));
    const hops = Array.from(document.querySelectorAll('.hop-head')).map(h => h.innerText.replace(/\\n/g, ' '));
    const code = document.querySelector('.hop:last-child .code-block').textContent;
    return JSON.stringify({ hops, cmd: code });
  })()`);
  out.push('单端口转发: ' + fwd);

  /* 4. 多级中继：跳板选 L2 双网卡机 */
  const relay = await evaluate(`(async () => {
    const sel = document.querySelector('.view-proxy .form-stack select');
    sel.value = 'h-l2-01'; sel.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 700));
    const activeType = document.querySelector('.linktype-card.is-active');
    const callout = document.querySelector('.callout');
    const hops = Array.from(document.querySelectorAll('.hop-head')).map(h => h.innerText.replace(/\\n/g, ' '));
    const cmds = Array.from(document.querySelectorAll('.hop .code-block')).map(c => c.textContent.trim());
    const chainText = document.querySelector('.view-proxy .code-tall') ? document.querySelector('.view-proxy .code-tall').textContent : '';
    /* 切到「链路说明」标签查看完整推导 */
    const chainTab = Array.from(document.querySelectorAll('.view-proxy .tab')).find(t => t.textContent.includes('链路说明'));
    if (chainTab) chainTab.click();
    await new Promise(r => setTimeout(r, 400));
    const chainFull = document.querySelector('.view-proxy .code-tall') ? document.querySelector('.view-proxy .code-tall').textContent : '';
    return JSON.stringify({
      selected: sel.options[sel.selectedIndex].textContent.trim().slice(0, 30),
      autoType: activeType ? activeType.querySelector('b').textContent.trim() : '无',
      targetSegment: chainFull.match(/目标网段 ([0-9./]+)/) ? chainFull.match(/目标网段 ([0-9./]+)/)[1] : '未显示',
      callout: callout ? callout.innerText.replace(/\\n+/g, ' | ').slice(0, 180) : '无',
      hops, cmds,
      hasRelayChain: /内网口|中继/.test(chainFull)
    });
  })()`);
  out.push('多级中继推导: ' + relay);

  /* 5. proxychains / msf 使用新地址 */
  const cfg = await evaluate(`(async () => {
    const btns = Array.from(document.querySelectorAll('.view-head-actions .btn'));
    btns.find(b => b.textContent.includes('proxychains')).click();
    await new Promise(r => setTimeout(r, 400));
    btns.find(b => b.textContent.includes('msf')).click();
    await new Promise(r => setTimeout(r, 500));
    const blocks = Array.from(document.querySelectorAll('.panel-sub .code-block'));
    return JSON.stringify({
      proxychains: blocks[0] ? blocks[0].textContent.split('\\n').slice(0, 7).join(' | ') : '无',
      msf: blocks[1] ? blocks[1].textContent.split('\\n')[0] : '无'
    });
  })()`);
  out.push('联动配置: ' + cfg);

  /* 5b. 出网探测：跳板机下拉框右侧按钮 + 弹窗 */
  const probeInline = await evaluate(`(async () => {
    const row = document.querySelector('.pivot-row');
    const btn = row ? Array.from(row.querySelectorAll('.btn')).find(b => b.textContent.includes('出网探测')) : null;
    const hint = document.querySelector('.pivot-hint');
    /* 打开探测弹窗 */
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 700));
    const modal = document.querySelector('.modal-probe');
    const items = Array.from(document.querySelectorAll('.probe-item')).map(i => i.innerText.replace(/\\n/g, ' '));
    const verdict = document.querySelector('.modal-probe .probe-result .res-line b');
    return JSON.stringify({
      btnNextToSelect: !!btn && row.contains(row.querySelector('select')),
      hintText: hint ? hint.innerText.replace(/\\n/g, ' ').slice(0, 60) : '无',
      modalOpened: !!modal,
      items,
      verdict: verdict ? verdict.textContent.trim() : '未探测',
      hasApplyBtn: !!Array.from(document.querySelectorAll('.modal-probe .btn')).find(b => b.textContent.includes('使用推荐工具')),
      noInlineBox: document.querySelectorAll('.view-proxy .probe-box').length === 0
    });
  })()`);
  out.push('探测按钮与弹窗: ' + probeInline);

  /* 5b-2. 采纳推荐 */
  const apply = await evaluate(`(async () => {
    const before = { tool: null, type: null };
    const btn = Array.from(document.querySelectorAll('.modal-probe .btn')).find(b => b.textContent.includes('使用推荐工具'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 700));
    const activeTool = document.querySelectorAll('.view-proxy select')[1];
    const activeType = document.querySelector('.linktype-card.is-active b');
    return JSON.stringify({
      modalClosed: PivotStore.state.ui.modal === null,
      tool: activeTool ? activeTool.value : '?',
      type: activeType ? activeType.textContent.trim() : '?',
      hopCmd: document.querySelector('.hop-body .code-block') ? document.querySelector('.hop-body .code-block').textContent : ''
    });
  })()`);
  out.push('采纳推荐: ' + apply);

  /* 5c. 攻击机网络设置移入右上角按钮弹窗 */
  const attackModal = await evaluate(`(async () => {
    const btn = Array.from(document.querySelectorAll('.view-head-actions .btn')).find(b => b.textContent.includes('攻击机网络'));
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 600));
    const modal = document.querySelector('.modal');
    const fields = Array.from(document.querySelectorAll('.modal .field > span')).map(s => s.textContent.trim());
    const inPanel = document.querySelectorAll('.proxy-grid .attack-box').length;
    const ok = !!modal && fields.length >= 4;
    /* 改一个 IP 并保存，验证命令跟着变 */
    const inp = document.querySelector('.modal input.mono');
    if (inp) { inp.value = '10.0.17.9'; inp.dispatchEvent(new Event('input')); }
    await new Promise(r => setTimeout(r, 200));
    const saveBtn = Array.from(document.querySelectorAll('.modal-foot .btn')).find(b => b.textContent.includes('保存'));
    if (saveBtn) saveBtn.click();
    await new Promise(r => setTimeout(r, 700));
    const serverCmd = document.querySelector('.view-proxy .code-tall') ? document.querySelector('.view-proxy .code-tall').textContent : '';
    const hopCmd = document.querySelector('.hop-body .code-block') ? document.querySelector('.hop-body .code-block').textContent : '';
    return JSON.stringify({
      opened: !!modal, fields, leftPanelBoxes: inPanel,
      savedAndRefreshed: /10\\.0\\.17\\.9/.test(hopCmd + serverCmd),
      attackIpNow: PivotStore.state.hosts.find(h => h.isLocal).ip
    });
  })()`);
  out.push('攻击机设置弹窗: ' + attackModal);

  /* 5c. 两栏高度是否平衡（防止大量留白） */
  const balance = await evaluate(`(() => {
    const cols = Array.from(document.querySelectorAll('.proxy-grid > .panel'));
    const heights = cols.map(c => Math.round(c.getBoundingClientRect().height));
    const gap = heights.length === 2 ? Math.abs(heights[0] - heights[1]) : -1;
    return JSON.stringify({
      heights,
      diff: gap,
      balanced: gap >= 0 && gap < 260,
      leftScroll: cols[0] ? cols[0].scrollHeight - cols[0].clientHeight : 0
    });
  })()`);
  out.push('两栏平衡: ' + balance);

  /* 6. 健康看板新列 */
  const board = await evaluate(`(() => {
    const rows = Array.from(document.querySelectorAll('.view-proxy tbody tr')).slice(0, 3);
    return JSON.stringify(rows.map(r => Array.from(r.querySelectorAll('td')).map(td => td.textContent.trim()).slice(0, 6)));
  })()`);
  out.push('健康看板: ' + board);

  /* 7. 拓扑边标签与新网段 */
  const topo = await evaluate(`(async () => {
    PivotStore.goto('topology');
    await new Promise(r => setTimeout(r, 1200));
    return JSON.stringify({
      segments: PivotStore.state.segments.map(s => s.segment),
      links: PivotStore.state.links.map(l => l.linkType + ':' + l.localSocks),
      legend: Array.from(document.querySelectorAll('.topo-legend .legend-row')).map(x => x.textContent.trim())
    });
  })()`);
  out.push('拓扑数据: ' + topo);

  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'proxy-redesign.png'), Buffer.from(shot.data, 'base64'));
  await evaluate('PivotStore.goto("proxy"); 1');
  await sleep(1200);
  const shot2 = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, 'proxy-panel.png'), Buffer.from(shot2.data, 'base64'));

  console.log('===== 代理编排台重构测试 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n错误 (' + errs.length + '): ' + (errs.length ? errs.join(' | ') : '无'));
  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
