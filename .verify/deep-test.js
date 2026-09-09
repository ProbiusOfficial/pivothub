/* 深度交互测试：出网探测 / 自动档部署 / 终端 / 文件管理 / 布局溢出检查 */
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9337;
const OUT = __dirname;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const child = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--remote-debugging-port=' + PORT, '--window-size=1680,1050',
    '--user-data-dir=' + path.join(process.env.TEMP || '.', 'ph-cdp4-' + Date.now()),
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
  let id = 0; const pending = new Map(); const errors = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); return; }
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
      errors.push(m.params.args.map((a) => a.value || a.description || '').join(' '));
    }
    if (m.method === 'Runtime.exceptionThrown') {
      const d = m.params.exceptionDetails;
      errors.push('[exception] ' + (d.exception && d.exception.description ? d.exception.description : d.text));
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

  await send('Runtime.enable');
  await send('Page.enable');
  for (let i = 0; i < 30; i++) {
    const c = await evaluate('!!(window.PivotStore && document.querySelector(".main"))');
    if (c) break;
    await sleep(400);
  }
  await evaluate('PivotStore.state.ui.disclaimerOpen = false; 1');
  await sleep(300);

  const out = [];

  /* 1. 出网探测 */
  await evaluate("PivotStore.goto('proxy'); 1");
  await sleep(600);
  await evaluate("document.querySelector('.view-proxy .btn-primary').click(); 1");
  await sleep(3200);
  out.push('出网探测: ' + JSON.stringify(await evaluate(`(() => {
    const st = PivotStore.state.ui.view;
    const els = document.querySelectorAll('.probe-state');
    return {
      states: Array.from(els).map(e => e.textContent.trim()),
      verdict: document.querySelector('.detect-result') ? document.querySelector('.detect-result').innerText.replace(/\\n+/g, ' | ') : '无结论'
    };
  })()`)));

  /* 2. 自动档部署 */
  const before = await evaluate('PivotStore.state.links.length');
  const deployInfo = await evaluate(`(async () => {
    PivotStore.goto('proxy');
    await new Promise(r => setTimeout(r, 500));
    const btns = Array.from(document.querySelectorAll('.view-proxy .seg-btn'));
    const auto = btns.find(b => b.textContent.trim() === '自动档');
    if (auto) auto.click();
    await new Promise(r => setTimeout(r, 250));
    const btn = Array.from(document.querySelectorAll('.view-proxy .btn')).find(b => /一键部署|生成命令/.test(b.textContent));
    const label = btn ? btn.textContent.trim() : '未找到按钮';
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 2800));
    return '档位按钮=' + (auto ? auto.className : '未找到') + ' / 主按钮=' + label + ' / 提示=' + (PivotStore.state.toasts.map(t => t.msg).join(';') || '无');
  })()`);
  const after = await evaluate('PivotStore.state.links.length');
  out.push('自动档部署: ' + deployInfo + ' → 链路数 ' + before + '→' + after);

  /* 3. 虚拟终端 */
  const term = await evaluate(`(() => {
    PivotStore.openTerminalById('s-1');
    PivotStore.execCommand('id');
    PivotStore.execCommand('ifconfig');
    PivotStore.execCommand('cat /etc/passwd');
    PivotStore.execCommand('sudo -l');
    return PivotStore.termState.lines.map(l => l.kind).join(',');
  })()`);
  out.push('终端命令: ' + term);

  /* 4. 文件管理（点击目录 + 上传） */
  await sleep(400);
  const fileTest = await evaluate(`(async () => {
    const rows = document.querySelectorAll('.file-row');
    if (rows.length) rows[0].click();
    await new Promise(r => setTimeout(r, 200));
    const up = Array.from(document.querySelectorAll('.file-panel .btn')).find(b => b.textContent.includes('上传'));
    if (up) up.click();
    await new Promise(r => setTimeout(r, 2600));
    return '文件行=' + rows.length + ' / 面包屑=' + document.querySelectorAll('.crumb-btn').length;
  })()`);
  out.push('文件管理: ' + fileTest);

  /* 5. proxychains / msf */
  const cfg = await evaluate(`(() => {
    PivotStore.goto('proxy');
    return 1;
  })()`);
  await sleep(600);
  await evaluate(`(() => {
    const b = Array.from(document.querySelectorAll('.view-proxy .btn')).find(x => x.textContent.includes('proxychains'));
    if (b) b.click();
    return 1;
  })()`);
  await sleep(400);
  out.push('proxychains: ' + (await evaluate("(PivotStore.state.ui.view, document.body.innerText.includes('strict_chain') ? '已生成' : '未生成')")));

  /* 6. 扫描导入 */
  await evaluate("PivotStore.goto('asset'); 1");
  await sleep(500);
  const hostBefore = await evaluate('PivotStore.state.hosts.length');
  await evaluate(`(() => {
    PivotStore.state.ui.modal = 'scan-import';
    return 1;
  })()`);
  await sleep(300);
  await evaluate(`(() => {
    const ta = document.querySelector('.modal textarea');
    if (ta) { ta.value = '10.10.40.7\\t22,80\\n10.10.40.8\\t445'; ta.dispatchEvent(new Event('input')); }
    return 1;
  })()`);
  await sleep(200);
  await evaluate(`(() => {
    const b = Array.from(document.querySelectorAll('.modal-foot .btn')).find(x => x.textContent.includes('解析并入库'));
    if (b) b.click();
    return 1;
  })()`);
  await sleep(600);
  out.push('扫描导入: 主机数 ' + hostBefore + ' → ' + (await evaluate('PivotStore.state.hosts.length')));

  /* 7. 凭据推荐 / Flag / 导出三格式 */
  const misc = await evaluate(`(async () => {
    PivotStore.goto('cred');
    await new Promise(r => setTimeout(r, 900));
    const rec = document.querySelectorAll('.rec-card').length;
    PivotStore.goto('flag');
    await new Promise(r => setTimeout(r, 900));
    const cards = document.querySelectorAll('.flag-card').length;
    const ring = document.querySelector('.ring');
    PivotStore.goto('export');
    await new Promise(r => setTimeout(r, 900));
    const md = PivotStore.buildMarkdown({ topo: true, timeline: true, creds: true, flags: true, placeholder: true, chain: true });
    const jsonLen = (() => { const b = Array.from(document.querySelectorAll('.seg-btn')).find(x => x.textContent.includes('JSON')); if (b) b.click(); return 1; })();
    await new Promise(r => setTimeout(r, 500));
    return '凭据推荐=' + rec + ' / Flag卡=' + cards + ' / 环=' + (ring ? '有' : '无') + ' / MD=' + md.length + ' 字 / JSON预览=' + (document.querySelector('.code-block') ? '有' : '无');
  })()`);
  out.push('凭据与 Flag: ' + misc);

  /* 8. 布局溢出检查（所有视图） */
  const views = ['dashboard', 'topology', 'shell', 'generator', 'proxy', 'asset', 'cred', 'flag', 'timeline', 'cheat', 'export'];
  const overflow = [];
  for (const v of views) {
    await evaluate(`PivotStore.goto('${v}'); 1`);
    await sleep(600);
    const r = await evaluate(`(() => {
      const de = document.documentElement;
      const main = document.querySelector('.main');
      const wide = [];
      main.querySelectorAll('*').forEach(el => {
        const rc = el.getBoundingClientRect();
        if (rc.width > 0 && (rc.right > window.innerWidth + 2 || rc.left < -2)) {
          wide.push(el.className.toString().slice(0, 30) + '@' + Math.round(rc.left) + ',' + Math.round(rc.right));
        }
      });
      return {
        docScroll: de.scrollWidth - de.clientWidth,
        bodyOverflow: getComputedStyle(document.body).overflow,
        wideCount: wide.length,
        sample: wide.slice(0, 3).join(' ; ')
      };
    })()`);
    if (r.docScroll > 0 || r.wideCount > 0) overflow.push(v + ' → ' + JSON.stringify(r));
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(OUT, 'shot-' + v + '.png'), Buffer.from(shot.data, 'base64'));
  }
  out.push('布局溢出: ' + (overflow.length ? overflow.join(' || ') : '无横向溢出'));

  /* 9. 拓扑图数据核对 */
  const topo = await evaluate(`(() => {
    PivotStore.goto('topology');
    return new Promise(res => setTimeout(() => {
      const c = document.querySelector('.chart-el canvas');
      res({
        canvas: c ? c.width + 'x' + c.height : '无',
        nodes: PivotStore.state.hosts.length,
        edges: PivotStore.state.links.length,
        legend: document.querySelectorAll('.topo-legend .legend-row').length
      });
    }, 900));
  })()`);
  out.push('拓扑图: ' + JSON.stringify(topo));

  /* 10. 拓扑节点点击 -> 右侧面板 */
  const clickNode = await evaluate(`(async () => {
    PivotStore.selectHost('h-l3-01');
    await new Promise(r => setTimeout(r, 400));
    const panel = document.querySelector('.topo-side .panel');
    const acts = document.querySelectorAll('.topo-side .action-grid .btn').length;
    return '侧栏=' + (panel ? panel.innerText.split('\\n').slice(0, 4).join('/') : '无') + ' / 操作按钮=' + acts;
  })()`);
  out.push('节点操作面板: ' + clickNode);

  console.log('===== 深度交互 =====');
  out.forEach((l) => console.log('· ' + l));
  console.log('\n===== 控制台错误 (' + errors.length + ') =====');
  console.log(errors.length ? errors.join('\n') : '（无）');

  ws.close(); child.kill(); process.exit(0);
})().catch((e) => { console.error('测试失败:', e.message); process.exit(2); });
