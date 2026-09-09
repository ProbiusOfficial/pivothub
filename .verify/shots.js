const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const PORT = 9347;
const OUT = path.resolve(__dirname, '..', 'docs', 'screenshots');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const VIEWS = [['dashboard','01-阶段看板'],['topology','02-网络拓扑'],['shell','03-Shell管理'],['proxy','04-代理编排台'],['generator','05-马生成器'],['asset','06-主机清单'],['cred','07-凭据库'],['flag','08-Flag收集墙'],['timeline','09-操作时间线'],['cheat','10-命令速查'],['export','11-复盘导出']];
(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const child = spawn(CHROME, ['--headless=new','--disable-gpu','--hide-scrollbars','--no-first-run','--remote-debugging-port='+PORT,'--window-size=1760,1080','--user-data-dir='+path.join(process.env.TEMP||'.','ph-shot-'+Date.now()),'http://127.0.0.1:8777/'], { stdio: 'ignore' });
  let page=null;
  for (let i=0;i<40&&!page;i++){ try{ const l=await (await fetch('http://127.0.0.1:'+PORT+'/json/list')).json(); page=l.find(t=>t.type==='page'&&t.webSocketDebuggerUrl);}catch(e){} if(!page) await sleep(300);}
  const ws=new WebSocket(page.webSocketDebuggerUrl); await new Promise(r=>ws.onopen=r);
  let id=0; const pending=new Map();
  ws.onmessage=(ev)=>{const m=JSON.parse(ev.data); if(m.id&&pending.has(m.id)){pending.get(m.id)(m.result);pending.delete(m.id);}};
  const send=(method,params)=>new Promise(res=>{const mid=++id;pending.set(mid,res);ws.send(JSON.stringify({id:mid,method,params:params||{}}));});
  const evaluate=async(e)=>{const r=await send('Runtime.evaluate',{expression:e,returnByValue:true,awaitPromise:true}); if(r.exceptionDetails) throw new Error(r.exceptionDetails.text); return r.result.value;};
  await send('Runtime.enable'); await send('Page.enable');
  for (let i=0;i<30;i++){ const c=await evaluate('!!(window.PivotStore && document.querySelector(".main"))'); if(c) break; await sleep(400); }
  await evaluate('PivotStore.state.ui.disclaimerOpen=false; 1');
  await sleep(1200);
  for (const [v, name] of VIEWS) {
    if (v === 'shell') {
      /* Shell 视图：选中会话以展示虚拟终端（固化面板已改为弹窗） */
      await evaluate(`(async () => {
        PivotStore.openTerminalById('s-2');
        await new Promise(r => setTimeout(r, 1200));
        PivotStore.execCommand('id');
        return 1;
      })()`);
      await sleep(900);
      let s = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(path.join(OUT, '03-Shell管理.png'), Buffer.from(s.data, 'base64'));
      /* 固化弹窗：打开 → 检测 → 执行 Python PTY */
      await evaluate(`(async () => {
        PivotStore.state.ui.modal = 'tty-fix';
        await new Promise(r => setTimeout(r, 600));
        const d = Array.from(document.querySelectorAll('.modal-fix .btn')).find(b => b.textContent.includes('交互能力检测'));
        if (d) d.click();
        await new Promise(r => setTimeout(r, 2700));
        const card = Array.from(document.querySelectorAll('.modal-fix .tty-card')).find(c => c.textContent.includes('Python PTY'));
        const btn = card && Array.from(card.querySelectorAll('.btn')).find(b => b.textContent.includes('执行并固化'));
        if (btn) btn.click();
        await new Promise(r => setTimeout(r, 1700));
        return 1;
      })()`);
      await sleep(900);
      s = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(path.join(OUT, '03b-终端固化弹窗.png'), Buffer.from(s.data, 'base64'));
      continue;
    }
    await evaluate(`PivotStore.goto('${v}'); 1`);
    await sleep(1400);
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(OUT, name + '.png'), Buffer.from(shot.data, 'base64'));
  }
  /* 合规声明弹窗单独一张 */
  await evaluate("PivotStore.state.ui.disclaimerOpen = true; 1");
  await sleep(900);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, '00-启动合规声明.png'), Buffer.from(shot.data, 'base64'));
  console.log('截图完成：' + fs.readdirSync(OUT).join(', '));
  ws.close(); child.kill(); process.exit(0);
})().catch(e=>{console.error(e);process.exit(2)});
