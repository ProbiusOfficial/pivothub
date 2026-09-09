/* ============================================================
   全局 store — 状态、派生数据、全部业务动作（全部走真实后端接口）
   后端接入时，仅需把动作体替换为 REST / WebSocket 调用。
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed, watch, ref } = Vue;

  const clone = (v) => JSON.parse(JSON.stringify(v));
  const pad = (n) => String(n).padStart(2, '0');
  const rid = (p) => p + '-' + Math.random().toString(36).slice(2, 7);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  /* 支持 ?project=<id> 直接打开指定项目（多项目并行时省去手点下拉框；无参数时用演示项目） */
  const urlProject = (function () {
    try {
      const m = /[?&]project=([^&#]+)/.exec(String(global.location && global.location.search || ''));
      return m ? decodeURIComponent(m[1]) : '';
    } catch (e) { return ''; }
  })();

  /* ---------- 状态 ---------- */
  const state = reactive({
    projectId: urlProject || 'proj-1',
    project: { id: 'proj-1', name: '', startAt: '', durationSec: 4 * 3600, note: '' },
    projects: [],
    segments: [],
    attack: { ip: '', segment: '', iface: '', note: '' },
    hosts: [],
    shells: [],
    links: [],
    creds: [],
    flags: [],
    timeline: [],
    commands: [],
    injectTips: [],
    ttyFixes: [],
    /* 静态目录（全部来自后端 /state，视图只读这些） */
    probes: [],
    tools: [],
    shellTypes: [],
    encoders: [],
    credKinds: [],
    layers: [],
    stageNames: [],
    scanSample: '',
    /* 资产探测流式扫描（模块级：扫描跑几分钟，切走视图再回来日志不丢） */
    recon: {
      jobId: null, shellId: null, status: '', segment: '',
      lines: [], result: null, startedAt: 0, elapsed: 0, error: '',
    },

    ui: {
      view: 'topology',
      modal: null,
      modalTitle: '',
      modalCode: '',
      modalData: null,
      selectedShellId: null,
      selectedCredId: null,
      disclaimerOpen: false,      /* 完整合规声明（顶栏入口按需打开） */
      disclaimerBrief: true,      /* 启动半透明提醒，1 秒后自动消失 */
      selectedHostId: null,
      selectedLinkId: null,
      focusHostId: null,
    },
    ws: { online: false, retry: 0 },
    timer: { running: true, elapsedSec: 0, durationSec: 4 * 3600 },
    toasts: [],
  });

  /* ---------- 派生数据 ---------- */
  const hostsById = {};
  state.hosts.forEach((h) => (hostsById[h.id] = h));

  const stats = computed(() => {
    const ownedHosts = state.hosts.filter((h) => h.owned && !h.isLocal).length;
    const flags = state.flags.length;
    return {
      hosts: state.hosts.filter((h) => !h.isLocal).length,
      ownedHosts,
      links: state.links.length,
      aliveLinks: state.links.filter((l) => l.status === 'alive').length,
      shells: state.shells.length,
      aliveShells: state.shells.filter((s) => s.alive).length,
      creds: state.creds.length,
      flags,
      flagsTotal: 6,
      segments: state.segments.length,
      maxLayer: Math.max(...state.hosts.map((h) => Number(String(h.layer).replace('L', '')) || 0)),
    };
  });

  /* 编排台可选工具 = 已启用且适配器已接入（MS4 仅 chisel；其余为下线状态） */
  const toolOptions = computed(() => (state.tools || []).filter((t) => t.enabled));

  const clockText = computed(() => {
    const e = state.timer.elapsedSec;
    return pad(Math.floor(e / 3600)) + ':' + pad(Math.floor((e % 3600) / 60)) + ':' + pad(e % 60);
  });

  const remainText = computed(() => {
    const r = Math.max(0, state.timer.durationSec - state.timer.elapsedSec);
    return pad(Math.floor(r / 3600)) + ':' + pad(Math.floor((r % 3600) / 60)) + ':' + pad(r % 60);
  });

  const timerPct = computed(() =>
    Math.min(100, (state.timer.elapsedSec / state.timer.durationSec) * 100)
  );

  /* ---------- 工具函数 ---------- */
  function toast(msg, kind) {
    const id = rid('toast');
    state.toasts.push({ id, msg, kind: kind || 'info' });
    setTimeout(() => {
      const i = state.toasts.findIndex((t) => t.id === id);
      if (i >= 0) state.toasts.splice(i, 1);
    }, 3200);
  }

  /* 后端不可用时的统一失败反馈 */
  function failApi(what) {
    toast(what + '失败：后端不可用或接口报错', 'err');
    termPush('err', escapeHtml(what + '失败：后端不可用'));
  }

  function copy(text) {
    const done = () => toast('已复制到剪贴板', 'ok');
    if (navigator.clipboard && window.isSecureContext !== false) {
      navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
    } else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { toast('复制失败，请手动选择', 'err'); }
    document.body.removeChild(ta);
  }

  function download(filename, content) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    toast('已导出 ' + filename, 'ok');
  }

  /* 极简 Markdown 渲染（加粗 / 行内代码 / 换行） */
  function md(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br />');
  }

  function ipOf(id) { const h = hostsById[id]; return h ? h.ip : '—'; }
  function hostOf(id) { return hostsById[id] || null; }
  function hostnameOf(id) { const h = hostsById[id]; return h ? (h.hostname || '—') : '—'; }
  function shellsOf(hostId) { return state.shells.filter((s) => s.hostId === hostId); }
  function credsOf(hostId) { return state.creds.filter((c) => c.hostId === hostId); }
  function flagsOf(hostId) { return state.flags.filter((f) => f.hostId === hostId); }
  function linksOf(hostId) {
    return state.links.filter((l) => l.fromHostId === hostId || l.toHostId === hostId);
  }
  function privClass(p) {
    if (!p) return 'priv-none';
    const k = String(p).toLowerCase();
    if (k.includes('root') || k.includes('system') || k.includes('administrator')) return 'priv-root';
    if (k.includes('www') || k.includes('apache') || k.includes('nginx') || k.includes('iis') || k.includes('tomcat') || k.includes('user')) return 'priv-www-data';
    return '';
  }
  function statusText(s) { return s === 'alive' ? '存活' : s === 'error' ? '失败' : '已停止'; }
  const KIND_LABEL = { shell: 'Shell', proxy: '代理', host: '资产', cred: '凭据', flag: 'Flag', note: '笔记' };
  const KIND_BADGE = { shell: 'ok', proxy: 'info', host: 'idle', cred: 'warn', flag: 'warn', note: 'idle' };
  function kindLabel(k) { return KIND_LABEL[k] || k; }
  function kindBadge(k) { return KIND_BADGE[k] || 'idle'; }
  function nowTime() {
    const d = new Date();
    return pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function addEvent(kind, title, opts) {
    const o = opts || {};
    const local = Object.assign({ id: rid('t'), time: nowTime(), kind, title }, o);
    state.timeline.unshift(local);
    if (apiMode) {
      /* 入库并由服务端 WS 广播；本地条目改用服务端 id 以便去重 */
      PivotAPI.post('/api/timeline/events', {
        projectId: state.projectId, kind, title, hostId: o.hostId || null,
        detail: o.detail || '', cmd: o.cmd || '', markdown: o.markdown || '',
      }).then((out) => { if (out && out.id) local.id = out.id; }).catch(() => {});
    }
  }

  /* ---------- 定时器 / 心跳 ---------- */
  let tickTimer = null;
  function startTicker() {
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(() => {
      if (state.timer.running) state.timer.elapsedSec += 1;
      /* 存活链路延迟抖动 */
      state.links.forEach((l) => {
        if (l.status !== 'alive') return;
        l.latency = Math.max(8, Math.round(l.latency + (Math.random() - 0.5) * 10));
      });
      /* Shell 心跳抖动 */
      state.shells.forEach((s) => {
        if (!s.alive) return;
        s.latency = Math.max(6, Math.round(s.latency + (Math.random() - 0.5) * 6));
      });
    }, 1000);
  }
  function toggleTimer() {
    state.timer.running = !state.timer.running;
    toast(state.timer.running ? '计时继续' : '计时已暂停', 'info');
  }

  /* ---------- 导航 ---------- */
  const navGroups = [
    {
      title: '作战',
      items: [
        { key: 'dashboard', label: '阶段看板', icon: 'gauge' },
        { key: 'topology', label: '网络拓扑', icon: 'share' },
        { key: 'asset', label: '资产列表', icon: 'server' },
      ],
    },
    {
      title: '执行',
      items: [
        { key: 'shell', label: 'Shell 管理', icon: 'terminal' },
        { key: 'recon', label: '资产探测', icon: 'radar' },
        { key: 'reverse', label: '反弹 Shell', icon: 'share' },
        { key: 'files', label: '文件管理', icon: 'folder' },
        { key: 'generator', label: '马生成器', icon: 'code' },
        { key: 'proxy', label: '代理编排台', icon: 'network' },
        { key: 'db', label: '数据库', icon: 'database' },
      ],
    },
    {
      title: '沉淀',
      items: [
        { key: 'cred', label: '凭据库', icon: 'key' },
        { key: 'flag', label: 'Flag 收集墙', icon: 'flag' },
        { key: 'timeline', label: '操作时间线', icon: 'clock' },
      ],
    },
    {
      title: '辅助',
      items: [
        { key: 'cheat', label: '命令速查', icon: 'book' },
        { key: 'export', label: '复盘导出', icon: 'download' },
      ],
    },
  ];

  function navBadge(key) {
    if (key === 'asset') return state.hosts.filter((h) => !h.isLocal).length || '';
    if (key === 'shell') return state.shells.filter((s) => s.alive).length || '';
    if (key === 'proxy') return state.links.filter((l) => l.status === 'alive').length || '';
    if (key === 'flag') return state.flags.length || '';
    if (key === 'cred') return state.creds.length || '';
    return '';
  }

  function goto(view, patch) {
    state.ui.view = view;
    if (patch) Object.assign(state.ui, patch);
  }

  /* 通用弹窗：任意视图可调用 */
  function openModal(name, opts) {
    const o = opts || {};
    state.ui.modal = name;
    state.ui.modalTitle = o.title || '';
    state.ui.modalCode = o.code || '';
    state.ui.modalData = o.data || null;
  }
  function closeModal() {
    state.ui.modal = null;
    state.ui.modalTitle = '';
    state.ui.modalCode = '';
    state.ui.modalData = null;
  }

  /* ---------- 拓扑选中 ---------- */
  const selected = reactive({ host: null, link: null });
  function selectHost(id) {
    state.ui.selectedHostId = id;
    state.ui.selectedLinkId = null;
    selected.host = hostsById[id] || null;
    selected.link = null;
  }
  function selectLink(id) {
    state.ui.selectedLinkId = id;
    state.ui.selectedHostId = null;
    selected.link = state.links.find((l) => l.id === id) || null;
    selected.host = null;
  }
  function clearSelection() {
    state.ui.selectedHostId = null;
    state.ui.selectedLinkId = null;
    selected.host = null;
    selected.link = null;
  }

  /* ---------- Shell 动作 ---------- */
  function openTerminalById(id) {
    const prev = state.shells.find((x) => x.id === state.ui.selectedShellId);
    if (prev && prev.id !== id && prev.kind === 'reverse') setRaw(prev.id, false);
    state.ui.selectedShellId = id;
    state.ui.view = 'shell';
    termState.inited = false;
    termState.lines = [];
    termState.rawLines = [];
    initTerm();
  }
  function openTerminal(host) {
    const s = state.shells.find((x) => x.hostId === host.id && x.alive);
    if (s) return openTerminalById(s.id);
    toast('该主机暂无存活 Shell，请先获取会话', 'err');
  }
  function heartbeatAll() {
    state.shells.forEach((s) => {
      if (s.alive) s.lastBeat = '刚刚';
    });
    toast('已对 ' + state.shells.filter((s) => s.alive).length + ' 个会话发起心跳', 'ok');
    if (apiMode) PivotAPI.post('/api/shells/heartbeat').catch(() => {});
  }
  function testShell(s) {
    if (apiMode) {
      PivotAPI.post('/api/shells/' + s.id + '/test')
        .then((out) => {
          Object.assign(s, out);
          if (out.alive) toast('连通性正常 · 延迟 ' + out.latency + 'ms', 'ok');
          else toast('连通性测试失败，已标记断线', 'err');
        })
        .catch(() => toast('连通性测试失败（后端不可用）', 'err'));
      return;
    }

  }
  function removeShell(s) {
    const i = state.shells.indexOf(s);
    if (i >= 0) state.shells.splice(i, 1);
    toast('已删除 Shell 会话', 'info');
    if (apiMode) PivotAPI.del('/api/shells/' + s.id).catch(() => {});
  }
  function addShell(form) {
    /* 服务端生成 id；乐观插入保证视图同步拿到会话对象 */
    const host = hostsById[form.hostId];
    const optimistic = {
      id: rid('s'), hostId: form.hostId, type: form.type, url: form.url,
      pass: form.pass, encoder: form.encoder, alive: true,
      latency: 18 + Math.round(Math.random() * 50), lastBeat: '刚刚',
      hostname: host ? host.hostname : '', privilege: host ? host.privilege : '',
      stable: false,
    };
    if (apiMode) {
      PivotAPI.post('/api/shells', {
        projectId: state.projectId, hostId: form.hostId, type: form.type,
        url: form.url, pass: form.pass, encoder: form.encoder, autoCollect: !!form.autoCollect,
      }).then((item) => {
        const i = state.shells.indexOf(optimistic);
        if (i >= 0) state.shells.splice(i, 1, item);
      }).catch(() => { /* 后端失联：保留乐观条目，稍后刷新会以服务端为准 */ });
      if (host) host.owned = true;
      return optimistic;
    }
    state.shells.push(optimistic);
    if (host) host.owned = true;
    addEvent('shell', '登记并连接 Shell：' + optimistic.url, { hostId: form.hostId, detail: '类型 ' + form.type + ' · 编码器 ' + form.encoder });
    if (form.autoCollect) {
      toast('已自动回传基础信息并入库资产表', 'ok');
      addEvent('host', '自动回传基础信息并入库', {
        hostId: form.hostId,
        detail: 'whoami=' + (host ? host.privilege || 'unknown' : 'unknown') + ' / uname=' + (host ? host.os : '') + ' / ip=' + (host ? host.ip : ''),
      });
    }
    toast('Shell 已保存并连接成功', 'ok');
    return optimistic;
  }

  /* ---------- 虚拟终端 ---------- */
  const termState = reactive({
    lines: [], input: '', history: [], histIdx: -1, inited: false,
    /* 终端形态：dumb = WebShell 原始伪终端；semi = 半交互；full = 已固化为交互 TTY */
    mode: 'dumb',
    modeLabel: '未固化（WebShell 伪终端）',
    detected: false,
    detecting: false,
    caps: { tty: false, term: '', shell: '', python: false, script: false, socat: false, nc: false, os: 'linux' },
    probeLines: [],
    /* 原始交互模式（反弹通道）：直接渲染目标 PTY 输出，真实提示符原样显示 */
    rawMode: false,
    rawLines: [],
    rawPending: '',   /* 跨帧的孤立 \r（\r\n 被切成两个 chunk 时用） */
    shellId: null,    /* 当前终端对应的会话（切换会话时必须重新初始化） */
  });
  /* 每个 Shell 已应用过的固化技法（shellId → [{id,name,time}]） */
  const ttyApplied = reactive({});
  /* 交互能力检测结论缓存（shellId → 结论）：持久化到 localStorage，
     刷新页面 / 切换会话都不再重跑探测；只有显式重测或结论失效才重新执行。 */
  const TTY_CACHE_KEY = 'pivothub.ttyCaps.v1';
  const TTY_CACHE_TTL = 7 * 24 * 3600 * 1000;
  let ttyCache = (function loadTtyCache() {
    try {
      const raw = global.localStorage && global.localStorage.getItem(TTY_CACHE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch (e) { return {}; }
  })();
  function persistTtyCache() {
    try { global.localStorage && global.localStorage.setItem(TTY_CACHE_KEY, JSON.stringify(ttyCache)); }
    catch (e) { /* 隐私模式 / 配额满：降级为内存缓存 */ }
  }
  function clearTtyCache(shellId) {
    if (shellId && ttyCache[shellId]) { delete ttyCache[shellId]; persistTtyCache(); }
  }
  const HINT_CMDS = ['id', 'whoami', 'uname -a', 'ifconfig', 'ls -la /var/www/html', 'cat /etc/passwd', 'ss -tunlp', 'ps aux | head', 'curl -s ifconfig.me', 'clear'];

  function activeShell() { return state.shells.find((s) => s.id === state.ui.selectedShellId) || null; }

  /* ANSI 控制序列：CSI / OSC / 字符集指定（ESC(B，mysql 等程序会输出）/ 单字符转义 */
  const ANSI_RE = new RegExp(
    '\\x1b\\][^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)' +
    '|\\x1b\\[[0-9;?<=>!]*[ -/]*[@-~]' +
    '|\\x1b[()][0-2A-Za-z]' +
    '|\\x1b[=>78MDEH]', 'g');

  /* 原始输出追加：简易终端行缓冲（\r\n 换行、单独 \r 行内回退、去 ANSI） */
  function rawAppend(text) {
    let s = String(text == null ? '' : text);
    if (termState.rawPending) { s = termState.rawPending + s; termState.rawPending = ''; }
    if (s.endsWith('\r')) { termState.rawPending = '\r'; s = s.slice(0, -1); }
    s = s.replace(/\r\n/g, '\n');
    if (!s) return;
    const lines = termState.rawLines;
    const parts = s.split('\n');
    for (let i = 0; i < parts.length; i++) {
      let seg = parts[i];
      if (seg.indexOf('\r') >= 0) seg = seg.slice(seg.lastIndexOf('\r') + 1);
      seg = seg.replace(ANSI_RE, '');
      if (i === 0 && lines.length) lines[lines.length - 1] += seg;
      else lines.push(seg);
    }
    if (lines.length > 2000) lines.splice(0, lines.length - 2000);
  }

  function stripTags(html) {
    return String(html == null ? '' : html)
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
  }

  function termPush(kind, html) {
    if (termState.rawMode) {  /* 原始模式：系统提示也并入同一条时间线 */
      rawAppend(stripTags(html) + '\n');
      return;
    }
    termState.lines.push({ kind, html });
  }

  /* 目标平台判定：Windows 主机 / ASPX-ASP 马 → windows，否则 linux */
  function shellPlatform(s) {
    if (s && s.platform) return s.platform;
    const host = hostsById[s.hostId] || {};
    if (/windows/i.test(host.os || '')) return 'windows';
    if (/asp/i.test(s.type || '')) return 'windows';
    return 'linux';
  }

  function resetTermMode() {
    const s = activeShell();
    termState.mode = 'dumb';
    termState.modeLabel = '未固化（WebShell 伪终端）';
    termState.detected = false;
    termState.detecting = false;
    termState.caps = { tty: false, term: '', shell: '', python: false, script: false, socat: false, nc: false, os: s ? shellPlatform(s) : 'linux' };
    termState.probeLines = [];
  }

  function initTerm() {
    const s = activeShell();
    if (!s) return;
    /* 同一会话已初始化过才跳过；点表格行切换会话时也必须重新初始化，
       否则新选中的反弹会话不会开启原始推送，终端一片空白。 */
    if (termState.inited && termState.shellId === s.id) return;
    termState.shellId = s.id;
    termState.inited = true;
    termState.lines = [];
    termState.rawLines = [];
    resetTermMode();
    /* 反弹通道 → 原始交互模式：真实提示符、Ctrl+C、交互式程序全部可用 */
    termState.rawMode = s.kind === 'reverse';
    if (termState.rawMode) {
      setRaw(s.id, true);
      rawAppend('[PivotHub] 原始交互模式 · 直接连接目标 PTY（真实提示符 / Ctrl+C / 交互程序可用）\n');
    }
    /* 该会话此前已固化过 → 恢复「已固化 TTY」形态 */
    if (s.stable) {
      termState.mode = 'full';
      termState.modeLabel = '已固化（交互 TTY）';
      termState.caps.tty = true;
    }
    /* 命中检测缓存 → 直接套用结论，不再重复跑一遍探测 */
    const cachedTty = applyCachedDetect(s);
    termPush('dim', 'PivotHub 虚拟终端 v1.0 — 会话 ' + s.id + ' · ' + s.type);
    termPush('dim', '目标 ' + ipOf(s.hostId) + ' · 编码器 ' + s.encoder + ' · 输入 help 查看可用命令');
    if (s.stable) {
      termPush('ok', '✓ 该会话此前已固化为交互 TTY，job control / su / vim 可正常使用');
    } else if (s.kind === 'reverse') {
      termPush('ok', '✓ 反弹会话（原始通道）已建立：命令与回显直连，无需逐请求等待');
      if (!termState.detected) termPush('dim', '→ 建议执行「交互能力检测」确认是否已具备 PTY / job control');
    } else {
      termPush('warn', '⚠ 当前为 WebShell 伪终端：无 TTY、无 job control，su / ssh / vim / top 等交互程序无法正常使用');
      termPush('dim', '→ 建议先执行「交互能力检测」，再选择固化技法升级为稳定交互终端');
    }
    if (cachedTty) termPush('dim', '已套用上次交互能力检测结果（需要重测：点「终端固化」重新检测）');
    termPush('out', '');
    /* 触发一次回车，让目标 shell 打印当前提示符（否则终端首屏是空的） */
    if (termState.rawMode) shellInput(s.id, { key: 'enter' }).catch(() => {});
  }
  function clearTerm() {
    termState.lines = [];
    termState.rawLines = [];
    if (termState.rawMode) rawAppend('[PivotHub] 终端已清屏\n');
    else termPush('dim', '终端已清屏');
  }
  function killTerm() {
    const s = activeShell();
    if (s && s.kind === 'reverse') setRaw(s.id, false);
    state.ui.selectedShellId = null;
    toast('终端已关闭', 'info');
  }

  /* ---------- 交互能力检测（服务端真实执行；失败按 reason 归因） ---------- */
  function detectTty() {
    const s = activeShell();
    if (!s) { toast('请先选择一个 Shell 会话', 'err'); return; }
    if (termState.detecting) return;
    if (apiMode) {
      termState.detecting = true;
      PivotAPI.post('/api/shells/' + s.id + '/tty/detect')
        .then((out) => {
          if (out && out.pivothubFallback) {
            /* 回退标记既用于「能力未实现」，也用于「会话不可达」——按 reason 归因，别一律说后端不可用 */
            termState.detecting = false;
            termState.detected = true;
            clearTtyCache(s.id);  /* 检测没跑成（命令受阻/通道断）：不留记录，下次自动重试 */
            const why = out.reason || '后端不可用';
            termPush('err', escapeHtml('交互能力检测未完成：' + why));
            if (/通道|断开|回连|不可达|关闭/.test(why)) {
              termPush('warn', escapeHtml('→ 会话已断开：HTTP 马请点「测试」重新探活；反弹会话需重新开监听并让靶机回连'));
            }
            return;
          }
          applyDetectResult(s, out);
        })
        .catch(() => {
          termState.detecting = false;
          clearTtyCache(s.id);
          failApi('交互能力检测');
        });
      return;
    }
    toast('后端不可用：请先启动 python -m pivothub', 'err');
  }
  /* 应用服务端检测结论（M1-8 契约：caps/mode/probeLines/summary；事件由服务端入库） */
  function applyDetectResult(s, out) {
    termState.detecting = false;
    termState.detected = true;
    if (!out) return;
    termState.caps = Object.assign(termState.caps, out.caps || {});
    (out.probeLines || []).forEach((l) => termPush(l.kind || 'out', escapeHtml(l.text || '')));
    if (out.mode) {
      termState.mode = out.mode;
      termState.modeLabel = out.modeLabel
        || (out.mode === 'full' ? '已固化（交互 TTY）'
          : out.mode === 'semi' ? '半交互（无 TTY / 无 job control）' : '未固化（WebShell 伪终端）');
    }
    if (out.mode === 'full') s.stable = true;
    if (out.summary) termPush(out.mode === 'full' ? 'ok' : 'warn', escapeHtml(out.summary));
    /* 缓存结论：切走 / 刷新页面都不重复探测（7 天过期；强制重测走「终端固化」） */
    ttyCache[s.id] = {
      caps: clone(out.caps || {}),
      mode: out.mode || termState.mode,
      modeLabel: termState.modeLabel,
      summary: out.summary || '',
      at: Date.now(),
    };
    /* 顺手清理过期记录，避免 localStorage 无限增长 */
    const now = Date.now();
    Object.keys(ttyCache).forEach((k) => {
      if (now - (ttyCache[k].at || 0) > TTY_CACHE_TTL) delete ttyCache[k];
    });
    persistTtyCache();
  }

  /* 命中缓存时直接套用结论（不重跑探测、不打印明细），返回是否命中 */
  function applyCachedDetect(s) {
    const c = ttyCache[s.id];
    if (!c) return false;
    if (Date.now() - c.at > TTY_CACHE_TTL) { clearTtyCache(s.id); return false; }
    termState.detected = true;
    termState.caps = Object.assign(termState.caps, c.caps || {});
    if (c.mode) {
      termState.mode = c.mode;
      termState.modeLabel = c.modeLabel || termState.modeLabel;
    }
    if (c.mode === 'full') s.stable = true;
    return true;
  }

  function finishDetect(s, isWin) {
    termState.detecting = false;
    termState.detected = true;
    const joined = termState.probeLines.join('\n');
    /* 已经固化过的会话：检测只做能力确认，不得把状态降级回半交互 */
    const alreadyFull = termState.mode === 'full' || !!s.stable;
    if (isWin) {
      termState.caps = { tty: alreadyFull, term: 'windows-console', shell: 'cmd.exe', python: false, script: false, socat: false, nc: false, os: 'windows', powershell: /powershell/i.test(joined) };
      if (!alreadyFull) {
        termState.mode = 'dumb';
        termState.modeLabel = '未固化（WebShell 伪终端）';
      }
      termPush('dim', '');
      termPush('ok', '检测结论：Windows 主机 · ' + (alreadyFull ? '已获得交互会话' : '无真实 TTY') + ' · 已确认 powershell 可用');
      if (!alreadyFull) termPush('dim', '推荐技法：PowerShell 交互会话 / ConPTY 伪终端（Win10 1809+）');
    } else {
      termState.caps = {
        tty: alreadyFull, term: alreadyFull ? 'xterm-256color' : 'dumb', shell: '/bin/sh',
        python: /python3/.test(joined), script: /script/.test(joined),
        socat: /socat/.test(joined), nc: /\/usr\/bin\/nc/.test(joined), os: 'linux',
      };
      if (!alreadyFull) {
        termState.mode = 'semi';
        termState.modeLabel = '半交互（无 TTY / 无 job control）';
      }
      termPush('dim', '');
      if (alreadyFull) {
        termPush('ok', '检测结论：已处于交互 TTY 形态（TERM=xterm-256color · job control 可用）');
      } else {
        termPush('warn', '检测结论：无 TTY（tty = not a tty）· TERM=dumb · 无 job control');
        termPush('ok', '可用工具：' + [termState.caps.python && 'python3', termState.caps.script && 'script', termState.caps.socat && 'socat', termState.caps.nc && 'nc'].filter(Boolean).join(' / ') || '（无）');
        termPush('dim', '推荐技法：Python PTY（最通用）→ 再用 Ctrl+Z + stty raw 完成收尾');
      }
    }
    toast('交互能力检测完成', 'ok');
    addEvent('shell', '终端交互能力检测：' + termState.modeLabel, {
      hostId: s.hostId,
      detail: isWin ? 'cmd.exe + powershell 可用，无真实 TTY' : 'tty=not a tty / TERM=dumb / 可用 python3、script',
    });
  }

  /* ---------- 固化技法执行 ---------- */
  function ttyFixList(shell) {
    const s = shell || activeShell();
    const plat = s ? shellPlatform(s) : 'linux';
    const lib = state.ttyFixes || [];
    return lib.filter((f) => f.platform === plat);
  }
  function ttyAppliedList(shellId) {
    const id = shellId || (activeShell() ? activeShell().id : null);
    return id ? (ttyApplied[id] || []) : [];
  }
  function isTtyApplied(recipeId, shellId) {
    return ttyAppliedList(shellId).some((x) => x.id === recipeId);
  }
  function renderTtyCmd(cmd) {
    const s = activeShell();
    const host = s ? hostsById[s.hostId] || {} : {};
    const cred = state.creds.find((c) => c.hostId === (host.id || '')) || {};
    return String(cmd)
      .replace(/\$LHOST/g, '203.0.113.7')
      .replace(/\$LPORT/g, '4444')
      .replace(/\$IP/g, host.ip || '10.10.20.5')
      .replace(/\$TARGET/g, host.ip || '10.10.30.8')
      .replace(/\$CRED/g, (cred.username || 'svc_web') + ' 凭据');
  }

  /* 固化技法执行：MS2 起服务端真实执行并依据回显判定 PTY */
  function applyTtyFix(recipe) {
    const s = activeShell();
    if (!s) { toast('请先选择一个 Shell 会话', 'err'); return; }
    if (apiMode) {
      PivotAPI.post('/api/shells/' + s.id + '/tty/upgrade', { fixId: recipe.id })
        .then((out) => {
          if (out && out.pivothubFallback) { failApi('该能力'); return; }
          const cmd = renderTtyCmd(recipe.cmd);
          cmd.split(/\r?\n/).filter((l) => l.trim()).forEach((l) => {
            if (l.trim().startsWith('#')) termPush('dim', escapeHtml(l));
            else termPush('in', escapeHtml(l));
          });
          if (out && out.output) out.output.split(/\r?\n/).forEach((l) => termPush('out', escapeHtml(l)));
          if (out && out.hasPty) {
            termState.mode = 'full';
            termState.modeLabel = '已固化（交互 TTY）';
            termState.caps.tty = true;
            s.stable = true;
            if (out.summary) termPush('out', escapeHtml(out.summary));
            /* 固化事件由服务端入库并经 WS 推送（含 PTY/TERM/窗口明细） */
            toast('终端已固化为交互 TTY', 'ok');
            clearTtyCache(s.id);  /* 形态变了：让下次打开重新探测（或由检测按钮刷新） */
          } else {
            termPush('err', escapeHtml((out && out.reason) || recipe.name + ' 未能建立 PTY'));
            toast('技法执行失败', 'err');
            clearTtyCache(s.id);
          }
        })
        .catch(() => failApi('终端固化'));
      return;
    }

  }

  /* 一键收尾：Ctrl+Z → stty raw → reset（PTY 已建立时使用） */
  function runTtyFinish() {
    const s = activeShell();
    if (!s) return;
    if (apiMode) {
      PivotAPI.post('/api/shells/' + s.id + '/tty/finish', { rows: 40, cols: 120 })
        .then((out) => {
          if (out && out.pivothubFallback) { failApi('该能力'); return; }
          termPush('dim', '# 收尾三步：挂起 → raw 模式 → reset');
          termPush('in', 'stty sane; stty rows ' + (out.rows || 40) + ' cols ' + (out.cols || 120));
          termPush('ok', (out && out.summary) || 'raw 模式已开启，终端状态已重置');
          if (out && out.ok) {
            termState.mode = 'full';
            termState.modeLabel = '已固化（交互 TTY）';
            termState.caps.tty = true;
            s.stable = true;
            clearTtyCache(s.id);
            toast('收尾完成：窗口尺寸已同步 ' + out.rows + 'x' + out.cols, 'ok');
          } else {
            toast('收尾命令已执行，但未回读到 stty size', 'warn');
          }
          /* 收尾事件由服务端入库 */
        })
        .catch(() => failApi('固化收尾'));
      return;
    }

  }

  function sendToTerminalText(text, asComment) {
    String(text).split(/\r?\n/).forEach((l) => {
      if (!l.trim()) return;
      if (asComment && l.trim().startsWith('#')) termPush('dim', escapeHtml(l));
      else if (l.trim().startsWith('#')) termPush('dim', escapeHtml(l));
      else execCommand(l.trim());
    });
  }

  /* 命令执行：反弹通道走原始输入（真实 PTY）；HTTP 马走哨兵 exec；失败显式落到终端 */
  function execCommand(cmd) {
    const s = activeShell();
    if (!s) return;
    termState.history.push(cmd);
    termState.histIdx = termState.history.length;
    const c = cmd.trim();
    if (apiMode && s.kind === 'reverse') {
      /* 原始模式：命令由目标 PTY 自己回显，不做本地回显，也不等哨兵 */
      shellInput(s.id, c ? { data: c + '\r' } : { key: 'enter' })
        .then((out) => {
          if (out && out.ok === false) {
            termPush('err', escapeHtml('输入失败：' + (out.error || '未知原因')));
          }
        });
      return;
    }
    termPush('in', escapeHtml(cmd));
    if (!c) return;
    if (apiMode) {
      PivotAPI.post('/api/shells/' + s.id + '/exec', { cmd: c })
        .then((out) => {
          if (out && out.pivothubFallback) { failApi('该能力'); return; }
          if (!out || out.ok === false) {
            const why = (out && (out.error || out.reason)) || '未知原因';
            termPush('err', escapeHtml('执行失败：' + why));
            if (out && out.stage === 'session') {
              termPush('warn', escapeHtml('→ 该会话的通道已断开：反弹 Shell 需让靶机重新回连；HTTP 马请点「测试」重新探活'));
            }
            return;
          }
          String(out.output || '').split(/\r?\n/).forEach((l) => termPush('out', escapeHtml(l)));
          if (out.timedOut) termPush('warn', escapeHtml('命令超时（结果可能不完整）'));
        })
        .catch((e) => {
          termPush('err', escapeHtml('请求失败：' + String(e && e.message || e)));
          termPush('warn', escapeHtml('→ 请确认 python -m pivothub 正在运行'));
        });
      return;
    }

  }

  /* ---------- 反弹通道原始交互（POST /api/shells/{id}/input | /raw） ---------- */
  function shellInput(shellId, payload) {
    if (!hasApi || !shellId) return Promise.resolve({ ok: false, error: '后端不可用' });
    return PivotAPI.post('/api/shells/' + shellId + '/input', payload || {})
      .catch((e) => ({ ok: false, error: String((e && e.message) || e) }));
  }
  /* 开关原始输出推送（面板终端打开时注册，切走/关闭时注销） */
  function setRaw(shellId, on) {
    if (!hasApi || !shellId) return Promise.resolve(null);
    return PivotAPI.post('/api/shells/' + shellId + '/raw', { on: !!on }).catch(() => null);
  }

  /* 一键获取 PTY：无 PTY 的反弹会话里 \x03 不会变成 SIGINT（Ctrl+C 无效），
     用 python3/script 在通道内套一层 PTY 后才能正常中断命令、跑 vim/su 等。 */
  function upgradePty() {
    const s = activeShell();
    if (!s || s.kind !== 'reverse') { toast('仅反弹会话支持获取 PTY', 'err'); return; }
    if (termState.caps.tty || s.stable) { toast('该会话已经是 PTY', 'info'); return; }
    const caps = termState.caps || {};
    let cmd = '';
    if (caps.python) cmd = "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'";
    else if (caps.script) cmd = 'script -qc /bin/bash /dev/null';
    if (!cmd) {
      toast('未检测到可用的 PTY 工具（python3 / script）——可到「终端固化」看其他技法', 'err');
      return;
    }
    shellInput(s.id, { data: cmd + '\r' }).then((out) => {
      if (out && out.ok === false) { toast('发送失败：' + (out.error || '未知原因'), 'err'); return; }
      toast('已发送 PTY 升级命令：' + cmd, 'info');
      /* PTY 起来后设置 TERM 与窗口尺寸：否则 readline 认为终端只有 1 列宽，
         长命令会横向滚动、回显被 `<` 截断（提示符被吃掉半截的观感来源）。 */
      setTimeout(() => {
        shellInput(s.id, {
          data: 'export TERM=xterm-256color; stty rows 40 cols 200 2>/dev/null\r',
        }).catch(() => {});
      }, 800);
      setTimeout(() => detectTty(), 2800);
    });
  }

  /* Ctrl+C：PTY 会话直接发 \x03；无 PTY 时会话被前台命令占住、\x03 也不会触发 SIGINT，
     改从同主机上的另一个存活会话按命令行结束该进程（否则只能干等命令自己结束）。 */
  function interruptCommand() {
    const s = activeShell();
    if (!s) return;
    if (s.kind !== 'reverse') { shellInput(s.id, { key: 'ctrl-c' }); return; }
    if (termState.caps.tty || s.stable) { shellInput(s.id, { key: 'ctrl-c' }); return; }
    const last = termState.history.filter((x) => String(x || '').trim()).slice(-1)[0] || '';
    const other = state.shells.find((x) => x.id !== s.id && x.hostId === s.hostId
      && x.alive && x.kind !== 'reverse')
      || state.shells.find((x) => x.id !== s.id && x.hostId === s.hostId && x.alive);
    if (!last || !other) {
      toast('该会话没有 PTY，Ctrl+C 无法中断：请点「获取 PTY」升级，或从同主机其他会话结束进程', 'warn');
      return;
    }
    /* 用 [p]ing 形式避免 pkill 匹配到自己的命令行 */
    const pat = '[p]' + String(last).trim().slice(1).replace(/'/g, "'\\''");
    execOn(other.id, "pkill -INT -f '" + pat + "' 2>/dev/null; echo PIVOTHUB_INT").then((out) => {
      if (out && out.ok) toast('已从 ' + ipOf(other.hostId) + ' 结束该命令（无 PTY，Ctrl+C 不生效）', 'info');
      else toast('中断失败：请手动在另一会话里结束该进程', 'err');
    });
  }

  
  function escapeHtml(t) {
    return String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /* ---------- 文件管理（Shell 管理侧栏与「文件管理」视图共用） ---------- */

  /* 上传通道：pull = 攻击机 HTTP 暂存 + 目标机 curl/wget 拉取；chunk = 原分片直传；
     auto = 先拉取，失败自动回退分片。选择持久化到 localStorage。 */
  const UPLOAD_MODE_KEY = 'pivothub.uploadMode';
  const UPLOAD_MODES = ['pull', 'chunk', 'auto'];
  const uploadMode = ref((function () {
    try {
      const v = global.localStorage && global.localStorage.getItem(UPLOAD_MODE_KEY);
      return UPLOAD_MODES.indexOf(v) >= 0 ? v : 'pull';
    } catch (e) { return 'pull'; }
  })());
  function setUploadMode(m) {
    if (UPLOAD_MODES.indexOf(m) < 0) return;
    uploadMode.value = m;
    try { global.localStorage && global.localStorage.setItem(UPLOAD_MODE_KEY, m); } catch (e) { /* 忽略 */ }
  }
  function uploadModeText(m) {
    m = m || uploadMode.value;
    return m === 'chunk' ? '分片直传' : (m === 'auto' ? '自动（拉取优先）' : 'HTTP 拉取');
  }

  function fileStateFor(shellId) {
    const s = state.shells.find((x) => x.id === shellId);
    return {
      shellId,
      cwd: '/',
      crumbs: ['/'],
      entries: [],
      loading: false,
      error: '',
      uploading: null,
      progress: 0,
      phase: '',
      tools: null,
      toolsLoading: false,
      toolsError: '',
      target: s ? s.hostId : null,
    };
  }
  function cwdPath(crumbs) { return crumbs.join('/').replace('//', '/') || '/'; }

  /* 服务端经会话层真实列目录；失败显式报错，不静默显示成空目录 */
  function refreshFileEntries(fs) {
    if (!apiMode || !fs.shellId) return;
    fs.loading = true;
    fs.error = '';
    PivotAPI.get('/api/shells/' + fs.shellId + '/files?path=' + encodeURIComponent(cwdPath(fs.crumbs)))
      .then((out) => {
        fs.loading = false;
        if (out && out.pivothubFallback) {
          fs.entries = [];
          fs.error = out.reason || '列目录失败';
          toast('列目录失败：' + fs.error, 'err');
          return;
        }
        fs.entries = (out && out.entries) || [];
        if (out && out.cwd) fs.cwd = out.cwd;
      })
      .catch((e) => {
        fs.loading = false;
        fs.entries = [];
        fs.error = String((e && e.message) || e);
        toast('列目录失败：' + fs.error, 'err');
      });
  }

  /* 导航：进入子目录 / 跳到任意路径 / 上一级 / 点面包屑 */
  function cdInto(fs, name) {
    fs.crumbs = fs.crumbs.concat([name]);
    fs.cwd = cwdPath(fs.crumbs);
    refreshFileEntries(fs);
  }
  function cdTo(fs, path) {
    const p = String(path || '/').trim() || '/';
    fs.crumbs = p === '/' ? ['/']
      : ['/'].concat(p.replace(/^\/+/, '').replace(/\/+$/, '').split('/').filter(Boolean));
    fs.cwd = cwdPath(fs.crumbs);
    refreshFileEntries(fs);
  }
  function cdUp(fs) {
    if (fs.crumbs.length > 1) fs.crumbs = fs.crumbs.slice(0, -1);
    fs.cwd = cwdPath(fs.crumbs);
    refreshFileEntries(fs);
  }
  function cdIndex(fs, i) {
    fs.crumbs = fs.crumbs.slice(0, i + 1);
    fs.cwd = cwdPath(fs.crumbs);
    refreshFileEntries(fs);
  }

  /* 文件编辑弹窗：全局共享状态（视图切换 / 弹窗位置都不影响正在编辑的内容） */
  const fileEdit = reactive({
    open: false, name: '', path: '', shellId: '', content: '',
    loading: false, saving: false, fs: null,
  });
  function _fullPath(fs, name) {
    const base = cwdPath(fs.crumbs);
    return (base === '/' ? '' : base) + '/' + name;
  }
  function readFile(entry, fs) {
    if (!apiMode || !fs.shellId) return false;
    fileEdit.open = true;
    fileEdit.loading = true;
    fileEdit.saving = false;
    fileEdit.name = entry.name;
    fileEdit.path = _fullPath(fs, entry.name);
    fileEdit.shellId = fs.shellId;
    fileEdit.fs = fs;
    fileEdit.content = '';
    PivotAPI.get('/api/shells/' + fs.shellId + '/files/content?path=' + encodeURIComponent(fileEdit.path))
      .then((out) => {
        fileEdit.loading = false;
        if (out && out.pivothubFallback) {
          fileEdit.content = '（读取失败：' + (out.reason || '后端未实现') + '）';
          return;
        }
        fileEdit.content = (out && out.content) || '';
      })
      .catch((e) => {
        fileEdit.loading = false;
        fileEdit.content = '（读取失败：' + String((e && e.message) || e) + '）';
      });
    return true;
  }
  function closeFileEdit() { fileEdit.open = false; }
  function saveFileEdit() {
    if (!fileEdit.open || !fileEdit.shellId) return;
    fileEdit.saving = true;
    PivotAPI.post('/api/shells/' + fileEdit.shellId + '/files/write',
      { path: fileEdit.path, content: fileEdit.content })
      .then((out) => {
        fileEdit.saving = false;
        if (out && out.pivothubFallback) { toast('写入失败：' + (out.reason || ''), 'err'); return; }
        toast('已写入 ' + fileEdit.name, 'ok');
        fileEdit.open = false;
        if (fileEdit.fs) refreshFileEntries(fileEdit.fs); /* 刷新大小 / 时间 */
      })
      .catch((e) => {
        fileEdit.saving = false;
        toast('写入失败：' + String((e && e.message) || e), 'err');
      });
  }

  /* 下载：读回文本内容后由浏览器落盘 */
  function downloadFile(entry, fs) {
    if (!apiMode || !fs.shellId) return;
    const path = _fullPath(fs, entry.name);
    PivotAPI.get('/api/shells/' + fs.shellId + '/files/content?path=' + encodeURIComponent(path))
      .then((out) => {
        if (out && out.pivothubFallback) { toast('下载失败：' + (out.reason || ''), 'err'); return; }
        download(entry.name, (out && out.content) || '');
      })
      .catch((e) => toast('下载失败：' + String((e && e.message) || e), 'err'));
  }

  /* 上传：真实文件选择器 → base64 → 按所选通道投递（进度取自 XHR 上传） */
  function _b64OfFile(file) {
    return file.arrayBuffer().then((buf) => {
      const bytes = new Uint8Array(buf);
      let bin = '';
      const CHUNK = 0x8000;
      for (let i = 0; i < bytes.length; i += CHUNK) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
      }
      return btoa(bin);
    });
  }
  function _postUpload(fs, url, body) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.setRequestHeader('Content-Type', 'application/json');
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) fs.progress = Math.max(1, Math.round((e.loaded / e.total) * 100));
      };
      xhr.onload = () => {
        let data = null;
        try { data = JSON.parse(xhr.responseText || 'null'); } catch (err) { /* 保留 null */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error('HTTP ' + xhr.status));
      };
      xhr.onerror = () => reject(new Error('网络错误'));
      xhr.send(JSON.stringify(body));
    });
  }
  function pickAndUpload(fs) {
    if (!apiMode || !fs.shellId || fs.uploading) return;
    const input = document.createElement('input');
    input.type = 'file';
    input.style.display = 'none';
    document.body.appendChild(input);
    const cleanup = () => { if (input.parentNode) input.parentNode.removeChild(input); };
    input.onchange = () => {
      const f = input.files && input.files[0];
      cleanup();
      if (f) uploadFile(fs, f);
    };
    input.oncancel = cleanup;
    input.click();
  }
  function uploadFile(fs, file) {
    if (!apiMode || !fs.shellId || fs.uploading || !file) return;
    fs.uploading = file.name;
    fs.progress = 0;
    fs.phase = '';
    const done = (method) => {
      fs.progress = 100;
      fs.phase = '';
      const name = file.name;
      setTimeout(() => {
        fs.uploading = null;
        fs.progress = 0;
        refreshFileEntries(fs);
        toast('上传完成：' + name + '（' + method + '）→ ' + cwdPath(fs.crumbs), 'ok');
      }, 250);
    };
    const fail = (msg) => {
      fs.uploading = null;
      fs.progress = 0;
      fs.phase = '';
      toast('上传失败：' + msg, 'err');
    };
    const chunk = () => {
      fs.phase = '分片直传…';
      return _uploadChunked(fs, file)
        .then(() => done('分片直传'))
        .catch((e) => fail(String((e && e.message) || e)));
    };

    if (uploadMode.value === 'chunk') { chunk(); return; }
    _uploadViaPull(fs, file)
      .then((out) => done('HTTP 拉取 · ' + ((out && out.tool) || '自动')))
      .catch((e) => {
        const msg = String((e && e.message) || e);
        if (uploadMode.value === 'auto' && e && e.fallback) {
          toast('HTTP 拉取不可用（' + msg + '），回退分片直传', 'info');
          chunk();
          return;
        }
        fail(msg);
      });
  }

  /* 通道一：分片直传（原实现：经 WebShell 通道分块 base64 落盘） */
  function _uploadChunked(fs, file) {
    return _b64OfFile(file)
      .then((b64) => _postUpload(fs, '/api/shells/' + fs.shellId + '/files/upload', {
        path: cwdPath(fs.crumbs), name: file.name, contentB64: b64,
      }))
      .then((out) => {
        if (out && out.pivothubFallback) throw new Error(out.reason || '后端未实现');
        return out || {};
      });
  }

  /* 通道二：攻击机 HTTP 暂存 → 目标机 curl/wget 等主动拉取（按字节数校验） */
  function _uploadViaPull(fs, file) {
    return _b64OfFile(file)
      .then((b64) => {
        fs.phase = '面板暂存 → 目标机拉取…';
        return _postUpload(fs, '/api/shells/' + fs.shellId + '/files/pull', {
          path: cwdPath(fs.crumbs), name: file.name, contentB64: b64,
        });
      })
      .then((out) => {
        if (out && out.pivothubFallback) {
          const err = new Error(out.reason || '目标机拉取失败');
          err.fallback = true;
          err.log = (out && out.log) || [];
          throw err;
        }
        return out || {};
      });
  }

  /* 目标机下载工具探测（HTTP 拉取通道）：结果写入 fs.tools，供界面展示 */
  function detectPullTools(fs, quiet) {
    if (!apiMode || !fs.shellId || fs.toolsLoading) return;
    fs.toolsLoading = true;
    fs.toolsError = '';
    PivotAPI.get('/api/shells/' + fs.shellId + '/files/pull/tools')
      .then((out) => {
        fs.toolsLoading = false;
        if (out && out.pivothubFallback) {
          fs.tools = [];
          fs.toolsError = out.reason || '探测失败';
          if (!quiet) toast('下载工具探测失败：' + fs.toolsError, 'err');
          return;
        }
        fs.tools = (out && out.tools) || [];
        if (!quiet) {
          toast(fs.tools.length
            ? '目标可用下载工具：' + fs.tools.map((t) => t.label).join(' / ')
            : '未检测到 curl/wget/python3 等下载工具（请用分片直传）',
            fs.tools.length ? 'ok' : 'err');
        }
      })
      .catch((e) => {
        fs.toolsLoading = false;
        fs.tools = [];
        fs.toolsError = String((e && e.message) || e);
        if (!quiet) toast('下载工具探测失败：' + fs.toolsError, 'err');
      });
  }

  /* ---------- 代理链路动作（apiMode 走服务端，状态由 SQLite + WS 驱动） ---------- */
  function testLink(id) {
    if (apiMode) {
      PivotAPI.post('/api/links/' + id + '/check')
        .then((out) => {
          const l = state.links.find((x) => x.id === id);
          if (l && out) Object.assign(l, out);
          if (out && out.status === 'alive') toast('链路正常 · 延迟 ' + out.latency + 'ms', 'ok');
          else toast('链路当前不可用（状态：' + statusText(out && out.status) + '）', 'err');
        })
        .catch(() => toast('链路健康检查失败（后端不可用）', 'err'));
      return;
    }

  }
  function restartLink(id) {
    if (apiMode) {
      PivotAPI.post('/api/links/' + id + '/restart')
        .then((out) => {
          const l = state.links.find((x) => x.id === id);
          if (l && out) Object.assign(l, out);
          toast('已发起重拉链路，等待回连', 'ok');
        })
        .catch(() => toast('重拉链路失败（后端不可用）', 'err'));
      return;
    }

  }
  function stopLink(id) {
    if (apiMode) {
      PivotAPI.del('/api/links/' + id)
        .then(() => {
          const l = state.links.find((x) => x.id === id);
          if (l) { l.status = 'stopped'; l.pid = null; }
          toast('已销毁链路', 'info');
        })
        .catch(() => toast('销毁链路失败（后端不可用）', 'err'));
      return;
    }

  }

  /* 本地移除链路（服务端已删；WS link.removed 也会走到这里） */
  function pruneLinkLocally(id) {
    const i = state.links.findIndex((x) => x.id === id);
    if (i >= 0) state.links.splice(i, 1);
    if (state.ui.selectedLinkId === id) {
      state.ui.selectedLinkId = null;
      selected.link = null;
    }
  }

  /* 删除链路记录：先按销毁流程结束进程，再从列表/拓扑移除（不可恢复） */
  function removeLink(l) {
    if (!l) return Promise.resolve(false);
    if (!apiMode) return Promise.resolve(false);
    return PivotAPI.del('/api/links/' + l.id + '/record')
      .then(() => {
        pruneLinkLocally(l.id);
        toast('已删除链路记录：' + l.tool + '（进程已清理）', 'ok');
        return true;
      })
      .catch(() => { failApi('删除链路'); return false; });
  }

  /* ---------- 攻击机网络（GET/PUT /api/attack，任务 C-A） ---------- */
  /* 保存攻击机网络：apiMode 下写服务端并整包回填（所有命令与链路地址随之同步），
     后端不可用时本地不落地（显式报错）。 */
  function saveAttack(cfg, done) {
    const patch = {
      ip: cfg.ip, segment: cfg.segment || state.attack.segment,
      iface: cfg.iface || state.attack.iface, note: cfg.note || state.attack.note || '',
    };
    Object.assign(state.attack, patch);
    const local = state.hosts.find((h) => h.isLocal);
    if (local) {
      local.ip = patch.ip;
      if (patch.segment) local.segment = patch.segment;
      if ((local.ifaces || []).length) {
        local.ifaces[0].ip = patch.ip;
        if (patch.iface) local.ifaces[0].iface = patch.iface;
        if (patch.segment) local.ifaces[0].segment = patch.segment;
      }
    }
    if (!apiMode) { if (done) done(true); return; }
    PivotAPI.put('/api/attack?projectId=' + encodeURIComponent(state.projectId), patch)
      .then((out) => { Object.assign(state.attack, out || {}); if (done) done(true); })
      .catch(() => { toast('攻击机配置已本地生效（后端不可用，未持久化）', 'warn'); if (done) done(false); });
  }

  /* 写入**指定项目**的攻击机网络（「同步到所有项目」用；不触碰本地状态） */
  function saveAttackFor(projectId, cfg) {
    if (!apiMode) return Promise.reject(new Error('后端不可用'));
    return PivotAPI.put('/api/attack?projectId=' + encodeURIComponent(projectId), {
      ip: cfg.ip, segment: cfg.segment || '', iface: cfg.iface || '', note: cfg.note || '',
    });
  }

  /* 面板所在机器的地址（GET /api/netinfo）：攻击机就是本机，用于自动填回连地址 */
  function netinfo() {
    if (!hasApi) return Promise.resolve({ hostname: '', ips: [] });
    return PivotAPI.get('/api/netinfo').catch(() => ({ hostname: '', ips: [] }));
  }

  /* ---------- 反弹 Shell 通道（POST /api/shells/reverse/*，任务 MS2 后端已有） ----------
     listen：攻击机侧真实 socket 监听；listeners：查询回连状态；
     register：把已回连的通道登记为面板会话（kind=reverse），后续 exec/文件/固化全复用会话层。 */
  function reverseListen(opts) {
    if (!hasApi) return Promise.resolve({ ok: false, stage: 'offline', error: '后端不可用（请启动 python -m pivothub）' });
    return PivotAPI.post('/api/shells/reverse/listen', {
      bind: opts.bind, port: Number(opts.port) || 0, label: opts.label || '', waitS: 0,
    }).catch((e) => ({ ok: false, stage: 'request', error: String((e && e.message) || e) }));
  }

  function reverseListeners() {
    if (!hasApi) return Promise.resolve({ listeners: [] });
    return PivotAPI.get('/api/shells/reverse/listeners').catch(() => ({ listeners: [] }));
  }

  /* 重试恢复面板重启时未能自动拉起的监听（地址又回来了等场景） */
  function reverseRestoreListeners() {
    if (!hasApi) return Promise.resolve({ restored: 0, failed: [] });
    return PivotAPI.post('/api/shells/reverse/listeners/restore', {})
      .catch(() => ({ restored: 0, failed: [] }));
  }

  /* 关闭监听（释放端口；休眠/断线后残留的监听会占住端口） */
  function reverseCloseListener(listenerId) {
    if (!hasApi) return Promise.resolve({ ok: false });
    return PivotAPI.del('/api/shells/reverse/listeners/' + encodeURIComponent(listenerId))
      .catch(() => ({ ok: false }));
  }
  function reverseCloseAll() {
    if (!hasApi) return Promise.resolve({ ok: false, closed: 0 });
    return PivotAPI.del('/api/shells/reverse/listeners').catch(() => ({ ok: false, closed: 0 }));
  }

  /* ---------- 数据库面板 ---------- */
  function dbList() {
    if (!hasApi) return Promise.resolve({ connections: [], kinds: [], defaultPorts: {} });
    return PivotAPI.get('/api/db/connections?projectId=' + encodeURIComponent(state.projectId))
      .catch(() => ({ connections: [], kinds: [], defaultPorts: {} }));
  }
  function dbCreate(form) {
    if (!hasApi) return Promise.resolve(null);
    return PivotAPI.post('/api/db/connections',
      Object.assign({ projectId: state.projectId }, form || {})).catch(() => null);
  }
  function dbDelete(id) {
    if (!hasApi) return Promise.resolve({ deleted: '' });
    return PivotAPI.del('/api/db/connections/' + encodeURIComponent(id))
      .catch(() => ({ deleted: '' }));
  }
  function dbTest(id) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用' });
    return PivotAPI.post('/api/db/connections/' + encodeURIComponent(id) + '/test', {})
      .catch(() => ({ ok: false, error: '后端不可达' }));
  }
  function dbQuery(id, sql) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用' });
    return PivotAPI.post('/api/db/connections/' + encodeURIComponent(id) + '/query', { sql })
      .catch(() => ({ ok: false, error: '后端不可达' }));
  }
  function dbTables(id) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用' });
    return PivotAPI.get('/api/db/connections/' + encodeURIComponent(id) + '/tables')
      .catch(() => ({ ok: false, error: '后端不可达' }));
  }

  /* ---------- 提权智能匹配（M5-2） ---------- */
  function privescRules(platform) {
    if (!hasApi) return Promise.resolve({ rules: [] });
    return PivotAPI.get('/api/privesc/rules' + (platform ? '?platform=' + encodeURIComponent(platform) : ''))
      .catch(() => ({ rules: [] }));
  }

  function privescScan(shellId) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用（请启动 python -m pivothub）' });
    return PivotAPI.post('/api/shells/' + encodeURIComponent(shellId) + '/privesc/scan', {})
      .catch(() => ({ ok: false, error: '后端不可达' }));
  }

  /* 在指定会话上执行命令（不改变当前终端选择）；模块化流程用 */
  function execOn(shellId, cmd) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用（请启动 python -m pivothub）' });
    return PivotAPI.post('/api/shells/' + shellId + '/exec', { cmd: cmd })
      .catch((e) => ({ ok: false, error: String((e && e.message) || e) }));
  }

  function reverseRegister(opts) {
    if (!hasApi) return Promise.resolve({ ok: false, stage: 'offline', error: '后端不可用（请启动 python -m pivothub）' });
    return PivotAPI.post('/api/shells/reverse/register', {
      projectId: state.projectId, listenerId: opts.listenerId, hostId: opts.hostId,
      type: opts.type || '反弹 Shell', autoCollect: opts.autoCollect !== false,
    }).then((out) => {
      if (out && out.ok && out.shell && !state.shells.some((s) => s.id === out.shell.id)) {
        state.shells.push(out.shell);
      }
      return out || { ok: false, stage: 'unknown', error: '空响应' };
    }).catch((e) => ({ ok: false, stage: 'request', error: String((e && e.message) || e) }));
  }

  /* ---------- 代理工具启用集（GET/PUT /api/tools） ----------
     只允许启用适配器已接入（status=online）的工具；保存后整包回填 state.tools，
     编排台下拉与探测推荐都只看 enabled 集合。 */
  function saveTools(enabled, done) {
    if (!apiMode) {
      toast('后端不可用：代理工具设置未保存', 'err');
      if (done) done(false);
      return;
    }
    PivotAPI.put('/api/tools?projectId=' + encodeURIComponent(state.projectId),
      { enabled: enabled || [] })
      .then((out) => {
        if (Array.isArray(out)) replaceArr(state.tools, out);
        if (done) done(true);
      })
      .catch((e) => {
        toast('保存代理工具设置失败：' + String((e && e.message) || e), 'err');
        if (done) done(false);
      });
  }

  /* ---------- 三种链路类型部署（POST /api/links/deploy，任务 C-B） ----------
     opts: {shellId, linkType, attackIp, listenPort, bindAddr, localPort,
            targetHost, targetPort, relayAddr, relayPort, relayShellId, targetSegment, waitS}
     返回 Promise<{ok, link?, stage?, error?, verify?, log?}>；失败不伪造成功。 */
  function deployLink(opts) {
    if (!hasApi) return Promise.resolve({ ok: false, stage: 'offline', error: '后端不可用（请启动 python -m pivothub）' });
    const body = Object.assign({ projectId: state.projectId }, opts || {});
    return PivotAPI.post('/api/links/deploy', body).then((out) => {
      if (out && out.ok && out.link) {
        if (!state.links.some((l) => l.id === out.link.id)) state.links.push(out.link);
      }
      return out || { ok: false, stage: 'unknown', error: '空响应' };
    }).catch((e) => ({ ok: false, stage: 'request', error: String(e && e.message || e) }));
  }

  /* 多级中继推导（GET /api/links/relay-plan）：与前端同一套规则，服务端复核 */
  function relayPlan(fromHostId, opts) {
    if (!hasApi) return Promise.resolve(null);
    const q = 'fromHostId=' + encodeURIComponent(fromHostId) +
      '&projectId=' + encodeURIComponent(state.projectId) +
      '&listenPort=' + encodeURIComponent((opts && opts.listenPort) || 1331) +
      '&localPort=' + encodeURIComponent((opts && opts.localPort) || 0) +
      '&bindAddr=' + encodeURIComponent((opts && opts.bindAddr) || '0.0.0.0');
    return PivotAPI.get('/api/links/relay-plan?' + q).catch(() => null);
  }

  /* 出网探测（POST /api/shells/{id}/probe，真实执行） */
  function probeShell(shellId, opts) {
    if (!hasApi) return Promise.resolve({ ok: false, stage: 'offline', error: '后端不可用（请启动 python -m pivothub）' });
    return PivotAPI.post('/api/shells/' + shellId + '/probe', opts || {})
      .catch((e) => ({ ok: false, stage: 'request', error: String(e && e.message || e) }));
  }

  /* ---------- 资产探测：流式扫描（POST /api/recon/scan/stream + WS recon.scan） ----------
     长扫描（fscan 扫 B 段）走流式：后台线程执行，日志逐行经 WS 推送；
     面板「实时日志」与所选会话的交互终端同步显示，可随时取消。 */
  /* 任务启动竞态缓冲：POST 返回 jobId 之前到达的 WS 帧先存下来，拿到 jobId 后回放 */
  let reconEarly = [];

  function applyReconEvent(msg) {
    const R = state.recon;
    if (msg.line != null) {
      R.lines.push({ kind: msg.kind || 'out', line: msg.line, seq: msg.seq });
      if (R.lines.length > 4000) R.lines.splice(0, R.lines.length - 4000);
    }
    if (msg.status) R.status = msg.status;
    if (msg.done) {
      R.result = {
        ok: msg.status === 'done', error: msg.error || '',
        hosts: msg.hosts || [], cmd: msg.cmd || '',
        scannerPath: msg.scannerPath || '', cached: !!msg.cached,
        ms: msg.ms || 0, timedOut: !!msg.timedOut, output: msg.output || '',
      };
      R.elapsed = msg.elapsed || 0;
      R.error = msg.error || '';
    }
  }

  function reconScanStream(params) {
    if (!hasApi) return Promise.resolve({ ok: false, error: '后端不可用（请启动 python -m pivothub）' });
    const body = Object.assign({ projectId: state.projectId }, params || {});
    const R = state.recon;
    R.jobId = null;
    R.status = 'starting';
    R.lines = [];
    R.result = null;
    R.error = '';
    R.shellId = body.shellId || null;
    R.segment = body.segment || '';
    R.startedAt = Date.now();
    R.elapsed = 0;
    reconEarly = [];
    return PivotAPI.post('/api/recon/scan/stream', body).then((out) => {
      if (out && out.ok && out.jobId) {
        R.jobId = out.jobId;
        R.status = 'running';
        /* 快任务（会话不可用等）可能在 POST 返回前就推完事件，这里补放 */
        const early = reconEarly;
        reconEarly = [];
        early.filter((m) => m.jobId === out.jobId).forEach(applyReconEvent);
      }
      return out || { ok: false, error: '空响应' };
    }).catch((e) => {
      R.status = 'error';
      R.error = String((e && e.message) || e);
      return { ok: false, error: R.error };
    });
  }

  function reconScanJob(jobId) {
    if (!hasApi || !jobId) return Promise.resolve(null);
    return PivotAPI.get('/api/recon/scan/jobs/' + encodeURIComponent(jobId)).catch(() => null);
  }

  function reconScanCancel(jobId) {
    if (!hasApi || !jobId) return Promise.resolve({ ok: false });
    return PivotAPI.post('/api/recon/scan/jobs/' + encodeURIComponent(jobId) + '/cancel')
      .catch(() => ({ ok: false }));
  }

  /* ---------- 主机 / 凭据 / Flag ---------- */
  function addHost(form) {
    if (apiMode) {
      PivotAPI.post('/api/hosts', {
        projectId: state.projectId,
        ip: form.ip, hostname: form.hostname, os: form.os, layer: form.layer,
        segment: form.segment, privilege: form.privilege, note: form.note,
        services: form.services || '',
      }).then((item) => {
        if (!hostsById[item.id]) {
          state.hosts.push(item);
          hostsById[item.id] = item;
        }
        toast('主机已登记并上拓扑', 'ok');
      }).catch(() => failApi('登记主机'));
      return null;
    }
    return null;
  }

  /* 本地级联清理（服务端已级联删除，这里同步前端状态；WS host.removed 也会走到这里） */
  function pruneHostLocally(hostId) {
    const i = state.hosts.findIndex((h) => h.id === hostId);
    if (i >= 0) state.hosts.splice(i, 1);
    delete hostsById[hostId];
    const drop = (arr, key) => {
      for (let j = arr.length - 1; j >= 0; j--) {
        const v = arr[j][key];
        if (v === hostId) arr.splice(j, 1);
      }
    };
    drop(state.shells, 'hostId');
    drop(state.creds, 'hostId');
    drop(state.flags, 'hostId');
    for (let j = state.links.length - 1; j >= 0; j--) {
      const l = state.links[j];
      if (l.fromHostId === hostId || l.toHostId === hostId) state.links.splice(j, 1);
    }
    state.timeline.forEach((t) => { if (t.hostId === hostId) t.hostId = null; });
    if (state.ui.selectedHostId === hostId) {
      state.ui.selectedHostId = null;
      if (selected.host && selected.host.id === hostId) selected.host = null;
    }
    if (!state.shells.some((s) => s.id === state.ui.selectedShellId)) {
      const first = state.shells.find((s) => s.alive);
      state.ui.selectedShellId = first ? first.id : null;
    }
    /* 资产探测的会话选择可能指向被删主机的 Shell */
    if (state.recon.shellId && !state.shells.some((s) => s.id === state.recon.shellId)) {
      state.recon.shellId = null;
    }
  }

  /* 移除资产：连带清理该主机上的会话 / 链路 / 凭据 / Flag（后端事务内完成） */
  function removeHost(h) {
    if (!h) return Promise.resolve(false);
    if (h.isLocal) { toast('本机节点（攻击机）不能移除', 'err'); return Promise.resolve(false); }
    if (!apiMode) return Promise.resolve(false);
    return PivotAPI.del('/api/hosts/' + h.id)
      .then((out) => {
        pruneHostLocally(h.id);
        const extra = [];
        if (out && out.shells) extra.push(out.shells + ' 个会话');
        if (out && out.links) extra.push(out.links + ' 条链路');
        if (out && out.creds) extra.push(out.creds + ' 条凭据');
        if (out && out.flags) extra.push(out.flags + ' 个 Flag');
        toast('已移除资产 ' + h.ip + (extra.length ? '（连带 ' + extra.join(' / ') + '）' : ''), 'ok');
        addEvent('host', '移除资产 ' + h.ip, { detail: extra.join(' / ') });
        return true;
      })
      .catch(() => { failApi('移除资产'); return false; });
  }
  function importScan(text) {
    if (apiMode) {
      PivotAPI.post('/api/hosts/import', { projectId: state.projectId, text: String(text) })
        .then((out) => {
          toast(out.added ? '已入库 ' + out.added + ' 台主机' : '未解析到新主机', out.added ? 'ok' : 'err');
          if (out.added) refreshState();
        })
        .catch(() => failApi('导入扫描结果'));
      return;
    }

  }
  function addCred(form) {
    if (apiMode) {
      PivotAPI.post('/api/creds', {
        projectId: state.projectId, hostId: form.hostId, username: form.username, secret: form.secret,
        kind: form.kind, services: form.services || '', source: form.source || '手动登记',
      }).then((item) => {
        if (!state.creds.some((x) => x.id === item.id)) state.creds.push(item);
        toast('凭据已入库', 'ok');
      }).catch(() => failApi('登记凭据'));
      return;
    }

  }
  function addFlag(form) {
    if (apiMode) {
      PivotAPI.post('/api/flags', {
        projectId: state.projectId, hostId: form.hostId, stage: form.stage,
        value: form.value, submitted: !!form.submitted,
      }).then((item) => {
        if (!state.flags.some((x) => x.id === item.id)) state.flags.push(item);
        toast('Flag 已记录', 'ok');
      }).catch(() => failApi('记录 Flag'));
      return;
    }

  }
  function addNote(form) {
    if (apiMode) {
      PivotAPI.post('/api/timeline/notes', {
        projectId: state.projectId, title: form.title, hostId: form.hostId || null,
        cmd: form.cmd || '', markdown: form.markdown || '',
      }).then(() => toast('笔记已加入时间线', 'ok')).catch(() => failApi('添加笔记'));
      return;
    }

  }

  /* 拓扑拖拽位置持久化（SQLite 保存，重启后恢复） */
  let posSaveTimer = null;
  function saveNodePos(hostId, x, y) {
    if (!apiMode || !hostId) return;
    clearTimeout(posSaveTimer);
    posSaveTimer = setTimeout(() => {
      PivotAPI.patch('/api/hosts/' + hostId + '/position', { x, y }).catch(() => {});
    }, 350);
  }

  /* 新建项目（用户显式入口）：后端创建干净工作区后自动切换过去 */
  function createProject() {
    if (!hasApi) { toast('后端不可用：请先启动 python -m pivothub', 'err'); return; }
    const defName = '比赛 ' + new Date().toLocaleDateString('zh-CN');
    const name = window.prompt('新项目名称（一场比赛 / 一个靶场）', defName);
    if (!name || !name.trim()) return;
    PivotAPI.post('/api/projects', { name: name.trim() })
      .then((p) => {
        state.projects.push(p);
        state.projectId = p.id; /* 触发 watch → 整包刷新为空项目 */
        toast('已创建项目：' + p.name, 'ok');
      })
      .catch(() => toast('创建失败：后端不可达', 'err'));
  }

  /* 删除项目（用户显式入口）：确认后级联删除服务端数据，并切到剩余第一个项目。
     至少保留一个项目（服务端同样有保护）。 */
  function deleteProject() {
    if (!hasApi) { toast('后端不可用：请先启动 python -m pivothub', 'err'); return; }
    const p = state.projects.find((x) => x.id === state.projectId);
    if (!p) return;
    if (state.projects.length <= 1) { toast('至少保留一个项目：请先新建项目再删除', 'err'); return; }
    if (!window.confirm('删除项目「' + p.name + '」？\n\n该项目的资产 / 会话 / 链路 / 凭据 / Flag / 时间线将一并删除，且不可恢复。')) return;
    PivotAPI.del('/api/projects/' + encodeURIComponent(p.id))
      .then((out) => {
        const rest = state.projects.filter((x) => x.id !== p.id);
        replaceArr(state.projects, rest);
        state.projectId = rest[0].id; /* 触发 watch → 整包重载该项目 */
        const extra = [];
        if (out && out.hosts) extra.push(out.hosts + ' 台主机');
        if (out && out.shells) extra.push(out.shells + ' 个会话');
        if (out && out.links) extra.push(out.links + ' 条链路');
        if (out && out.creds) extra.push(out.creds + ' 条凭据');
        if (out && out.flags) extra.push(out.flags + ' 个 Flag');
        toast('已删除项目：' + p.name + (extra.length ? '（连带 ' + extra.join(' / ') + '）' : ''), 'ok');
      })
      .catch(() => toast('删除失败：后端不可达，或该项目不允许删除', 'err'));
  }

  /* ---------- 导出 ---------- */
  function buildMarkdown(opt) {
    const p = state.project;
    let out = '# ' + p.name + ' · Writeup\n\n';
    out += '> 生成时间：' + new Date().toLocaleString('zh-CN') + '  \n> 工具：PivotHub（链透中枢）· 本报告为初稿，需人工润色\n\n';
    out += '## 0. 概览\n\n';
    out += '| 指标 | 数值 |\n|---|---|\n';
    out += '| 已控主机 | ' + stats.value.ownedHosts + ' / ' + stats.value.hosts + ' |\n';
    out += '| 层级深度 | L1 → L' + stats.value.maxLayer + ' |\n';
    out += '| 代理链路 | ' + stats.value.aliveLinks + ' / ' + stats.value.links + ' 存活 |\n';
    out += '| 凭据 | ' + state.creds.length + ' 条 |\n';
    out += '| Flag | ' + state.flags.length + ' / ' + stats.value.flagsTotal + ' |\n\n';

    if (opt.topo) {
      out += '## 1. 网络拓扑\n\n```\n';
      out += '攻击端 127.0.0.1\n';
      state.links.forEach((l) => {
        out += '  └─[' + l.tool + ' ' + l.direction + ' ' + (l.localSocks || '') + ']→ ' + ipOf(l.fromHostId) + '  ⇒  ' + (l.targetSegment || '') + '\n';
      });
      out += '```\n\n' + (opt.placeholder ? '![拓扑快照](screenshots/topology.png)\n\n' : '');
    }
    if (opt.chain) {
      out += '## 2. 跳板链参数\n\n| 工具 | 方向 | 入口 | 出口 | 本地 Socks | 目标网段 |\n|---|---|---|---|---|---|\n';
      state.links.forEach((l) => {
        out += '| ' + l.tool + ' | ' + l.direction + ' | ' + ipOf(l.fromHostId) + ' | ' + ipOf(l.toHostId) + ' | ' + (l.localSocks || '-') + ' | ' + (l.targetSegment || '-') + ' |\n';
      });
      out += '\n';
    }
    if (opt.timeline) {
      out += '## 3. 操作时间线\n\n';
      state.timeline.slice().reverse().forEach((e) => {
        out += '### ' + e.time + ' · ' + kindLabel(e.kind) + ' — ' + e.title + '\n\n';
        if (e.hostId) out += '- 主机：`' + ipOf(e.hostId) + '`\n';
        if (e.detail) out += '- ' + e.detail + '\n';
        if (e.cmd) out += '\n```bash\n' + e.cmd + '\n```\n';
        if (e.markdown) out += '\n' + e.markdown + '\n';
        out += '\n';
      });
    }
    if (opt.creds) {
      out += '## 4. 凭据清单（明文）\n\n| 账号 | 类型 | 凭据 | 来源主机 | 适用服务 |\n|---|---|---|---|---|\n';
      state.creds.forEach((c) => {
        out += '| `' + c.username + '` | ' + c.kind + ' | `' + c.secret + '` | ' + ipOf(c.hostId) + ' | ' + (c.services || []).join(',') + ' |\n';
      });
      out += '\n';
    }
    if (opt.flags) {
      out += '## 5. Flag 收集\n\n| 主机 | 阶段 | Flag | 状态 |\n|---|---|---|---|\n';
      state.flags.forEach((f) => {
        out += '| ' + ipOf(f.hostId) + ' | ' + f.stage + ' | `' + f.value + '` | ' + (f.submitted ? '已提交' : '待提交') + ' |\n';
      });
      out += '\n';
    }
    out += '## 6. 总结与反思\n\n> 待补充：本层关键突破点、踩坑与改进思路。\n';
    return out;
  }

  /* ---------- 后端接入（assets/js/api.js）----------
     全部数据来自 FastAPI + SQLite；后端不可用时动作显式报错。 */
  const hasApi = typeof global.PivotAPI !== 'undefined';
  let apiMode = false;

  function replaceArr(arr, items) { arr.splice(0, arr.length, ...(items || [])); }
  function rebuildHostsById() {
    Object.keys(hostsById).forEach((k) => delete hostsById[k]);
    state.hosts.forEach((h) => (hostsById[h.id] = h));
  }

  /* 用服务端全量状态原位替换本地数组（保持 Vue 响应式与对象引用） */
  function applyState(data) {
    if (!data) return;
    Object.assign(state.project, data.project || {});
    if (data.project && data.project.durationSec) state.timer.durationSec = data.project.durationSec;
    replaceArr(state.projects, data.projects);
    replaceArr(state.segments, data.segments);
    if (data.attack) Object.assign(state.attack, data.attack); /* 攻击机网络从服务端回填 */
    replaceArr(state.hosts, data.hosts);
    replaceArr(state.shells, data.shells);
    replaceArr(state.links, data.links);
    replaceArr(state.creds, data.creds);
    replaceArr(state.flags, data.flags);
    replaceArr(state.timeline, data.timeline);
    replaceArr(state.commands, data.commands);
    replaceArr(state.injectTips, data.injectTips);
    replaceArr(state.ttyFixes, data.ttyFixes);
    /* 静态目录：全部来自后端 /state，视图只读 state.* */
    if (data.probes) replaceArr(state.probes, data.probes);
    if (data.tools) replaceArr(state.tools, data.tools);
    if (data.shellTypes) replaceArr(state.shellTypes, data.shellTypes);
    if (data.encoders) replaceArr(state.encoders, data.encoders);
    if (data.credKinds) replaceArr(state.credKinds, data.credKinds);
    if (data.layers) replaceArr(state.layers, data.layers);
    if (data.stageNames) replaceArr(state.stageNames, data.stageNames);
    if (data.scanSample) state.scanSample = data.scanSample;
    rebuildHostsById();
    if (!state.shells.some((s) => s.id === state.ui.selectedShellId)) {
      const first = state.shells.find((s) => s.alive);
      state.ui.selectedShellId = first ? first.id : null;
    }
    termState.inited = false;
  }

  function refreshState() {
    if (!hasApi) return Promise.resolve(false);
    return PivotAPI.getState(state.projectId)
      .then((data) => { applyState(data); return true; })
      .catch(() => false);
  }

  /* WebSocket 事件按 type 分派（README §6.2） */
  function handleWsEvent(msg) {
    if (!msg || !msg.type) return;
    switch (msg.type) {
      case 'shell.beat': {
        const s = state.shells.find((x) => x.id === msg.shellId);
        if (s) {
          s.alive = msg.alive !== false;
          if (msg.latency != null) s.latency = msg.latency;
          if (msg.lastBeat) s.lastBeat = msg.lastBeat;
        }
        break;
      }
      case 'shell.output': {
        if (state.ui.selectedShellId !== msg.shellId) break;
        if (msg.kind === 'raw') { rawAppend(msg.line || ''); break; }
        /* 原始模式下其余推送（扫描镜像/系统提示）并入同一条流 */
        if (termState.rawMode) { rawAppend(String(msg.line || '') + '\n'); break; }
        termPush(msg.kind || 'out', escapeHtml(msg.line || ''));
        break;
      }
      case 'shell.tty': {
        const s = state.shells.find((x) => x.id === msg.shellId);
        if (s) s.stable = !!msg.hasPty;
        if (state.ui.selectedShellId === msg.shellId && msg.mode) {
          termState.mode = msg.mode;
          termState.modeLabel = msg.mode === 'full' ? '已固化（交互 TTY）'
            : msg.mode === 'semi' ? '半交互（无 TTY / 无 job control）' : '未固化（WebShell 伪终端）';
        }
        break;
      }
      case 'probe.result': break; /* MS3：出网探测逐探针回传 */
      case 'link.state': {
        const l = state.links.find((x) => x.id === msg.linkId);
        if (l) {
          if (msg.status) l.status = msg.status;
          if (msg.latency != null) l.latency = msg.latency;
          if (msg.traffic != null) l.traffic = msg.traffic;
        }
        break;
      }
      case 'link.created': {
        if (msg.link && !state.links.some((x) => x.id === msg.link.id)) state.links.push(msg.link);
        break;
      }
      case 'link.removed': {
        if (msg.linkId) pruneLinkLocally(msg.linkId);
        break;
      }
      case 'host.found': {
        if (msg.host && !hostsById[msg.host.id]) {
          state.hosts.push(msg.host);
          hostsById[msg.host.id] = msg.host;
        }
        break;
      }
      case 'host.removed': {
        if (msg.hostId) pruneHostLocally(msg.hostId);
        break;
      }
      case 'recon.scan': {
        const R = state.recon;
        if (!R.jobId) {
          /* 任务刚发起、jobId 还没从 POST 回来：先缓存，拿到后回放（快任务会抢跑） */
          if (R.status === 'starting') {
            reconEarly.push(msg);
            if (reconEarly.length > 200) reconEarly.shift();
          }
          break;
        }
        if (msg.jobId !== R.jobId) break;  /* 只认当前任务的日志 */
        applyReconEvent(msg);
        break;
      }
      case 'host.update': {
        if (msg.host && hostsById[msg.host.id]) {
          Object.assign(hostsById[msg.host.id], msg.host);
        }
        break;
      }
      case 'shell.created': {
        if (msg.shell && !state.shells.some((x) => x.id === msg.shell.id)) {
          state.shells.push(msg.shell);
        }
        break;
      }
      case 'cred.found': {
        if (msg.cred && !state.creds.some((x) => x.id === msg.cred.id)) state.creds.push(msg.cred);
        break;
      }
      case 'timeline.push': {
        if (msg.event && !state.timeline.some((x) => x.id === msg.event.id)) {
          state.timeline.unshift(msg.event);
        }
        break;
      }
      case 'project.removed': {
        if (!msg.projectId) break;
        replaceArr(state.projects, state.projects.filter((p) => p.id !== msg.projectId));
        if (state.projectId === msg.projectId && state.projects.length) {
          state.projectId = state.projects[0].id; /* 触发 watch 重新加载 */
        }
        break;
      }
      case 'ws.online': state.ws.online = msg.online !== false; break;
      case 'tools.updated': {
        if (Array.isArray(msg.tools)) replaceArr(state.tools, msg.tools);
        break;
      }
      case 'attack.updated': {
        /* 其他标签页改了攻击机网络：整份覆盖，本页所有回连命令与链路地址随之同步 */
        if (msg.attack) Object.assign(state.attack, msg.attack);
        break;
      }
      default: break;
    }
  }

  /* 初始化：从后端加载项目状态（后端不可用时显式提示） */
  function init() {
    startTicker();
    /* 合规提醒不挡操作：浮层停留 1 秒自动消失，完整声明在顶栏「合规声明」 */
    setTimeout(() => { state.ui.disclaimerBrief = false; }, 1000);
    if (!hasApi) {
      toast('后端不可用：请启动 python -m pivothub', 'err');
      state.ws.online = false;
      return;
    }
    refreshState().then((ok) => {
      if (ok) {
        apiMode = true;
        PivotAPI.mode = 'api';
        state.ws.online = true;
        PivotAPI.connectWs(handleWsEvent, (on) => { state.ws.online = on; });
      } else {
        apiMode = false;
        state.ws.online = false;
        toast('加载项目状态失败：后端不可用', 'err');
      }
    });
    /* 项目切换器：切 projectId 后整包重拉该项目状态 */
    watch(() => state.projectId, () => {
      if (!apiMode) return;
      refreshState().then(() => toast('已加载项目数据（SQLite）', 'info'));
    });
  }

  global.PivotStore = {
    state, selected, stats, toolOptions, clockText, remainText, timerPct, navGroups, termState, ttyApplied,
    HINT_CMDS,
    toast, copy, download, md, ipOf, hostOf, hostnameOf, shellsOf, credsOf, flagsOf, linksOf,
    privClass, statusText, kindLabel, kindBadge, addEvent, nowTime, navBadge, goto,
    openModal, closeModal,
    selectHost, selectLink, clearSelection,
    openTerminalById, openTerminal, heartbeatAll, testShell, removeShell, addShell,
    activeShell, initTerm, termPush, clearTerm, killTerm, execCommand, escapeHtml,
    shellInput, setRaw, rawAppend, upgradePty, interruptCommand,
    detectTty, ttyFixList, ttyAppliedList, isTtyApplied, renderTtyCmd, applyTtyFix, runTtyFinish,
    shellPlatform, sendToTerminalText,
    fileStateFor, cwdPath, refreshFileEntries, cdInto, cdTo, cdUp, cdIndex, fileEdit, downloadFile,
    testLink, restartLink, stopLink, removeLink,
    saveAttack, saveAttackFor, netinfo, saveTools, deployLink, relayPlan, probeShell,
    reverseListen, reverseListeners, reverseRestoreListeners, reverseRegister, reverseCloseListener, reverseCloseAll,
    dbList, dbCreate, dbDelete, dbTest, dbQuery, dbTables,
    privescRules, privescScan, execOn,
    reconScanStream, reconScanJob, reconScanCancel,
    addHost, removeHost, importScan, addCred, addFlag, addNote,
    buildMarkdown, init, toggleTimer, rid, sleep,
    saveNodePos, refreshState, isApiMode: () => apiMode,
    readFile, saveFileEdit, closeFileEdit, uploadFile, pickAndUpload, createProject, deleteProject,
    uploadMode, setUploadMode, uploadModeText, detectPullTools,
  };
})(window);
