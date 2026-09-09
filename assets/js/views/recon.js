/* ============================================================
   资产探测视图 — ① 内网信息收集 ② 上传扫描器扫内网 ③ 结果导入
   扫描走流式：后台任务 + WS 逐行日志（反弹 Shell 会话同时镜像到交互终端），
   状态放模块级/store：扫描可能持续数分钟，切走视图再回来不丢日志与结果。
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed, watch, toRefs, nextTick } = Vue;
  const S = PivotStore;

  const DEFAULT_PORTS =
    '21,22,80,135,139,443,445,1433,1521,3306,3389,5432,6379,8080,8443,10000';
  const DEFAULT_TEMPLATE = '{SCANNER} -h {SEGMENT} -p {PORTS} {EXTRA}';

  const R = reactive({
    shellId: null,
    env: null, envLoading: false, envError: '',
    segment: '', ports: DEFAULT_PORTS,
    scannerMode: 'builtin',          /* builtin | local | upload */
    scanners: [],                    /* tools/ 内置扫描器（GET /api/recon/scanners） */
    localScanner: '',
    scannerName: '', scannerB64: '', scannerSize: 0, forceUpload: false,
    remoteDir: '',                   /* 目标侧暂存目录（留空 = 默认 /tmp 或 %TEMP%） */
    probeTitles: true,
    template: '', extraArgs: '', timeoutS: 300,
    selected: {},                    /* ip -> bool */
    importing: false,
  });
  let pollTimer = null;
  let pollTick = 0;

  function fmtSize(n) {
    if (!n) return '';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  /* 端口 / 服务 / 标题展示 */
  function portText(h) {
    const info = h.portInfo || [];
    if (!info.length) return (h.ports || []).join(', ') || '—';
    return info.map((p) => p.service ? p.port + '/' + p.service : String(p.port)).join(', ');
  }
  function titleText(h) {
    const info = h.portInfo || [];
    const hit = info.filter((p) => p.title);
    if (!hit.length) return '';
    return hit.map((p) => p.port + ': ' + p.title).join(' | ');
  }

  global.Components['recon-view'] = {
    name: 'ReconView',
    template: '#tpl-recon',
    setup() {
      const ui = S.state.ui;
      const live = S.state.recon;      /* 流式扫描状态（store 级，切视图不丢） */
      const logEl = Vue.ref(null);
      const shells = computed(() => S.state.shells.slice()
        .sort((a, b) => (b.alive ? 1 : 0) - (a.alive ? 1 : 0)));
      const knownSet = computed(() => {
        const m = {};
        S.state.hosts.forEach((h) => { m[h.ip] = true; });
        return m;
      });
      /* 目标平台：按所选会话的宿主 OS 推导，用于过滤可用的本地扫描器 */
      const targetPlatform = computed(() => {
        const sh = S.state.shells.find((x) => x.id === R.shellId);
        const host = sh ? S.state.hosts.find((h) => h.id === sh.hostId) : null;
        return host && /windows/i.test(host.os || '') ? 'windows' : 'linux';
      });
      const localScanners = computed(
        () => R.scanners.filter((s) => s.platform === targetPlatform.value));
      const currentShell = computed(
        () => S.state.shells.find((x) => x.id === R.shellId) || null);
      const isReverse = computed(() => !!currentShell.value && currentShell.value.kind === 'reverse');
      const scanning = computed(() => live.status === 'running' || live.status === 'starting');
      const scanResult = computed(() => live.result);
      const liveLines = computed(() => live.lines);
      /* 目标暂存目录默认值提示（留空时后端用这个） */
      const defaultRemoteDir = computed(
        () => targetPlatform.value === 'windows'
          ? 'C:\\Windows\\Temp\\.pivothub-recon'
          : '/tmp/.pivothub-recon');

      /* 拉取 tools/ 内置扫描器（fscan 等） */
      function loadScanners() {
        PivotAPI.get('/api/recon/scanners')
          .then((out) => {
            R.scanners = (out && out.tools) || [];
            const first = R.scanners.filter((s) => s.platform === targetPlatform.value)[0];
            if (first && !R.localScanner) R.localScanner = first.key;
            if (R.scanners.length && R.scannerMode === 'builtin' && !R.scannerB64) {
              R.scannerMode = 'local';
            }
          })
          .catch(() => { R.scanners = []; });
      }

      /* 初始会话：优先跟随 Shell 管理里选中的，否则第一个存活会话 */
      if (!R.shellId) {
        const list = shells.value;
        const keep = list.find((s) => s.id === ui.selectedShellId);
        R.shellId = keep ? keep.id : ((list.find((s) => s.alive) || list[0] || {}).id || null);
      }
      loadScanners();
      watch(shells, () => {
        const list = shells.value;
        if (!list.length) { R.shellId = null; return; }
        if (!list.some((s) => s.id === R.shellId)) R.shellId = list[0].id;
      });
      watch(() => R.shellId, (v) => { if (v) ui.selectedShellId = v; });

      const selectedCount = computed(
        () => Object.keys(R.selected).filter((k) => R.selected[k]).length);
      const allSelected = computed(() => {
        const hs = (scanResult.value && scanResult.value.hosts) || [];
        return hs.length > 0 && hs.every((h) => R.selected[h.ip]);
      });

      /* ---------- ① 信息收集 ---------- */
      function loadEnv() {
        if (!R.shellId || R.envLoading) return;
        R.envLoading = true;
        R.envError = '';
        PivotAPI.post('/api/recon/env', { shellId: R.shellId })
          .then((out) => {
            R.envLoading = false;
            if (!out || out.ok === false) {
              R.envError = (out && out.error) || '信息收集失败';
              return;
            }
            R.env = out;
            if (!R.segment && out.segments && out.segments.length) R.segment = out.segments[0];
          })
          .catch((e) => {
            R.envLoading = false;
            R.envError = String((e && e.message) || e);
          });
      }

      /* ---------- ② 扫描器选择与扫描（流式） ---------- */
      function pickScanner() {
        const input = document.createElement('input');
        input.type = 'file';
        input.style.display = 'none';
        document.body.appendChild(input);
        const cleanup = () => { if (input.parentNode) input.parentNode.removeChild(input); };
        input.onchange = () => {
          const f = input.files && input.files[0];
          cleanup();
          if (!f) return;
          const reader = new FileReader();
          reader.onload = () => {
            const bytes = new Uint8Array(reader.result);
            let bin = '';
            const CHUNK = 0x8000;
            for (let i = 0; i < bytes.length; i += CHUNK) {
              bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
            }
            R.scannerName = f.name;
            R.scannerSize = f.size;
            R.scannerB64 = btoa(bin);
            R.scannerMode = 'upload';
            S.toast('已选择扫描器 ' + f.name + '（' + fmtSize(f.size) + '）', 'ok');
          };
          reader.readAsArrayBuffer(f);
        };
        input.oncancel = cleanup;
        input.click();
      }

      function scrollLog() {
        nextTick(() => { if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight; });
      }
      watch(() => live.lines.length, scrollLog);

      /* 轮询兜底：WS 丢帧 / 页面切换后补全状态（日志仍以 WS 为准，按 seq 去重合并） */
      function stopPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
      function applySnapshot(snap) {
        if (!snap) return;
        if (Array.isArray(snap.lines)) {
          const last = live.lines.length ? live.lines[live.lines.length - 1].seq || 0 : 0;
          snap.lines.forEach((r) => {
            if (!r.seq || r.seq > last) live.lines.push({ kind: r.kind, line: r.line, seq: r.seq });
          });
          if (live.lines.length > 4000) live.lines.splice(0, live.lines.length - 4000);
        }
        if (snap.status) live.status = snap.status;
        if (snap.elapsed != null) live.elapsed = snap.elapsed;
        if (snap.status !== 'running' && snap.status !== 'starting') {
          live.result = {
            ok: snap.status === 'done', error: snap.error || '',
            hosts: snap.hosts || [], cmd: snap.cmd || '',
            scannerPath: snap.scannerPath || '', cached: !!snap.cached,
            ms: snap.ms || 0, timedOut: !!snap.timedOut, output: snap.output || '',
          };
          live.error = snap.error || '';
          stopPoll();
          scrollLog();
        }
      }
      function startPoll() {
        stopPoll();
        pollTick = 0;
        pollTimer = setInterval(() => {
          if (live.status !== 'running' && live.status !== 'starting') { stopPoll(); return; }
          if (live.startedAt) live.elapsed = Math.round((Date.now() - live.startedAt) / 1000);
          pollTick += 1;
          if (pollTick % 2 === 0 && live.jobId) {
            S.reconScanJob(live.jobId).then((snap) => { if (snap) applySnapshot(snap); });
          }
        }, 1000);
      }

      function runScan() {
        if (scanning.value || !R.shellId || !R.segment) return;
        R.selected = {};
        S.reconScanStream({
          shellId: R.shellId,
          segment: R.segment.trim(),
          ports: R.ports,
          timeoutS: R.timeoutS,
          localScanner: R.scannerMode === 'local' ? R.localScanner : '',
          scannerName: R.scannerMode === 'upload' ? R.scannerName : '',
          scannerB64: R.scannerMode === 'upload' ? R.scannerB64 : '',
          forceUpload: R.forceUpload,
          probeTitles: R.probeTitles,
          template: R.template,
          extraArgs: R.extraArgs,
          remoteDir: R.remoteDir,
        }).then((out) => {
          if (!out || !out.ok) {
            S.toast('扫描未启动：' + ((out && out.error) || '未知原因'), 'err');
            return;
          }
          if (!isReverse.value) {
            S.toast('扫描任务已启动（HTTP 马无流式回显，建议改用反弹 Shell 会话）', 'warn');
          } else {
            S.toast('扫描任务已启动，日志实时推送到面板与交互终端', 'ok');
          }
          startPoll();
        });
      }

      function cancelScan() {
        if (!live.jobId) return;
        S.reconScanCancel(live.jobId).then((out) => {
          S.toast(out && out.ok ? '已请求取消扫描' : '取消失败（任务可能已结束）',
            out && out.ok ? 'info' : 'err');
        });
      }

      /* 打开该会话的交互终端：后续扫描日志实时显示在终端里 */
      function openTerminal() {
        if (!R.shellId) { S.toast('请先选择会话', 'err'); return; }
        S.openTerminalById(R.shellId);
        S.toast('已打开交互终端，扫描日志会实时显示', 'info');
      }

      function clearLog() { live.lines = []; }

      /* 结果到达 → 未入库的主机默认勾选 */
      watch(() => live.result, (res) => {
        if (!res || !res.hosts) return;
        const sel = {};
        res.hosts.forEach((h) => { sel[h.ip] = !knownSet.value[h.ip]; });
        R.selected = sel;
        if (res.ok) {
          S.toast('扫描完成：发现 ' + res.hosts.length + ' 台主机', 'ok');
        } else if (!res.error) {
          S.toast('扫描结束：发现 ' + res.hosts.length + ' 台主机', 'warn');
        } else {
          S.toast('扫描未完成：' + res.error, 'err');
        }
      }, { deep: false });

      /* ---------- ③ 勾选导入 ---------- */
      function toggleAll() {
        const hs = (scanResult.value && scanResult.value.hosts) || [];
        const next = !allSelected.value;
        hs.forEach((h) => { R.selected[h.ip] = next; });
      }

      function importSelected() {
        const hs = ((scanResult.value && scanResult.value.hosts) || [])
          .filter((h) => R.selected[h.ip]);
        if (!hs.length) return;
        const shell = S.state.shells.find((s) => s.id === R.shellId) || {};
        R.importing = true;
        PivotAPI.post('/api/recon/import', {
          projectId: S.state.projectId,
          fromHostId: shell.hostId || '',
          hosts: hs.map((h) => ({
            ip: h.ip,
            ports: h.ports,
            hostname: h.hostname,
            note: [h.note, titleText(h)].filter(Boolean).join(' · '),
          })),
        }).then((out) => {
          R.importing = false;
          if (!out) { S.toast('导入失败：空响应', 'err'); return; }
          S.toast('已导入 ' + out.added + ' 台主机'
            + (out.skipped ? '（跳过 ' + out.skipped + '）' : '') + '，已上拓扑', 'ok');
          R.selected = {};
          S.refreshState();
        }).catch((e) => {
          R.importing = false;
          S.toast('导入失败：' + String((e && e.message) || e), 'err');
        });
      }

      /* 选中的本地扫描器带默认模板（fscan → -nobr）时自动填入 */
      watch([() => R.localScanner, () => R.scannerMode], () => {
        if (R.scannerMode !== 'local') return;
        const s = R.scanners.find((x) => x.key === R.localScanner);
        if (s && s.template && !R.template) R.template = s.template;
      });

      /* 页面切回来时若任务仍在跑，恢复轮询 */
      if (scanning.value && live.jobId) startPoll();

      return {
        ...toRefs(R),
        ui, live, logEl, shells, knownSet, selectedCount, allSelected, targetPlatform, localScanners,
        currentShell, isReverse, scanning, scanResult, liveLines, defaultRemoteDir,
        ipOf: S.ipOf, goto: S.goto, defaultTemplate: DEFAULT_TEMPLATE, icon: global.icon,
        portText, titleText,
        loadEnv, loadScanners, pickScanner, runScan, cancelScan, openTerminal, clearLog,
        toggleAll, importSelected, fmtSize,
      };
    },
  };
})(window);
