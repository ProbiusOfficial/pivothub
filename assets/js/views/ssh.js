/* ============================================================
   SSH 会话视图 — 独立于 Shell 管理
   ① 独立新建（真实连接测试通过才落库）② 从 Shell 管理「提升为 SSH 会话」
   纳管后是标准 Shell 记录（kind=ssh），可复用交互终端 / 文件管理 / 心跳
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed, watch } = Vue;
  const S = PivotStore;

  global.Components['ssh-view'] = {
    name: 'SshView',
    template: '#tpl-ssh',
    setup() {
      const ui = S.state.ui;

      const form = reactive({
        host: '', port: 22, username: 'root', password: '', hostId: '',
        platform: '', autoHost: true, testResult: null, busy: false,
        fromShellId: '',      /* 来自「提升」时的来源会话（仅作提示） */
      });

      /* 只展示 SSH 会话：Shell 管理仍显示全部会话，互不影响 */
      const sessions = computed(() =>
        S.state.shells.filter((s) => s.kind === 'ssh')
          .sort((a, b) => (b.alive ? 1 : 0) - (a.alive ? 1 : 0)));

      const aliveCount = computed(() => sessions.value.filter((s) => s.alive).length);

      function resetForm() {
        form.host = ''; form.port = 22; form.username = 'root'; form.password = '';
        form.hostId = ''; form.platform = ''; form.autoHost = true;
        form.testResult = null; form.busy = false; form.fromShellId = '';
      }

      function openAdd(preset) {
        resetForm();
        if (preset) Object.assign(form, preset);
        ui.modal = 'ssh-add';
      }

      /* 从 Shell 管理「提升」：预填该会话所属主机，凭据需用户填写（面板不猜） */
      function prefillFromShell(shell) {
        if (!shell) return {};
        const host = S.hostOf(shell.hostId) || {};
        const preset = { fromShellId: shell.id, host: host.ip || '', hostId: shell.hostId || '' };
        if (shell.platform === 'windows' || /windows/i.test(host.os || '')) preset.platform = 'windows';
        return preset;
      }

      /* 跳转携带 promoteShellId → 自动开弹窗预填并清标记（避免重复触发） */
      watch(() => ui.promoteShellId, (id) => {
        if (!id) return;
        const shell = S.state.shells.find((s) => s.id === id);
        openAdd(prefillFromShell(shell));
        ui.promoteShellId = null;
      }, { immediate: true });

      function saveSsh() {
        if (!form.host || !form.username) { S.toast('主机与用户名不能为空', 'err'); return; }
        if (form.busy) return;
        form.busy = true;
        form.testResult = { ok: true, msg: '正在连接 ' + form.username + '@' + form.host + '…' };
        S.sshCreate({
          host: form.host.trim(), port: Number(form.port) || 22,
          username: form.username.trim(), password: form.password,
          hostId: form.hostId || '', platform: form.platform || '',
          autoHost: form.autoHost !== false,
        }).then((out) => {
          form.busy = false;
          if (!out || !out.ok) {
            form.testResult = { ok: false, msg: (out && out.error) || 'SSH 连接失败' };
            S.toast('SSH 纳管失败：' + ((out && out.error) || '未知原因'), 'err');
            return;
          }
          form.testResult = { ok: true, msg: '连接成功 · ' + (out.hostname || '') + ' · ' + (out.platform || '') };
          S.toast('SSH 会话已纳管：' + form.username + '@' + form.host, 'ok');
          ui.modal = null;
          if (out.shell) ui.selectedShellId = out.shell.id;
          if (S.refreshState) S.refreshState();
        });
      }

      function test(s) { S.testShell(s); }
      function heartbeatAll() { S.heartbeatAll(); }
      function remove(s) {
        if (ui.selectedShellId === s.id) ui.selectedShellId = null;
        S.removeShell(s);
      }
      function openTerminal(s) {
        ui.selectedShellId = s.id;
        S.openTerminalById(s.id);
      }
      function latencyClass(s) {
        if (!s.alive) return 'muted';
        return s.latency < 80 ? 'text-ok' : s.latency < 200 ? 'text-warn' : 'text-err';
      }
      /* SSH 会话的 url 形如 ssh://user@host:port；解析出用户名与端口用于展示 */
      function userOf(s) {
        const m = /^ssh:\/\/([^@]+)@/.exec(s.url || '');
        return m ? m[1] : (s.url || '—');
      }
      function targetOf(s) {
        const m = /^ssh:\/\/[^@]+@(.+)$/.exec(s.url || '');
        return m ? m[1] : '';
      }

      return {
        ui, form, sessions, aliveCount,
        hosts: S.state.hosts,
        shells: S.state.shells,
        ipOf: S.ipOf, hostnameOf: S.hostnameOf, goto: S.goto, icon: global.icon,
        openAdd, saveSsh, test, remove, openTerminal, heartbeatAll, latencyClass,
        userOf, targetOf,
      };
    },
  };
})(window);
