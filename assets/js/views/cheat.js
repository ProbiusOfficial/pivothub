/* ============================================================
   命令速查库 — 分类检索 / 变量替换 / 发送到虚拟终端
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, computed } = Vue;
  const S = PivotStore;

  const CAT_ICONS = {
    信息收集: 'radar',
    'Linux 提权': 'cpu',
    'Windows 提权': 'shield',
    域渗透: 'user',
    横向移动: 'route',
    权限维持: 'key',
  };

  global.Components['cheat-view'] = {
    name: 'CheatView',
    template: '#tpl-cheat',
    setup() {
      const q = ref('');
      const cat = ref('');
      const ctxHostId = ref(S.state.hosts[5] ? S.state.hosts[5].id : S.state.hosts[0].id);

      /* ---------- 提权智能匹配（M5-2） ---------- */
      const psShells = computed(() => S.state.shells.filter((s) => s.alive));
      const psShellId = ref(((S.state.shells.find((s) => s.alive) || S.state.shells[0] || {}).id) || '');
      const psBusy = ref(false);
      const psResult = ref(null);

      function privescScan() {
        const id = psShellId.value || (psShells.value[0] || {}).id;
        if (!id) { S.toast('没有存活的 Shell 会话', 'err'); return; }
        psShellId.value = id;
        psBusy.value = true;
        S.privescScan(id).then((out) => {
          psBusy.value = false;
          if (!out || !out.ok) {
            S.toast('提权扫描失败：' + ((out && out.error) || '未知原因'), 'err');
            return;
          }
          psResult.value = out;
          S.toast('提权匹配完成：命中 ' + out.findings.length + ' 条',
            out.findings.length ? 'ok' : 'info');
        });
      }

      function execFinding(f) {
        const sid = psShellId.value;
        if (!sid) { S.toast('请先选择会话', 'err'); return; }
        const cmd = String(f.cmd || '').split(/\r?\n/).filter((l) => l.trim())[0];
        if (!cmd) return;
        S.state.ui.selectedShellId = sid;
        S.termState.inited = false;
        S.initTerm();
        S.execCommand(cmd);
        S.goto('shell');
        S.toast('已发送到终端：' + f.name, 'ok');
      }

      const commands = computed(() => S.state.commands);
      const categories = computed(() => {
        const map = {};
        S.state.commands.forEach((c) => { map[c.category] = (map[c.category] || 0) + 1; });
        return Object.keys(map).map((name) => ({ name, count: map[name], icon: CAT_ICONS[name] || 'book' }));
      });
      const filtered = computed(() => {
        const key = q.value.trim().toLowerCase();
        return S.state.commands
          .filter((c) => (cat.value ? c.category === cat.value : true))
          .filter((c) => (key ? (c.title + c.cmd + c.note + c.category + c.os).toLowerCase().indexOf(key) >= 0 : true));
      });

      function render(tpl) {        const h = S.hostOf(ctxHostId.value) || {};
        const seg = (h.segment || '10.85.101.0/24').split('.').slice(0, 3).join('.');
        return String(tpl)
          .replace(/\{IP\}/g, h.ip || '10.85.101.4')
          .replace(/\{SEG\}/g, seg)
          .replace(/\{DOMAIN\}/g, 'supercorp.local')
          .replace(/\{USER\}/g, 'svc_web')
          .replace(/\{PASS\}/g, 'P@ssw0rd2026!')
          .replace(/\{HASH\}/g, '8f3c1c2f9c1a...')
          .replace(/\{PUBKEY\}/g, 'ssh-rsa AAAAB3Nza...pivothub');
      }

      function copy(text) { S.copy(text); }

      function run(c) {
        const host = S.hostOf(ctxHostId.value) || {};
        const shell = S.state.shells.find((s) => s.hostId === host.id && s.alive) || S.state.shells[0];
        if (!shell) { S.toast('没有可用 Shell 会话', 'err'); return; }
        S.state.ui.selectedShellId = shell.id;
        S.termState.inited = false;
        S.initTerm();
        S.execCommand(render(c.cmd).split(/\r?\n/).filter((l) => l.trim())[0]);
        S.goto('shell');
        S.toast('命令已发送到虚拟终端', 'ok');
      }

      return {
        q, cat, ctxHostId, commands, categories, filtered,
        hosts: S.state.hosts,
        psShells, psShellId, psBusy, psResult, privescScan, execFinding,
        icon: global.icon,
        render, copy, run,
      };
    },
  };
})(window);
