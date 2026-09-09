/* ============================================================
   凭据库视图 — 凭据登记 / 复用推荐 / 横向尝试
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, ref, computed } = Vue;
  const S = PivotStore;

  global.Components['cred-view'] = {
    name: 'CredView',
    template: '#tpl-cred',
    setup() {
      const ui = S.state.ui;
      const filter = ref('');
      const targetHostId = ref(S.state.hosts[6] ? S.state.hosts[6].id : S.state.hosts[0].id);

      const form = reactive({
        username: '', kind: '密码', secret: '', hostId: S.state.hosts[1] ? S.state.hosts[1].id : '',
        services: '', source: '',
      });

      const creds = computed(() => S.state.creds);
      const filtered = computed(() => {
        const q = filter.value.trim().toLowerCase();
        if (!q) return S.state.creds;
        return S.state.creds.filter((c) =>
          [c.username, c.kind, (c.services || []).join(','), c.source, S.ipOf(c.hostId)].join(' ').toLowerCase().indexOf(q) >= 0
        );
      });
      const reuseCount = computed(() => S.state.creds.filter((c) => c.reuse).length);
      const pwnedCount = computed(() => S.state.hosts.filter((h) => h.owned && !h.isLocal).length);

      /* ---------- 凭据复用推荐（按网段 / 域 / 服务匹配打分） ---------- */
      const recommendations = computed(() => {
        const target = S.hostOf(targetHostId.value);
        if (!target) return [];
        const targetIsDomain = /supercorp|\.local|DC0/i.test((target.hostname || '') + (target.note || ''));
        return S.state.creds
          .filter((c) => c.hostId !== target.id)
          .map((c) => {
            const src = S.hostOf(c.hostId) || {};
            let score = 0;
            const reasons = [];
            if (src.segment === target.segment) { score += 40; reasons.push('同网段 ' + target.segment); }
            if (targetIsDomain && /supercorp|administrator|svc_/i.test(c.username)) { score += 35; reasons.push('域账号，可用于域内横向'); }
            const overlap = (c.services || []).filter((s) => (target.services || []).includes(s));
            if (overlap.length) { score += 20; reasons.push('服务匹配：' + overlap.join('/')); }
            if (c.kind === 'NTLM 哈希') { score += 15; reasons.push('哈希可直接 PtH，无需明文'); }
            if (c.kind === '密码' && /root|administrator|admin/i.test(c.username)) { score += 10; reasons.push('高权限账号'); }
            if (c.reuse) score += 5;
            return Object.assign({}, c, {
              score: Math.min(99, score),
              reason: reasons.length ? reasons.join('；') : '弱关联，建议先做口令喷洒验证',
            });
          })
          .filter((c) => c.score > 0)
          .sort((a, b) => b.score - a.score)
          .slice(0, 5);
      });

      function openAdd() {
        const d = ui.modalData || {};
        if (d.hostId) form.hostId = d.hostId;
        ui.modal = 'cred-add';
      }
      function save() {
        if (!form.username || !form.secret) { S.toast('账号与凭据内容不能为空', 'err'); return; }
        S.addCred(form);
        ui.modal = null;
        form.username = ''; form.secret = ''; form.services = ''; form.source = '';
      }
      function useOn(c, hostId) {
        const target = S.hostOf(hostId || targetHostId.value) || {};
        /* 横向必须由真实执行产生结果，这里只给操作指引 */
        S.toast('横向到 ' + target.ip + ' 需要真实执行：请在 Shell 管理里用该凭据登录，或改用「代理编排台」建隧道', 'info');
      }

      return {
        ui, filter, targetHostId, form, creds, filtered, recommendations, reuseCount, pwnedCount,
        hosts: S.state.hosts, kinds: S.state.credKinds || [],
        ipOf: S.ipOf, copy: S.copy, openAdd, save, useOn,
      };
    },
  };
})(window);
