/* ============================================================
   Flag 收集墙 — 记录 / 一键复制提交 / 阶段完成度
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed } = Vue;
  const S = PivotStore;

  global.Components['flag-view'] = {
    name: 'FlagView',
    template: '#tpl-flag',
    setup() {
      const ui = S.state.ui;
      const total = S.stats.value.flagsTotal;

      const form = reactive({
        hostId: S.state.hosts[1] ? S.state.hosts[1].id : '',
        stage: 'L1 入口', value: '', submitted: false,
      });

      const flags = computed(() => S.state.flags);
      const submitted = computed(() => S.state.flags.filter((f) => f.submitted).length);
      const ringBg = computed(() => {
        const p = Math.round((submitted.value / total) * 100);
        return 'conic-gradient(var(--ok) 0% ' + p + '%, var(--border) ' + p + '% 100%)';
      });
      const stages = computed(() =>
        (S.state.stageNames || []).map((name) => ({
          name,
          got: S.state.flags.filter((f) => f.stage === name).length,
          total: 2,
        }))
      );

      function openAdd() { ui.modal = 'flag-add'; }
      function save() {
        if (!form.value.trim()) { S.toast('请填写 Flag 内容', 'err'); return; }
        S.addFlag(form);
        ui.modal = null;
        form.value = ''; form.submitted = false;
      }

      return {
        ui, form, flags, total, submitted, ringBg, stages,
        hosts: S.state.hosts, stageNames: S.state.stageNames || [],
        ipOf: S.ipOf, hostnameOf: S.hostnameOf, copy: S.copy, openAdd, save,
        icon: global.icon,
      };
    },
  };
})(window);
