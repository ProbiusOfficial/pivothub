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

      /* A12：标记已交 / 撤销（PATCH 持久化，不再只改本地状态） */
      function toggleSubmitted(f) {
        const next = !f.submitted;
        f.submitted = next;   /* 乐观更新，失败再回滚 */
        S.updateFlag(f.id, { submitted: next }).then((item) => {
          if (!item) { f.submitted = !next; S.toast('更新提交状态失败', 'err'); }
          else S.toast(next ? '已标记提交' : '已撤销提交', 'ok');
        });
      }
      /* A12：编辑（改绑主机 / 阶段 / 内容 / 备注） */
      const edit = reactive({ id: '', hostId: '', stage: '', value: '', note: '', busy: false });
      function openEdit(f) {
        edit.id = f.id; edit.hostId = f.hostId; edit.stage = f.stage;
        edit.value = f.value; edit.note = f.note || ''; edit.busy = false;
        ui.modal = 'flag-edit';
      }
      function saveEdit() {
        if (!edit.value.trim()) { S.toast('Flag 内容不能为空', 'err'); return; }
        edit.busy = true;
        S.updateFlag(edit.id, {
          hostId: edit.hostId, stage: edit.stage, value: edit.value, note: edit.note,
        }).then((item) => {
          edit.busy = false;
          if (!item) { S.toast('保存失败（改绑主机须属于同一项目）', 'err'); return; }
          S.toast('Flag 已更新', 'ok');
          ui.modal = null;
        });
      }
      /* A12：删除 */
      function del(f) {
        if (!window.confirm('确认删除该 Flag？\n' + f.value)) return;
        S.removeFlag(f.id).then((out) => {
          S.toast(out ? 'Flag 已删除' : '删除失败', out ? 'ok' : 'err');
        });
      }

      /* A12：阶段自定义 —— 项目级阶段名（Flag 墙分组统计与下拉的数据源） */
      const stageEdit = reactive({ list: [], busy: false });
      function openStages() {
        stageEdit.list = (S.state.stageNames || []).slice();
        stageEdit.busy = false;
        ui.modal = 'stage-edit';
      }
      function addStage() { stageEdit.list.push(''); }
      function removeStage(i) { stageEdit.list.splice(i, 1); }
      function saveStages() {
        const clean = stageEdit.list.map((x) => String(x || '').trim()).filter(Boolean);
        if (!clean.length) { S.toast('至少保留一个阶段名（或点「恢复默认」）', 'err'); return; }
        stageEdit.busy = true;
        S.saveStages(clean, (ok) => { stageEdit.busy = false; if (ok) ui.modal = null; });
      }
      function resetStages() {
        stageEdit.busy = true;
        S.saveStages([], (ok) => { stageEdit.busy = false; if (ok) ui.modal = null; });
      }

      return {
        ui, form, flags, total, submitted, ringBg, stages,
        hosts: S.state.hosts, stageNames: S.state.stageNames || [],
        ipOf: S.ipOf, hostnameOf: S.hostnameOf, copy: S.copy, openAdd, save,
        toggleSubmitted, edit, openEdit, saveEdit, del,
        stageEdit, openStages, addStage, removeStage, saveStages, resetStages,
        icon: global.icon,
      };
    },
  };
})(window);
