/* ============================================================
   操作时间线 — 自动事件 + 手动笔记（Markdown）
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, ref, computed } = Vue;
  const S = PivotStore;

  global.Components['timeline-view'] = {
    name: 'TimelineView',
    template: '#tpl-timeline',
    setup() {
      const ui = S.state.ui;
      const kindFilter = ref('');
      const hostFilter = ref('');
      const kinds = ['shell', 'proxy', 'host', 'cred', 'flag', 'note'];

      const form = reactive({ title: '', hostId: '', cmd: '', markdown: '' });

      const filtered = computed(() =>
        S.state.timeline
          .filter((e) => (kindFilter.value ? e.kind === kindFilter.value : true))
          .filter((e) => (hostFilter.value ? e.hostId === hostFilter.value : true))
      );

      function openNote() {
        const d = ui.modalData || {};
        form.hostId = d.hostId || '';
        form.title = '';
        form.cmd = '';
        form.markdown = '';
        ui.modal = 'note-add';
      }
      function save() {
        if (!form.title.trim()) { S.toast('请填写标题', 'err'); return; }
        S.addNote(form);
        ui.modal = null;
      }
      function focusHost(id) {
        S.selectHost(id);
        S.goto('topology');
      }

      return {
        ui, kindFilter, hostFilter, kinds, form, filtered,
        hosts: S.state.hosts,
        ipOf: S.ipOf, kindLabel: S.kindLabel, kindBadge: S.kindBadge, md: S.md,
        openNote, save, focusHost,
      };
    },
  };
})(window);
