/* ============================================================
   文件管理视图 — 选会话 / 浏览目录 / 在线编辑 / 上传下载
   所有操作经会话层真实落到目标机，不做本地模拟。
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed, watch } = Vue;
  const S = PivotStore;

  global.Components['files-view'] = {
    name: 'FilesView',
    template: '#tpl-files',
    setup() {
      const ui = S.state.ui;

      /* 会话下拉：存活会话排前 */
      const shells = computed(() => S.state.shells.slice()
        .sort((a, b) => (b.alive ? 1 : 0) - (a.alive ? 1 : 0)));

      const shellId = ref(null);
      const fs = reactive(S.fileStateFor(null));
      const pathInput = ref('');

      function pickDefault() {
        const list = shells.value;
        const keep = list.find((s) => s.id === shellId.value);
        if (keep) return keep.id;
        const alive = list.find((s) => s.alive);
        return alive ? alive.id : (list[0] ? list[0].id : null);
      }

      function load() {
        Object.assign(fs, S.fileStateFor(shellId.value));
        pathInput.value = '';
        if (shellId.value) {
          S.refreshFileEntries(fs);
          S.detectPullTools(fs, true); /* 静默探测目标可用下载工具，供「HTTP 拉取」展示 */
        }
      }

      /* 初始选择：优先跟随 Shell 管理里选中的会话 */
      shellId.value = pickDefault();
      watch(shellId, () => { ui.selectedShellId = shellId.value; load(); }, { immediate: true });
      watch(shells, () => {
        const next = pickDefault();
        if (next !== shellId.value) shellId.value = next;
      });

      function enter(f) { S.cdInto(fs, f.name); }
      function cd(i) { S.cdIndex(fs, i); }
      function up() { S.cdUp(fs); }
      function go() { S.cdTo(fs, pathInput.value); }
      function refresh() { S.refreshFileEntries(fs); }
      function open(f) {
        if (S.isApiMode() && S.readFile(f, fs)) return;
        S.toast('读取失败：后端不可用', 'err');
      }
      function download(f) { S.downloadFile(f, fs); }
      function upload() { S.pickAndUpload(fs); }
      function setMode(m) { S.setUploadMode(m); }
      function detectTools() { S.detectPullTools(fs); }

      return {
        ui, fs, shellId, shells, pathInput,
        uploadMode: S.uploadMode, uploadModeText: S.uploadModeText,
        ipOf: S.ipOf, icon: global.icon, goto: S.goto,
        enter, cd, up, go, refresh, open, download, upload, setMode, detectTools,
      };
    },
  };
})(window);
