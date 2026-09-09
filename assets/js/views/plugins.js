/* ============================================================
   插件市场 — 数据插件（命令库 / 马模板 / 固化技法 / 提权规则）
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, computed } = Vue;
  const S = PivotStore;

  const TYPE_LABEL = {
    commands: '命令库', payloads: '马模板', tty_fixes: '固化技法',
    privesc: '提权规则', adapter: 'Adapter',
  };

  global.Components['plugins-view'] = {
    name: 'PluginsView',
    template: '#tpl-plugins',
    setup() {
      const ui = S.state.ui;
      const items = ref([]);
      const source = ref('');
      const remoteError = ref('');
      const busyId = ref('');
      const filter = ref('all');

      const typeLabel = (t) => TYPE_LABEL[t] || t || '插件';
      const filtered = computed(() => {
        const f = filter.value;
        return items.value.filter((p) => (f === 'all' ? true
          : f === 'installed' ? p.installed : p.type === f));
      });
      const installedCount = computed(() => items.value.filter((p) => p.installed).length);

      function load() {
        S.pluginsList().then((out) => {
          items.value = (out && out.items) || [];
          source.value = (out && out.registrySource) || '';
          remoteError.value = (out && out.remoteError) || '';
        });
      }

      function afterChange(msg) {
        busyId.value = '';
        load();
        S.refreshState();  /* 插件贡献的命令/规则需要整包重载才可见 */
        S.toast(msg, 'ok');
      }

      function install(p) {
        busyId.value = p.id;
        S.pluginInstall(p.id).then((out) => {
          if (!out || !out.ok) { busyId.value = ''; S.toast('安装失败（清单不可达或内容不合法）', 'err'); return; }
          afterChange('已安装插件：' + p.name);
        });
      }

      function toggle(p) {
        busyId.value = p.id;
        S.pluginToggle(p.id, !p.enabled).then((out) => {
          if (!out || !out.ok) { busyId.value = ''; S.toast('操作失败', 'err'); return; }
          afterChange((p.enabled ? '已停用：' : '已启用：') + p.name);
        });
      }

      function uninstall(p) {
        if (!window.confirm('卸载插件「' + p.name + '」？其贡献的命令/规则将立即从面板消失。')) return;
        busyId.value = p.id;
        S.pluginUninstall(p.id).then((out) => {
          if (!out || !out.ok) { busyId.value = ''; S.toast('卸载失败', 'err'); return; }
          afterChange('已卸载插件：' + p.name);
        });
      }

      load();

      return {
        ui, items, source, remoteError, busyId, filter, filtered, installedCount, typeLabel,
        load, install, toggle, uninstall, icon: global.icon,
      };
    },
  };
})(window);
