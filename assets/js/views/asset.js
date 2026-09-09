/* ============================================================
   资产列表视图 — 资产登记 / 搜索过滤 / 扫描结果导入 / 移除
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, ref, computed } = Vue;
  const S = PivotStore;

  global.Components['asset-view'] = {
    name: 'AssetView',
    template: '#tpl-asset',
    setup() {
      const ui = S.state.ui;
      const filter = ref('');
      const layerFilter = ref('');
      const scanText = ref('');

      const form = reactive({
        ip: '', hostname: '', os: 'Linux', layer: 'L2',
        segment: '10.85.101.0/24', privilege: '', services: '', note: '',
      });

      const layers = computed(() => S.state.layers || []);
      const filtered = computed(() => {
        const q = filter.value.trim().toLowerCase();
        return S.state.hosts
          .filter((h) => !h.isLocal)
          .filter((h) => (layerFilter.value ? h.layer === layerFilter.value : true))
          .filter((h) => {
            if (!q) return true;
            return [h.ip, h.hostname, h.os, (h.services || []).join(','), h.note, h.privilege]
              .join(' ').toLowerCase().indexOf(q) >= 0;
          });
      });

      const ownedCount = computed(() => S.state.hosts.filter((h) => h.owned && !h.isLocal).length);
      const serviceCount = computed(() => {
        const set = new Set();
        S.state.hosts.forEach((h) => (h.services || []).forEach((s) => set.add(s)));
        return set.size;
      });
      const rootCount = computed(() => S.state.hosts.filter((h) => /root|system|administrator/i.test(h.privilege || '')).length);
      const scanPreview = computed(() => {
        const n = String(scanText.value).split(/\r?\n/).filter((l) => /^\d+\.\d+\.\d+\.\d+/.test(l.trim())).length;
        return '将解析 ' + n + ' 条记录';
      });

      function openAdd() { ui.modal = 'host-add'; }
      function save() {
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(form.ip)) { S.toast('请输入合法 IP', 'err'); return; }
        S.addHost(form);
        ui.modal = null;
        form.ip = ''; form.hostname = ''; form.privilege = ''; form.services = ''; form.note = '';
      }
      function importScan() { ui.modal = 'scan-import'; }
      function doImport() { S.importScan(scanText.value); ui.modal = null; }
      function focus(h) {
        S.selectHost(h.id);
        S.goto('topology');
        S.toast('已定位到 ' + h.ip, 'info');
      }
      function openCred(hostId) { S.openModal('cred-add', { data: { hostId } }); }

      /* 移除资产：连带会话 / 链路 / 凭据 / Flag，先确认再删 */
      function remove(h) {
        const shells = S.shellsOf(h.id).length;
        const extra = [];
        if (shells) extra.push(shells + ' 个会话');
        const links = S.linksOf(h.id).length;
        if (links) extra.push(links + ' 条链路');
        const creds = S.credsOf(h.id).length;
        if (creds) extra.push(creds + ' 条凭据');
        const flags = S.flagsOf(h.id).length;
        if (flags) extra.push(flags + ' 个 Flag');
        const tip = extra.length ? '，并连带删除 ' + extra.join(' / ') : '';
        if (!global.confirm('移除资产 ' + h.ip + (h.hostname ? '（' + h.hostname + '）' : '') + tip + '？')) return;
        S.removeHost(h);
      }

      return {
        ui, filter, layerFilter, layers, filtered, form, scanText, scanSample: S.state.scanSample,
        ownedCount, serviceCount, rootCount, scanPreview,
        hosts: S.state.hosts, segments: S.state.segments,
        shellsOf: S.shellsOf, flagsOf: S.flagsOf, privClass: S.privClass,
        openAdd, save, importScan, doImport, focus, openCred, remove,
      };
    },
  };
})(window);
