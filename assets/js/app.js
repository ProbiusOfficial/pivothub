/* ============================================================
   应用入口 — 组装外壳、注册视图组件、挂载
   ============================================================ */
(function (global) {
  'use strict';

  if (!global.Vue) {
    document.getElementById('app').innerHTML =
      '<div class="boot-screen"><div class="boot-logo">PivotHub</div>' +
      '<div class="boot-text">Vue 3 加载失败，请检查网络或改为本地依赖（assets/vendor/vue.global.prod.js）</div></div>';
    return;
  }
  if (!global.echarts) {
    console.warn('[PivotHub] ECharts 未加载，拓扑图将不可用。');
  }

      const S = PivotStore;
      /* 面板由后端托管，location.host 即后端地址（换端口 / 远程访问时不再写死） */
      const backendAddr = global.location.host || '127.0.0.1:8000';
  S.init();

  const app = Vue.createApp({
    name: 'PivotHubApp',
    template: '#tpl-app',
    setup() {
      /* ---------- 全局设置：攻击机网络（面板所在机器就是攻击机） ---------- */
      const gcfg = Vue.reactive({
        ip: '', iface: '', segment: '', note: '',
        applyAll: true, detecting: false, detected: [], ifaces: [],
      });

      /* 网段候选：本机各网卡所在网段 + 当前项目已知网段（去重） */
      const gcfgSegments = Vue.computed(() => {
        const set = new Set();
        (gcfg.ifaces || []).forEach((it) => { if (it.segment) set.add(it.segment); });
        (S.state.segments || []).forEach((sg) => { if (sg.segment) set.add(sg.segment); });
        return [...set];
      });

      /* 静默拉一次本机网卡列表，供网卡/网段下拉框使用（不覆盖已填的 IP） */
      function loadIfaces() {
        S.netinfo().then((out) => {
          gcfg.ifaces = (out && out.interfaces) || [];
          gcfg.detected = (out && out.ips) || [];
        }).catch(() => { /* 后端不可用时保持手工输入 */ });
      }

      function onIfaceSelect(v) {
        if (v === '__custom__') {
          const cur = window.prompt('输入网卡名（如 tun0 / eth0 / WLAN）', gcfg.iface || '');
          if (cur != null) gcfg.iface = cur.trim();
          return;
        }
        gcfg.iface = v;
        const hits = (gcfg.ifaces || []).filter((it) => it.name === v);
        const hit = hits.find((it) => it.ip === gcfg.ip) || hits[0];
        if (hit) {
          gcfg.ip = hit.ip;
          if (hit.segment) gcfg.segment = hit.segment;
        }
      }

      function onSegmentSelect(v) {
        if (v === '__custom__') {
          const cur = window.prompt('输入网段（CIDR，如 10.0.0.0/24）', gcfg.segment || '');
          if (cur != null) gcfg.segment = cur.trim();
          return;
        }
        gcfg.segment = v;
      }

      function openGlobalSettings() {
        const a = S.state.attack || {};
        gcfg.ip = a.ip || '';
        gcfg.iface = a.iface || '';
        gcfg.segment = a.segment || '';
        gcfg.note = a.note || '';
        gcfg.detected = [];
        gcfg.ifaces = [];
        gcfg.applyAll = true;
        S.state.ui.modal = 'global-cfg';
        loadIfaces();
      }

      function detectLocalIp() {
        gcfg.detecting = true;
        S.netinfo().then((out) => {
          gcfg.detecting = false;
          gcfg.detected = (out && out.ips) || [];
          gcfg.ifaces = (out && out.interfaces) || [];
          if (gcfg.detected.length) {
            gcfg.ip = gcfg.detected[0];
            const hit = gcfg.ifaces.find((it) => it.ip === gcfg.ip);
            if (hit) {
              gcfg.iface = hit.name;
              if (hit.segment) gcfg.segment = hit.segment;
            }
            S.toast('已填入本机地址 ' + gcfg.ip + '（共检测到 ' + gcfg.detected.length + ' 个）', 'ok');
          } else {
            S.toast('未检测到非回环 IPv4 地址（请手工填写靶场网络内的地址）', 'warn');
          }
        });
      }

      function saveGlobalSettings() {
        const cfg = {
          ip: String(gcfg.ip || '').trim(),
          iface: gcfg.iface, segment: gcfg.segment, note: gcfg.note,
        };
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(cfg.ip)) {
          S.toast('请填写合法的攻击机 IPv4 地址', 'err');
          return;
        }
        const others = gcfg.applyAll
          ? S.state.projects.filter((p) => p.id !== S.state.projectId)
          : [];
        S.saveAttack(cfg, (ok) => {
          if (!ok) return;
          if (!others.length) {
            S.state.ui.modal = null;
            S.toast('攻击机网络已保存', 'ok');
            return;
          }
          Promise.all(others.map((p) => S.saveAttackFor(p.id, cfg).catch(() => null))).then((rs) => {
            const bad = rs.filter((x) => !x).length;
            S.state.ui.modal = null;
            S.toast('攻击机网络已保存，并同步到 ' + (others.length - bad) + '/' + others.length + ' 个其他项目',
              bad ? 'warn' : 'ok');
          });
        });
      }

      return {
        ui: S.state.ui,
        ws: S.state.ws,
        backendAddr,
        timer: S.state.timer,
        stats: S.stats,
        clockText: S.clockText,
        project: S.state.project,
        projects: S.state.projects,
        navGroups: S.navGroups,
        projectId: Vue.computed({
          get: () => S.state.projectId,
          set: (v) => {
            S.state.projectId = v;
            const p = S.state.projects.find((x) => x.id === v);
            if (p) S.state.project.name = p.name;
            S.toast('已切换项目：' + (p ? p.name : v), 'info');
          },
        }),
        icon: global.icon,
        navBadge: S.navBadge,
        toggleTimer: S.toggleTimer,
        createProject: S.createProject,
        deleteProject: S.deleteProject,
        gcfg, gcfgSegments, openGlobalSettings, loadIfaces, onIfaceSelect, onSegmentSelect,
        detectLocalIp, saveGlobalSettings,
        fileEdit: S.fileEdit, saveFileEdit: S.saveFileEdit, closeFileEdit: S.closeFileEdit,
      };
    },
  });

  Object.keys(global.Components).forEach((name) => {
    app.component(name, global.Components[name]);
  });

  app.mount('#app');
})(window);
