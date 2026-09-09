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
  S.init();

  const app = Vue.createApp({
    name: 'PivotHubApp',
    template: '#tpl-app',
    setup() {
      /* ---------- 全局设置：攻击机网络（面板所在机器就是攻击机） ---------- */
      const gcfg = Vue.reactive({
        ip: '', iface: '', segment: '', note: '',
        applyAll: true, detecting: false, detected: [],
      });

      function openGlobalSettings() {
        const a = S.state.attack || {};
        gcfg.ip = a.ip || '';
        gcfg.iface = a.iface || '';
        gcfg.segment = a.segment || '';
        gcfg.note = a.note || '';
        gcfg.detected = [];
        gcfg.applyAll = true;
        S.state.ui.modal = 'global-cfg';
      }

      function detectLocalIp() {
        gcfg.detecting = true;
        S.netinfo().then((out) => {
          gcfg.detecting = false;
          gcfg.detected = (out && out.ips) || [];
          if (gcfg.detected.length) {
            gcfg.ip = gcfg.detected[0];
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
        gcfg, openGlobalSettings, detectLocalIp, saveGlobalSettings,
        fileEdit: S.fileEdit, saveFileEdit: S.saveFileEdit, closeFileEdit: S.closeFileEdit,
      };
    },
  });

  Object.keys(global.Components).forEach((name) => {
    app.component(name, global.Components[name]);
  });

  app.mount('#app');
})(window);
