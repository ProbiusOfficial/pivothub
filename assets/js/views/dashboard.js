/* ============================================================
   阶段看板 — 已控主机 / 层级深度 / Flag 进度 / 剩余时间 / 攻击路径
   ============================================================ */
(function (global) {
  'use strict';
  const { computed } = Vue;
  const S = PivotStore;

  global.Components['dashboard-view'] = {
    name: 'DashboardView',
    template: '#tpl-dashboard',
    setup() {
      const stats = S.stats;
      const timer = S.state.timer;
      const project = S.state.project;

      /* 攻击路径：以最深一跳为终点，回溯出跳板链 */
      const chainNodes = computed(() => {
        const links = S.state.links;
        if (!links.length) return [];
        /* 找到最深的链路（to 节点不再作为任何链路的 from） */
        const fromIds = links.map((l) => l.fromHostId);
        const deepest = links.slice().sort((a, b) => (fromIds.includes(b.toHostId) ? -1 : 1))[0];
        const path = [];
        let cur = deepest;
        let guard = 0;
        while (cur && guard++ < 8) {
          const host = S.hostOf(cur.fromHostId);
          if (!host) break;
          path.unshift(Object.assign({}, host, { link: cur }));
          cur = links.find((l) => l.toHostId === cur.fromHostId);
        }
        return path;
      });

      const stageProgress = computed(() =>
        (S.state.stageNames || []).map((name) => ({
          name,
          done: S.state.flags.filter((f) => f.stage === name).length,
          total: 2,
        }))
      );

      const recent = computed(() => S.state.timeline.slice(0, 6));
      const links = computed(() => S.state.links);

      function pct(a, b) { return b ? Math.min(100, Math.round((a / b) * 100)) + '%' : '0%'; }

      return {
        project, stats, timer, chainNodes, stageProgress, recent, links,
        remainText: S.remainText, timerPct: S.timerPct,
        ipOf: S.ipOf, kindLabel: S.kindLabel, kindBadge: S.kindBadge, goto: S.goto, pct,
      };
    },
  };
})(window);
