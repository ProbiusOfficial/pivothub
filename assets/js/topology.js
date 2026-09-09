/* ============================================================
   拓扑视图 — 跳板链有向图（ECharts Graph）
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed, onMounted, onBeforeUnmount, watch, nextTick } = Vue;
  const S = PivotStore;

  const LAYOUT_MODES = [
    { key: 'layer', label: '分层排布' },
    { key: 'chain', label: '链路放射' },
    { key: 'force', label: '力导向' },
  ];

  const topoState = reactive({
    layout: 'layer',
    showLabels: true,
    dimOffline: true,
    dragging: false,
  });

  let chart = null;
  let resizeHandler = null;
  const posCache = {};

  /* ---------- 分层坐标计算 ---------- */
  function computeLayerPositions() {
    const hosts = S.state.hosts;
    const byLayer = {};
    hosts.forEach((h) => {
      const key = h.isLocal ? 'LOCAL' : h.layer;
      (byLayer[key] = byLayer[key] || []).push(h);
    });
    const order = ['LOCAL', 'L1', 'L2', 'L3'];
    const colX = { LOCAL: 70, L1: 340, L2: 620, L3: 900 };
    const positions = {};
    order.forEach((k) => {
      const list = byLayer[k] || [];
      list.forEach((h, i) => {
        const gap = 96;
        const total = (list.length - 1) * gap;
        positions[h.id] = [colX[k] || 900, 340 - total / 2 + i * gap];
      });
    });
    /* 未在已知层级的节点兜底排布 */
    hosts.forEach((h, i) => {
      if (!positions[h.id]) positions[h.id] = [340, 120 + i * 90];
    });
    return positions;
  }

  /* ---------- 链路放射坐标（以攻击端为中心按跳数分层） ---------- */
  function computeChainPositions() {
    const hosts = S.state.hosts;
    const root = hosts.find((h) => h.isLocal) || hosts[0];
    /* BFS 计算跳数 */
    const dist = { [root.id]: 0 };
    let frontier = [root.id];
    const adj = {};
    S.state.links.forEach((l) => {
      (adj[l.fromHostId] = adj[l.fromHostId] || []).push(l.toHostId);
      (adj[l.toHostId] = adj[l.toHostId] || []).push(l.fromHostId);
    });
    while (frontier.length) {
      const next = [];
      frontier.forEach((id) => {
        (adj[id] || []).forEach((n) => {
          if (dist[n] === undefined) { dist[n] = dist[id] + 1; next.push(n); }
        });
      });
      frontier = next;
    }
    hosts.forEach((h) => { if (dist[h.id] === undefined) dist[h.id] = 2; });
    const rings = {};
    hosts.forEach((h) => (rings[dist[h.id]] = rings[dist[h.id]] || []).push(h));
    const cx = 480, cy = 340;
    const positions = {};
    Object.keys(rings).forEach((d) => {
      const list = rings[d];
      if (Number(d) === 0) { positions[list[0].id] = [cx, cy]; return; }
      const r = 110 + Number(d) * 150;
      list.forEach((h, i) => {
        const a = (Math.PI * 2 * i) / list.length - Math.PI / 2 + Number(d) * 0.4;
        positions[h.id] = [cx + r * Math.cos(a) * 1.35, cy + r * Math.sin(a) * 0.72];
      });
    });
    return positions;
  }

  /* ---------- 生成 ECharts option ---------- */
  function buildOption() {
    const segColor = {};
    S.state.segments.forEach((s) => (segColor[s.segment] = s.color));
    const positions = topoState.layout === 'chain' ? computeChainPositions() : computeLayerPositions();

    const nodes = S.state.hosts.map((h) => {
      const color = h.isLocal ? '#7b8f9c' : (segColor[h.segment] || '#3ba7ff');
      const dim = topoState.dimOffline && !h.owned;
      const p = posCache[h.id] || positions[h.id] || [480, 340];
      return {
        id: h.id,
        name: h.ip,
        x: p[0],
        y: p[1],
        symbolSize: h.owned ? 46 : 34,
        itemStyle: {
          color: h.owned ? color : '#0e161d',
          borderColor: dim ? '#2a3b48' : color,
          borderWidth: h.owned ? 3 : 2,
          shadowBlur: h.owned ? 16 : 0,
          shadowColor: color,
          opacity: dim ? 0.72 : 1,
        },
        label: {
          show: true,
          color: dim ? '#7b8f9c' : '#d7e4ec',
          fontSize: 11,
          fontFamily: 'JetBrains Mono, Consolas, monospace',
          position: 'bottom',
          distance: 6,
          formatter: h.ip + (h.privilege ? '\n' + h.privilege : ''),
        },
      };
    });

    const edges = S.state.links.map((l) => {
      const alive = l.status === 'alive';
      const err = l.status === 'error';
      const relay = l.linkType === 'relay';
      const fwd = l.linkType === 'portfwd';
      const color = alive ? (relay ? '#a97bff' : fwd ? '#ffc247' : '#00e5a0') : err ? '#ff4d5e' : '#4a5f6d';
      const port = (l.localSocks || '').split(':')[1] || '';
      const what = fwd ? (l.targetHost || '') + ':' + (l.targetPort || '') : 'socks:' + port;
      return {
        source: l.fromHostId,
        target: l.toHostId,
        id: l.id,
        lineStyle: {
          color: color,
          width: relay ? 2.6 : alive ? 2 : 1.4,
          type: alive ? (relay ? 'dashed' : 'solid') : 'dashed',
          curveness: 0.12,
          opacity: alive ? 0.9 : 0.6,
        },
        label: {
          show: topoState.showLabels,
          formatter: l.tool + ' · ' + (relay ? '中继' : fwd ? '转发' : 'Socks') + ' · ' + what,
          fontSize: 9.5,
          color: alive ? '#8ba0ae' : '#5f7484',
          backgroundColor: 'rgba(7,11,15,0.85)',
          padding: [2, 4],
          borderRadius: 3,
        },
      };
    });

    // 反弹 Shell 会话边：目标主机 → 攻击机（面板本机），与代理链路分开着色
    const localHost = S.state.hosts.find((h) => h.isLocal);
    if (localHost) {
      S.state.shells
        .filter((s) => s.kind === 'reverse' && s.hostId && s.hostId !== localHost.id)
        .forEach((s) => {
          edges.push({
            source: s.hostId,
            target: localHost.id,
            id: 'rev-' + s.id,
            lineStyle: {
              color: '#3ba7ff', width: 2, type: 'dashed', curveness: 0.18,
              opacity: s.alive ? 0.9 : 0.4,
            },
            label: {
              show: topoState.showLabels,
              formatter: '反弹 Shell',
              fontSize: 9.5,
              color: '#8ba0ae',
              backgroundColor: 'rgba(7,11,15,0.85)',
              padding: [2, 4],
              borderRadius: 3,
            },
          });
        });
    }

    return {
      backgroundColor: 'transparent',
      animationDuration: 380,
      animationDurationUpdate: 340,
      tooltip: {
        trigger: 'item',
        backgroundColor: 'rgba(10,16,21,0.95)',
        borderColor: '#263a49',
        borderWidth: 1,
        textStyle: { color: '#d7e4ec', fontSize: 12 },
        formatter(params) {
          if (params.dataType === 'edge') {
            const l = S.state.links.find((x) => x.id === params.data.id);
            if (!l) {
              const rid = String((params.data && params.data.id) || '');
              if (rid.startsWith('rev-')) {
                const sh = S.state.shells.find((x) => x.id === rid.slice(4));
                if (sh) {
                  return '<b>反弹 Shell 会话</b><br/>主机：' + S.ipOf(sh.hostId) + '<br/>' +
                    '会话：' + sh.type + '<br/>延迟：' + (sh.latency || 0) + 'ms<br/>' +
                    '状态：' + (sh.alive ? '已回连' : '断开');
                }
              }
              return '';
            }
            const typeText = l.linkType === 'relay' ? '多级中继' : l.linkType === 'portfwd' ? '单端口转发' : 'Socks 代理';
            return (
              '<b>代理链路 · ' + typeText + '</b><br/>' +
              '工具：' + l.tool + '<br/>方向：' + l.direction + '<br/>' +
              '入口：' + S.ipOf(l.fromHostId) + '<br/>出口：' + S.ipOf(l.toHostId) + '<br/>' +
              (l.linkType === 'portfwd'
                ? '转发：' + (l.targetHost || '') + ':' + (l.targetPort || '') + ' → ' + l.localSocks + '<br/>'
                : '本地入口：' + (l.localSocks || '-') + '<br/>') +
              '覆盖：' + (l.targetSegment || '-') + '<br/>状态：' + S.statusText(l.status)
            );
          }
          const h = S.hostOf(params.data.id);
          if (!h) return '';
          const ifaceText = (h.ifaces || []).map((i) => i.iface + ' ' + i.ip).join(' / ') || '-';
          return (
            '<b>' + h.ip + '</b><br/>' +
            (h.hostname ? '主机名：' + h.hostname + '<br/>' : '') +
            '系统：' + h.os + '<br/>层级：' + h.layer + '<br/>' +
            '网卡：' + ifaceText + '<br/>' +
            '权限：' + (h.privilege || '无') + '<br/>' +
            'Shell：' + S.shellsOf(h.id).length + ' · 凭据：' + S.credsOf(h.id).length + ' · Flag：' + S.flagsOf(h.id).length
          );
        },
      },
      series: [
        {
          type: 'graph',
          layout: topoState.layout === 'force' ? 'force' : 'none',
          force: { repulsion: 420, edgeLength: 180, gravity: 0.06, layoutAnimation: true },
          roam: true,
          draggable: true,
          zoom: 0.85,
          scaleLimit: { min: 0.35, max: 3 },
          focusNodeAdjacency: false,
          data: nodes,
          edges: edges,
          edgeSymbol: ['none', 'arrow'],
          edgeSymbolSize: [0, 7],
          emphasis: {
            focus: 'adjacency',
            lineStyle: { width: 3 },
            label: { color: '#00e5a0' },
          },
        },
      ],
    };
  }

  /* ---------- 组件 ---------- */
  global.Components['topology-view'] = {
    name: 'TopologyView',
    template: '#tpl-topology',
    setup() {
      const chartEl = ref(null);
      const ui = S.state.ui;

      /* 视图内部代理对象，模板里用 topo.xxx */
      const topo = {
        layout: topoState.layout,
        showLabels: topoState.showLabels,
        dimOffline: topoState.dimOffline,
        setLayout(k) {
          topoState.layout = k;
          if (k !== 'force') Object.keys(posCache).forEach((id) => delete posCache[id]);
          topo.layout = k;
          render(true);
        },
        render(rebuild) {
          if (!chart) return;
          if (rebuild) chart.setOption(buildOption(), true);
          else chart.setOption(buildOption());
        },
        fit() { if (chart) chart.resize(); toast('视图已自适应', 'info'); },
        resetPositions() {
          Object.keys(posCache).forEach((id) => delete posCache[id]);
          render(true);
          toast('布局已重置', 'ok');
        },
      };

      function render(rebuild) {
        if (!chart) return;
        chart.setOption(buildOption(), !!rebuild);
      }

      function onNodeClick(params) {
        if (topoState.dragging) return;
        if (params.dataType === 'edge') S.selectLink(params.data.id);
        else S.selectHost(params.data.id);
      }
      function onBlankClick() { S.clearSelection(); }

      function onDragStart() { topoState.dragging = true; }
      function onDragEnd(params) {
        const p = params.data && params.data.id ? params.data.id : null;
        if (p) {
          posCache[p] = [params.offsetX, params.offsetY];
          if (chart) chart.setOption({ series: [{ data: [{ id: p, x: params.offsetX, y: params.offsetY }] }] });
          if (S.saveNodePos) S.saveNodePos(p, params.offsetX, params.offsetY); /* 拖拽位置持久化到 SQLite */
        }
        setTimeout(() => (topoState.dragging = false), 60);
      }

      onMounted(() => {
        if (!chartEl.value || !global.echarts) return;
        chart = global.echarts.init(chartEl.value, null, { renderer: 'canvas' });
        chart.setOption(buildOption(), true);
        chart.on('click', onNodeClick);
        chart.on('mouseup', (p) => { if (p.target === undefined) onBlankClick(); });
        chart.on('dragstart', onDragStart);
        chart.on('dragend', onDragEnd);
        resizeHandler = () => chart && chart.resize();
        window.addEventListener('resize', resizeHandler);
        /* 链路状态变化后自动刷新 */
        watch(
          () => S.state.links.map((l) => l.status + l.latency).join(','),
          () => { if (chart) chart.setOption(buildOption()); }
        );
        watch(
          () => S.state.hosts.length + S.state.links.length,
          () => nextTick(() => { if (chart) chart.setOption(buildOption(), true); })
        );
        /* 服务端持久化的拖拽位置到达后恢复到 posCache */
        watch(
          () => S.state.hosts.map((h) => h.id + ':' + (h.posX != null ? h.posX + ',' + h.posY : '')).join('|'),
          () => {
            S.state.hosts.forEach((h) => {
              if (h.posX != null && h.posY != null && posCache[h.id] === undefined) {
                posCache[h.id] = [h.posX, h.posY];
              }
            });
            if (chart) chart.setOption(buildOption());
          },
          { immediate: true }
        );
      });

      onBeforeUnmount(() => {
        if (resizeHandler) window.removeEventListener('resize', resizeHandler);
        if (chart) { chart.dispose(); chart = null; }
      });

      /* 模板需要的辅助 */
      const selected = S.selected;
      function openCredModal(hostId) { S.openModal('cred-add', { data: { hostId } }); }
      function openFlagModal(hostId) { S.openModal('flag-add', { data: { hostId } }); }
      function openNoteModal(hostId) { S.openModal('note-add', { data: { hostId } }); }
      /* 删除链路记录（先按销毁流程结束进程，再从列表/拓扑移除） */
      function removeLink(id) {
        const l = S.state.links.find((x) => x.id === id);
        if (!l) return;
        if (!global.confirm('删除链路记录 ' + l.tool + '（' + S.ipOf(l.fromHostId) + ' → ' + S.ipOf(l.toHostId) +
          '）？\n会先按销毁流程结束相关进程，记录不可恢复。')) return;
        S.removeLink(l);
      }

      return {
        topo, chartEl, selected, ui, segments: S.state.segments, layoutModes: LAYOUT_MODES,
        hosts: S.state.hosts,
        icon: global.icon,
        ipOf: S.ipOf, shellsOf: S.shellsOf, credsOf: S.credsOf, flagsOf: S.flagsOf,
        privClass: S.privClass, statusText: S.statusText,
        goto: S.goto, openTerminal: S.openTerminal, openTerminalById: S.openTerminalById,
        testLink: S.testLink, restartLink: S.restartLink, stopLink: S.stopLink, removeLink,
        openCredModal, openFlagModal, openNoteModal,
      };
    },
  };
})(window);
