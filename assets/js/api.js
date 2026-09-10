/* ============================================================
   PivotAPI — 后端 REST + WebSocket 客户端（零依赖）
   仅在 FastAPI 后端可用时生效；任何失败都会抛错，
   由 store.js 捕获后显式提示。
   ============================================================ */
(function (global) {
  'use strict';

  const jfetch = async (path, opts) => {
    const res = await fetch(path, opts);
    if (res.status === 501) {
      const err = new Error('not implemented (501)');
      err.notImplemented = true;
      throw err;
    }
    if (!res.ok) {
      // ⚠️ 修正：原先只抛 `HTTP <status> <path>`，把后端的 detail 整条丢掉，
      // 导致「主机不存在(404)」与「路由不存在(404)」在界面上同形，
      // 用户看到「登记失败：HTTP 404 /api/...」会误判成接口缺失。
      // 现在优先展示后端 detail/error，HTTP 信息降为后缀（保留原有格式兼容）。
      let detail = '';
      try {
        const txt = await res.text();
        if (txt) {
          try {
            const j = JSON.parse(txt);
            const d = (j && (j.detail || j.error || j.message));
            detail = typeof d === 'string' ? d : (d ? JSON.stringify(d) : '');
          } catch (e) { detail = String(txt).slice(0, 300); }
        }
      } catch (e) { /* 读体失败不影响主流程 */ }
      const err = new Error(detail
        ? detail + ' · HTTP ' + res.status + ' ' + path
        : 'HTTP ' + res.status + ' ' + path);
      err.status = res.status;
      err.path = path;
      err.detail = detail;
      throw err;
    }
    const text = await res.text();
    return text ? JSON.parse(text) : null;
  };

  const jsonBody = (body) => ({
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });

  const API = {
    mode: 'unknown', // 'api' | 'offline'
    ws: null,

    async getState(projectId) {
      const data = await jfetch('/api/projects/' + (projectId || 'proj-1') + '/state');
      API.mode = 'api';
      return data;
    },
    async post(path, body) { return jfetch(path, jsonBody(body)); },
    async put(path, body) {
      return jfetch(path, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    },
    async get(path) { return jfetch(path); },
    async patch(path, body) {
      return jfetch(path, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    },
    async del(path) { return jfetch(path, { method: 'DELETE' }); },

    /* WebSocket：自动重连（指数退避，上限 10s），按 type 分派 */
    connectWs(onEvent, onOnline) {
      let retry = 0;
      let closed = false;
      const open = () => {
        if (closed) return;
        const proto = global.location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(proto + '://' + global.location.host + '/ws');
        API.ws = ws;
        ws.onopen = () => { retry = 0; onOnline && onOnline(true); };
        ws.onmessage = (ev) => {
          try { onEvent && onEvent(JSON.parse(ev.data)); } catch (e) { /* 忽略坏帧 */ }
        };
        ws.onclose = () => {
          API.ws = null;
          onOnline && onOnline(false);
          const delay = Math.min(10000, 1500 * Math.pow(1.6, retry++));
          setTimeout(open, delay);
        };
        ws.onerror = () => { try { ws.close(); } catch (e) { /* noop */ } };
      };
      open();
      return () => { closed = true; try { API.ws && API.ws.close(); } catch (e) { /* noop */ } };
    },
  };

  global.PivotAPI = API;
})(window);
