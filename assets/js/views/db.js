/* ============================================================
   数据库面板 — 经会话连接目标数据库 / SQL 查询 / 结果可视化
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed } = Vue;
  const S = PivotStore;

  const KIND_LABEL = {
    mysql: 'MySQL', postgres: 'PostgreSQL', sqlite: 'SQLite',
    redis: 'Redis', mssql: 'SQL Server',
  };

  global.Components['db-view'] = {
    name: 'DbView',
    template: '#tpl-db',
    setup() {
      const ui = S.state.ui;
      const conns = ref([]);
      const kinds = ref([]);
      const activeId = ref('');
      const busy = ref(false);
      const showForm = ref(false);
      const result = ref(null);
      const sql = ref('');
      const testOut = ref(null);
      const form = reactive({
        name: '', kind: 'mysql', host: '127.0.0.1', port: 0,
        username: '', password: '', dbName: '', shellId: '', note: '',
      });

      const active = computed(() => conns.value.find((c) => c.id === activeId.value) || null);
      const shells = computed(() => S.state.shells.filter((s) => s.alive));
      const kindLabel = (k) => KIND_LABEL[k] || k;

      function load() {
        S.dbList().then((out) => {
          conns.value = (out && out.connections) || [];
          kinds.value = (out && out.kinds) || [];
          if (activeId.value && !conns.value.some((c) => c.id === activeId.value)) activeId.value = '';
          if (!activeId.value && conns.value.length) activeId.value = conns.value[0].id;
        });
      }

      function pick(c) {
        activeId.value = c.id;
        result.value = null;
        testOut.value = null;
      }

      function openForm() {
        Object.assign(form, {
          name: '', kind: 'mysql', host: '127.0.0.1', port: 0,
          username: '', password: '', dbName: '', shellId: '', note: '',
        });
        showForm.value = true;
      }

      function save() {
        if (!String(form.host || '').trim()) { S.toast('请填写主机 / SQLite 路径', 'err'); return; }
        busy.value = true;
        S.dbCreate(Object.assign({}, form)).then((out) => {
          busy.value = false;
          if (!out || !out.id) { S.toast('保存失败（后端不可用或参数不合法）', 'err'); return; }
          showForm.value = false;
          activeId.value = out.id;
          load();
          S.toast('已保存数据库连接：' + out.name, 'ok');
        });
      }

      function remove(c) {
        if (!window.confirm('删除数据库连接「' + c.name + '」？')) return;
        S.dbDelete(c.id).then(() => {
          if (activeId.value === c.id) activeId.value = '';
          load();
        });
      }

      function test(c) {
        busy.value = true;
        testOut.value = null;
        S.dbTest(c.id).then((out) => { busy.value = false; testOut.value = out; });
      }

      function run(sqlText) {
        const c = active.value;
        if (!c) { S.toast('请先选择数据库连接', 'err'); return; }
        const q = String(sqlText != null ? sqlText : sql.value).trim();
        if (!q) { S.toast('请输入 SQL', 'err'); return; }
        busy.value = true;
        S.dbQuery(c.id, q).then((out) => { busy.value = false; result.value = out; });
      }

      function listTables() {
        const c = active.value;
        if (!c) return;
        busy.value = true;
        S.dbTables(c.id).then((out) => {
          busy.value = false;
          result.value = out;
          if (out && out.sql) sql.value = out.sql;
        });
      }

      function quick(q) { sql.value = q; run(q); }

      load();

      return {
        ui, conns, kinds, activeId, active, shells, busy, showForm, form,
        sql, result, testOut, kindLabel,
        load, pick, openForm, save, remove, test, run, listTables, quick,
        icon: global.icon,
      };
    },
  };
})(window);
