/* ============================================================
   数据库面板 — 自动探测结构（库/表/列树）+ SQL 查询 + 结果可视化
   ============================================================ */
(function (global) {
  'use strict';
  const { ref, reactive, computed, watch } = Vue;
  const S = PivotStore;

  const KIND_LABEL = {
    mysql: 'MySQL', postgres: 'PostgreSQL', sqlite: 'SQLite',
    redis: 'Redis', mssql: 'SQL Server',
  };

  /* 标识符引用：MySQL 反引号 / PostgreSQL·SQLite 双引号 / SQL Server 方括号 */
  function quoteId(kind, name) {
    if (kind === 'mysql') return '`' + String(name).replace(/`/g, '``') + '`';
    if (kind === 'mssql') return '[' + String(name).replace(/]/g, ']]') + ']';
    return '"' + String(name).replace(/"/g, '""') + '"';
  }

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

      /* 结构树 */
      const schema = ref([]);
      const schemaBusy = ref(false);
      const schemaError = ref('');
      const schemaMs = ref(0);
      const expandedDbs = reactive({});
      const expandedTables = reactive({});
      const activeTable = ref('');

      const form = reactive({
        name: '', kind: 'mysql', host: '127.0.0.1', port: 0,
        username: '', password: '', dbName: '', shellId: '', note: '',
      });

      const active = computed(() => conns.value.find((c) => c.id === activeId.value) || null);
      const shells = computed(() => S.state.shells.filter((s) => s.alive));
      const kindLabel = (k) => KIND_LABEL[k] || k;
      const tableCount = computed(() => schema.value.reduce((n, d) => n + d.tables.length, 0));

      function load() {
        S.dbList().then((out) => {
          conns.value = (out && out.connections) || [];
          kinds.value = (out && out.kinds) || [];
          if (activeId.value && !conns.value.some((c) => c.id === activeId.value)) activeId.value = '';
          if (!activeId.value && conns.value.length) activeId.value = conns.value[0].id;
        });
      }

      /* ---------- 结构探测（选中连接即自动加载） ---------- */
      function loadSchema() {
        const c = active.value;
        if (!c) return;
        schemaBusy.value = true;
        schemaError.value = '';
        S.dbSchema(c.id).then((out) => {
          schemaBusy.value = false;
          if (!out || !out.ok) {
            schema.value = [];
            schemaError.value = (out && out.error) || '结构探测失败';
            return;
          }
          schema.value = out.databases || [];
          schemaMs.value = out.ms || 0;
          /* 默认展开所有库，第一张表也展开，省一次点击 */
          schema.value.forEach((d) => { expandedDbs[d.name] = true; });
          const first = schema.value[0];
          if (first && first.tables.length) {
            const key = first.name + '.' + first.tables[0].name;
            expandedTables[key] = true;
          }
        });
      }

      watch(activeId, (v) => {
        result.value = null;
        testOut.value = null;
        schema.value = [];
        schemaError.value = '';
        activeTable.value = '';
        Object.keys(expandedTables).forEach((k) => delete expandedTables[k]);
        if (v) loadSchema();
      });

      function toggleDb(name) { expandedDbs[name] = !expandedDbs[name]; }

      /* 点表名：展开列 + 自动预览数据 */
      function openTable(dbName, t) {
        const key = dbName + '.' + t.name;
        expandedTables[key] = true;
        activeTable.value = key;
        const c = active.value;
        if (!c) return;
        const q = previewSql(c.kind, dbName, t.name);
        sql.value = q;
        run(q);
      }

      function previewSql(kind, dbName, tblName) {
        if (kind === 'redis') return 'KEYS ' + quoteId(kind, tblName) + '*';
        const t = quoteId(kind, tblName);
        if (kind === 'sqlite') return 'SELECT * FROM ' + t + ' LIMIT 200';
        if (kind === 'mssql') return 'SELECT TOP 200 * FROM ' + quoteId(kind, dbName) + '.' + t;
        return 'SELECT * FROM ' + quoteId(kind, dbName) + '.' + t + ' LIMIT 200';
      }

      /* ---------- 连接管理 ---------- */
      function pick(c) { activeId.value = c.id; }

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

      /* ---------- 查询 ---------- */
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
        schema, schemaBusy, schemaError, schemaMs, expandedDbs, expandedTables,
        activeTable, tableCount,
        load, pick, openForm, save, remove, test, run, listTables, quick,
        loadSchema, toggleDb, openTable,
        icon: global.icon,
      };
    },
  };
})(window);
