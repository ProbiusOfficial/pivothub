/* ============================================================
   复盘导出 — Markdown / HTML / JSON 预览与下载
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, ref, computed } = Vue;
  const S = PivotStore;

  const FORMATS = [
    { key: 'md', label: 'Markdown', ext: 'md', mime: 'text/markdown;charset=utf-8' },
    { key: 'html', label: 'HTML 报告', ext: 'html', mime: 'text/html;charset=utf-8' },
    { key: 'json', label: 'JSON 数据', ext: 'json', mime: 'application/json;charset=utf-8' },
  ];

  function buildJson() {
    return JSON.stringify({
      project: S.state.project,
      generatedAt: new Date().toISOString(),
      stats: S.stats.value,
      segments: S.state.segments,
      hosts: S.state.hosts,
      shells: S.state.shells,
      proxyLinks: S.state.links,
      credentials: S.state.creds,
      flags: S.state.flags,
      timeline: S.state.timeline,
    }, null, 2);
  }

  function buildHtml(mdText) {
    const body = S.md(mdText.replace(/^#/gm, '')).split('<br />').join('\n');
    return '<!DOCTYPE html>\n<html lang="zh-CN"><head><meta charset="utf-8" />\n' +
      '<title>' + S.state.project.name + ' · PivotHub 报告</title>\n' +
      '<style>body{background:#070b0f;color:#d7e4ec;font-family:system-ui,"PingFang SC",sans-serif;max-width:900px;margin:0 auto;padding:32px;line-height:1.7}' +
      'h1,h2{color:#00e5a0}code,pre{font-family:Consolas,monospace;background:#0e161d;color:#a8f0d3;padding:2px 5px;border-radius:3px}' +
      'pre{padding:12px;overflow:auto;border:1px solid #1d2b37}table{border-collapse:collapse;width:100%}td,th{border:1px solid #1d2b37;padding:6px 9px;text-align:left}' +
      'blockquote{border-left:3px solid #00e5a0;margin:0;padding-left:12px;color:#8ba0ae}</style></head>\n<body>\n<pre>' +
      body.replace(/&/g, '&amp;').replace(/</g, '&lt;') + '</pre>\n</body></html>';
  }

  global.Components['export-view'] = {
    name: 'ExportView',
    template: '#tpl-export',
    setup() {
      const fmt = ref('md');
      const opt = reactive({ topo: true, timeline: true, creds: true, flags: true, placeholder: true, chain: true });
      const formats = FORMATS;

      const preview = computed(() => {
        if (fmt.value === 'json') return buildJson();
        const mdText = S.buildMarkdown(opt);
        return fmt.value === 'html' ? buildHtml(mdText) : mdText;
      });
      const currentFormat = computed(() => FORMATS.find((f) => f.key === fmt.value) || FORMATS[0]);
      const sizeText = computed(() => {
        const kb = (new Blob([preview.value]).size / 1024).toFixed(1);
        return kb + ' KB · ' + preview.value.split('\n').length + ' 行';
      });

      function copy() { S.copy(preview.value); }
      function download() {
        const f = currentFormat.value;
        const blob = new Blob([preview.value], { type: f.mime });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'pivothub-writeup.' + f.ext;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
        S.toast('已导出 pivothub-writeup.' + f.ext, 'ok');
        S.addEvent('note', '导出 ' + f.label + ' 报告', { detail: '包含拓扑 / 时间线 / 凭据 / Flag 选项' });
      }

      return { fmt, opt, formats, preview, currentFormat, sizeText, copy, download, toast: S.toast };
    },
  };
})(window);
