# PivotHub Docker 靶场（scripts/lab）

> ⚠ 合规：仅用于 CTF 竞赛 / 授权靶场 / 教学演示，禁止对任何未授权目标使用。
> 所有端口仅绑定 127.0.0.1。

## 场景一览（对应 PRD 三类典型出网环境）

| 场景 | compose 服务 | 面板登记 | 用途 |
|---|---|---|---|
| 1. 可反向 TCP 出网 | `web-dmz` → 127.0.0.1:8801 | URL `http://127.0.0.1:8801/shell.php` 密码 `pivothub` 类型 `PHP 一句话马` | frp/chisel 反向代理（MS3）、终端固化全流程（内置 python3/script/socat/nc） |
| 2. 仅 HTTP 出网 | `http-only` → 127.0.0.1:8802（internal 网络，无出网路由） | 同上，端口 8802 | Neo-reGeorg HTTP 隧道（MS3） |
| 3. 双网卡多级串联 | `l2-jump` → 127.0.0.1:8803；`l3-core` 仅 deep 网内可达 | L2 节点 8803；L3 经二级代理访问 | MS4 多级串联、统一 Socks 映射 |

## 启动与复跑

```bash
cd scripts/lab
docker compose up -d --build
docker compose ps
# 面板（http://127.0.0.1:8000/）→ Shell 管理 → 添加连接 → 填上表 → 自动回传 ✓
```

## 无 Docker 环境的本机联调靶（miniweb）

本机无 Docker/PHP 时，用零依赖的 miniweb（stdlib，真实子进程 + 真实文件系统）验证
会话协议栈与文件管理：

```bash
PY scripts/lab/miniweb/miniweb.py --port 8787 --pwd cmd --dir ./wwwroot
# 面板登记：URL http://127.0.0.1:8787/shell.php  密码 cmd  类型 PHP 一句话马
```

说明：miniweb 与真实 PHP 一句话马使用同一 POST 协议与同一载荷格式；区别在于
服务器端由 Python 解释规范载荷（真实执行命令/真实读写文件），而非真实 PHP 引擎。
TTY 固化完整闭环（Linux pty）请在场景 1 容器内验证。

## 文件说明

- `files/shell.php`：标准 PHP 一句话马（POST 字段=密码）
- `files/cmd.jsp`：JSP 命令执行马（GET/POST 字段 cmd）
- `files/Dockerfile.linux`：php:8.2-apache + python3/socat/nc/script（固化技法依赖）
- `miniweb/miniweb.py`：本机零依赖联调靶
