# ②孤岛·封锁边界-评测 · Writeup

> 生成时间：2026/9/11 03:45:07  
> 工具：PivotHub（链透中枢）· 本报告为初稿，需人工润色

## 0. 概览

| 指标 | 数值 |
|---|---|
| 已控主机 | 1 / 1 |
| 层级深度 | L1 → L1 |
| 代理链路 | 0 / 0 存活 |
| 凭据 | 1 条 |
| Flag | 3 / 6 |

## 1. 网络拓扑

```
攻击端 127.0.0.1
```

![拓扑快照](screenshots/topology.png)

## 2. 跳板链参数

| 工具 | 方向 | 入口 | 出口 | 本地 Socks | 目标网段 |
|---|---|---|---|---|---|

## 3. 操作时间线

### 16:58 · 资产 — 新建项目：②孤岛·封锁边界-评测

- 已创建攻击端本机节点 10.8.0.14（取当前攻击机网络配置）

### 17:03 · 资产 — 添加 Shell 自动登记主机 10.8.0.6

- 主机：`10.8.0.6`
- 添加 Shell 时未选择归属主机：由 URL 地址自动创建，请人工补充信息

### 17:03 · 资产 — 自动回传基础信息并入库

- 主机：`10.8.0.6`
- whoami=www-data / uname=Linux web-edge 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux

### 17:03 · Shell — 登记并连接 Shell：http://10.8.0.6:8083/xp.php

- 主机：`10.8.0.6`
- 类型 PHP 一句话马 · 编码器 none · 延迟 139ms · whoami=www-data / uname=Linux web-edge 6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30) x86_64 GNU/Linux

### 17:04 · 代理 — 出网探测完成：仅 HTTP(S) 出网

- 主机：`10.8.0.6`
- 推荐 Neo-reGeorg（HTTP 隧道，复用已登记 Webshell） · 备选 chisel over HTTP / 冰蝎·哥斯拉内置 HTTP 隧道 · 证据 ICMP=ok; DNS=fail; HTTP=ok; TCP=fail

### 17:14 · Flag — 拿到 Flag：L1 入口

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:14 · Flag — 拿到 Flag：L2 内网

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:14 · Flag — 拿到 Flag：L2 内网

- 主机：`10.8.0.6`
- flag{REDACTED}

### 17:15 · 凭据 — 登记凭据 admin

- 主机：`10.8.0.6`
- 密码 · 来源 /var/www/html/application/extra/ops.php 明文

## 4. 凭据清单（明文）

| 账号 | 类型 | 凭据 | 来源主机 | 适用服务 |
|---|---|---|---|---|
| `admin` | 密码 | `REDACTED` | 10.8.0.6 | oa,web |

## 5. Flag 收集

| 主机 | 阶段 | Flag | 状态 |
|---|---|---|---|
| 10.8.0.6 | L1 入口 | `flag{REDACTED}` | 待提交 |
| 10.8.0.6 | L2 内网 | `flag{REDACTED}` | 待提交 |
| 10.8.0.6 | L2 内网 | `flag{REDACTED}` | 待提交 |

## 6. 总结与反思

> 待补充：本层关键突破点、踩坑与改进思路。
