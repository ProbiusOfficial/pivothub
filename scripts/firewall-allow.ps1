<#
  PivotHub 防火墙一次性配置（管理员 PowerShell 运行一次即可）

  背景：Windows 防火墙的入站放行是「按可执行文件的完整路径」记规则的。
  本机联调 / 测试时 chisel 客户端会被上传到临时目录再执行，路径每次都不一样，
  于是每次都会弹「是否允许访问网络」；点「取消」还会自动生成 Block 规则，
  日积月累既弹窗又可能把复用路径的进程静默拦掉。

  这个脚本做三件事：
    1. 清理历史遗留在 %TEMP% 下的 chisel 规则（含「取消」自动生成的 Block 规则）；
    2. 给面板的 python 与 tools\chisel.exe 各加一条 Any Profile 的入站放行；
    3. 打印可选的「彻底静音」命令（默认不执行，见文末）。

  用法（二选一）：
    · 右键 PowerShell「以管理员身份运行」，执行：
        powershell -ExecutionPolicy Bypass -File <仓库>\scripts\firewall-allow.ps1
    · 或在管理员 PowerShell 里直接粘贴本文件内容。
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Get-RuleProgram($rule) {
  $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
  if ($app) { return $app.Program }
  return ''
}

Write-Host '[1/3] 清理 %TEMP% 下的历史 chisel 规则 ...' -ForegroundColor Cyan
$tempRoots = @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp')) |
  Where-Object { $_ } | Select-Object -Unique
$stale = @()
foreach ($rule in (Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue)) {
  $prog = Get-RuleProgram $rule
  if (-not $prog) { continue }
  $isTemp = $false
  foreach ($t in $tempRoots) { if ($prog -like "$t*") { $isTemp = $true } }
  if ($isTemp -and ($prog -like '*chisel*')) { $stale += $rule }
}
foreach ($rule in $stale) { Remove-NetFirewallRule -Name $rule.Name }
Write-Host ("      已删除 {0} 条临时路径规则（Block/Allow 都含）" -f $stale.Count)

Write-Host '[2/3] 放行面板 python 与 tools\chisel.exe 的入站连接 ...' -ForegroundColor Cyan
$targets = @()
$panel = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.CommandLine -like '*-m pivothub*' } | Select-Object -First 1
if ($panel -and $panel.ExecutablePath) { $targets += $panel.ExecutablePath }
$cmdPy = Get-Command python -ErrorAction SilentlyContinue
if ($cmdPy -and $cmdPy.Source) { $targets += $cmdPy.Source }
$targets += (Join-Path $root 'tools\chisel.exe')
$targets = $targets | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($prog in $targets) {
  $name = 'PivotHub: ' + (Split-Path $prog -Leaf)
  Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
  New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
    -Program $prog -Profile Any | Out-Null
  Write-Host "      已放行 $prog"
}

Write-Host '[3/3] 完成。' -ForegroundColor Green
Write-Host ''
Write-Host '  可选：若希望以后任何程序都不再弹「防火墙已阻止」提示（仍按规则放行/拦截，只是不再弹窗），'
Write-Host '  在管理员 PowerShell 里执行一次：'
Write-Host '      netsh advfirewall set allprofiles settings inboundusernotification disable'
Write-Host '  恢复提示：'
Write-Host '      netsh advfirewall set allprofiles settings inboundusernotification enable'
