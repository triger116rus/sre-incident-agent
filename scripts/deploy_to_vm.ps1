# Деплой SRE Incident Agent с win10_r на Vultr VM.
# Запуск: pwsh scripts/deploy_to_vm.ps1 209.250.254.114
# Порядок: копир app+scripts -> bootstrap (docker/venv/systemd) -> env (ключ скрыто) -> рестарт -> health.
# Требуется SSH-доступ по ключу ~/.ssh/vultr_sre_ed25519 (инжектится через web-консоль Vultr).
param(
    [Parameter(Mandatory=$true)][string]$VmIp,
    [string]$RemoteDir = "/opt/sre-agent",
    [int]$Port = 8080
)
$ErrorActionPreference = "Stop"
$proj = $PSScriptRoot | Split-Path | Split-Path
$app     = Join-Path $proj "app"
$scripts = Join-Path $proj "scripts"
$sshKey  = "$env:USERPROFILE\.ssh\vultr_sre_ed25519"
$sshArgs = @("-i", $sshKey, "-o", "StrictHostKeyChecking=accept-new")

function Invoke-Remote($cmd) { ssh @sshArgs "root@$VmIp" $cmd }

"==> Копир app/ и scripts/ -> ${VmIp}:${RemoteDir}"
Invoke-Remote "mkdir -p $RemoteDir/app/static $RemoteDir/scripts"
scp @sshArgs "$app\llm.py" "$app\agent.py" "$app\sandbox.py" "$app\main.py" "$app\requirements.txt" "${VmIp}:${RemoteDir}/app/" | Out-Null
scp @sshArgs "$app\static\index.html" "${VmIp}:${RemoteDir}/app/static/" | Out-Null
scp @sshArgs "$scripts\bootstrap_vm.sh" "${VmIp}:${RemoteDir}/scripts/" | Out-Null

"==> Bootstrap на VM (docker + venv + systemd, 3-5 мин)"
Invoke-Remote "cd $RemoteDir && bash scripts/bootstrap_vm.sh"

"==> VULTR_API_KEY в /etc/sre-agent/env (ввод скрыт, содержимое не выводится)"
$key = Read-Host "Вставь VULTR_API_KEY (ввод скрыт)" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
if (-not $plain) { throw "Ключ пустой" }
printf '%s\n' "VULTR_API_KEY=$plain" | ssh @sshArgs "root@$VmIp" "umask 027 && cat > /etc/sre-agent/env"
Remove-Variable plain, bstr

"==> Рестарт сервиса с env"
Invoke-Remote "systemctl restart sre-agent && sleep 2 && systemctl is-active sre-agent"

"==> Health изнутри VM"
Invoke-Remote "curl -s http://127.0.0.1:$Port/api/health; echo"

"==> Health снаружи"
(Invoke-WebRequest -UseBasicParsing "http://$VmIp`:$Port/api/health" -TimeoutSec 15).StatusCode
"Готово. Демо-URL: http://${VmIp}:$Port"