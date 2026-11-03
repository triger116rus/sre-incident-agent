# Записывает VULTR_API_KEY на VM (скрытый ввод) и проверяет Vultr Inference.
# Запуск: pwsh scripts/set_vultr_env.ps1
param(
    [string]$VmIp = "209.250.254.114"
)
$ErrorActionPreference = "Stop"
$sshKey = "$env:USERPROFILE\.ssh\vultr_sre_ed25519"

$key = Read-Host "Вставь VULTR_API_KEY (ввод скрыт)" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
if (-not $plain) { throw "Ключ пустой" }
if ($plain -notmatch '^[A-Za-z0-9]{20,}$') { throw "Ключ выглядит не как Vultr API key (проверь, что скопировал целиком)" }

printf '%s\n' "VULTR_API_KEY=$plain" | ssh -i $sshKey "root@$VmIp" "umask 027 && cat > /etc/sre-agent/env"
Remove-Variable plain, bstr

ssh -i $sshKey "root@$VmIp" "systemctl restart sre-agent && sleep 2 && systemctl is-active sre-agent && echo '--- /v1/models:' && curl -s -H \"Authorization: Bearer \$(cat /etc/sre-agent/env | cut -d= -f2)\" https://api.vultrinference.com/v1/models"