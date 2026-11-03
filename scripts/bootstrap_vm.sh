#!/usr/bin/env bash
# SRE Incident Agent — установка окружения на Vultr VM (Ubuntu 24.04).
# Запуск: bash bootstrap_vm.sh          (на самой VM, под root)
# Что делает: Docker + образ песочницы, venv с зависимостями,
# системный юнит, env-файл (VULTR_API_KEY задаётся отдельно через deploy-скрипт),
# файрвол 8080, автостарт сервиса.
set -euo pipefail

APP_DIR=/opt/sre-agent
ENV_DIR=/etc/sre-agent
PORT=8080

[ -d "$APP_DIR/app" ] || { echo "Нет $APP_DIR/app — сначала копируй файлы deploy_to_vm.ps1"; exit 1; }

echo "==> apt базовые пакеты"
apt-get update -qq
apt-get install -y -qq docker.io python3-venv ca-certificates

echo "==> docker сервис + образ песочницы"
systemctl enable --now docker
docker pull python:3.12-alpine

echo "==> venv + зависимости"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/app/requirements.txt"

echo "==> пользователь сервиса"
id -u sreagent >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin sreagent
usermod -aG docker sreagent

echo "==> env-файл (ключ задаётся deploy_to_vm.ps1)"
mkdir -p "$ENV_DIR"
touch "$ENV_DIR/env"
chown root:sreagent "$ENV_DIR/env"
chmod 640 "$ENV_DIR/env"

echo "==> systemd unit"
cat > /etc/systemd/system/sre-agent.service <<UNIT
[Unit]
Description=SRE Incident Agent (Vultr Agent Rush)
After=network-online.target docker.service
Wants=network-online.target

[Service]
WorkingDirectory=$APP_DIR/app
EnvironmentFile=$ENV_DIR/env
ExecStart=$APP_DIR/venv/bin/python main.py
User=sreagent
Restart=on-failure
RestartSec=5
# сниппет-песочница сама ограничивает ресурсы; сервису — жёсткий потолок
MemoryMax=768M

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now sre-agent

echo "==> ufw: ssh + порт демо"
if command -v ufw >/dev/null; then
  ufw allow 22/tcp >/dev/null
  ufw allow $PORT/tcp >/dev/null
  ufw --force enable >/dev/null
fi

sleep 2
systemctl --no-pager -l status sre-agent | head -n 12 || true
echo "==> health:"; curl -s "http://127.0.0.1:$PORT/api/health" || echo "(health недоступен — смотри journalctl -u sre-agent)"
echo "Готово. Демо-URL: http://$(curl -s ifconfig.me):$PORT"