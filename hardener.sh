#!/bin/bash
# ==============================================================================
# VoIP Server Hardening Script (Asterisk + GoIP/DBL)
# Installation: curl -sSL https://raw.githubusercontent.com/USER/REPO/main/voip_hardener.sh | sudo bash
# ==============================================================================

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Функция логирования
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  VoIP Server Hardening Script${NC}"
echo -e "${GREEN}  Asterisk + GoIP/DBL Protection${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
  log_error "Скрипт нужно запускать с sudo: curl ... | sudo bash"
fi

# Проверка ОС
if ! command -v apt-get &> /dev/null; then
  log_error "Скрипт поддерживает только Ubuntu/Debian (apt-get не найден)"
fi

log_info "Обновление репозиториев и установка пакетов..."
apt-get update -qq
apt-get install -y -qq ufw fail2ban iptables-persistent > /dev/null 2>&1

log_info "Настройка UFW (Firewall)..."
ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null

# SSH (важно не потерять доступ!)
ufw allow 22/tcp comment 'SSH' > /dev/null

# SIP
ufw allow 5060/udp comment 'SIP UDP' > /dev/null
ufw allow 5060/tcp comment 'SIP TCP' > /dev/null
ufw allow 5061/tcp comment 'SIPS TLS' > /dev/null

# RTP (диапазон по умолчанию)
ufw allow 10000:20000/udp comment 'Asterisk RTP' > /dev/null

# Web (для DBL/GoIP/Freepbx)
ufw allow 80/tcp comment 'HTTP' > /dev/null
ufw allow 443/tcp comment 'HTTPS' > /dev/null

ufw --force enable > /dev/null 2>&1
log_info "UFW настроен и включен"

log_info "Настройка Fail2ban..."
cat <<'EOF' > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 86400
findtime = 3600
maxretry = 5
backend  = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3

[asterisk]
enabled  = true
port     = 5060,5061
filter   = asterisk
logpath  = /var/log/asterisk/messages
maxretry = 5
bantime  = 604800

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = iptables-allports[name=recidive]
bantime  = 2592000
findtime = 86400
maxretry = 3
EOF

systemctl enable fail2ban > /dev/null 2>&1
systemctl restart fail2ban > /dev/null 2>&1
log_info "Fail2ban настроен и запущен"

log_info "Применение сетевых настроек ядра..."
cat <<'EOF' > /etc/sysctl.d/99-voip-security.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF

sysctl --system > /dev/null 2>&1
log_info "Sysctl настройки применены"

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  ✅ Базовый харденинг завершен!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${YELLOW}⚠️  ВАЖНО:${NC}"
echo -e "  1. Добавь IP твоих GoIP шлюзов в /etc/fail2ban/jail.local (ignoreip)"
echo -e "  2. Проверь настройки Asterisk (sip.conf/pjsip.conf)"
echo -e "  3. Убедись, что RTP диапазон совпадает с rtp.conf"
echo ""
echo -e "${YELLOW}Полезные команды:${NC}"
echo -e "  • fail2ban-client status asterisk  — посмотреть забаненные IP"
echo -e "  • ufw status numbered              — посмотреть правила firewall"
echo -e "  • tail -f /var/log/fail2ban.log    — логи fail2ban"
echo ""
