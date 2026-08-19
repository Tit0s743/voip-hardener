#!/bin/bash
# ==============================================================================
# VoIP Server Hardening Script v2.0 (Asterisk + GoIP/DBL)
# URL: https://raw.githubusercontent.com/Tit0s743/voip-hardener/main/hardener.sh
# Usage: curl -sSL <URL> | sudo bash
# ==============================================================================

set -euo pipefail

# === ЦВЕТА ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[✔]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✘]${NC} $1"; exit 1; }
log_step()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  VoIP Server Hardening Script v2.0${NC}"
echo -e "${GREEN}  Asterisk + GoIP/DBL Protection${NC}"
echo -e "${GREEN}============================================================${NC}"
echo -e "  $(date '+%Y-%m-%d %H:%M:%S') | $(hostname)"
echo -e "${GREEN}============================================================${NC}"

# === 1. ПРОВЕРКА ПРАВ ROOT ===
log_step "1/8 Проверка прав доступа"
if [ "$EUID" -ne 0 ]; then
  log_error "Скрипт требует root. Запусти: curl ... | sudo bash"
fi
log_info "Права root подтверждены"

# === 2. ПРОВЕРКА ОС ===
log_step "2/8 Проверка операционной системы"
if ! command -v apt-get &> /dev/null; then
  log_error "Поддерживаются только Debian/Ubuntu (apt-get не найден)"
fi

OS_INFO=$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)
log_info "ОС: ${OS_INFO:-Debian/Ubuntu}"

# === 3. ПРОВЕРКА СЕТИ И DNS ===
log_step "3/8 Проверка сетевого подключения"
if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
  log_warn "Нет пинга до 8.8.8.8 — возможна проблема с сетью"
  log_warn "Продолжаю, но apt может не сработать..."
else
  log_info "Сеть доступна (ping 8.8.8.8 OK)"
fi

if ! ping -c 1 -W 3 archive.ubuntu.com &> /dev/null && ! ping -c 1 -W 3 deb.debian.org &> /dev/null; then
  log_warn "DNS не резолвит зеркала apt — установка может не сработать"
else
  log_info "DNS работает корректно"
fi

# === 4. ОЖИДАНИЕ APT LOCK И ОБНОВЛЕНИЕ СИСТЕМЫ ===
log_step "4/8 Обновление системы и установка зависимостей"

# Функция ожидания освобождения apt lock
wait_for_apt() {
  local timeout=300  # 5 минут максимум
  local elapsed=0
  local interval=5

  while fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock &> /dev/null; do
    if [ $elapsed -ge $timeout ]; then
      log_error "apt заблокирован более ${timeout} сек. Убей зависший процесс вручную."
    fi
    if [ $elapsed -eq 0 ]; then
      echo -ne "${YELLOW}[⚠]${NC} apt занят другим процессом (unattended-upgrades?). Ожидание"
    fi
    echo -ne "."
    sleep $interval
    elapsed=$((elapsed + interval))
  done

  if [ $elapsed -gt 0 ]; then
    echo ""
    log_info "apt lock освобождён через ${elapsed} сек"
  fi
}

# Убиваем все интерактивные вопросы (ключевое для iptables-persistent!)
export DEBIAN_FRONTEND=noninteractive

# Ждём apt lock
wait_for_apt

# Фиксим возможные битые пакеты от прошлых сбоев
dpkg --configure -a 2>/dev/null || true
apt-get -f install -y -qq 2>/dev/null || true

log_info "Обновление списка пакетов (apt update)..."
apt-get update -qq

log_info "Установка системных обновлений (apt upgrade)..."
apt-get upgrade -y -qq 2>&1 | tail -1 || true

log_info "Установка необходимых пакетов..."
PACKAGES="ufw fail2ban iptables-persistent curl wget lsof net-tools"
for pkg in $PACKAGES; do
  if dpkg -l "$pkg" &> /dev/null; then
    log_info "  $pkg — уже установлен"
  else
    echo -ne "  $pkg — устанавливаю... "
    apt-get install -y -qq "$pkg" 2>/dev/null
    log_info "готово"
  fi
done

# === 5. ПРОВЕРКА ASTERISK ===
log_step "5/8 Проверка Asterisk"
if command -v asterisk &> /dev/null; then
  AST_VER=$(asterisk -V 2>/dev/null || echo "unknown")
  log_info "Asterisk найден: $AST_VER"
else
  log_warn "Asterisk НЕ установлен! Скрипт настроит защиту, но"
  log_warn "Fail2ban-фильтр asterisk не будет работать до установки."
fi

# Проверяем/создаём директорию логов Asterisk
AST_LOG_DIR="/var/log/asterisk"
if [ -d "$AST_LOG_DIR" ]; then
  log_info "Директория логов Asterisk: $AST_LOG_DIR (существует)"
else
  log_warn "Директория $AST_LOG_DIR не найдена — создаю..."
  mkdir -p "$AST_LOG_DIR"
  touch "$AST_LOG_DIR/messages"
  chmod 750 "$AST_LOG_DIR"
  log_info "Директория логов создана"
fi

# Проверяем logger.conf
AST_LOGGER="/etc/asterisk/logger.conf"
if [ -f "$AST_LOGGER" ]; then
  if grep -q "security" "$AST_LOGGER" 2>/dev/null; then
    log_info "logger.conf: канал security включён"
  else
    log_warn "logger.conf: канал 'security' НЕ найден!"
    log_warn "Добавь 'messages => notice,warning,error,security' в $AST_LOGGER"
  fi
else
  log_warn "Файл $AST_LOGGER не найден (Asterisk не установлен?)"
fi

# === 6. НАСТРОЙКА UFW ===
log_step "6/8 Настройка UFW (Firewall)"

ufw --force reset > /dev/null 2>&1
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null

# SSH
SSH_PORT=$(grep -E "^#?Port " /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}')
SSH_PORT=${SSH_PORT:-22}
ufw allow "${SSH_PORT}/tcp" comment 'SSH' > /dev/null
log_info "SSH: порт ${SSH_PORT}/tcp открыт"

# SIP
ufw allow 5060/udp comment 'SIP UDP' > /dev/null
ufw allow 5060/tcp comment 'SIP TCP' > /dev/null
ufw allow 5061/tcp comment 'SIPS TLS' > /dev/null
log_info "SIP: 5060/udp, 5060/tcp, 5061/tcp открыты"

# RTP
RTP_START=10000
RTP_END=20000
if [ -f /etc/asterisk/rtp.conf ]; then
  CUSTOM_START=$(grep -E "^rtpstart=" /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2)
  CUSTOM_END=$(grep -E "^rtpend=" /etc/asterisk/rtp.conf 2>/dev/null | cut -d= -f2)
  if [ -n "$CUSTOM_START" ] && [ -n "$CUSTOM_END" ]; then
    RTP_START=$CUSTOM_START
    RTP_END=$CUSTOM_END
    log_info "RTP: обнаружен кастомный диапазон в rtp.conf"
  fi
fi
ufw allow "${RTP_START}:${RTP_END}/udp" comment 'Asterisk RTP' > /dev/null
log_info "RTP: ${RTP_START}:${RTP_END}/udp открыт"

# Web
ufw allow 80/tcp comment 'HTTP' > /dev/null
ufw allow 443/tcp comment 'HTTPS' > /dev/null
log_info "Web: 80/tcp, 443/tcp открыты"

# IAX2 (если используется)
ufw allow 4569/udp comment 'IAX2' > /dev/null
log_info "IAX2: 4569/udp открыт"

ufw --force enable > /dev/null 2>&1
log_info "UFW включён и активен"

# === 7. НАСТРОЙКА FAIL2BAN ===
log_step "7/8 Настройка Fail2ban"

# Определяем IP сервера для подсказки
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

cat <<EOF > /etc/fail2ban/jail.local
# ==============================================================================
# Fail2ban Configuration — VoIP Hardener v2.0
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ==============================================================================

[DEFAULT]
bantime  = 86400
findtime = 3600
maxretry = 5
backend  = auto
ignoreip = 127.0.0.1/8 ::1
# ⚠️  ДОБАВЬ IP СВОИХ GoIP ШЛЮЗОВ СЮДА (через пробел):
# ignoreip = 127.0.0.1/8 ::1 192.168.1.50 10.0.0.100

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 86400

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
log_info "Fail2ban настроен и перезапущен"

# === 8. HARDENING ЯДРА (SYSCTL) ===
log_step "8/8 Харденинг ядра (sysctl)"

cat <<'EOF' > /etc/sysctl.d/99-voip-security.conf
# VoIP Security Hardening
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_timestamps = 0
EOF

sysctl --system > /dev/null 2>&1
log_info "Параметры ядра применены"

# === ИТОГ ===
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  ✅ ХАРДЕНИНГ ЗАВЕРШЁН УСПЕШНО!${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${CYAN}📊 Статус защиты:${NC}"
echo -e "  UFW:      $(ufw status | head -1)"
echo -e "  Fail2ban: $(systemctl is-active fail2ban)"
echo -e "  SSH порт: ${SSH_PORT}"
echo -e "  RTP:      ${RTP_START}:${RTP_END}/udp"
echo -e "  IP сервера: ${SERVER_IP:-unknown}"
echo ""
echo -e "${YELLOW}⚠️  ОБЯЗАТЕЛЬНЫЕ ДЕЙСТВИЯ ПОСЛЕ УСТАНОВКИ:${NC}"
echo -e "  1. Добавь IP GoIP шлюзов в /etc/fail2ban/jail.local (ignoreip)"
echo -e "  2. Проверь Asterisk logger.conf (канал security)"
echo -e "  3. Убедись: allowguest=no в sip.conf/pjsip.conf"
echo ""
echo -e "${CYAN}🔧 Полезные команды:${NC}"
echo -e "  sudo fail2ban-client status asterisk"
echo -e "  sudo ufw status numbered"
echo -e "  sudo tail -f /var/log/fail2ban.log"
echo ""
