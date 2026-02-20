#!/bin/bash
# ==========================================
# Script: DIWAN TUNNELING BEYOND ULTIMATE 2026
# Level: Enterprise VPN Management System
# Features: SSH, Xray, gRPC, Sentry, TeleBot
# ==========================================

# [ CONFIGURATION ]
BOT_TOKEN="GANTI_TOKEN_BOT_MU"
CHAT_ID="GANTI_CHAT_ID_MU"

export TERM=xterm
export DEBIAN_FRONTEND=noninteractive

# [ COLORS & UI ]
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# [ FUNCTION: SEND TELEGRAM ]
send_tele() {
    if [[ "$BOT_TOKEN" != "GANTI_TOKEN_BOT_MU" ]]; then
        curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
            -d chat_id="$CHAT_ID" \
            -d text="$1" \
            -d parse_mode="HTML" > /dev/null
    fi
}

# [ 1. PRE-INSTALL & OPTIMIZATION ]
PRE_INSTALL() {
    clear
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${YELLOW}    STARTING DIWAN TUNNELING INSTALLER 2026      ${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    apt update -y && apt upgrade -y
    apt install -y jq curl wget git zip unzip socat net-tools htop vnstat ufw haproxy nginx bc rsyslog cron lsof screen
    
    # Tuning Kernel for Speed
    cat > /etc/sysctl.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_max_syn_backlog=65536
net.ipv4.tcp_max_tw_buckets=6000
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.ip_forward=1
EOF
    sysctl -p > /dev/null 2>&1
    
    # Create Directories
    mkdir -p /etc/diwan/{ssh,vmess,vless,trojan,shadowsocks}
    mkdir -p /etc/xray /var/log/xray
    touch /var/log/xray/access.log
}

# [ 2. DOMAIN & SSL AUTO-GEN ]
SSL_SETUP() {
    echo -e "${GREEN}[*] Configuring Domain & Auto-SSL...${NC}"
    read -p " Masukkan Domain Anda: " domain
    if [[ -z "$domain" ]]; then
        domain="diwan-$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 4).execshell.cloud"
    fi
    echo "$domain" > /etc/xray/domain
    
    # Install ACME
    curl https://get.acme.sh | sh -s email=admin@$domain
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
}

# [ 3. XRAY CORE & CONFIG (gRPC & MULTIPATH) ]
XRAY_INSTALL() {
    echo -e "${GREEN}[*] Installing Xray Core with Multi-Protocol...${NC}"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Load High-Performance Config
    wget -q -O /etc/xray/config.json "https://raw.githubusercontent.com/diwanbhoikfost/error404/main/configure/config.json"
    
    # Geo-Data Update
    wget -q -O /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
    wget -q -O /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
}

# [ 4. DIWAN SENTRY V3 (PROTECTION ENGINE) ]
SENTRY_SETUP() {
    echo -e "${GREEN}[*] Activating Sentry V3 (Protection Engine)...${NC}"
    cat > /usr/local/sbin/diwan-sentry <<EOF
#!/bin/bash
MAX_LOGIN=2
LOG="/var/log/diwan-sentry.log"
DATE=\$(date "+%Y-%m-%d %H:%M:%S")

# SSH/Dropbear Logic
for user in \$(awk -F: '(\$3 >= 1000 && \$3 != 65534) {print \$1}' /etc/passwd); do
    count=\$(ps -u \$user | grep -E "sshd|dropbear" | wc -l)
    if [ "\$count" -gt "\$MAX_LOGIN" ]; then
        msg="🚨 <b>SENTRY KICK!</b>%0AUser: <code>\$user</code>%0AIP: <code>\$(curl -s ifconfig.me)</code>%0AReason: Multi-login (\$count devices)"
        curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" -d chat_id="$CHAT_ID" -d text="\$msg" -d parse_mode="HTML"
        echo "\$DATE | KICKED: \$user (\$count)" >> \$LOG
        pkill -u \$user
    fi
done
EOF
    chmod +x /usr/local/sbin/diwan-sentry
    (crontab -l ; echo "* * * * * /usr/local/sbin/diwan-sentry") | crontab -
}

# [ 5. AUTO-BACKUP & CLEANER ]
MAINTENANCE_SETUP() {
    echo -e "${GREEN}[*] Configuring Auto-Maintenance...${NC}"
    # Auto Backup
    cat > /usr/local/sbin/diwan-backup <<EOF
#!/bin/bash
zip -r /root/backup-\$(date +%F).zip /etc/diwan/ /etc/xray/ /etc/ssh/
EOF
    chmod +x /usr/local/sbin/diwan-backup
    (crontab -l ; echo "0 0 * * * /usr/local/sbin/diwan-backup") | crontab -
}

# [ 6. ULTIMATE DASHBOARD MENU ]
MENU_SETUP() {
    cat > /usr/local/bin/menu <<'EOF'
#!/bin/bash
# Color definition inside menu
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

clear
IP=$(curl -s ifconfig.me)
DOMAIN=$(cat /etc/xray/domain)
UPTIME=$(uptime -p)
TRAF=$(vnstat --oneline | awk -F';' '{print $11}')

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}           DIWAN TUNNELING - DASHBOARD 2026        ${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo -e " 🔹 IP VPS    : $IP"
echo -e " 🔹 Domain    : $DOMAIN"
echo -e " 🔹 Uptime    : $UPTIME"
echo -e " 🔹 Traffic   : $TRAF"
echo -e "${CYAN}╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺${NC}"
echo -e " [1] SSH & Websocket Menu     [5] Sentry Protection Log"
echo -e " [2] VMess (Xray) Menu        [6] Speedtest Server"
echo -e " [3] VLess (Xray) Menu        [7] Backup & Restore Data"
echo -e " [4] Trojan (Xray) Menu       [8] Restart All Services"
echo -e " [0] Exit Dashboard           [9] Reboot VPS"
echo -e "${CYAN}╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺╺${NC}"
read -p " Pilih Menu: " opt
case $opt in
    5) tail -f /var/log/diwan-sentry.log ;;
    8) systemctl restart xray nginx haproxy; echo "Services Restarted!"; sleep 2; menu ;;
    9) reboot ;;
    0) exit ;;
    *) echo "Menu belum tersedia di versi demo ini!"; sleep 2; menu ;;
esac
EOF
    chmod +x /usr/local/bin/menu
    echo "menu" >> /root/.bashrc
}

# [ 7. EXECUTE ALL ]
INSTALL_NOW() {
    PRE_INSTALL
    SSL_SETUP
    XRAY_INSTALL
    SENTRY_SETUP
    MAINTENANCE_SETUP
    MENU_SETUP
    
    # Final Tele Notif
    IP=$(curl -s ifconfig.me)
    msg="🚀 <b>INSTALLASI BEYOND SELESAI!</b>%0A%0AIP: <code>$IP</code>%0ADomain: <code>$(cat /etc/xray/domain)</code>%0AMode: <b>Enterprise Enabled</b>"
    send_tele "$msg"
    
    clear
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}      INSTALLASI DIWAN TUNNELING BERHASIL!       ${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e " Sentry Protection : ACTIVE"
    echo -e " Telegram Notif    : ACTIVE"
    echo -e " Ketik 'menu' untuk mengelola VPS kamu."
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

INSTALL_NOW
