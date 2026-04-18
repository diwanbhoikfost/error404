#!/bin/bash
# base Scripts : # Bringas Tunnel | Bringas Family @2016
# Create anyewhere : 2016 november 14
# Recoder : Lunatic Tunneling ( LT )
# Autheeer :  Bringas Tunnel
# Bandung Barat | jawa Barat | desa Jati | Indonesia
# Recode ? Jangan Hilangkan Watermark tod bodoh
# awas ada trap , gua masih baik ngasi tau 
export TERM=xterm
export DEBIAN_FRONTEND=noninteractive
dpkg-reconfigure debconf -f noninteractive 2>/dev/null

rm -f $0

# ══════════════════════════════════════════════
#              COLOR PALETTE
# ══════════════════════════════════════════════
NC='\e[0m'
BOLD='\033[1m'
DIM='\033[2m'

CYAN='\033[38;5;51m'
CYAN_SOFT='\033[38;5;75m'
CYAN_DIM='\033[38;5;67m'
PURPLE='\033[38;5;141m'
GOLD='\033[38;2;255;215;0m'
WHITE='\033[1;97m'

GREEN='\033[38;5;82m'
GREEN_DIM='\033[38;5;70m'
RED='\033[38;5;196m'
YELLOW='\033[38;5;226m'
ORANGE='\033[38;5;214m'
BLUE='\033[38;5;39m'

BIRU="\033[38;2;0;191;255m"
HIJAU="\033[38;2;173;255;47m"
PUTIH="\033[38;2;255;255;255m"
CYANS="\033[38;2;35;235;195m"
RESET="\033[0m"

OK="${GREEN}[  OK  ]${NC}"
ERROR="${RED}[ FAIL ]${NC}"

LINE="${CYAN_DIM}────────────────────────────────────────────────${NC}"
LINE_THIN="${DIM}┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${NC}"

# ══════════════════════════════════════════════
#              SPINNER LOADING
# ══════════════════════════════════════════════
loading() {
    local pid=$1
    local text="$2"
    local frames=('⣾' '⣽' '⣻' '⢿' '⡿' '⣟' '⣯' '⣷')
    local i=0
    tput civis
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}${frames[$i]}${NC}  ${WHITE}%-40s${NC}" "$text"
        i=$(( (i + 1) % ${#frames[@]} ))
        sleep 0.08
    done
    wait "$pid"
    local exit_code=$?
    tput cnorm
    printf "\r\033[2K"
    if [[ $exit_code -eq 0 ]]; then
        echo -e "  ${GREEN}✔${NC}  ${WHITE}${text}${NC}"
    else
        echo -e "  ${RED}✖${NC}  ${WHITE}${text}${NC}  ${DIM}(non-fatal)${NC}"
    fi
    return $exit_code
}

# ══════════════════════════════════════════════
#              PRINT HELPERS
# ══════════════════════════════════════════════
print_error() {
    echo -e "  ${RED}✖${NC}  ${WHITE}$1${NC}"
}

print_info() {
    echo -e "  ${CYAN_SOFT}→${NC}  ${WHITE}$1${NC}"
}

print_ok() {
    echo -e "  ${GREEN}✔${NC}  ${CYAN_SOFT}$1${NC}"
}

print_install() {
    echo ""
    echo -e "$LINE"
    echo -e "  ${GOLD}${BOLD}$1${NC}"
    echo -e "$LINE"
    sleep 0.4
}

print_success() {
    if [[ $? -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}✔${NC}  ${GREEN}$1${DIM} — done${NC}"
        echo -e "$LINE_THIN"
        sleep 0.5
    fi
}

is_root() {
    if [[ $EUID -eq 0 ]]; then
        print_ok "Running as root. Starting installation..."
    else
        print_error "This script must be run as root!"
        exit 1
    fi
}
# ══════════════════════════════════════════════
#              INITIAL BANNER
# ══════════════════════════════════════════════
clear
echo ""
echo -e "$LINE"
echo -e "  ${CYAN}▌${NC}  ${BOLD}${WHITE}  LUNATIC TUNNELING — PACKETS INSTALLER${NC}"
echo -e "$LINE"
echo -e "    ${CYAN}➤${NC}  ${WHITE}Update & upgrade system packages${NC}"
echo -e "    ${CYAN}➤${NC}  ${WHITE}Install required dependencies${NC}"
echo -e "$LINE"
echo ""

sleep 2

(apt update -y >/dev/null 2>&1) & loading $! "Updating package lists"
(apt upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >/dev/null 2>&1) & loading $! "Upgrading installed packages"
(apt install git -y >/dev/null 2>&1) & loading $! "Installing git"
(apt install at -y >/dev/null 2>&1) & loading $! "Installing at"
(apt install curl -y >/dev/null 2>&1) & loading $! "Installing curl"
(apt install wget -y >/dev/null 2>&1) & loading $! "Installing wget"
(apt install jq -y >/dev/null 2>&1) & loading $! "Installing jq"
(apt install lolcat -y >/dev/null 2>&1) & loading $! "Installing lolcat"
(apt install ruby rubygems -y >/dev/null 2>&1) & loading $! "Installing ruby & rubygems"
(gem install lolcat --no-document >/dev/null 2>&1) & loading $! "Installing lolcat gem"
(apt install dos2unix -y >/dev/null 2>&1) & loading $! "Installing dos2unix"
(apt install python-is-python3 -y >/dev/null 2>&1) & loading $! "Installing python-is-python3"
(apt install python3 -y >/dev/null 2>&1) & loading $! "Installing python3"
(apt install socat -y >/dev/null 2>&1) & loading $! "Installing socat"
(apt install netcat -y >/dev/null 2>&1) & loading $! "Installing netcat"
(apt install ufw -y >/dev/null 2>&1) & loading $! "Installing ufw"
(apt install telnet -y >/dev/null 2>&1) & loading $! "Installing telnet"
(apt install speedtest-cli -y >/dev/null 2>&1) & loading $! "Installing speedtest-cli"

# buat ubuntu 22 dan 25
(apt install netcat-traditional -y >/dev/null 2>&1) & loading $! "Installing netcat-traditional"
(apt install netcat-openbsd -y >/dev/null 2>&1) & loading $! "Installing netcat-openbsd"
(apt install nodejs -y >/dev/null 2>&1) & loading $! "Installing nodejs"
(apt install npm -y >/dev/null 2>&1 && npm install -g pm2 >/dev/null 2>&1) & loading $! "Installing npm + pm2"

IPVPS=$(curl -sS ipv4.icanhazip.com)
export IP=$(curl -sS icanhazip.com)

# Deteksi interface jaringan utama (dipakai oleh vnSTATS_SETUP)
NET=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
[[ -z "$NET" ]] && NET="eth0"

# GIT REPO
WORKING_LINK="https://raw.githubusercontent.com/yansyntax/yan2/main/"

function ADD_CEEF() {
EMAILCF="newvpnlunatix293@gmail.com"
KEYCF="88a8619c3dec8a0c9a14cf353684036108844"
echo "$EMAILCF" > /usr/bin/emailcf
echo "$KEYCF" > /usr/bin/keycf
}

function check_os_version() {
    local os_id os_version

    os_id=$(grep -w ID /etc/os-release | cut -d= -f2 | tr -d '"')
    os_version=$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')

    case "$os_id" in
        ubuntu)
            case "$os_version" in
                20.04|22.04|22.10|23.04|24.04|24.10|25.04|25.10)
                    print_ok "OS Supported: Ubuntu $os_version"
                    ;;
                *)
                    print_error "Ubuntu $os_version is not supported."
                    exit 1
                    ;;
            esac
            ;;
        debian)
            case "$os_version" in
                10|11|12|13)
                    print_ok "OS Supported: Debian $os_version"
                    ;;
                *)
                    print_error "Debian $os_version is not supported."
                    exit 1
                    ;;
            esac
            ;;
        *)
            print_error "OS ($os_id $os_version) is not supported."
            exit 1
            ;;
    esac
}

if [[ $(uname -m) == "x86_64" ]]; then
    print_ok "Architecture Supported: $(uname -m)"
else
    print_error "Architecture Not Supported: $(uname -m)"
    exit 1
fi

# Cek versi OS
check_os_version

if [ "${EUID}" -ne 0 ]; then
   print_error "You need to run this script as root"
   exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
   print_error "OpenVZ is not supported"
   exit 1
fi

# ══════════════════════════════════════════════
#              PERSIAPAN SISTEM XRAY
# ══════════════════════════════════════════════
print_install "Creating Directories & Xray Configuration"

mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain

mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray

echo ""
echo -e "$LINE"
echo -e "  ${GOLD}${BOLD}Creating Log Files${NC}"
echo -e "$LINE"
echo -e "    ${CYAN}➤${NC}  /var/log/xray/access.log"
echo -e "    ${CYAN}➤${NC}  /var/log/xray/error.log"
echo -e "    ${CYAN}➤${NC}  /var/log/auth.log"
echo -e "    ${CYAN}➤${NC}  /var/log/kern.log"
echo -e "    ${CYAN}➤${NC}  /var/log/mail.log"
echo -e "    ${CYAN}➤${NC}  /var/log/user.log"
echo -e "    ${CYAN}➤${NC}  /var/log/cron.log"
echo -e "$LINE"

touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/auth.log
touch /var/log/kern.log
touch /var/log/mail.log
touch /var/log/user.log
touch /var/log/cron.log

mkdir -p /var/lib/luna >/dev/null 2>&1

print_success "Log files created successfully"
