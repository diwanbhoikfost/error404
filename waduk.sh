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
