#!/bin/bash
# base Scripts : LT x GPT
# Create anyewhere : 2015
# Bringas Tunnel | Bringas Family
# Lunatic Tunneling ( LT )
# Autheeer :  Lunatic Tunneling
# Bandung Barat | jawa Barat
# Who i am : from Indonesia
# Recode ? Jangan Hilangkan Watermark tod bodoh
export TERM=xterm
export DEBIAN_FRONTEND=noninteractive
dpkg-reconfigure debconf -f noninteractive 2>/dev/null

rm -f $0

apt update -y
apt upgrade -y
apt install git -y
apt install at -y
apt install curl -y
apt install wget -y
apt install jq -y
apt install lolcat -y
apt install gem -y
gem install lolcat -y
apt install dos2unix -y
apt install python -y
apt install python3 -y
apt install socat -y
apt install netcat -y
apt install ufw -y
apt install telnet 


# buat ubuntu 22 dan 25 
apt install netcat-traditional -y
apt install netcat-openbsd -y
apt install nodejs -y
apt install npm && npm install -g pm2

IPVPS=$(curl -sS ipv4.icanhazip.com)
export IP=$( curl -sS icanhazip.com )

# GIT REPO
LUNAREP="https://raw.githubusercontent.com/diwanbhoikfost/error404/main/"

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
                    echo -e "${OK} Your OS is supported: Ubuntu $os_version"
                    ;;
                *)
                    echo -e "${ERROR} Ubuntu version $os_version is not supported."
                    exit 1
                    ;;
            esac
            ;;
        debian)
            case "$os_version" in
                10|11|12|13)
                    echo -e "${OK} Your OS is supported: Debian $os_version"
                    ;;
                *)
                    echo -e "${ERROR} Debian version $os_version is not supported."
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo -e "${ERROR} Your OS ($os_id $os_version) is not supported."
            exit 1
            ;;
    esac
}

if [[ $( uname -m ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# Cek versi OS
check_os_version


if [ "${EUID}" -ne 0 ]; then
   echo "You need to run this script as root"
   exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
   echo "OpenVZ is not supported"
   exit 1
fi

# =========================[ WARNA ANSI ]=========================
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RED="\e[31m"
NC="\e[0m" # No Color
OK="[${GREEN}OK${NC}]"
ERROR="[${RED}ERROR${NC}]"

BIRU="\033[38;2;0;191;255m"
HIJAU="\033[38;2;173;255;47m"
PUTIH="\033[38;2;255;255;255m"
CYANS="\033[38;2;35;235;195m"
GOLD="\033[38;2;255;215;0m"
RESET="\033[0m"
# =========================[ FUNGSI UTILITAS ]=========================


print_error() {
    echo -e "${ERROR} ${RED}$1${NC}"
}

print_info() {
    echo -e "${YELLOW}[*] $1${NC}"
}

# Menampilkan pesan OK
print_ok() {
    echo -e "${OK} ${BLUE}$1${NC}"
}


# Menampilkan proses instalasi
print_install() {
    echo -e "${BIRU}──────────────────────────────────────${NC}"
    echo -e "${GOLD}# $1${NC}"
    echo -e "${BIRU}──────────────────────────────────────${NC}"
    sleep 1
}


# Menampilkan pesan sukses jika exit code 0
print_success() {
    if [[ $? -eq 0 ]]; then
    echo -e "${BIRU}──────────────────────────────────────${NC}"
    echo -e "${HIJAU}# $1 Sukses!${NC}"
    echo -e "${BIRU}──────────────────────────────────────${NC}"
        sleep 1
    fi
}

# Cek apakah user adalah root
is_root() {
    if [[ $EUID -eq 0 ]]; then
        print_ok "User root terdeteksi. Memulai proses instalasi..."
    else
        print_error "User saat ini bukan root. Silakan gunakan sudo atau login sebagai root!"
        exit 1
    fi
}

# =========================[ PERSIAPAN SISTEM XRAY ]=========================

print_install "Membuat direktori dan file konfigurasi Xray"

mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain

mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/auth.log
touch /var/log/kern.log
touch /var/log/mail.log
touch /var/log/user.log
touch /var/log/cron.log

mkdir -p /var/lib/luna >/dev/null 2>&1

print_success "Direktori dan file konfigurasi Xray berhasil dibuat"

# =========================[ CEK PENGGUNAAN RAM ]=========================

print_install "Menghitung penggunaan RAM"

mem_used=0
mem_total=0

while IFS=":" read -r key value; do
    value_kb=${value//[^0-9]/}  # Hanya ambil angka
    case $key in
        "MemTotal") 
            mem_total=$value_kb
            mem_used=$value_kb
            ;;
        "Shmem") 
            mem_used=$((mem_used + value_kb))
            ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
            mem_used=$((mem_used - value_kb))
            ;;
    esac
done < /proc/meminfo

Ram_Usage=$((mem_used / 1024))  # dalam MB
Ram_Total=$((mem_total / 1024)) # dalam MB

print_ok "RAM Digunakan : ${Ram_Usage} MB / ${Ram_Total} MB"

# =========================[ INFO SISTEM ]=========================

export tanggal=$(date +"%d-%m-%Y - %X")
export OS_Name=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip)

print_ok "Tanggal     : $tanggal"
print_ok "OS          : $OS_Name"
print_ok "Kernel      : $Kernel"
print_ok "Arsitektur  : $Arch"
print_ok "IP Publik   : $IP"

# =========================[ FUNGSI SETUP UTAMA ]=========================

PROXY_SETUP() {
    # Set zona waktu ke Asia/Jakarta
    timedatectl set-timezone Asia/Jakarta
    print_success "Timezone diset ke Asia/Jakarta"

    # Otomatis simpan aturan iptables
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Ambil OS info
    OS_ID=$(grep -w ^ID /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_NAME=$(grep -w PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

    print_success "Direktori Xray berhasil disiapkan"

# ubuntu
    # Instalasi tergantung distribusi OS
    if [[ "$OS_ID" == "ubuntu" ]]; then
        print_info "Deteksi OS: $OS_NAME"
        print_info "Menyiapkan dependensi untuk Ubuntu..."

        apt-get install haproxy -y
        apt install haproxy -y
        apt-get install nginx -y
        apt install nginx -y
        systemctl stop haproxy
        systemctl stop nginx

        print_success "HAProxy untuk Ubuntu ${OS_ID} telah terinstal"

## debian
    elif [[ "$OS_ID" == "debian" ]]; then
        print_info "Deteksi OS: $OS_NAME"
        print_info "Menyiapkan dependensi untuk Debian..."

        apt install haproxy -y
        apt install nginx -y        
        systemctl stop haproxy
        systemctl stop nginx
        
        print_success "HAProxy untuk Debian ${OS_ID} telah terinstal"

    else
        print_error "OS Tidak Didukung: $OS_NAME"
        exit 1
    fi
}

TOOLS_SETUP() {
    clear
    print_install "Menginstal paket dasar dan dependensi"

    # Paket utama
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y

    # Paket dasar
    apt install -y \
        zip pwgen openssl netcat socat cron bash-completion figlet sudo \
        zip unzip p7zip-full screen git cmake make build-essential \
        gnupg gnupg2 gnupg1 apt-transport-https lsb-release jq htop lsof tar \
        dnsutils python3-pip python ruby ca-certificates bsd-mailx msmtp-mta \
        ntpdate chrony chronyd ntpdate easy-rsa openvpn \
        net-tools rsyslog dos2unix sed xz-utils libc6 util-linux shc gcc g++ \
        libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev \
        libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison \
        libnss3-tools libevent-dev zlib1g-dev libssl-dev libsqlite3-dev \
        libxml-parser-perl dirmngr

    # Bersih-bersih dan setting iptables-persistent
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get remove --purge -y exim4 ufw firewalld
    sudo apt-get install -y debconf-utils

    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    apt install -y iptables iptables-persistent netfilter-persistent
    
    apt install rsyslog -y
    # Sinkronisasi waktu
    systemctl enable chronyd chrony
    systemctl restart chronyd chrony
    systemctl restart syslog
    ntpdate pool.ntp.org
    chronyc sourcestats -v
    chronyc tracking -v

    print_success "Semua paket dasar berhasil diinstal dan dikonfigurasi"
}

DOMENS_SETUP() {
clear
# === CREDENTIAL CLOUDFLARE ===
CF_ID="newvpnlunatix293@gmail.com"
CF_KEY="88a8619c3dec8a0c9a14cf353684036108844"

# === DOMAIN UTAMA ===
DOMAIN="execshell.cloud"
IPVPS=$(curl -s ipv4.icanhazip.com)

# === Generate Subdomain Random ===
SUBDOMAIN=$(cat /dev/urandom | tr -dc a-z0-9 | head -c 5)
RECORD="$SUBDOMAIN.$DOMAIN"

# === Get Zone ID dari Cloudflare ===
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
     -H "X-Auth-Email: $CF_ID" \
     -H "X-Auth-Key: $CF_KEY" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

# === Cek apakah record sudah ada ===
RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$RECORD" \
     -H "X-Auth-Email: $CF_ID" \
     -H "X-Auth-Key: $CF_KEY" \
     -H "Content-Type: application/json" | jq -r .result[0].id)

# === Tambah / Update Record ===
if [[ "$RECORD_ID" == "null" ]]; then
  echo "➕ Menambahkan record baru: $RECORD"
  curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
       -H "X-Auth-Email: $CF_ID" \
       -H "X-Auth-Key: $CF_KEY" \
       -H "Content-Type: application/json" \
       --data "{\"type\":\"A\",\"name\":\"$RECORD\",\"content\":\"$IPVPS\",\"ttl\":120,\"proxied\":false}" > /dev/null
else
  echo "🔄 Mengupdate record lama: $RECORD"
  curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
       -H "X-Auth-Email: $CF_ID" \
       -H "X-Auth-Key: $CF_KEY" \
       -H "Content-Type: application/json" \
       --data "{\"type\":\"A\",\"name\":\"$RECORD\",\"content\":\"$IPVPS\",\"ttl\":120,\"proxied\":false}" > /dev/null
fi

# === Simpan Hasil Domain ke File (APPEND) ===
echo "$RECORD" >> /etc/xray/domain 
echo "$RECORD" >> ~/domain # /root/domain
}


#!/bin/bash
# ==============================
# SCRIPT SETUP DOMAIN XRAY
# ==============================

# === CREDENTIAL CLOUDFLARE ===
CF_ID="newvpnlunatix293@gmail.com"
CF_KEY="88a8619c3dec8a0c9a14cf353684036108844"

# === DOMAIN UTAMA ===
DOMAIN="execshell.cloud"
IPVPS=$(curl -s ipv4.icanhazip.com)

# ==============================
# MENU PILIHAN DOMAIN
# ==============================
DOMAIN_MENU() {
clear
echo "=============================="
echo -e "\e[93;1m    DIWAN VPN TUNNELING  \e[0m "
echo "=============================="
echo "         SETUP DOMAIN "
echo "=============================="
echo "1. Random Domain (Default)"
echo "2. Custom Domain (Pointing dulu ke Cloudflare)"
echo "=============================="
read -p "Pilih [1-2]: " pilih

case $pilih in
1)
    DOMENS_SETUP
    ;;
2)
    CUSTOM_DOMAIN
    ;;
*)
    echo "❌ Pilihan tidak valid"
    sleep 2
    DOMAIN_MENU
    ;;
esac
}

# ==============================
# OPSI 1: RANDOM DOMAIN (DEFAULT)
# ==============================
DOMENS_SETUP() {
clear
# === Generate Subdomain Random ===
SUBDOMAIN=$(tr -dc a-z0-9 </dev/urandom | head -c 5)
RECORD="$SUBDOMAIN.$DOMAIN"

# === Get Zone ID ===
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
 -H "X-Auth-Email: $CF_ID" \
 -H "X-Auth-Key: $CF_KEY" \
 -H "Content-Type: application/json" | jq -r .result[0].id)

# === Get Record ID ===
RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$RECORD" \
 -H "X-Auth-Email: $CF_ID" \
 -H "X-Auth-Key: $CF_KEY" \
 -H "Content-Type: application/json" | jq -r .result[0].id)

# === Add / Update Record ===
if [[ "$RECORD_ID" == "null" ]]; then
  echo "➕ Menambahkan domain: $RECORD"
  curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
   -H "X-Auth-Email: $CF_ID" \
   -H "X-Auth-Key: $CF_KEY" \
   -H "Content-Type: application/json" \
   --data "{\"type\":\"A\",\"name\":\"$RECORD\",\"content\":\"$IPVPS\",\"ttl\":120,\"proxied\":false}" > /dev/null
else
  echo "🔄 Update domain: $RECORD"
  curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
   -H "X-Auth-Email: $CF_ID" \
   -H "X-Auth-Key: $CF_KEY" \
   -H "Content-Type: application/json" \
   --data "{\"type\":\"A\",\"name\":\"$RECORD\",\"content\":\"$IPVPS\",\"ttl\":120,\"proxied\":false}" > /dev/null
fi

# === Simpan Domain ===
echo "$RECORD" | tee -a /etc/xray/domain ~/domain
echo "✅ Domain aktif: $RECORD"
sleep 2
}

# ==============================
# OPSI 2: CUSTOM DOMAIN
# ==============================
CUSTOM_DOMAIN() {
clear
echo "========================================"
echo "  CUSTOM DOMAIN (WAJIB POINTING DULU)"
echo "========================================"
echo "Contoh: vpn.domainkamu.com"
echo
read -p "Masukkan domain: " CDOMAIN

if [[ -z "$CDOMAIN" ]]; then
  echo "❌ Domain tidak boleh kosong"
  sleep 2
  CUSTOM_DOMAIN
fi

# === Simpan Domain ===
echo "$CDOMAIN" | tee -a /etc/xray/domain ~/domain
echo "✅ Domain custom digunakan: $CDOMAIN"
sleep 2
}



SSL_SETUP() {
    clear
    print_install "Memasang SSL Certificate pada domain"

    # Cek domain
    if [[ ! -f /root/domain ]]; then
        print_error "File /root/domain tidak ditemukan!"
        return 1
    fi

    domain=$(cat /root/domain)

    # Hentikan service yang menggunakan port 80
    webserver_port=$(lsof -i:80 | awk 'NR==2 {print $1}')
    if [[ -n "$webserver_port" ]]; then
        print_info "Menghentikan service $webserver_port yang menggunakan port 80..."
        systemctl stop "$webserver_port"
    fi

    systemctl stop nginx >/dev/null 2>&1

    # Hapus sertifikat lama
    rm -f /etc/xray/xray.key /etc/xray/xray.crt
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Download ACME.sh
    curl -s https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Upgrade dan konfigurasi ACME
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Proses issue SSL
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    if [[ $? -ne 0 ]]; then
        print_error "Gagal mendapatkan sertifikat SSL dari Let's Encrypt"
        return 1
    fi

    # Pasang sertifikat ke direktori Xray
    ~/.acme.sh/acme.sh --installcert -d "$domain" \
        --fullchainpath /etc/xray/xray.crt \
        --keypath /etc/xray/xray.key \
        --ecc

    chmod 600 /etc/xray/xray.key /etc/xray/xray.crt

    print_success "Sertifikat SSL berhasil dipasang untuk domain: $domain"
}


FODER_SETUP() {
local main_dirs=(
        "/etc/xray" "/var/lib/luna" "/etc/lunatic" "/etc/limit" "/etc/zivpn"
        "/etc/vmess" "/etc/vless" "/etc/trojan" "/etc/ssh" "/usr/local/bin/zivpn" 
    )
    
    local lunatic_subdirs=("vmess" "vless" "trojan" "ssh" "bot" "zivpn")
    local lunatic_types=("usage" "ip" "detail")

    local protocols=("vmess" "vless" "trojan" "ssh" "zivpn")

    for dir in "${main_dirs[@]}"; do
        mkdir -p "$dir"
    done

    for service in "${lunatic_subdirs[@]}"; do
        for type in "${lunatic_types[@]}"; do
            mkdir -p "/etc/lunatic/$service/$type"
        done
    done

    for protocol in "${protocols[@]}"; do
        mkdir -p "/etc/limit/$protocol"
    done

    local databases=(
        "/etc/lunatic/vmess/.vmess.db"
        "/etc/lunatic/vless/.vless.db"
        "/etc/lunatic/trojan/.trojan.db"
        "/etc/lunatic/ssh/.ssh.db"
        "/etc/lunatic/bot/.bot.db"
    )

    for db in "${databases[@]}"; do
        touch "$db"
        echo "& plugin Account" >> "$db"
    done

    touch /etc/.{ssh,vmess,vless,trojan}.db
    echo "IP=" > /var/lib/luna/ipvps.conf
}

XRAY_SETUP() {
    clear
    print_install "Xray Core Versions 4.22.24 (bangladeshi)"

    # Buat directory untuk socket domain jika belum ada
    local domainSock_dir="/run/xray"
    [[ ! -d $domainSock_dir ]] && mkdir -p "$domainSock_dir"
    chown www-data:www-data "$domainSock_dir"
    # Install Xray Core
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version 24.10.31
    # Konfigurasi file dan service custom
    wget -q -O /etc/xray/config.json "${LUNAREP}configure/config.json"
    wget -q -O /etc/systemd/system/runn.service "${LUNAREP}configure/runn.service"

    # Validasi domain
    if [[ ! -f /etc/xray/domain ]]; then
        print_error "File domain tidak ditemukan di /etc/xray/domain"
        return 1
    fi
    local domain=$(cat /etc/xray/domain)
    local IPVS=$(cat /etc/xray/ipvps)

    print_success "Xray Core Versi 24.10.31 berhasil dipasang"
    clear

    # Tambahkan info kota dan ISP
    curl -s ipinfo.io/city >> /etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2- >> /etc/xray/isp

    print_install "Memasang Konfigurasi Paket Tambahan"

    # Haproxy dan Nginx Config
    wget -q -O /etc/haproxy/haproxy.cfg k"${LUNAREP}configure/haproxy.cfg"
    wget -q -O /etc/nginx/conf.d/xray.conf "${LUNAREP}configure/xray.conf"
    curl -s "${LUNAREP}configure/nginx.conf" > /etc/nginx/nginx.conf

    # Ganti placeholder domain
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

    # Gabungkan sertifikat ke haproxy
    cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem

    # Tambahkan service unit untuk xray
    cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    chmod +x /etc/systemd/system/runn.service
    rm -rf /etc/systemd/system/xray.service.d

    print_success "Konfigurasi Xray dan Service berhasil"
}

PW_DEFAULT() {
    clear
    print_install "Mengatur Password Policy dan Konfigurasi SSH"

    # Download file konfigurasi password PAM
    local password_url="https://raw.githubusercontent.com/diwanbhoikfost/error404/main/configure/password"
    wget -q -O /etc/pam.d/common-password "$password_url"
    chmod 644 /etc/pam.d/common-password

    # Konfigurasi layout keyboard non-interaktif
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration

    debconf-set-selections <<EOF
keyboard-configuration keyboard-configuration/layout select English
keyboard-configuration keyboard-configuration/layoutcode string us
keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC
keyboard-configuration keyboard-configuration/modelcode string pc105
keyboard-configuration keyboard-configuration/v
