#!/bin/bash

scriptVersion=1.0

# Color Codes
function colorCodes() {
RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}
green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}
yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}
blue(){
    echo -e "\033[34m\033[01m$1\033[0m"
}
bold(){
    echo -e "\033[1m\033[01m$1\033[0m"
}

}

function defVars() {
CURRENT_WG_NIC="NONE"
CURRENT_WG_NIC_LOCATION=null
SERVER_WG_NIC="NONE"

}

function startup() {
clear

# ROOT ACCESS CHECK
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi


# CREDIT : Angristn Script 
if [ "$(systemd-detect-virt)" == "openvz" ]; then
	echo "OpenVZ is not supported"
	exit 1
fi

if [ "$(systemd-detect-virt)" == "lxc" ]; then
	echo "LXC is not supported (yet)."
	echo "WireGuard can technically run in an LXC container,"
	echo "but the kernel module has to be installed on the host,"
	echo "the container has to be run with some specific parameters"
	echo "and only the tools need to be installed in the container."
	exit 1
fi

# CREDIT : Angristn Script 
source /etc/os-release
OS="${ID}"
if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
	if [[ ${VERSION_ID} -lt 10 ]]; then
		echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
		exit 1
	fi
	OS=debian # overwrite if raspbian
elif [[ ${OS} == "ubuntu" ]]; then
	RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
	if [[ ${RELEASE_YEAR} -lt 18 ]]; then
		echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
		exit 1
	fi
elif [[ ${OS} == "fedora" ]]; then
	if [[ ${VERSION_ID} -lt 32 ]]; then
		echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
		exit 1
	fi
elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
	if [[ ${VERSION_ID} == 7* ]]; then
		echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
		exit 1
	fi
elif [[ -e /etc/oracle-release ]]; then
	source /etc/os-release
	OS=oracle
elif [[ -e /etc/arch-release ]]; then
	OS=arch
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
	exit 1
fi

# Check if extDot folder exists
# Define extDot folder path
EXTDOT_FOLDER="/usr/local/extDot"
if [[ -d "$EXTDOT_FOLDER" ]]; then
  echo "[ O K ] extDot folder"
else
  # Create extDot folder
  mkdir -p "$EXTDOT_FOLDER"
  echo "extDot folder created."
  echo "[ O K ] extDot folder"
fi

}


function installWireGuard() {

# Install WireGuard tools and module
if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
	apt-get update
	apt-get install -y wireguard iptables resolvconf qrencode
elif [[ ${OS} == 'debian' ]]; then
	if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
		echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
		apt-get update
	fi
	apt update
	apt-get install -y iptables resolvconf qrencode
	apt-get install -y -t buster-backports wireguard
elif [[ ${OS} == 'fedora' ]]; then
	if [[ ${VERSION_ID} -lt 32 ]]; then
		dnf install -y dnf-plugins-core
		dnf copr enable -y jdoss/wireguard
		dnf install -y wireguard-dkms
	fi
	dnf install -y wireguard-tools iptables qrencode
elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
	if [[ ${VERSION_ID} == 8* ]]; then
		yum install -y epel-release elrepo-release
		yum install -y kmod-wireguard
		yum install -y qrencode # not available on release 9
	fi
	yum install -y wireguard-tools iptables
elif [[ ${OS} == 'oracle' ]]; then
	dnf install -y oraclelinux-developer-release-el8
	dnf config-manager --disable -y ol8_developer
	dnf config-manager --enable -y ol8_developer_UEKR6
	dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
	dnf install -y wireguard-tools qrencode iptables
elif [[ ${OS} == 'arch' ]]; then
	pacman -S --needed --noconfirm wireguard-tools qrencode
fi

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir -p /etc/wireguard >/dev/null 2>&1
mkdir -p /usr/local/extDot >/dev/null 2>&1
chmod 600 -R /etc/wireguard/
chmod 600 -R /usr/local/extDot

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

sysctl --system

}

function checkWireGuard() {

if command -v wg &> /dev/null
then
    echo "[ O K ] WireGuard App"
else
    echo -e "\n${RED}[ERROR] WireGuard does not seem to be installed.${NC}"
	echo -e "${ORANGE}[INFO] Installing WireGuard ${NC}"
	installWireGuard
fi

}


function UninstallWireGuard() {

echo -e "\n${RED}WARNING: This will uninstall WireGuard Only!${NC}"
read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
REMOVE=${REMOVE:-n}

if [[ $REMOVE == 'y' ]]; then

wg-quick down --all
systemctl disable wg-quick@*
systemctl stop wg-quick@*

startup

if [[ ${OS} == 'ubuntu' ]]; then	
	apt-get remove -y wireguard wireguard-tools
elif [[ ${OS} == 'debian' ]]; then
	apt-get remove -y wireguard wireguard-tools
elif [[ ${OS} == 'fedora' ]]; then
	dnf remove -y --noautoremove wireguard-tools
	if [[ ${VERSION_ID} -lt 32 ]]; then
		dnf remove -y --noautoremove wireguard-dkms
		dnf copr disable -y jdoss/wireguard
	fi
elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
	yum remove -y --noautoremove wireguard-tools
		if [[ ${VERSION_ID} == 8* ]]; then
			yum remove --noautoremove kmod-wireguard
		fi
elif [[ ${OS} == 'oracle' ]]; then
	yum remove --noautoremove wireguard-tools
elif [[ ${OS} == 'arch' ]]; then
	pacman -Rs --noconfirm wireguard-tools
fi

rm -f /etc/sysctl.d/wg.conf

# Reload sysctl
sysctl --system

# Remove Crontab command if exssits
CRTLINE="/usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh"
CRONTAB=$(crontab -l)
if [[ $CRONTAB == *"$CRTLINE"* ]]; then
NEW_CRONTAB=$(echo "$CRONTAB" | grep -v "$CRTLINE")
echo "$NEW_CRONTAB" | crontab -
echo "Line removed successfully."
else
echo -e "${ORANGE}The specified line does not exist in the crontab. ${NC}"
fi

else
	echo
	echo -e "${ORANGE}Removal aborted! ${NC}"
fi
}

function viewWGinterfaces() {

if [ -d "/etc/wireguard" ]; then
    bold "WireGuard folder exists."
    conf_files=$(find /etc/wireguard -type f -name "*.conf")
    if [ -n "$conf_files" ]; then
        green "All Available Interfaces :"
        count=1
        for conf_file in $conf_files; do
            filename=$(basename -- "$conf_file")
            extension="${filename##*.}"
            filename="${filename%.*}"
            yellow "$count. $filename"
            ((count++))
        done
    else
        red "WARNIG: No WireGuard configuration ."
    fi
else
    red "ERROR: WireGuard folder does not exist."
fi
}

function getHomeDirDEL() {
DIRSTAT=0
# Check if /home/wireguard/${SERVER_WG_NIC} exists
if [ -d "/home/wireguard/${SERVER_WG_NIC}" ]; then
    HOME_DIRDEL="/home/wireguard/${SERVER_WG_NIC}"
# Check if SUDO_USER is set
elif [ -d "/root/wireguard/${SERVER_WG_NIC}" ]; then
	HOME_DIRDEL="/root/wireguard/${SERVER_WG_NIC}"
elif [ -d "/home/${SUDO_USER}/wireguard/${SERVER_WG_NIC}" ]; then
	HOME_DIRDEL="/home/${SUDO_USER}/wireguard/${SERVER_WG_NIC}"
else
red " - [ERROR] no config folder has found."
DIRSTAT=1
fi

}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/wireguard/${SERVER_WG_NIC}/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/wireguard/${SERVER_WG_NIC}/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root/wireguard/${SERVER_WG_NIC}"
		else
			HOME_DIR="/home/${SUDO_USER}/wireguard/${SERVER_WG_NIC}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root/wireguard/${SERVER_WG_NIC}"
	fi

	echo "$HOME_DIR"
}

# MENU RETURN
function B2main() {
read -p "Press enter to back to menu"
clear
mainMenuWG
}

function SelectWgNIC() {
clear

yellow "=== WireGuard Server Selector ==============================="
echo
if [ -d "/etc/wireguard" ]; then
    conf_files=$(find /etc/wireguard -type f -name "*.conf")
    if [ -n "$conf_files" ]; then
        green " - The following WireGuard configuration files were found:"
		green "-------------------------------------------------------------"
        count=1
        for conf_file in $conf_files; do
            filename=$(basename -- "$conf_file")
            extension="${filename##*.}"
            filename="${filename%.*}"
            echo "   - $count. $filename"
            ((count++))
        done
		echo
		green "-------------------------------------------------------------"

        read -p "Enter the number of the configuration file you want to use: " selection

        if [[ "$selection" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= count-1 )); then
            conf_file=$(echo "$conf_files" | sed -n "${selection}p")
            CURRENT_WG_NIC=$(basename -- "$conf_file" .conf)
            CURRENT_WG_NIC_LOCATION="$conf_file"
			echo
			yellow "You have selected [$CURRENT_WG_NIC]"
        else
            red "[ERROR] Invalid selection - Set to NONE server."
            CURRENT_WG_NIC="NONE"
            CURRENT_WG_NIC_LOCATION="NONE"
        fi
    else
        echo "No WireGuard configuration files were found."
        CURRENT_WG_NIC="NONE"
        CURRENT_WG_NIC_LOCATION="NONE"
    fi
else
    echo "WireGuard folder does not exist."
    CURRENT_WG_NIC="NONE"
    CURRENT_WG_NIC_LOCATION="NONE"
fi

SERVER_WG_NIC=$CURRENT_WG_NIC
echo
}


function mtuSet() {
MIN_MTU=576
MAX_MTU=1500
DEFAULT_MTU=1420
echo
yellow "   - Setup MTU size parameter"
while true; do

  read -rp "   - Enter MTU size [${MIN_MTU}~${MAX_MTU}]: " -e -i "${DEFAULT_MTU}" mtu

  if ! [[ "$mtu" =~ ^[0-9]+$ ]]; then
    red "   - [ERROR] MTU size must be a positive integer."
  elif ((mtu < MIN_MTU || mtu > MAX_MTU)); then
    red "   - [ERROR] MTU size must be between ${MIN_MTU} and ${MAX_MTU}."
  else
    green "   - MTU size set to $mtu."
    break
  fi
done
}

function createNewWgNIC() {
clear
echo
echo
yellow "=============== ExtremeDOT - WireGuard new Interface Creator ==============="

echo
echo "You can keep the default options and just press enter if you are ok with them."
echo
NEWWGNICNAME=""
SERVER_WG_NIC=""

latest_file=$(find /etc/wireguard -type f -name "wg*.conf" | sort -r | head -n1)
latest_num=$(find /etc/wireguard -type f -name "wg*.conf" | sed 's/.*wg\([0-9]*\)\.conf/\1/g' | sort -rn | head -n1)

# Show the number of the latest wg[number].conf file
if [ -n "$latest_num" ]; then
	new_numPlusOne=$((latest_num+1))
	NEWWGNICNAME="wg$new_numPlusOne"
else
	NEWWGNICNAME="wg0"
fi

echo

yellow " - Please enter your VPS Server public details"
# Detect public IPv4 or IPv6 address and pre-fill for the user
SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
if [[ -z ${SERVER_PUB_IP} ]]; then
	# Detect public IPv6 address
	SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
fi
read -rp " - IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
	read -rp " - Public interface : " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
done

function check_server_ip_available {
    local server_ip="$1"
    local ip_type="$2"

    # WIREGUARD
    if [ -d "/etc/wireguard" ]; then
        local wg_conf_files=$(find /etc/wireguard -type f -name "*.conf")
        for file in $wg_conf_files; do
            if grep -q "$server_ip" "$file"; then
                red "   - [ERROR] $server_ip is already used in the [WireGuard] $file."
                return 1
            fi
        done
    fi

    # OPENVPN
    if [ -d "/etc/openvpn" ]; then
        local openvpn_conf_files=$(find /etc/openvpn -type f -name "*.conf")
        for file in $openvpn_conf_files; do
            if grep -q "$server_ip" "$file"; then
                red "   - [ERROR] $server_ip is already used in the [OpenVPN] $file."
                return 1
            fi
        done
    fi

    # OPENCONNECT
    if [ -d "/etc/openconnect" ]; then
        local openconnect_conf_files=$(find /etc/openconnect -type f -name "*.conf")
        for file in $openconnect_conf_files; do
            if grep -q "$server_ip" "$file"; then
                red "   - [ERROR] $server_ip is already used in the [OpenConnect] $file."
                return 1
            fi
        done
    fi

    # ALL RUNNING NETWORK INTERFACES
    local network_interfaces
    if [ "$ip_type" == "IPv6" ]; then
        network_interfaces=$(ifconfig -a | awk '/inet6 /{print $2}')
    else
        network_interfaces=$(ifconfig -a | awk '/inet /{print $2}')
    fi

    while read -r interface_ip; do
        if [ "$interface_ip" == "$server_ip" ]; then
            red "[ERROR] The server $ip_type address $server_ip is already used on the network interface $interface."
            return 1
        fi
    done <<< "$network_interfaces"

    # If the server IP address is not used, return 0
    return 0
}

server_ip_available=false
echo
yellow " - New WireGuard Server Interface Setup"
until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
read -e -i "$NEWWGNICNAME" -p " - Please enter name for Interface : " input
SERVER_WG_NIC="${input:-$NEWWGNICNAME}"
done



while [ -e "/etc/wireguard/${SERVER_WG_NIC}.conf" ]; do
    red "[ERROR] A WireGuard interface configuration with the name [ ${SERVER_WG_NIC} ] already exists"
	echo
	SERVER_WG_NIC=""
	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
	read -e -i "$NEWWGNICNAME" -p " - Please enter another name: " input
	SERVER_WG_NIC="${input:-$NEWWGNICNAME}"
	done
done

while [ "$server_ip_available" = false ]; do


	SERVER_WG_IPV4=""
	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3}(2[0-4][0-9]|25[0-5]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp " - IPv4 Network Gateway: " -e -i "10.66.$((RANDOM % 253 + 2)).1" SERVER_WG_IPV4
	done

    # Generate random default IPv6 address #456 
	#https://github.com/angristan/wireguard-install/pull/456/commits/7674f367047268a4af28a4e33c536f1a6f0133c2
	DEFAULT_IPV6=$(echo "`date +%s%N``cat /etc/machine-id`" | sha256sum | cut -c 55-65 | sed 's/../&\n/g' | xargs printf "fd%s:%s%s:%s%s::1")
	SERVER_WG_IPV6=""
    until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
        #read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
		read -rp " - IPv6 Network Gateway: " -e -i "${DEFAULT_IPV6}" SERVER_WG_IPV6
    done

    # Call the function to check if the server IP addresses are available
    error_message=""
    if ! check_server_ip_available "$SERVER_WG_IPV4" "IPv4"; then
        error_message+="IPv4"
    fi
    if ! check_server_ip_available "$SERVER_WG_IPV6" "IPv6"; then
        error_message+="IPv6"
    fi

    if [ -z "$error_message" ]; then
        green "   - The server IP addresses $SERVER_WG_IPV4 and $SERVER_WG_IPV6 are set."
        server_ip_available=true
    else
        red "   - [ERROR] The $error_message address(es) are already used. Please enter different IP addresses."
    fi
done
get_program_using_port() {
  local port=$1
  local result=$(lsof -i4TCP:${port} -s TCP:LISTEN)
  if [[ -n $result ]]; then
    local program=$(echo "$result" | grep "$port" | cut -d' ' -f1)
    red "Port ${port} is already in use by [ ${program} ] proccess."
    yellow "Please enter another port"
	echo
        return 0
  else
    return 1
  fi
}

RANDOM_PORT=$(shuf -i49152-65535 -n1)

until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ] && ! get_program_using_port "${SERVER_PORT}"; do
  read -rp " - Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
done

# Adguard DNS by default
echo
yellow " - Set Default DNS resolvers values to use for CLIENTS"
yellow "   - The Default values [V4 & V6] are ADGUARD's Public DNS "
yellow "   - Enter V4 network DNS "

until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
	read -rp "   - First IPv4 DNS resolver: " -e -i 94.140.14.14 CLIENT_DNS_1
done
until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
	read -rp "   - Second IPv4 DNS resolver: " -e -i 94.140.15.15 CLIENT_DNS_2
	if [[ ${CLIENT_DNS_2} == "" ]]; then
		CLIENT_DNS_2="${CLIENT_DNS_1}"
	fi
done

# DNS v6
yellow "   - Enter V6 network DNS "
read -rp "   - First IPv6 DNS resolver: " -e -i 2a10:50c0::ad1:ff CLIENT_DNS6_1
read -rp "   - Second IPv6 DNS resolver: " -e -i 2a10:50c0::ad2:ff CLIENT_DNS6_2
echo
until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
	yellow " - WireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
	read -rp " - Allowed IPs list for generated clients: " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
	if [[ ${ALLOWED_IPS} == "" ]]; then
		ALLOWED_IPS="0.0.0.0/0,::/0"
	fi
done

echo ""
echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
echo "You will be able to generate a client at the end of the installation."
read -n1 -r -p " - Press any key to continue..."

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard >/dev/null 2>&1
mkdir -p /usr/local/extDot >/dev/null 2>&1

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

# Save WireGuard settings
echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
CLIENT_DNS6_1=${CLIENT_DNS6_1}
CLIENT_DNS6_2=${CLIENT_DNS6_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/${SERVER_WG_NIC}_params

# Add server interface
echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

if pgrep firewalld; then
FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
# "
else
echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = /usr/local/extDot/wgExpCtrl_${SERVER_WG_NIC}.sh
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

# "
fi

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

# "

sysctl --system

#########ADD POST UP SCRIPT


### make bash scrip 
mkdir -p /usr/local/extDot/
sleep 1
touch /usr/local/extDot/wgExpCtrl_${SERVER_WG_NIC}.sh
chmod 777 /usr/local/extDot/wgExpCtrl_${SERVER_WG_NIC}.sh
sleep 1

cat <<EOF > /usr/local/extDot/wgExpCtrl_${SERVER_WG_NIC}.sh
#!/bin/bash

check_client_expiration() {
    local client_name=\$1
    local wg_config_file="\$2"
    local user_info_file="/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf"

    if ! grep -qE "^### Client \$client_name$" "\$wg_config_file"; then
        echo "Client \$client_name is not defined in \$wg_config_file"
        return 1
    fi

    local client_section=\$(grep -E "^### Client \$client_name$" "\$wg_config_file")
    local allowed_ips_line=\$(grep -A 5 -E "^\$client_section\$" "\$wg_config_file" | awk '/AllowedIPs/')

    local current_date=\$(date +%Y-%m-%d)
    local expiration_date=\$(grep "\$client_name" "\$user_info_file" | awk -F'=' '{print \$2}')

    if [[ "\$current_date" > "\$expiration_date" ]]; then
        if ! grep -qE "^# \$allowed_ips_line" "\$wg_config_file"; then
            sed -i "/^\$client_section\$/,/AllowedIPs/s/^AllowedIPs/# AllowedIPs/" "\$wg_config_file"
        fi
    else
        sed -i "/^\$client_section\$/,/AllowedIPs/s/^# AllowedIPs/AllowedIPs/" "\$wg_config_file"
    fi
}

config_files=/etc/wireguard/${SERVER_WG_NIC}.conf

while IFS='=' read -r client_name expiration_date || [[ -n "\$client_name" ]]; do
    for config_file in \$config_files; do
        check_client_expiration "\$client_name" "\$config_file"
    done
done < "/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf"


generate_hash() {
    file="\$1"
    hash_code=\$(sha256sum "\$file" | awk '{ print \$1 }')
}

store_hash() {
    interface="\$1"
    hash_code="\$2"
    echo "\$interface:\$hash_code" >> /usr/local/extDot/confHash_${SERVER_WG_NIC}.log
}

check_and_sync() {
    interface="\$1"
    config_file="\$2"
    previous_hash="\$3"

    current_hash=\$(generate_hash "\$config_file")

    if [[ "\$current_hash" != "\$previous_hash" ]]; then
        wg syncconf "\$interface" <(wg-quick strip "\$interface")
        store_hash "\$interface" "\$current_hash"

    fi
}

config_files=/etc/wireguard/${SERVER_WG_NIC}.conf

for config_file in \$config_files; do
    interface_name=\$(basename "\$config_file" .conf)
    previous_hash=\$(grep -e "^\$interface_name:" /usr/local/extDot/confHash_${SERVER_WG_NIC}.log | awk -F':' '{ print \$2 }')
    
    if [[ -z "\$previous_hash" ]]; then
        hash_code=\$(generate_hash "\$config_file")
        store_hash "\$interface_name" "\$hash_code"
    else
        check_and_sync "\$interface_name" "\$config_file" "\$previous_hash"
    fi
done

EOF

chmod +x /usr/local/extDot/wgExpCtrl_${SERVER_WG_NIC}.sh

########



if [ ! -f /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf ]; then
	echo "No userInfo file , creating ... "
else
	echo "Old userInfo file has found, cleaning data on it ..."
	rm /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf
	sleep 1
fi
	
touch /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf
chmod +x /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf

INSTART=1
sleep 1

systemctl start "wg-quick@${SERVER_WG_NIC}"
systemctl enable "wg-quick@${SERVER_WG_NIC}"

####

# add a cronjob to refresh every 1 hour user expiration
CRTLINE="/usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh"
CRONTAB=$(crontab -l)

if [[ $CRONTAB == *"$CRTLINE"* ]]; then
	echo "Crontab has Updated Before."
else
	echo "The specified line does not exist in the crontab."
	chmod +x /usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh
	crontab -l | { cat; echo "45 * * * * /usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh" ; } | crontab -
fi

clear
green "=== [${SERVER_WG_NIC}] WireGuard Server is created"
echo
yellow "========================== Configuration Overview =========================="
green "WireGurad Interface : [${SERVER_WG_NIC}]"
green "WireGurad Port      : [$SERVER_PORT]"
green "V4 network          : [$SERVER_WG_IPV4]"
green "V6 network          : [$SERVER_WG_IPV6]"
green "DNS Resolvers V4    : [${CLIENT_DNS_1}] [${CLIENT_DNS_2}]"
green "DNS Resolvers V6    : [${CLIENT_DNS6_1}] [${CLIENT_DNS6_2}]"
yellow "============================================================================"

#newClient
# Check if WireGuard is running
systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"

WG_RUNNING=$?


if [[ ${WG_RUNNING} -ne 0 ]]; then
	echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
	echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
	echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
else # WireGuard is running
	echo -e "\n${GREEN}WireGuard is running.${NC}"
	echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
	echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.\n${NC}"
fi

yellow "============================================================================"
echo
yellow "- How to add Clients? "
echo
echo -e "${GREEN}  a: Enter to ${ORANGE}2) Select Interface ${GREEN}menu and Select wireguard server${NC}"
echo -e "${GREEN}  b: then select ${ORANGE}11) Add New Client ${GREEN}menu and setup new clients.\n${NC}"
yellow "============================================================================"
echo
echo
CURRENT_WG_NIC=${SERVER_WG_NIC}
}

function verifyWGServer() {
echo
yellow " - Please Confirm Selected WireGuard Server"
if [[ "${SERVER_WG_NIC}" == "NONE" ]]; then
	red " - [ERROR] Please select the server first."
	echo
	read -p " - Press enter to select WireGuard Server"
	SelectWgNIC
	echo
else
	read -rp " - Is [ ${SERVER_WG_NIC} ] the correct server? [y/n]: " -e -i "y" response
	if [[ "$response" =~ ^[Yy]$ ]]; then
		echo "   - Proceeding with the selected server."
	else
		echo "   - Please select the correct server."
		B2main
  fi
fi
}
echo
# code12, setup cant read params file for getting ip detaisl
function readBASEConf() {
if [ ! -f "/etc/wireguard/${SERVER_WG_NIC}_params" ]; then
    red "   - [ERROR] No Compatible config has found. [CODE12]"
	B2main
else
	SERVER_WG_IPV4=$(grep "^SERVER_WG_IPV4=" /etc/wireguard/${SERVER_WG_NIC}_params | cut -d= -f2)
	SERVER_WG_IPV6=$(grep "^SERVER_WG_IPV6=" /etc/wireguard/${SERVER_WG_NIC}_params | cut -d= -f2)
fi

}

function newClient() {
echo

yellow "=========================== ADD NEW USER CLIENTS ==========================="
echo

verifyWGServer

# If SERVER_PUB_IP is IPv6, add brackets if missing
if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
	if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
fi
ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"
echo
yellow " - Client Configuration "
yellow "   - Setup Client Name "
yellow "   - The client name must consist of alphanumeric character(s)."
yellow "   - It may also include underscores or dashes and can't exceed 15 chars."
CLIENT_NAME=""
until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
	read -rp "   - Enter Client Name:  " -e CLIENT_NAME
	CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${CLIENT_EXISTS} != 0 ]]; then
		echo ""
		echo -e "${ORANGE}   - A client with the specified name was already created, please choose another name.${NC}"
		echo ""
	fi
done

echo

# Get current date
current_date=$(date +'%Y-%m-%d')
# Prompt user to set expiration date with default value of current date
yellow "   - Setup Expiration Date for clinet"

read -e -i "y"  -p "   - Enable expiration date for [${CLIENT_NAME}] ? (y/n): " response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
yellow "     - Enter expiration date in (YYYY-MM-DD) format: "
read -rp "     - Expiration date: " -e -i "$current_date" expiration_date
expiration_date=${expiration_date:-$current_date}

until date -d "$expiration_date" >/dev/null 2>&1; do
	echo -e "${RED}     - [ERROR] Invalid date format. Please use the format YYYY-MM-DD ${NC}"
	read -rp "     - Expiration date: " -e -i "$current_date" expiration_date
done

# add to database
# Check if file exists, create it if it doesn't

if [ ! -f /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf ]; then
touch /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf
chmod +x /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf
fi

echo "${CLIENT_NAME}=$expiration_date" >> /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf

fi

# Clean VARS
BASEIP=""
IPV4_EXISTS=""
IPV6_EXISTS=""
mtu=""

readBASEConf

for DOT_IP in {2..254}; do
	DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${DOT_EXISTS} == '0' ]]; then
		break
	fi
done

if [[ ${DOT_EXISTS} == '1' ]]; then
	echo ""
	echo "   - The subnet configured supports only 253 clients."
	B2main
fi

BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
echo 
yellow "   - Setup Network IP for [${CLIENT_NAME}] "
until [[ ${IPV4_EXISTS} == '0' ]]; do
	read -rp "   - Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
	CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
	IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${IPV4_EXISTS} != 0 ]]; then
		echo ""
		echo -e "${ORANGE}   - A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
		echo ""
	fi
done

BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
until [[ ${IPV6_EXISTS} == '0' ]]; do
	read -rp "   - Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
	CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
	IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${IPV6_EXISTS} != 0 ]]; then
		echo ""
		echo -e "${ORANGE}   - A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
		echo ""
	fi
done

# MTU Size
mtuSet

# Generate key pair for the client
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
CLIENT_PRE_SHARED_KEY=$(wg genpsk)

HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
mkdir -p $HOME_DIR

# Create client file and add the server as a peer
echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2},${CLIENT_DNS6_1},${CLIENT_DNS6_2}
MTU = ${mtu}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf"

# Add the client as a peer to the server
echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

# Generate QR code if qrencode is installed
if command -v qrencode &>/dev/null; then
	echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
	qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf"
	echo ""
fi

echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf${NC}"

B2main

}

function listClients() {
clear
echo
yellow "=== All Clients Information ================================"
green " INFO: Expired account are on red color"
echo
green " [ROW]. [ EXPIRE  AT ] - [CLIENT NAME]"
echo
NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
	echo
	red "You have no existing clients!"
	B2main
fi

WG_CONF="/etc/wireguard/${SERVER_WG_NIC}.conf"

if [[ -f "$WG_CONF" ]]; then

  USER_INFO="/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf"
  
  if [[ -f "$USER_INFO" ]]; then
	clients=$(grep -E "^### Client" "$WG_CONF" | cut -d ' ' -f 3)
	counter=1
	while read -r client; do
	expiration_date=$(grep -E "^${client}=" "$USER_INFO" | cut -d '=' -f 2)
    if [[ "$(date +%Y-%m-%d)" > "$expiration_date" ]]; then
        echo -e "\e[31m   - $counter. [ $expiration_date ] - $client\e[0m"
    else
        echo "   - $counter. [ $expiration_date ] - $client"
    fi

    ((counter++))
done <<< "$clients"
    
  else
	echo
    red "[Error] This server configuration file may have been created with another script e."
	red "        also it's not compatible with this script for expiration date feature."
	echo
  fi
else
  red "[Error] Server configuration file not found."
fi
echo
B2main

}


function genQRClients() {
	clear
	yellow "=== QR GENERATOR FOR EXSISTING CLIENTS =============================================="
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		red "You have no existing clients!"
		B2main
	fi
	CLIENT_NUMBER=""

	echo ""
	yellow " - Select the existing client you want to generate QR code for it"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	echo
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${ORANGE}${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf${NC}"
	echo
	B2main
	
	}
	

function updateExpClient() {
clients_file="/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf"
clients=($(grep -oP '^[^=]+' "$clients_file"))
echo "Existing clients:"
for i in "${!clients[@]}"; do
  echo "$((i+1)). ${clients[i]}"
done

client_number=""

# Prompt for client selection
read -p "Select a client number: " client_number
# Validate client selection
if [[ ! "$client_number" =~ ^[0-9]+$ ]] || [[ "$client_number" -lt 1 ]] || [[ "$client_number" -gt "${#clients[@]}" ]]; then
  echo "Invalid client number."
  B2main
fi

# Get selected client name
selected_client="${clients[client_number-1]}"

current_date=$(date +'%Y-%m-%d')
echo "Enter expiration date in (YYYY-MM-DD) format: "
read -rp "Expiration date: " -e -i "$current_date" new_expiration_date
new_expiration_date=${new_expiration_date:-$current_date}
until date -d "$new_expiration_date" >/dev/null 2>&1; do
	echo -e "${RED} [ERROR] Invalid date format. Please use the format YYYY-MM-DD ${NC}"
	read -rp "Expiration date: " -e -i "$current_date" new_expiration_date
done

# Update expiration date in the userInfo_${SERVER_WG_NIC}.conf file
sed -i "s/^$selected_client=.*/$selected_client=$new_expiration_date/" "$clients_file"
echo
green "[ O K ] Expiration date updated for $selected_client."
echo

B2main

}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		B2main
	fi

	CLIENT_NUMBER=-100

	echo ""
	echo "Select the existing client you want to revoke"
	echo "     0) Back to Main Menu"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 0 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [0-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done
	
	if [[ -n $CLIENT_NUMBER ]]; then
		if [[ $CLIENT_NUMBER -eq 0 ]]; then
			B2main
		elif [[ $CLIENT_NUMBER -eq -100 ]]; then
			B2main
		fi
	else
		B2main
	fi	
		
	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-${CLIENT_NAME}.conf"
	
	# remove expiration data 
	if [ -f "/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf" ]; then
		sed -i "/$CLIENT_NAME/d" "/usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf"
		yellow "Line containing '$CLIENT_NAME' has been removed from userInfo_${SERVER_WG_NIC}.conf."
	else
		red "[ERROR] The file /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf does not exist."
	fi

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
	B2main
}

function oldDataBackup() {
	current_datetime=$(date +'%Y-%m-%d_%H-%M-%S')
	backup_folder="/usr/local/extDot/backup/$current_datetime"
	mkdir -p "$backup_folder"
	cp -r /etc/wireguard/* "$backup_folder"
	mv /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf "$backup_folder/userInfo_${SERVER_WG_NIC}.conf"
}

function removeWGNIC() {
clear
echo
red "=== REMOVING WIREGUARD SERVER ============================================================" 
verifyWGServer
echo
red " - DELETE [${SERVER_WG_NIC}] ? "
read -p " - Enter DEL or D to confirm removing : " response
if [[ "$response" == "DEL" || "$response" == "del" || "$response" == "D" || "$response" == "d" ]]; then
	systemctl stop "wg-quick@${SERVER_WG_NIC}"
	systemctl disable "wg-quick@${SERVER_WG_NIC}"
	rm -f "/etc/wireguard/${SERVER_WG_NIC}.conf"
	rm -f "/etc/wireguard/${SERVER_WG_NIC}_params"
	rm -f "/usr/local/extDot/confHash_${SERVER_WG_NIC}.log"
	rm -f "/usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh"
	red " - Delete Client File?"	
	read -p " - Remove ${SERVER_WG_NIC} client files? [y/n]: " response
	if [[ "$response" == "Y" || "$response" == "y" || "$response" == "yes" ]]; then
		getHomeDirDEL
		
		if [ "$DIRSTAT" == "1" ]; then
			echo 
			yellow " - Config Dir: ${HOME_DIRDEL}"
			rm -r ${HOME_DIRDEL}
		fi

		yellow " - all clients has removed from [${HOME_DIRDEL}] folder"
	fi		
else
    red " - Skip to remove profile"
fi

}

#########################################################
# EXTREME DOT MENU ITEMS ################################
#########################################################
function mainMenuWG() {
#MAIN MENU SCRIPt
echo -e "${GREEN}"
yellow "=== EXTREME DOT - WireGuard Server ==========================================[Version $scriptVersion]"
echo
echo -e "${GREEN}                                                     Selected Interface: ${ORANGE}$CURRENT_WG_NIC ${NC}"
blue "--- Interface Setup  ---------------------------------------------------------------------"
echo "1) View Available Interfaces                         2) Select Interface"
echo "3) Create New Interface                              4) Delete Selected Interface"
echo "5) Enable Service                                    6) Disable Service"
echo "7) Start Service                                     8) Stop Service"
echo "9) Edit All Server's Config files"
echo
blue "--- Client Modification ------------------------------------------------------------------"
echo "11) Add New Client                                   12) Show all users informations"
echo "13) Generate QR for Clients                          14) Update User Expiration Date"
echo "15) Revoke existing user                             16) Edit UserInfo file"
echo
blue "--- Miscelanous --------------------------------------------------------------------------"
echo "21) Permission Fix for Script                        22) Syncing Configs to Apply Users"
echo "23) Read Status of Selected Config                   24) Read the System Log"
echo
echo "------------------------------------------------------------------------------------------"
echo "   98) Uninstall WireGuard       99) Update Script to Latest               0) Exit"
yellow "Please Enter the Number =================================================================="
echo -e "${GREEN}"
MENUITEMR=""
until [[ $MENUITEMR =~ ^[0-9]+$ ]] && [ "$MENUITEMR" -ge 0 ] && [ "$MENUITEMR" -le 99 ]; do
read -rp "$MENUITEMR [Please Select 0-99]: " -e  MENUITEMR
done

#################################
case $MENUITEMR in

0) # EXIT
echo -e "${NC}"
exit
;;

1) # View Available Interfaces
viewWGinterfaces
B2main
;;

2) # Select Interface
SelectWgNIC
B2main
;;

3) # Create New Interface 
createNewWgNIC
B2main
;;

4) # Delete Selected Interface
removeWGNIC
B2main
;;

5) # Enable Service
systemctl enable "wg-quick@${SERVER_WG_NIC}"
B2main
;;

6) # Disable Service
systemctl disable "wg-quick@${SERVER_WG_NIC}"
B2main
;;

7) # Start Service
systemctl start "wg-quick@${SERVER_WG_NIC}"
B2main
;;

8) # Stop Service
systemctl stop "wg-quick@${SERVER_WG_NIC}"
B2main
;;

9) # Read config file
nano /etc/wireguard/${SERVER_WG_NIC}.conf
nano /etc/wireguard/${SERVER_WG_NIC}_params
B2main
;;

11) # Add New Client 
newClient
B2main
;;

12) # Show all users informations 
listClients
B2main
;;

13) # Generate QR for Clients
genQRClients
B2main
;;

14) # Update User Expiration Date 
updateExpClient
B2main
;;

15) # Revoke existing user
revokeClient
B2main
;;

16) #Edit UserInfo
nano /usr/local/extDot/userInfo_${SERVER_WG_NIC}.conf
B2main
;;

21) # Permission Fix for Script 
sudo chmod +x /usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh
B2main
;;

22) # Syncing Configs to Apply Users 
sudo bash /usr/local/extDot/${SERVER_WG_NIC}_wgExpCtrl.sh
B2main
;;

23) # Read Status Log
systemctl status wg-quick@${SERVER_WG_NIC}
B2main
;;

24) # Read System log
journalctl -xe
B2main
;;

98) # Uninstall WireGuard
uninstallWg
;;

99) #update
mkdir -p /tmp/extdotmenu1
cd /tmp/extdotmenu1
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
wget  https://raw.githubusercontent.com/ExtremeDot/ExDOT-WireGuard-Server/main/exDOT-WG.sh
chmod +x /tmp/extdotmenu1/exDOT-WG.sh
mv /tmp/extdotmenu1/exDOT-WG.sh /usr/local/bin/exDOT-WG
chmod +x /usr/local/bin/exDOT-WG
bash /usr/local/bin/exDOT-WG ; exit

;;

esac

}

#########################################################
# EXTREME DOT MENU START ################################
#########################################################
defVars
colorCodes
startup
checkWireGuard
mainMenuWG
