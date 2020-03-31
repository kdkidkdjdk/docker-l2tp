#!/bin/sh
PATH=${PATH}:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# This is a Shell script for configure and start L2TP/IPSec VPN server with Docker image
# 
# Copyright (C) 2018 - 2019 Teddysun <i@teddysun.com>
#
# Reference URL:
# https://github.com/libreswan/libreswan
# https://github.com/xelerance/xl2tpd

if [ ! -f "/.dockerenv" ]; then
    echo "Error: This script must be run in a Docker container." >&2
    exit 1
fi

if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
    echo "Error: This Docker image must be run in privileged mode." >&2
    exit 1
fi

ip link delete dummy0 >/dev/null 2>&1

rand(){
    str=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
    echo ${str}
}

is_64bit(){
    if [ "$(getconf WORD_BIT)" = "32" ] && [ "$(getconf LONG_BIT)" = "64" ]; then
        return 0
    else
        return 1
    fi
}

# Environment file name
l2tp_env_file="/etc/l2tp/l2tp.env"
# Set Environment
if [ -f "${l2tp_env_file}" ]; then
    echo "Loading previously generated environment variables for L2TP/IPSec VPN Server..."
    . "${l2tp_env_file}"
else
    echo "Environment file not found. Generate default one..."
    cat > "${l2tp_env_file}" <<EOF
# This file is part of L2TP/IPSec VPN Server Docker image.
# Define your own values for these environment variables.
# DO NOT put "" or '' around values, or add space around =
# DO NOT use these special characters within values: \ " '

VPN_IPSEC_PSK=psk123456
VPN_USERS_LIST=test:123456,test2:123456
VPN_PUBLIC_IP=
VPN_L2TP_NET=192.168.18.0/24
VPN_L2TP_LOCAL=192.168.18.1
VPN_L2TP_REMOTE=192.168.18.10-192.168.18.250
VPN_XAUTH_NET=192.168.20.0/24
VPN_XAUTH_REMOTE=192.168.20.10-192.168.20.250
VPN_DNS1=8.8.8.8
VPN_DNS2=8.8.4.4
VPN_SHA2_TRUNCBUG=no
EOF
    . "${l2tp_env_file}"
fi

# Check environment variables:
VPN_L2TP_NET=${VPN_L2TP_NET:-'192.168.18.0/24'}
VPN_L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.18.1'}
VPN_L2TP_REMOTE=${VPN_L2TP_REMOTE:-'192.168.18.10-192.168.18.250'}
VPN_XAUTH_NET=${VPN_XAUTH_NET:-'192.168.20.0/24'}
VPN_XAUTH_REMOTE=${VPN_XAUTH_REMOTE:-'192.168.20.10-192.168.20.250'}
VPN_DNS1=${VPN_DNS1:-'8.8.8.8'}
VPN_DNS2=${VPN_DNS2:-'8.8.4.4'}
VPN_SHA2_TRUNCBUG=${VPN_SHA2_TRUNCBUG:-'no'}

if printf '%s' "${VPN_IPSEC_PSK} ${VPN_USERS_LIST}" | LC_ALL=C grep -q '[^ -~]\+'; then
    echo "Error: Environment variables must not contain non-ASCII characters." >&2
    exit 1
fi

case "${VPN_IPSEC_PSK} ${VPN_USERS_LIST}" in
    *[\\\"\']*)
    echo "Error: Environment variables must not contain these special characters like: \\ \" '"
    exit 1
    ;;
esac

# Environment variables:
# VPN_PUBLIC_IP
[ -z "${VPN_PUBLIC_IP}" ] && VPN_PUBLIC_IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
[ -z "${VPN_PUBLIC_IP}" ] && VPN_PUBLIC_IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )

# Create IPSec config
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
    protostack=netkey
    uniqueids=no
    interfaces=%defaultroute
    virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!${VPN_L2TP_NET},%v4:!${VPN_XAUTH_NET}

conn shared
    left=%defaultroute
    leftid=${VPN_PUBLIC_IP}
    right=%any
    encapsulation=yes
    authby=secret
    pfs=no
    rekey=no
    keyingtries=5
    dpddelay=30
    dpdtimeout=120
    dpdaction=clear
    ikev2=never
    ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,aes256-sha2
    phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
    sha2-truncbug=${VPN_SHA2_TRUNCBUG}

conn l2tp-psk
    auto=add
    leftprotoport=17/1701
    rightprotoport=17/%any
    type=transport
    phase2=esp
    also=shared

conn xauth-psk
    auto=add
    leftsubnet=0.0.0.0/0
    rightaddresspool=${VPN_XAUTH_REMOTE}
    modecfgdns=${VPN_DNS1},${VPN_DNS2}
    leftxauthserver=yes
    rightxauthclient=yes
    leftmodecfgserver=yes
    rightmodecfgclient=yes
    modecfgpull=yes
    xauthby=file
    ike-frag=yes
    cisco-unity=yes
    also=shared
EOF

cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
local ip = ${VPN_L2TP_LOCAL}
ip range = ${VPN_L2TP_REMOTE}
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
ms-dns ${VPN_DNS1}
ms-dns ${VPN_DNS2}
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
EOF

cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "${VPN_IPSEC_PSK}"
EOF

cat /dev/null > /etc/ppp/chap-secrets
cat /dev/null > /etc/ipsec.d/passwd
VPN_USERS_NUMBER=`echo ${VPN_USERS_LIST} | awk -F ',' '{print NF}'`
for i in `seq ${VPN_USERS_NUMBER}`
do
	VPN_USER=`echo ${VPN_USERS_LIST} | awk -F ',' '{print $'$i'}'`
    VPN_USER_LOGIN=`echo ${VPN_USER} | awk -F ':' '{print $1}'`
	VPN_USER_PASSWORD=`echo ${VPN_USER} | awk -F ':' '{print $2}'`

    # Check credentials value:
    # VPN_USER_LOGIN 
    # VPN_USER_PASSWORD
    if [ -z "${VPN_USER_LOGIN}" ] || [ -z "${VPN_USER_PASSWORD}" ]; then
        echo "Error: VPN_IPSEC_PSK or VPN_USERS_LIST value illegal. Please edit your environment file and retry again." >&2
        exit 1
    fi

    echo "${VPN_USER_LOGIN} l2tpd ${VPN_USER_PASSWORD} *" >> /etc/ppp/chap-secrets
	VPN_USER_PASSWORD_ENC=$(openssl passwd -1 "$VPN_USER_PASSWORD")
	echo "${VPN_USER_LOGIN}:${VPN_USER_PASSWORD_ENC}:xauth-psk" >> /etc/ipsec.d/passwd
done

chmod 600 /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ipsec.d/passwd

# Update sysctl settings
if is_64bit; then
    SHM_MAX=68719476736
    SHM_ALL=4294967296
else
    SHM_MAX=4294967295
    SHM_ALL=268435456
fi

sysctl -eqw kernel.msgmnb=65536
sysctl -eqw kernel.msgmax=65536
sysctl -eqw kernel.shmmax=${SHM_MAX}
sysctl -eqw kernel.shmall=${SHM_ALL}
sysctl -eqw net.ipv4.ip_forward=1
sysctl -eqw net.ipv4.conf.all.accept_source_route=0
sysctl -eqw net.ipv4.conf.all.accept_redirects=0
sysctl -eqw net.ipv4.conf.all.send_redirects=0
sysctl -eqw net.ipv4.conf.all.rp_filter=0
sysctl -eqw net.ipv4.conf.default.accept_source_route=0
sysctl -eqw net.ipv4.conf.default.accept_redirects=0
sysctl -eqw net.ipv4.conf.default.send_redirects=0
sysctl -eqw net.ipv4.conf.default.rp_filter=0
sysctl -eqw net.ipv4.conf.eth0.send_redirects=0
sysctl -eqw net.ipv4.conf.eth0.rp_filter=0

# Create iptables rules
iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -I INPUT 6 -p udp --dport 1701 -j DROP
iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
iptables -I FORWARD 2 -i eth+ -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 3 -i ppp+ -o eth+ -j ACCEPT
iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "${VPN_L2TP_NET}" -d "${VPN_L2TP_NET}" -j ACCEPT
iptables -I FORWARD 5 -i eth+ -d "${VPN_XAUTH_NET}" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 6 -s "${VPN_XAUTH_NET}" -o eth+ -j ACCEPT
iptables -A FORWARD -j DROP
iptables -t nat -I POSTROUTING -s "${VPN_XAUTH_NET}" -o eth+ -m policy --dir out --pol none -j MASQUERADE
iptables -t nat -I POSTROUTING -s "${VPN_L2TP_NET}" -o eth+ -j MASQUERADE

# Load IPsec kernel module
modprobe af_key

# Start services
mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid
/usr/sbin/ipsec start
exec /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf
