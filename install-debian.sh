#!/bin/bash

REAL_SSH_PORT=7922

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 
	exit 1
fi

sed -i "s/Port 22/Port $REAL_SSH_PORT/g" /etc/ssh/sshd_config

iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport $REAL_SSH_PORT -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
apt-get update && apt-get upgrade -y && apt-get install -y vim git python-dev openssl python-openssl python-pyasn1 python-twisted iptables-persistent

useradd -m -d /home/cowrie -s /bin/bash cowrie

su cowrie <<'EOF'
FAKE_HOSTNAME=srv07
FAKE_VERSION="SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1"
cd /home/cowrie
git clone http://github.com/micheloosterhof/cowrie
cd /home/cowrie/cowrie
cp cowrie.cfg.dist cowrie.cfg
sed -i "s/svr04/$FAKE_HOSTNAME/g" cowrie.cfg
sed -i "s/= SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2/= $FAKE_VERSION/g" cowrie.cfg
./start.sh
EOF

echo "Done! Reconnect via ssh to port $REAL_SSH_PORT"

# we're doing this at last so it doesn't break the connection during install
service ssh restart
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
