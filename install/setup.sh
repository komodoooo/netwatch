#!/bin/bash
mkdir /opt/netwatch
if [ ! -f creds ]; then
    echo "Credentials not found."
    exit 1
fi
mv creds /opt/netwatch/creds
apt update && apt install -y git nmap
echo installing nmap-vulners...
git clone https://github.com/vulnersCom/nmap-vulners.git
cp -r nmap-vulners/ /usr/share/nmap/scripts/
nmap --script-updatedb
pip install -r requirements.txt --break-system-packages