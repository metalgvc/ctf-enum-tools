#!/bin/bash

PYTHON=$(which python)
sudo apt install arp-scan netdiscover
sudo apt install xsltproc httrack paramspider httpx-toolkit exiftool cewl nikto nuclei ffuf whatweb amap nmap crackmapexec wafw00f
sudo apt install smtp-user-enum smbmap enum4linux ssh-audit hydra swaks sslscan snmp onesixtyone hashcat recon-ng python3-impacket
# odat

# domain discovery script dependencies
sudo apt install whois dmitry knockpy subfinder dnsenum sublist3r metagoofil


# install/update xssuccessor
PROJDIR="/opt/xssuccessor"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor.git $PROJDIR
else
  cd $PROJDIR
  $PYTHON xssuccessor.py --update
  cd -
fi

PROJDIR="/opt/xsstrike"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/s0md3v/XSStrike.git $PROJDIR
  cd "$PROJDIR"
  pip install -r requirements.txt --break-system-packages
else
  cd $PROJDIR
  $PYTHON xsstrike.py --update
  cd -
fi

# install/update lfier
PROJDIR="/opt/lfier"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/Cybersecurity-Ethical-Hacker/lfier.git $PROJDIR
else
  cd $PROJDIR
  $PYTHON lfier.py --update
  cd -
fi

# install/update oredirectme
PROJDIR="/opt/oredirectme"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/Cybersecurity-Ethical-Hacker/oredirectme.git $PROJDIR
else
  cd $PROJDIR
  $PYTHON oredirectme.py --update
  cd -
fi

PROJDIR="/opt/username-anarchy"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/urbanadventurer/username-anarchy.git $PROJDIR
fi

# install OWASP D4N155 (password gen tools)
PROJDIR="/opt/D4N155"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/owasp/D4N155.git $PROJDIR
  cd $PROJDIR
  pipenv install -r requirements.txt
  cd -
fi

PROJDIR="/opt/FinalRecon"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/thewhiteh4t/FinalRecon.git $PROJDIR
  cd $PROJDIR
  pip3 install -r requirements.txt
  cd -
fi

PROJDIR="/opt/discover"
if [[ ! -d $PROJDIR ]]; then
  sudo mkdir $PROJDIR
  sudo chown $USER:$USER $PROJDIR
  git clone https://github.com/leebaird/discover.git $PROJDIR
fi

# dalfox
go install github.com/hahwul/dalfox/v2@latest
