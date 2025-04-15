#!/bin/bash

# https://nmap.org/book/man-port-scanning-techniques.html

# TODO:
#  - prompt to open html report after each script scan ??
#  - convert all nmap-*.xml into html -> join into one html file and prompt to open at the end
#  - add -y parameter to enum all available

function show_help() {
    echo "Usage: $0 -i <IP|host> [-x <xmllogfile>]"
    echo ""
    echo "Options:"
    echo "  -i        The IP address (required)"
    echo "  -x        xml logfile"
    echo "  -h        Show this help message"
}

IP=""
NMAP_XML_OUTFILE=""

# Parse options
while getopts "i:x:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        x) NMAP_XML_OUTFILE="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z $IP ]]; then
  show_help
  exit 1
fi

XML_OUT_PARAM=""
NMAP_UDP_XML_OUTFILE=""
if [[ -n $NMAP_XML_OUTFILE ]]; then
  XML_OUT_PARAM="-oX $NMAP_XML_OUTFILE"
  NMAP_UDP_XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-udp.xml}"
fi

source ./enum.conf

########################################################################################################################
NMAP_HTML_OUTFILE="${NMAP_XML_OUTFILE/.xml/.html}"
NMAP_UDP_HTML_OUTFILE="${NMAP_UDP_XML_OUTFILE/.xml/.html}"

# top 1000 TCP ports (SYN scan), detect services -----------------------------------------------------------------------
if [[ -f $NMAP_XML_OUTFILE ]]; then
  ask "[nmap] run TCP scan [top 1000] ? (y/N)" choice
else
  choice="y"
fi

if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

  echo -e "${GREEN}nmap -sS -sC -sV -Pn -T4 $IP $XML_OUT_PARAM${NC}"
  sudo nmap -sS -sC -sV -Pn -T4 $IP $XML_OUT_PARAM

  tip "bypass firewall params:\n\t-g 53 - \t source port\n\t-f - \t fragment packets\n\t--mtu\n\t-D RND:5 - \t rand IP\n\t--data-length \n\t--scan-delay <time>"

  xsltproc "$NMAP_XML_OUTFILE" -o "$NMAP_HTML_OUTFILE"
  separator

  ask "[firefox] open ${NMAP_HTML_OUTFILE} ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    firefox $NMAP_HTML_OUTFILE &
  fi
fi

OPENED_TCP_PORTS=$(grep 'state="open"' "$NMAP_XML_OUTFILE" | awk -F'portid="' '{print $2}' | awk -F'"' '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')

# full scan ------------------------------------------------------------------------------------------------------------
ask "[nmap] run FULL TCP scan ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

  echo -e "${GREEN}nmap -sS -sC -sV -Pn -T4 -n --disable-arp-ping -p- -O $IP $XML_OUT_PARAM${NC}"
  sudo nmap -sS -sC -sV -Pn -T4 -n --disable-arp-ping -p- -O $IP $XML_OUT_PARAM

  tip "bypass firewall params:\n\t-g 53 - \t source port\n\t-f - \t fragment packets\n\t--mtu\n\t-D RND:5 - \t rand IP\n\t--data-length \n\t--scan-delay <time>"

  xsltproc "$NMAP_XML_OUTFILE" -o "$NMAP_HTML_OUTFILE"
  separator

  OPENED_TCP_PORTS=$(grep 'state="open"' "$NMAP_XML_OUTFILE" | awk -F'portid="' '{print $2}' | awk -F'"' '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')

  ask "[firefox] open full scan report ${NMAP_HTML_OUTFILE} ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    firefox $NMAP_HTML_OUTFILE &
  fi
fi

# scan UDP -------------------------------------------------------------------------------------------------------------

ask "[nmap] scan UDP ports [top 200] ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}sudo nmap -v -sU -sV -sC -Pn -n --disable-arp-ping -T4 $IP --top-ports 200 -oX $NMAP_UDP_XML_OUTFILE${NC}"
  sudo nmap -v -sU -sV -sC -Pn -n --disable-arp-ping -T4 $IP --top-ports 200 -oX $NMAP_UDP_XML_OUTFILE

  xsltproc "$NMAP_UDP_XML_OUTFILE" -o "$NMAP_UDP_HTML_OUTFILE"
  separator

  ask "[firefox] open UDP scan report ${NMAP_UDP_HTML_OUTFILE} ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    firefox $NMAP_UDP_HTML_OUTFILE &
  fi
fi



# http -----------------------------------------------------------------------------------------------------------------
if grep -q 'portid="80"' "$NMAP_XML_OUTFILE" || grep -q 'portid="443"' "$NMAP_XML_OUTFILE"; then
    ask "[nmap] HTTP(S) server detected. Run http scripts ? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-http.xml}"
      echo -e "${GREEN}nmap -Pn -p 80,443 --script 'http-* and safe' $IP -oX $XML_OUTFILE${NC}"
      sudo nmap -Pn -p 80,443 --script "http-* and safe" $IP -oX $XML_OUTFILE

      HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
      xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
      separator

      ask "[firefox] open http scripts report ${HTML_SCRIP_OUTFILE} ? (y/N)" choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        firefox $HTML_SCRIP_OUTFILE &
      fi
    fi
fi

# SMTP -----------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="25"' "$NMAP_XML_OUTFILE"; then
    ask "[nmap] SMTP service detected. Run SMTP enumeration ? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-smtp.xml}"
      echo -e "${GREEN}nmap -Pn -p 25 --script 'smtp-* and safe' $IP -oX $XML_OUTFILE${NC}"
      sudo nmap -Pn -p 25 --script "smtp-* and safe" $IP -oX $XML_OUTFILE

      HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
      xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
      separator

      tip "telnet $IP 25"
      tip "- VRFY user"

      tip "nmap --script smtp-enum-users - may be a lot of false-positive results"
      tip "- nmap ... --script smtp-enum-users --script-args 'smtp-enum-users.methods={EXPN, VRFY, RCPT}, userdb=${USER_NAMES_LIST}'"
    fi
fi

# mysql ----------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="3306"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] MySQL service detected. Run MySQL version enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-mysql.xml}"
    echo -e "${GREEN}nmap -Pn -sV -p 3306 --script 'mysql*' $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn -sV -p 3306 --script "mysql* and safe" $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi
fi

# MSSQL ----------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="1433"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] MSSQL service detected. Run MSSQL enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-mssql.xml}"
    echo -e "${GREEN}nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -Pn -sV -p 1433 $IP -oX $XML_OUTFILE${NC}"
    sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -Pn -sV -p 1433 $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "MSSQL"
  tip "- impacket-mssqlclient -h"
  tip "- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server"
  tip "- https://academy.hackthebox.com/module/112/section/1246"
fi

# RDP ------------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="3389"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] RDP service detected. Run RDP enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-rdp.xml}"
    echo -e "${GREEN}nmap --script 'rdp*' -Pn -sV -p 3389 $IP -oX $XML_OUTFILE${NC}"
    sudo nmap --script "rdp*" -Pn -sV -sC -p 3389 $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "RDP"
  tip "- https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp"
  tip "- https://academy.hackthebox.com/module/112/section/1242"
  tip "- /xfreerdp /u:user /p:\"password\" /v:${IP}"
fi

# Oracle TNS -----------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="1521"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] Oracle TNS Listener detected. Run Oracle enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-oracle-tns.xml}"
    echo -e "${GREEN}nmap --script 'oracle*' -Pn -sV -p 1521 $IP -oX $XML_OUTFILE${NC}"
    sudo nmap --script "oracle*" -Pn -sV -p 1521 $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "Oracle TNS"
  tip "- odat -h"
  tip "- https://academy.hackthebox.com/module/112/section/2117"
fi

# ftp ------------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="21"' "$NMAP_XML_OUTFILE" || \
   grep -q "ftp" "$NMAP_XML_OUTFILE"; then

    ask "[nmap] FTP service detected. Run FTP enumeration? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-ftp.xml}"
      #echo -e "${GREEN}nmap -p 21 --script ftp-anon,ftp-syst,ftp-brute $IP -oX $XML_OUTFILE${NC}"
      echo -e "${GREEN}nmap -Pn -p 20,21 --script 'ftp-* and safe' $IP -oX $XML_OUTFILE${NC}"
      sudo nmap -Pn -p 20,21 --script "ftp-* and safe" $IP -oX $XML_OUTFILE

      HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
      xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
      separator
    fi
fi

# SMB ------------------------------------------------------------------------------------------------------------------
if grep -q 'port protocol="tcp" portid="445"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] SMB service detected. Run SMB enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-smb.xml}"
    echo -e "${GREEN}nmap -Pn -p 445 --script \"smb* and safe\" $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn -p 445 --script "smb* and safe" $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "smbclient -L -N //${IP}"
  tip "- smbclient -U user //${IP}"
fi

# NFS ------------------------------------------------------------------------------------------------------------------
if grep -q 'portid="111"' "$NMAP_XML_OUTFILE" || grep -q 'portid="2049"' "$NMAP_XML_OUTFILE"; then
  ask "[nmap] NFS service detected. Run NFS enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-nfs.xml}"
    echo -e "${GREEN}nmap -Pn -p 111,2049 --script 'nfs* and safe' $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn -p 111,2049 --script "nfs* and safe" $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "showmount -e ${IP}"
  tip "- sudo mount -t nfs ${IP}:/ ./target-NFS/ -o nolock"
fi

# R-Services -----------------------------------------------------------------------------------------------------------
if grep -q -E 'portid="512"|portid="513"|portid="514"' "$NMAP_XML_OUTFILE"; then
  tip "R-services detected"
  tip "- https://academy.hackthebox.com/module/112/section/1240"
  tip "- 512 https://book.hacktricks.xyz/network-services-pentesting/512-pentesting-rexec"
  tip "- 513 https://book.hacktricks.xyz/network-services-pentesting/pentesting-rlogin"
  tip "- 514 https://book.hacktricks.xyz/network-services-pentesting/pentesting-rsh"
  tip "- commands: rwho, rusers, rlogin"
fi

# WinRM ----------------------------------------------------------------------------------------------------------------
if grep -q -E 'portid="5985"|portid="5986"' "$NMAP_XML_OUTFILE"; then
  tip "WinRM detected"
  tip "- https://academy.hackthebox.com/module/112/section/1242"
  tip "- https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm"
  tip "- evil-winrm -i ${IP} -u user -p password"
fi

# WMI ------------------------------------------------------------------------------------------------------------------
if grep -q -E 'portid="135"|portid="593"' "$NMAP_XML_OUTFILE"; then
  tip "WMI/MSRPC detected"
  tip "- https://academy.hackthebox.com/module/112/section/1242"
  tip "- https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc"
  tip "- impacket-wmiexec -h"
  tip "- impacket-wmiexec user:password@${IP} \"command\""
fi

# IPMI -----------------------------------------------------------------------------------------------------------------
if grep -q 'portid="623"' "$NMAP_XML_OUTFILE" || grep -q 'portid="623"' "$NMAP_UDP_XML_OUTFILE"; then
  ask "[nmap] IPMI service detected. Run IPMI enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-ipmi.xml}"
    echo -e "${GREEN}nmap -sU -sS --script ipmi-version -p 623 $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -sU -sS --script "ipmi-version" -p 623 $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi

  tip "links:"
  tip "- https://academy.hackthebox.com/module/112/section/1245"
  tip "- https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi"
  tip "- ipmitool -I lanplus -H $IP -U '' -P '' user list"
  tip "- msf> search type:auxiliary ipmi"
fi

# SNMP -----------------------------------------------------------------------------------------------------------------
if grep -q 'portid="161"' "$NMAP_UDP_XML_OUTFILE"; then
  ask "[nmap] SNMP service detected. Run SNMP enumeration (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-scripts-snmp.xml}"
    echo -e "${GREEN}nmap -sU -sV -sC -p 161 $IP --script \"snmp*\" -oX $XML_OUTFILE${NC}"
    sudo nmap -sU -sV -sC -p 161 $IP --script "snmp*" -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE=${XML_OUTFILE/.xml/.html}
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator
  fi
fi

# vuln scripts ---------------------------------------------------------------------------------------------------------
if [[ -n $OPENED_TCP_PORTS ]]; then
  ask "[nmap] run default vuln scripts ? (y/N)" choice

  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-script-vuln.xml}"
    echo -e "${GREEN}nmap -Pn -sV --script 'vuln and not dos' -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn -sV --script "vuln and not dos" -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE="${XML_OUTFILE/.xml/.html}"
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator

    ask "[firefox] open vuln script report ${HTML_SCRIP_OUTFILE} ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      firefox $HTML_SCRIP_OUTFILE &
    fi
  fi
fi

# malware scripts ------------------------------------------------------------------------------------------------------
if [[ -n $OPENED_TCP_PORTS ]]; then
  ask "[nmap] run default malware scripts ? (y/N)" choice

  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-script-malware.xml}"
    echo -e "${GREEN}nmap -Pn --script malware -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn --script malware -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE="${XML_OUTFILE/.xml/.html}"
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator

    ask "[firefox] open malware script report ${HTML_SCRIP_OUTFILE} ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      firefox $HTML_SCRIP_OUTFILE &
    fi
  fi
fi

# vulscan --------------------------------------------------------------------------------------------------------------
if [[ -n $OPENED_TCP_PORTS ]]; then
  ask "[nmap] run vulscan (exploitdb) script ? (y/N)" choice

  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

    # install/update vulscan script
    NMAP_SCRIPTS_DIR=$(locate scripts | grep 'nmap/scripts' | head -n 1)
    NMAP_VULSCAN_SCRIPT_DIR=${NMAP_SCRIPTS_DIR}/vulscan
    if [[ -d $NMAP_SCRIPTS_DIR ]]; then

      # install vulscan
      if [[ ! -d ${ENUM_APP_DIR}/vulscan ]]; then
        echo "installing nmap vulscan script..."
        git clone https://github.com/scipag/vulscan ${ENUM_APP_DIR}/vulscan
        sudo ln -s ${ENUM_APP_DIR}/vulscan ${NMAP_SCRIPTS_DIR}/vulscan
      fi

      # update vulscan db
      if [[ -d ${ENUM_APP_DIR}/vulscan ]]; then
        ask "[nmap] update vulnscan-db ? (y/N)" choice

        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
          echo "updating vulscan script db..."
          #databases="cve exploitdb openvas osvdb scipvuldb securityfocus securitytracker xforce"
          databases="exploitdb"
          for DB in $databases; do
              curl https://www.computec.ch/projekte/vulscan/download/${DB}.csv -o ${ENUM_APP_DIR}/vulscan/${DB}.csv.1

              if [ -f ${ENUM_APP_DIR}/vulscan/${DB}.csv.1 ]; then
                  mv ${ENUM_APP_DIR}/vulscan/${DB}.csv.1 ${ENUM_APP_DIR}/vulscan/${DB}.csv
              fi
          done

          sudo nmap --script-updatedb
        fi
      fi
    fi

    XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-script-vulscan.xml}"

    # --script-args vulscanversiondetection=0
    # run scan
    echo -e "${GREEN}nmap -Pn -sV -sS --script=vulscan/vulscan.nse --script-args 'vulscandb=exploitdb.csv, vulscanversiondetection=1' -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE${NC}"
    sudo nmap -Pn -sV -sS --script=vulscan/vulscan.nse --script-args "vulscandb=exploitdb.csv, vulscanversiondetection=1" -p $OPENED_TCP_PORTS $IP -oX $XML_OUTFILE

    HTML_SCRIP_OUTFILE="${XML_OUTFILE/.xml/.html}"
    xsltproc "$XML_OUTFILE" -o "$HTML_SCRIP_OUTFILE"
    separator

    ask "[firefox] open vulscan script report ${HTML_SCRIP_OUTFILE} ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      firefox $HTML_SCRIP_OUTFILE &
    fi
  fi
fi

# TODO: compile all report html files into one and prompt to open

tip "scan all UDP ports"
tip "- nmap -Pn -sU -p- ${IP}"

tip "links:"
tip "- https://book.hacktricks.xyz/network-services-pentesting"