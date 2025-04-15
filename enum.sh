#!/bin/bash

# TODO:
#  - -y flag - yes to all ask & cmd
#  - ask "... (y/N/h)" - where h - shows help info
#  - prompt (y/N/e) - where e - edit prompted command
#  - catch CTRL+C & show confirm message to exit
#  - organize log reports
#  - collect found urls, virtual hosts, services etc. to use further automatic enumeration
#  - crackmapexec !
#  - arachni ? https://github.com/Arachni/arachni

function show_help() {
    echo "Usage: $0 -i <IP> -o <output_directory> [-H <HOST>] [-p <WEB_PORT>]"
    echo ""
    echo "Options:"
    echo "  -i       The IP address of the target (required)"
    echo "  -H        Host; useful to specify virtualhost, e.g \"admin.site.com\" (optional; required when -i is not specified)"
    echo "  -p        Port for web service enumeration (optional)"
    echo "  -h        Show this help message"
}

IP=""
WEB_PORT=""
HOST=""

# Parse options
while getopts "i:H:p:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        H) HOST="$OPTARG" ;;
        p) WEB_PORT="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z "$IP" && -z "$HOST" ]]; then
    echo "Error: Either -i <IP> or -H <HOST> must be specified."
    show_help
    exit 1
fi

source ./enum.conf

# get HOST from /etc/hosts
if [[ -z $HOST && -n $IP ]]; then
  HOST=$(grep -w "$IP" /etc/hosts | awk '{print $2}' | head -n 1)
fi

# get IP from /etc/hosts
if [[ -n $HOST && -z $IP ]]; then
  IP=$(grep -w "$HOST" /etc/hosts | awk '{print $1}' | head -n 1)
fi

# get location
if [[ -z $HOST ]]; then
  location=$(curl --max-time 10 -I -s "$IP" | grep -i 'location' | awk '{print $2}')
  HOST=$(echo -n "$location" | awk -F/ '{print $3}')

  if [[ -n $HOST ]]; then
    echo "New host found: $HOST"
    ask "add to /etc/hosts ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      sudo sh -c "echo '$IP $HOST' >> /etc/hosts"
    fi
  fi
fi

if [[ -z $HOST ]]; then
  HOST=$IP
fi

URL="http://${HOST}"
if [[ -n $WEB_PORT && $WEB_PORT == 443 ]]; then
  URL="https://${HOST}:${WEB_PORT}"
elif [[ -n $WEB_PORT && $WEB_PORT != 80 ]]; then
  URL="http://${HOST}:${WEB_PORT}"
fi

OUTDIR=$(realpath "./results/${HOST}")

mkdir -p /tmp/autotool
mkdir -p "${OUTDIR}/logs"

ENUMLOGFILE="${OUTDIR}/logs/enum.log"

NMAP_XML_OUTFILE="${OUTDIR}/enum-nmap.xml"
NMAP_UDP_XML_OUTFILE="${NMAP_XML_OUTFILE/.xml/-udp.xml}"

echo "url: $URL"
echo "host: $HOST"
echo "ip: $IP"
echo "logs: $OUTDIR"
separator

# open in Firefox
if [[ "$HOST" != "$IP" ]]; then
  ask "open ${URL} in FF (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    firefox $URL &>/dev/null &
  fi
  separator

  # TODO open BurpSuite ??
fi

# ======================================================================================================================
# whatweb
echo -e "${GREEN}whatweb \"${URL}\"${NC}"
whatweb "${URL}" | tee "${ENUMLOGFILE/.log/-whatweb.log}"
tip "use 'searchsploit ...' for found technologies"
separator

# get robots.txt & known files
knownfiles="robots.txt sitemap.xml crossdomain.xml clientaccesspolicy.xml"
for kfile in $knownfiles; do
  status_code=$(curl --max-time 10 -L -o /dev/null -s -w "%{http_code}" "$URL/${kfile}")
  if [[ "$status_code" -eq 200 ]]; then
    echo -e "${YELLOW}${kfile} found. Downloading...${NC}"
    curl -L -o "${OUTDIR}/${kfile}" "${URL}/${kfile}"
    cat "${OUTDIR}/${kfile}"
    separator
  fi
done

# ======================================================================================================================
# DNS
ask "Run DNS enumeration? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    dnsenum "$HOST" | tee "${ENUMLOGFILE/.log/-dnsenum.log}"
    separator

    sublist3r -d "$HOST" -o "${ENUMLOGFILE/.log/-sublist3r-d.log}"
    separator

    PTR_RECORD=$(dig -x "$IP" +short)
    if [[ -n "$PTR_RECORD" ]]; then
        echo "$PTR_RECORD" | tee "${ENUMLOGFILE/.log/-dns-revlookup.log}"
    fi
    separator
fi

# ======================================================================================================================
# NMAP
if [[ -f "$NMAP_XML_OUTFILE" ]]; then
  ask "[enum] run enum-host-nmap.sh -i $IP ? (y/N)" choice
else
  # run nmap if $NMAP_XML_OUTFILE is not exist
  choice="y"
fi

if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./enum-host-nmap.sh -i "$IP" -x "$NMAP_XML_OUTFILE" | tee "${ENUMLOGFILE/.log/-enum-host-nmap-all.log}"
fi

OPENED_TCP_PORTS=$(grep 'state="open"' "$NMAP_XML_OUTFILE" | awk -F'portid="' '{print $2}' | awk -F'"' '{print $1}' | sort -u | tr '\n' ',' | sed 's/,$//')
echo "opened TCP ports: ${OPENED_TCP_PORTS}"

# ======================================================================================================================
# DNS internal enum
if grep -q 'port protocol="tcp" portid="53"' "$NMAP_XML_OUTFILE"; then
  ask "[enum] DNS server detected. Start enum local DNS records ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

    if [[ "$HOST" == "$IP" ]]; then
      ask "specify domain:" TMPHOST
      if [[ -n $TMPHOST ]]; then HOST=$TMPHOST; fi
    fi

    if [[ "$HOST" != "$IP" ]]; then
      ./enum-dns-internal.sh -d $HOST -i $IP -o $OUTDIR | tee "${ENUMLOGFILE/.log/-dns-internal.log}"
    else
      echo -e "${RED}domain is not specified; skip enum-dns-internal script!${NC}"
    fi
  fi
fi

# ======================================================================================================================
# amap
if [[ -n $OPENED_TCP_PORTS ]]; then
  ask "[enum] run 'amap' for opened ports ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    ports=$(echo "$OPENED_TCP_PORTS" | tr ',' ' ')
    echo -e "${GREEN}amap -q -b ${IP} ${ports}${NC}"
    amap -q -b $IP $ports | tee "${ENUMLOGFILE/.log/-amap.log}"
  fi
fi

# ======================================================================================================================
# SMB enum
if { grep -q 'port protocol="tcp" portid="139"' "$NMAP_XML_OUTFILE" && \
     grep -q 'port protocol="tcp" portid="445"' "$NMAP_XML_OUTFILE"; } || \
     grep -q "netbios-ssn" "$NMAP_XML_OUTFILE" || grep -q "microsoft-ds" "$NMAP_XML_OUTFILE"; then

      ask "[enum] 'crackmapexec' list smb shares ? (y/N):" choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        crackmapexec smb $IP --shares -u '' -p '' | tee "${ENUMLOGFILE/.log/-crackmapexec-smb.log}"
        separator
      fi

      ask "[enum] 'impacket-samrdump' enum domain users ? (y/N):" choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        impacket-samrdump "$IP" | tee "${ENUMLOGFILE/.log/-impacket-samrdump.log}"
        separator
      fi

      ask "[enum] run 'smbmap -H ${IP}' ? (y/N):" choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        smbmap -H "$IP" | tee "${ENUMLOGFILE/.log/-smbmap.log}"
        separator
      fi

      ask "[enum] Run SMB enum4linux? (y/N):" choice
      if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
          enum4linux -a "$IP" | tee "${ENUMLOGFILE/.log/-enum4linux.log}"
          separator
      fi
fi

# ======================================================================================================================
# FTP enum
if grep -q 'port protocol="tcp" portid="21"' "$NMAP_XML_OUTFILE" || \
   grep -q "ftp" "$NMAP_XML_OUTFILE"; then

    ask "[enum] FTP service detected. Run FTP enumeration? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        echo -e "Connecting to FTP server for manual check..."
        tip "commands: status, ls -R, put <file>, get <file>"

        tip "tnftp ftp://user:pass@${IP}:21"
        tip "- ls -la"
        tip "- ls -R"

        cmd "ftp anonymous@${IP}"
        separator
    fi

    tip "get all files: wget -m --no-passive ftp://anonymous:anonymous@${IP}"
fi

# ======================================================================================================================
# SSH
if grep -q 'port protocol="tcp" portid="22"' "$NMAP_XML_OUTFILE"; then
  ask "[enum] SSH detected. Run ssh-audit ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    ssh-audit "$IP" | tee "${ENUMLOGFILE/.log/-ssh-audit.log}"
    separator
  fi

  tip "to look what auth methods supports use -v & -o PreferredAuthentications=password"
  tip "- ssh -v user@${IP} -o PreferredAuthentications=password"
fi

# ======================================================================================================================
# SMTP
if grep -q 'port protocol="tcp" portid="25"' "$NMAP_XML_OUTFILE"; then
  ask "[enum] SMTP detected. Run SMTP enumeration ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    cmd "smtp-user-enum -M VRFY -U $SHORT_NAMES_LIST -t $HOST -p 25 -w 20" "${ENUMLOGFILE/.log/-smtp-user-enum-fast.log}"
    separator

    ask "[enum] 'smtp-user-enum' long username list - very slow (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      cmd "smtp-user-enum -M VRFY -U $USER_NAMES_LIST -t $HOST -p 25 -w 20" "${ENUMLOGFILE/.log/-smtp-user-enum-slow.log}"
      separator
    fi
  fi

  ask "[enum] 'swaks' manual enum ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    tip "swaks --help"
    cmd "swaks --server $HOST --to admin@${HOST}"
    separator
  fi

  tip "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp"
fi

# ======================================================================================================================
# Oracle TNS
if grep -q 'port protocol="tcp" portid="1521"' "$NMAP_XML_OUTFILE"; then
  ask "[enum] Oracle TNS. Run Oracle enumeration ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo -e "${GREEN}odat all -s ${IP}${NC}"
    sudo odat all -s $IP | tee "${ENUMLOGFILE/.log/-odat-all.log}"
  fi

  tip "sqlplus -h"
  tip "- sqlplus user/pass@10.129.33.212:1521/DB"
  tip "- sqlplus user/pass@10.129.33.212:1521/DB as sysdba"
  tip "- SQL> SELECT * FROM all_users;"
  tip "- SQL> SELECT name,password FROM sys.user$;"
  tip "- SQL> SELECT table_name FROM all_tables;"
  tip "https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener"
fi

# ======================================================================================================================
# IMAP
if grep -q -E 'portid="143"|portid="993"' "$NMAP_XML_OUTFILE"; then

    ask "[enum] IMAP service detected. Start enum ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      IMAPLOG="${ENUMLOGFILE/.log/-imap.log}"
      echo '' > $IMAPLOG

      echo -e "${GREEN}curl --url \"imap://${IP}\" --user anonymous:anonymous -v${NC}" | tee -a $IMAPLOG
      curl --url "imap://${IP}" --user anonymous:anonymous -v | tee -a $IMAPLOG

      echo -e "${GREEN}curl --url \"imaps://${IP}\" -k --user anonymous:anonymous -v${NC}" | tee -a $IMAPLOG
      curl --url "imaps://${IP}" -k --user anonymous:anonymous -v | tee -a $IMAPLOG

      echo -e "${GREEN}openssl s_client -connect ${IP}:imaps${NC}" | tee -a $IMAPLOG
      openssl s_client -connect ${IP}:imaps | tee -a $IMAPLOG

      if grep -q 'portid="993"' "$NMAP_XML_OUTFILE"; then
        echo -e "${GREEN}nmap --script ssl-enum-ciphers -p 993 ${IP}${NC}" | tee -a $IMAPLOG
        nmap --script ssl-enum-ciphers -p 993 ${IP} | tee -a $IMAPLOG

        echo -e "${GREEN}sslscan ${IP}:993${NC}" | tee -a $IMAPLOG
        sslscan ${IP}:993 | tee -a $IMAPLOG
      fi
    fi

    tip "links"
    tip "https://book.hacktricks.xyz/network-services-pentesting/pentesting-imap"
    tip "https://www.atmail.com/blog/imap-101-manual-imap-sessions/"

    tip "list emails and read"
    tip "- curl 'imaps://${IP}' -k --user anonymous:anonymous -v"
    tip "- curl -v -k --url \"imaps://${IP}/INBOX?ALL\" --user anonymous:anonymous"
    tip "- curl -v -k --url \"imaps://${IP}/INBOX;UID=1\" --user anonymous:anonymous"

    tip "list & fetch emails"
    tip "- curl -v -u \"username:password\" --url \"imaps://${IP}/INBOX\" --request \"LIST \\\"\\\" *\""
    tip "- curl -v -u \"username:password\" --url \"imaps://${IP}/INBOX\" --request \"FETCH 1:* BODY[]\" -o emails.txt"

    tip "extract info from certificate"
    tip "- echo '<certificate>' > server_cert.pem"
    tip "- openssl x509 -in server_cert.pem -noout -text"

    tip "bruteforce"
    tip "hydra -L ${USER_NAMES_LIST} -P ${ROCKYOU_WLIST} imap://${IP}"
fi

# ======================================================================================================================
# POP3
if grep -q -E 'portid="110"|portid="995"' "$NMAP_XML_OUTFILE"; then

    ask "[enum] POP3 service detected. Start enum ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      POP3LOG="${ENUMLOGFILE/.log/-pop3.log}"
      echo '' > $POP3LOG

      echo -e "${GREEN}curl --url \"pop3://${IP}\" --user anonymous:anonymous -v${NC}" | tee $POP3LOG
      curl --url "pop3://${IP}" --user anonymous:anonymous -v | tee -a $POP3LOG

      echo -e "${GREEN}curl --url \"pop3s://${IP}\" -k --user anonymous:anonymous -v${NC}" | tee -a $POP3LOG
      curl --url "pop3s://${IP}" -k --user anonymous:anonymous -v | tee -a $POP3LOG

      echo -e "${GREEN}openssl s_client -connect ${IP}:pop3s${NC}" | tee -a $POP3LOG
      openssl s_client -connect ${IP}:pop3s | tee -a $POP3LOG

      if grep -q 'portid="995"' "$NMAP_XML_OUTFILE"; then
        echo -e "${GREEN}nmap --script ssl-enum-ciphers -p 995 ${IP}${NC}" | tee -a $POP3LOG
        nmap --script ssl-enum-ciphers -p 995 ${IP} | tee -a $POP3LOG

        echo -e "${GREEN}sslscan ${IP}:995${NC}" | tee -a $POP3LOG
        sslscan ${IP}:995 | tee -a $POP3LOG
      fi
    fi

    tip "https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop"
    tip "list emails and read"
    tip "- curl 'pop3s://${IP}' -k --user anonymous:anonymous -v"

    tip "extract info from certificate"
    tip "- echo '<certificate>' > server_cert.pem"
    tip "- openssl x509 -in server_cert.pem -noout -text"

    tip "bruteforce"
    tip "hydra -L ${USER_NAMES_LIST} -P ${ROCKYOU_WLIST} pop3://${IP}"
fi

# ======================================================================================================================
# sslscan
if [[ $URL == https* ]]; then
    ask "[enum] run sslscan $URL ? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      sslscan "$URL" | tee "${ENUMLOGFILE/.log/-sslscan.log}"
      separator
    fi
fi

# ======================================================================================================================
# SNMP
if grep -q 'port protocol="udp" portid="161"' "$NMAP_UDP_XML_OUTFILE"; then
    ask "[enum] SNMP detected. Run SNMP enumeration ? (y/N):" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

      # echo -e "${GREEN}snmpwalk -v2c -c public ${IP}${NC}"
      cmd "snmpwalk -v2c -c public $IP" "${ENUMLOGFILE/.log/-snmpwalk.log}"
      separator

      # echo -e "${GREEN}onesixtyone -c $SNMP_ONESIXTYONE_WLIST -o ${ENUMLOGFILE/.log/-onesixtyone.log} $IP${NC}"
      cmd "onesixtyone $IP -c $SNMP_ONESIXTYONE_WLIST -o \"${ENUMLOGFILE/.log/-onesixtyone.log}\" $IP"
      separator

      tip "if found community by onesixtyone"
      tip "- try: snmpwalk -v2c -c <community> ${IP}"
    fi
fi



# ======================================================================================================================
# WEB enum script
ask "[enum] run './enum-web.sh -u $URL' ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./enum-web.sh -u $URL | tee "${ENUMLOGFILE/.log/-web-all.log}"
fi

# ======================================================================================================================
# bruteforce services script
ask "[enum] run ./bruteforce-services.sh -i $IP -o $OUTDIR -x $NMAP_XML_OUTFILE ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./bruteforce-services.sh -H $HOST -o $OUTDIR -x $NMAP_XML_OUTFILE | tee "${ENUMLOGFILE/.log/-bruteforce-services-all.log}"
fi

# ----------------------------------------------------------------------------------------------------------------------
# results

separator
tip "crackmapexec -h"
tip "do not forget to look into books"

tip "links:"
tip "- https://book.hacktricks.xyz/"
tip "- https://pentestbook.six2dez.com/others/web-checklist"

tip "extract info from certificate"
tip "- echo '<certificate>' > server_cert.pem"
tip "- openssl x509 -in server_cert.pem -noout -text"

separator
echo -e "${GREEN}SEE RESULTS IN:${NC} $OUTDIR/..."
