#!/bin/bash

# https://academy.hackthebox.com/module/112/section/1061


function show_help() {
    echo "Usage: $0 -d <domain>"
    echo ""
    echo "Options:"
    echo "  -d        Domain (required)"
    echo "  -h        Show this help message"
}

DOMAIN=""

# Parse options
while getopts "d:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z $DOMAIN ]]; then
  show_help
  exit 1
fi

OUTDIR="./results/${DOMAIN}"

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

LOGFILE="${OUTDIR}/logs/domain-discovery.log"

source ./enum.conf

########################################################################################################################

CRT_RSLT=$(curl -s "https://crt.sh/?q=${DOMAIN}&output=json")

SUBDOMAINS=""
separator

host "${DOMAIN}" | tee ${LOGFILE/.log/-host.log}
separator

echo -e "${GREEN}https://crt.sh/?q=${DOMAIN} results${NC}"
echo $CRT_RSLT | jq | tee ${LOGFILE/.log/-crtsh.log}
separator

########################################################################################################################
# whois
echo -e "${GREEN}whois ${DOMAIN}${NC}"
whois $DOMAIN | tee ${LOGFILE/.log/-whois.log}
separator

echo -e "${GREEN}extracted domains list from crt.sh${NC}"
SUBDOMAINS=$(echo $CRT_RSLT | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u)
echo "$SUBDOMAINS" | tee ${LOGFILE/.log/-crtsh-subdomains.log}
separator

########################################################################################################################
# host
OUTLOGF=${LOGFILE/.log/-host-subdomains.log}
echo -e "${YELLOW}host <subdomain>${NC}" | tee "$OUTLOGF"
IP_LIST=""
for i in $SUBDOMAINS;do
  echo -e "${GREEN}host ${i}${NC}" | tee -a "$OUTLOGF"
  RSLT=$(host $i | grep "has address" | grep "$DOMAIN" | sort -u)

  while read -r ip; do
    IP_LIST+="$ip"$'\n'
  done <<< "$(echo "$RSLT" | cut -d" " -f4)"

  echo "$RSLT" | cut -d" " -f1,4 | tee -a "$OUTLOGF"
  echo -e "${GREEN}-----------${NC}"
done
IP_LIST=$(echo "$IP_LIST" | sort -u)
separator

########################################################################################################################
# FinalRecon
ask "[domain-discovery] run FinalRecon --full ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cmd "python /opt/FinalRecon/finalrecon.py --url \"https://${DOMAIN}\" --full" ${LOGFILE/.log/-FinalRecon.log}
  separator
fi

########################################################################################################################
# dig
ask "[domain-discovery] run dig A,AAAA,MX,TXT,axfr,... ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  OUTLOGF=${LOGFILE/.log/-dig.log}
  echo -e "${GREEN}dig any ${DOMAIN}${NC}" | tee "$OUTLOGF"
  dig any $DOMAIN | tee -a "$OUTLOGF"
  separator | tee -a "$OUTLOGF"
  sleep 1

  modes="A AAAA MX TXT CNAME NS SOA axfr"
  for mode in modes; do
    echo -e "${GREEN}dig A ${DOMAIN}${NC}" | tee -a "$OUTLOGF"
    dig $mode $DOMAIN | tee -a "$OUTLOGF"
    separator | tee -a "$OUTLOGF"
    sleep 1
  done

  tip "reverse lookup:"
  tip "- dig -x <IP>"
fi

########################################################################################################################
# dmitry
ask "[domain-discovery] run 'dmitry -iwnse ${DOMAIN}' ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  OUTLOGF=${LOGFILE/.log/-dmitry.log}
  echo -e "${GREEN}dmitry -iwnse ${DOMAIN}${NC}" | tee "$OUTLOGF"
  dmitry -iwnse "${DOMAIN}" | tee -a "$OUTLOGF"
  separator
fi

########################################################################################################################
# knockpy
ask "[domain-discovery] run 'knockpy -d ${DOMAIN} --recon' ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  OUTLOGF=${LOGFILE/.log/-knockpy.log}
  echo -e "${GREEN}knockpy -d ${DOMAIN} --recon${NC}" | tee "$OUTLOGF"
  knockpy -d "${DOMAIN}" --recon --useragent "${UA}" | tee -a "$OUTLOGF"
  separator
fi

########################################################################################################################
# subfinder
ask "[domain-discovery] run 'subfinder -d ${DOMAIN} -recursive' ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  OUTLOGF=${LOGFILE/.log/-subfinder.log}
  echo -e "${GREEN}subfinder -d \"${DOMAIN}\" -recursive${NC}" | tee "$OUTLOGF"
  subfinder -d "${DOMAIN}" -recursive | tee -a "$OUTLOGF"
  separator
fi

########################################################################################################################
# sublist3r
ask "[domain-discovery] run 'sublist3r -d ${DOMAIN}' ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  OUTLOGF=${LOGFILE/.log/-sublist3r.log}
  echo -e "${GREEN}sublist3r -d \"${DOMAIN}\"${NC}" | tee "$OUTLOGF"
  sublist3r -d "${DOMAIN}" | tee -a "$OUTLOGF"
  separator
fi

########################################################################################################################
# TODO: SimplyEmail

########################################################################################################################
# dnsenum
tip "dnsenum --dnsserver <DNS IP> --enum -p 0 -s 0 -o subdomains.txt -f $DNS_NAMELIST $DOMAIN"
tip "dnsenum --enum $DOMAIN -f $DNS_NAMELIST -r"
ask "[domain-discovery][dnsenum] bruteforce subdomain ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cmd "dnsenum --enum $DOMAIN -o ${LOGFILE/.log/-dnsenum.txt} -f $DNS_NAMELIST -r" ${LOGFILE/.log/-dnsenum.log}
  cmd "dnsenum --enum $DOMAIN -o ${LOGFILE/.log/-dnsenum-2.txt} -f $DNS_NAMELIST_2 -r" ${LOGFILE/.log/-dnsenum.log}
  separator
fi

########################################################################################################################
# theHarvester
ask "[domain-discovery] run theHarvester -d ${DOMAIN} ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo "${GREEN}theHarvester -d ${DOMAIN}${NC}"
  theHarvester -d "${DOMAIN}" | tee ${LOGFILE/.log/-theHarvester.log}
  separator
fi

########################################################################################################################
# search files & metadata
ask "[domain-discovery] run 'metagoofil' - search files & metadata ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  METAGOOFIL=${LOGFILE/.log/-metagoofil.log}
  echo -e "${GREEN}Search files & metadata${NC}" | tee $METAGOOFIL
  cmd "metagoofil -d ${DOMAIN} -t pdf,doc,xls,docx,xlsx" $METAGOOFIL
  separator
fi

########################################################################################################################
# web.archive.org
ask "[domain-discovery] FF open web archive for ${DOMAIN} ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  firefox "https://web.archive.org/web/20250000000000*/${DOMAIN}" 2>/dev/null &
fi

########################################################################################################################
# shodan
shodan info > /dev/null 2>&1
if [ $? -eq 0 ]; then
  SHODANLOG=${LOGFILE/.log/-shodan.log}
  echo '' > "$SHODANLOG"

  for i in $IP_LIST;do
    echo -e "${GREEN}shodan host ${i}${NC}" | tee -a "$SHODANLOG"
    shodan host $i | tee -a "$SHODANLOG"
  done
fi
