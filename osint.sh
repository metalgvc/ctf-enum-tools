#!/bin/bash


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

LOGFILE="${OUTDIR}/logs/osint.log"

source ./enum.conf

########################################################################################################################

ask "[osint] open https://osintframework.com/ ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  firefox "https://osintframework.com/" >/dev/null 2>&1 &
fi

ask "[osint] open analyze malware & phishing online tools ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  firefox "https://phishtank.com/" >/dev/null 2>&1 &
  sleep 2
  firefox "https://www.threatminer.org/" >/dev/null 2>&1 &
  #firefox "http://threatcrowd.org/" >/dev/null 2>&1 &
fi

ask "[osint] open https://builtwith.com/${DOMAIN} ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  firefox "https://builtwith.com/${DOMAIN}" >/dev/null 2>&1 &
fi

ask "[osint][trufflehog] search leaked creds in github, docker, S3, ...  ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cmd "trufflehog"

  tip "also old tools:"
  tip "- https://github.com/michenriksen/gitrob"
  tip "- https://github.com/UnkL4b/GitMiner"

  separator
fi

ask "[osint] run ./domain-discovery.sh -d \"${DOMAIN}\"  ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./domain-discovery.sh -d "${DOMAIN}"
  separator
fi

ask "[osint] run recon-ng tool ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}recon-ng -w ${DOMAIN}${NC}"
  recon-ng -w $DOMAIN
  separator
fi

ask "[osint] run 'Discover' tool (https://github.com/leebaird/discover) ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}'Discover' tool${NC}"
  /opt/discover/discover.sh
  separator
fi

tip "use 'maltego' tool for gather information for domain/site"
tip "- use free/anonymous email https://proton.me/ for registration"

tip "search user/email/password on leaked DBs like BreachCompilation"

tip "Google Dorks"
tip "- https://www.exploit-db.com/google-hacking-database"

# Usage is similar to nmap. To scan a network segment for some ports


# TODO D/L masscan exclude file https://github.com/robertdavidgraham/masscan/blob/master/data/exclude.conf"
tip "masscan"
tip "- # Usage is similar to nmap. To scan a network segment for some ports"
tip "- > masscan -p80,8000-8100 10.0.0.0/8"
tip "- "
tip "- # scan the entire Internet excluding exclude.txt"
tip "- # exclude file https://github.com/robertdavidgraham/masscan/blob/master/data/exclude.conf"
tip "- > masscan 0.0.0.0/0 -p0-65535 --excludefile exclude.txt --max-rate 100000"
tip "- "
tip "- cheatsheet"
tip "- https://sweshi.com/CyberSecurityTutorials/Penetration%20Testing%20and%20Ethical%20Hacking/masscan%20tutorial.php"


tip "shodan"
tip "- use free/anonymous email https://proton.me/ for registration"
tip "- shodan filters: https://github.com/JavierOlmedo/shodan-filters"

tip "LINKS:"
tip "- www.archive.org      sites archives"
tip "- www.domaintools.com  domain names info"
tip "- www.alexa.com        DB of sites"
tip "- serversniff.net      network tools"
tip "- centralops.net       network tools"
tip "- www.robtex.com       domain & network info"
tip "- www.pipl.com         search person"
tip "- wink.com             search person"
tip "- www.isearch.com      search person"
tip "- www.tineye.com       info about image, photo"
tip "- www.sec.gov/edgar.shtml  info about public companies"