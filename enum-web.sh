#!/bin/bash

# TODO:
# - XSS scan https://github.com/hahwul/dalfox

source ./enum.conf

function show_help() {
    echo "Usage: $0 -u <URL>"
    echo ""
    echo "Options:"
    echo "  -u        URL (required)"
    echo "  -h        Show this help message"
}

URL=""

# Parse options
while getopts "u:h" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Check for required parameters
if [[ -z "$URL" ]]; then
    echo "Error: -u <URL> is required."
    show_help
    exit 1
fi

parseUrl "$URL" HOST

OUTDIR=$(realpath "./results/${HOST}")

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

ENUMLOGFILE="${OUTDIR}/logs/enum-web.log"

MIRRORED_SITE_DIR="${OUTDIR}/web-mirror"
URLS_LIST_FILE="${OUTDIR}/urls.list"
FUZZ_PARAMS_URLS="${OUTDIR}/urls-fuzz-params.list"
SITE_WORDS="${OUTDIR}/site-words.list"
SITE_EMAILS="${OUTDIR}/site-emails.list"

# ======================================================================================================================
# open site

ask "[enum-web] open $URL in firefox ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  firefox "$URL" >/dev/null 2>&1 &
  separator
fi

# ======================================================================================================================
# whatweb
ask "[enum-web] run whatweb ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}whatweb \"${URL}\"${NC}"
  whatweb "${URL}" | tee "${ENUMLOGFILE/.log/-whatweb.log}"
  tip "use 'searchsploit ...' for found technologies"
  separator
fi

# ======================================================================================================================
# detect WAF
ask "[enum-web] detect WAF ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}wafw00f ${URL}${NC}"
  wafw00f "$URL" | tee "${ENUMLOGFILE/.log/-wafw00f.log}"
  separator
fi

# ======================================================================================================================
# HTB ReconSpider
ask "[enum-web] run HTB/scrapy ./scripts/ReconSpider.py ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  RECONRSLTS="${OUTDIR}/ReconSpider.json"
  echo -e "${GREEN}python3 ./scripts/ReconSpider.py ${URL} ${RECONRSLTS}${NC}"
  python3 ./scripts/ReconSpider.py "${URL}" "${RECONRSLTS}"
  echo -e "${BLUE}results: ${RECONRSLTS}${NC}"
  separator
fi

# ======================================================================================================================
# httrack mirror site
ask "[enum-web] create web-site mirror & collect urls ? (Y/n):" choice
if [[ -z $choice || "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}httrack --mirror \"$URL\" -O \"${MIRRORED_SITE_DIR}\"${NC}"
  httrack --mirror "$URL" -O "${MIRRORED_SITE_DIR}"

  grep -o -P "https?://[^\s\)]+" "${MIRRORED_SITE_DIR}/hts-cache/new.txt" | sort -u > "${URLS_LIST_FILE}"

  echo -e "${BLUE}site saved in ${MIRRORED_SITE_DIR}${NC}"
  echo -e "${BLUE}links list saved in ${URLS_LIST_FILE}${NC}"
  separator
fi

# ======================================================================================================================
# collect urls with parameters for fuzzing
ask "[enum-web] Collect fuzz-params urls ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    paramspider -d $HOST -s 2>&1 | grep -Ei "https?://" | sort -u | httpx-toolkit -silent -mc 200 | awk '{print $1}' > "${FUZZ_PARAMS_URLS}"
    tip "Alternatively, you can use tools like waybackurls, urlfinder, katana to collect URLs"
    echo -e "${BLUE}RESULTS: ${FUZZ_PARAMS_URLS}${NC}"
    separator
fi

# ======================================================================================================================
# exiftool - image metadata
ask "[enum-web] extract image metadata ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

  LOG_FILE=${ENUMLOGFILE/.log/-img-metadata.log}
  echo '' > "$LOG_FILE"

  find "$MIRRORED_SITE_DIR" -type f \( -iname "*.jpg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.bmp" -o -iname "*.tif" -o -iname "*.webp" \) | while read -r IMAGE_PATH; do
    echo "Processing: $IMAGE_PATH" >> "$LOG_FILE"
    exiftool "$IMAGE_PATH" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"
  done

  echo -e "${BLUE}RESULTS: ${LOG_FILE}${NC}"
  separator
fi

# ======================================================================================================================
# cewl
# TODO: get from local mirror if exists
ask "[enum-web] run cewl - gather emails & words from $URL ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo -e "${GREEN}cewl -d 4 -w ${SITE_WORDS} -e --email_file ${SITE_EMAILS} --lowercase --ua \"$UA\" $URL${NC}"
    cewl -d 4 -w "${SITE_WORDS}" -e --email_file "${SITE_EMAILS}" --lowercase --ua "$UA" $URL

    echo -e "${BLUE}words: ${SITE_WORDS}${NC}"
    echo -e "${BLUE}emails: ${SITE_EMAILS}${NC}"
    separator
fi

# ======================================================================================================================
# OWASP D4N155

if [[ -f "${SITE_WORDS}" ]]; then
  ask "[enum-web] [OWASP D4N155] generate password list from ${SITE_WORDS} ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    cd /opt/D4N155/
    pipenv run bash main -b "${SITE_WORDS}" -o "${OUTDIR}/site-passwords-offline-D4N155.lst"
    cd -
  fi
  tip "https://github.com/OWASP/D4N155"
  separator
fi

ask "[enum-web] [OWASP D4N155] gather words from $URL & generate passwords ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    cd /opt/D4N155/
    pipenv run bash main -w "${URL}"
    cd -

    tip "copy wordlist to ${OUTDIR}/site-passwords-online-D4N155.lst"
    tip "https://github.com/OWASP/D4N155"
    separator
fi

# ======================================================================================================================
# nikto
ask "[enum-web] Run nikto -h \"${URL}\" ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    nikto -h "$URL" -output "${ENUMLOGFILE/.log/-nikto.txt}"
    separator
fi

# ======================================================================================================================
# nuclei
ask "[enum-web] Run nuclei -u \"${URL}\" ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    nuclei -u "$URL" -o "${ENUMLOGFILE/.log/-nuclei.log}"
    separator
fi

# TODO: analyze website and grab emails, links, comments, etc
#for js_file in $(curl -s "$URL" | grep -oP '(?<=src=")[^"]*\.js'); do
#    linkfinder -i "$URL/$js_file" -o cli | tee -a "$OUTDIR/enum_js_analysis.txt"
#done

# ======================================================================================================================
# ffuf script
ask "[enum-web] run enum-web-ffuf.sh -u $URL -o $OUTDIR ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./enum-web-ffuf.sh -u $URL -o $OUTDIR | tee "${ENUMLOGFILE/.log/-ffuf-all.log}"
  separator
fi

# ======================================================================================================================
# XSS script
ask "[enum-web] run XSS script [enum-web-xss.sh] ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  ./enum-web-xss.sh -u $URL -o $OUTDIR | tee "${ENUMLOGFILE/.log/-xss-all.log}"
  separator
fi

# ======================================================================================================================
# https://github.com/Cybersecurity-Ethical-Hacker

# lfier
ask "[enum-web] Run lfier (LFI finder for collected urls) ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    python /opt/lfier/lfier.py -l "${FUZZ_PARAMS_URLS}" | tee "${ENUMLOGFILE/.log/-lfier.log}"
    tip "https://github.com/Cybersecurity-Ethical-Hacker/lfier"
    separator
fi

# oredirectme
ask "[enum-web] Run oredirectme (Open Redirect finder for collected urls) ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    python /opt/oredirectme/oredirectme.py -l "${FUZZ_PARAMS_URLS}" | tee "${ENUMLOGFILE/.log/-oredirectme.log}"
    tip "https://github.com/Cybersecurity-Ethical-Hacker/oredirectme"
    separator
fi

# ======================================================================================================================
# ZAP scanner
ask "[enum-web] open ZAP scanner ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  #zaproxy
  owasp-zap
  separator
fi

# ======================================================================================================================
# BeEF XSS
ask "[enum-web] open BeEF XSS framework ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  tip "msf enum browser vulns using XSS:"
  tip "- module auxiliary/server/browser_autopwn2"

  sudo beef-xss
  separator
fi

# ======================================================================================================================
# OpenVAS scanner
ask "[enum-web] start OpenVAS scanner ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  sudo gvm-start
  separator
fi

# ======================================================================================================================
# TODO sqlmap
#ask "start sqlmap ? (y/N)" choice
#if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
#  sqlmap ...
#  separator
#fi
# ======================================================================================================================

# ======================================================================================================================
# webscarab
ask "[enum-web] start webscarab ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  webscarab
  separator
fi

# ======================================================================================================================
tip "vuln DBs links:"
tip "- https://nvd.nist.gov/vuln/search"
tip "- www.opencve.io"
tip "- cve.mitre.org"
#tip "- www.securityfocus.com"
#tip "- blog.osvdb.org"
#tip "- www.packetstormsecurity.org"
tip "- exchange.xforce.ibmcloud.com"
tip "- www.kb.cert.org/vuls"
tip "- www.us-cert.gov/cas/techalerts"
tip "- www.securiteam.com"
tip "- secunia.com/advisories/historic/"
tip "- cxsecurity.com"
tip "- www.xssed.com"
tip "- securityvulns.com"
tip "- www.sebug.net"
tip "- techblog.mediaservice.net"
tip "- www.intelligentexploit.com"
