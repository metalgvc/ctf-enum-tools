#!/bin/bash

# TODO:
# - XSS scan https://github.com/hahwul/dalfox

source ./enum.conf

function show_help() {
    echo "Usage: $0 -u <URL>"
    echo ""
    echo "Options:"
    echo "  -u        URL (required)"
    echo "  -o        Output directory for results"
    echo "  -h        Show this help message"
}

URL=""
OUTDIR=""

# Parse options
while getopts "u:o:h" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
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

if [[ -z $OUTDIR ]]; then
  OUTDIR="./results/${HOST}"
fi

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

ENUMLOGFILE="${OUTDIR}/logs/enum-web-xss.log"

URLS_LIST_FILE="${OUTDIR}/urls.list"
FUZZ_PARAMS_URLS="${OUTDIR}/urls-fuzz-params.list"
MIRRORED_SITE_DIR="${OUTDIR}/web-mirror"

# ======================================================================================================================
tip "xss/sqli - check inputs with: '<s>000'\")};--//'"

tip "configure own XSS Hunter server:"
tip "- XSS Hunter & https://github.com/trufflesecurity/xsshunter"

# site mirror ans collect urls
if [[ ! -s "${URLS_LIST_FILE}" ]]; then
  warnm "Not found: ${URLS_LIST_FILE}"

  ask "[enum-web] create web-site mirror & collect urls ? (Y/n):" choice
  if [[ -z $choice || "$choice" == "y" || "$choice" == "Y" ]]; then
    echo -e "${GREEN}httrack --mirror \"$URL\" -O \"${MIRRORED_SITE_DIR}\"${NC}"
    httrack --mirror "$URL" -O "${MIRRORED_SITE_DIR}"

    grep -o -P "https?://[^\s\)]+" "${MIRRORED_SITE_DIR}/hts-cache/new.txt" | sort -u > "${URLS_LIST_FILE}"
    separator
  fi
fi

# ======================================================================================================================
# xssuccessor https://github.com/Cybersecurity-Ethical-Hacker
ask "[enum-web-xss] Run xssuccessor ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

  if [[ ! -s $FUZZ_PARAMS_URLS ]]; then
    echo -e "${GREEN}collecting fuzz-params urls...${NC}"
    paramspider -d $HOST -s 2>&1 | grep -Ei "https?://" | sort -u | httpx-toolkit -silent -mc 200 | awk '{print $1}' > "${FUZZ_PARAMS_URLS}"
    separator
  fi

  if [[ -s $FUZZ_PARAMS_URLS ]]; then
    python /opt/xssuccessor/xssuccessor.py -p /opt/xssuccessor/xss_payloads.txt -o "${ENUMLOGFILE/.log/-xssuccessor.txt}" -l "${FUZZ_PARAMS_URLS}"
  else
    echo -e "${RED}Empty ${FUZZ_PARAMS_URLS}${NC}"
  fi

  tip "https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor"
  separator
fi

# ======================================================================================================================
ask "[enum-web-xss] Run xsstrike ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cmd "python /opt/xsstrike/xsstrike.py -u \"$URL\" --crawl" "${ENUMLOGFILE/.log/-xsstrike.txt}"
  tip "https://github.com/s0md3v/XSStrike/wiki/Usage"
  tip "- try paramspider and run xsstrike with params"
  tip "- or see input names GET/POST and test"
  tip "- curl -s \"http://$URL\" | grep input | grep name"
  separator
fi


# ======================================================================================================================
# dalfox https://github.com/hahwul/dalfox
tip "https://dalfox.hahwul.com/page/overview/"
tip "- dalfox file $URLS_LIST_FILE"
tip "- cat $URLS_LIST_FILE | dalfox pipe"
tip "- see full urls list: $URLS_LIST_FILE"

ask "[enum-web-xss] Run dalfox ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  cmd "dalfox url \"$URL\" --user-agent \"$UA\"" "${ENUMLOGFILE/.log/-dalfox-url.log}"
  separator
fi

# ======================================================================================================================
tip "https://www.zaproxy.org/docs/desktop/ui/dialogs/options/spider/"
tip "- spider the site and run active scan"
tip "- see alerts and check for XSS"
ask "[enum-web-xss] Run ZAProxy ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  zaproxy &
  separator
fi