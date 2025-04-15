#!/bin/bash

# see https://nmap.org/book/host-discovery-strategies.html
# https://nmap.org/book/nse-usage.html

function show_help() {
    echo "Usage: $0 -i <interface> [-o <output_directory>]"
    echo ""
    echo "Options:"
    echo "  -i        interface e.g. eth0"
    echo "  -o        Output directory for results (optional)"
    echo "  -h        Show this help message"
}

IPS=""
OUTDIR=""

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
source "${SCRIPT_DIR}/enum.conf"

# Parse options
while getopts "i:o:h" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        o) OUTDIR="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z $INTERFACE ]]; then
  show_help
  exit 1
fi

NETWORK=$(ip -4 addr show "$INTERFACE" | awk '/inet / {
  split($2, ip_mask, "/");
  ip = ip_mask[1];
  mask = ip_mask[2];
  split(ip, ip_parts, ".");
  network = ip_parts[1] "." ip_parts[2] "." ip_parts[3] ".0/" mask;
  print network;
  exit
}')

if [[ -z $OUTDIR ]]; then
  OUTDIR="${SCRIPT_DIR}/results/enum-network-${NETWORK//[^0-9]/_}"
fi

if [[ ! -d $OUTDIR ]]; then
  mkdir -p $OUTDIR
fi

echo -e "${GREEN}Network: ${NETWORK}${NC}"
echo -e "${GREEN}outdir: ${OUTDIR}${NC}"
separator

########################################################################################################################

ask "[enum-network] run arp-scan ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  sudo arp-scan $NETWORK -I $INTERFACE | tee "${OUTDIR}/arp-scan.out"
  separator
fi

ask "[enum-network] run netdiscover ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}netdiscover -r $NETWORK -P${NC}"
  sudo netdiscover -r $NETWORK -P | tee "${OUTDIR}/netdiscover.out"
  separator
fi

ask "[enum-network][nmap] run/try multiple ping methods ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}nmap -n -sn -PE -PP -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -T4 -g 53 ${NETWORK}${NC}"
  sudo nmap -n -sn -PE -PP -PS21,22,23,25,80,113,443,31339 -PA80,113,443,10042 -T4 -g 53 $NETWORK -oX "${OUTDIR}/nmap-ping.xml" -oN "${OUTDIR}/nmap-ping.nmap" | tee "${OUTDIR}/nmap-ping.out"
  separator
fi

ask "[enum-network] run whatweb $NETWORK ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}whatweb ${NETWORK}${NC}"
  whatweb $NETWORK 2>&1 | grep -v 'ERROR Opening' | tee "${OUTDIR}/whatweb.out"
  separator
fi

ask "[enum-network][nmap] run discovery, broadcast scripts ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  echo -e "${GREEN}nmap --script discovery,broadcast --script-args=newtargets -e $INTERFACE $NETWORK${NC}"
  NMAP_XML_OUTFILE="${OUTDIR}/nmap-discovery.xml"
  NMAP_HTML_OUTFILE="${NMAP_XML_OUTFILE//.xml/.html}"
  sudo nmap --script discovery,broadcast --script-args=newtargets -e $INTERFACE $NETWORK -oX "$NMAP_XML_OUTFILE" | tee "${OUTDIR}/nmap-discovery.out"
  xsltproc "$NMAP_XML_OUTFILE" -o "$NMAP_HTML_OUTFILE"

  ask "[firefox] open $NMAP_HTML_OUTFILE ? (y/N)" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    firefox "$NMAP_HTML_OUTFILE" &>/dev/null &
  fi
  separator
fi

echo -e "${GREEN}SEE RESULTS IN: ${OUTDIR}/...${NC}"
