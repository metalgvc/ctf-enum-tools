#!/bin/bash

# https://academy.hackthebox.com/module/112/section/1061

function show_help() {
    echo "Usage: $0 -d <domain> -i <DNS IP>"
    echo ""
    echo "Options:"
    echo "  -d        Domain (required)"
    echo "  -i        DNS server IP (required)"
    echo "  -h        Show this help message"
}

DOMAIN=""
DNSIP=""

# Parse options
while getopts "d:i:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        i) DNSIP="$OPTARG" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

if [[ -z $DOMAIN || -z $DNSIP ]]; then
  show_help
  exit 1
fi

OUTDIR="./results/${DOMAIN}"

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

LOGFILE="${OUTDIR}/logs/dns-internal-${DOMAIN}.log"
echo '' > "${LOGFILE}"

source ./enum.conf

# prepare DNS list
DNSLIST="${ENUM_APP_DIR}/dnslist.list"
cat "$DNS_NAMELIST" "$DNS_NAMELIST_2" | sort -u > "${DNSLIST}"

# ======================================================================================================================

DIGLOG=${LOGFILE/.log/-dig.log}
echo '' > "${DIGLOG}"

gmsg "dig @${DNSIP} $DOMAIN AXFR" $DIGLOG
dig @${DNSIP} $DOMAIN AXFR | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN ANY" $DIGLOG
dig @${DNSIP} $DOMAIN ANY +nocomments | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN CNAME" $DIGLOG
dig @${DNSIP} $DOMAIN CNAME | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN MX" $DIGLOG
dig @${DNSIP} $DOMAIN MX | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN A" $DIGLOG
dig @${DNSIP} $DOMAIN A | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN TXT" $DIGLOG
dig @${DNSIP} $DOMAIN TXT | tee -a $DIGLOG
separator

gmsg "dig @${DNSIP} $DOMAIN NS" $DIGLOG
dig @${DNSIP} $DOMAIN NS | tee -a $DIGLOG
separator

ask "[enum-dns-internal] run detailed dig ... ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  gmsg "dig @${DNSIP} $DOMAIN SOA" $DIGLOG
  dig @${DNSIP} $DOMAIN SOA | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN AAAA" $DIGLOG
  dig @${DNSIP} $DOMAIN AAAA | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN PTR" $DIGLOG
  dig @${DNSIP} $DOMAIN PTR | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN SRV" $DIGLOG
  dig @${DNSIP} $DOMAIN SRV | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN SPF" $DIGLOG
  dig @${DNSIP} $DOMAIN SPF | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN HINFO" $DIGLOG
  dig @${DNSIP} $DOMAIN HINFO | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN NAPTR" $DIGLOG
  dig @${DNSIP} $DOMAIN NAPTR | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN RP" $DIGLOG
  dig @${DNSIP} $DOMAIN RP | tee -a $DIGLOG
  separator

  gmsg "dig @${DNSIP} $DOMAIN WKS" $DIGLOG
  dig @${DNSIP} $DOMAIN WKS | tee -a $DIGLOG
  separator
fi

separator
gmsg "dig summary:"
cat $DIGLOG | grep -vE '^;' | grep -vE '^$' | tee -a $DIGLOG
separator

ask "[enum-dns-internal] run subbrute for ${DOMAIN} ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  RESOLVERS="${OUTDIR}/resolvers.txt"
  SUBBRUTELOG=${LOGFILE/.log/-subbrute.log}
  echo '' > "${SUBBRUTELOG}"

  gmsg "python3 /opt/subbrute/subbrute.py ${DOMAIN} -s ${DNSLIST} -r ${RESOLVERS}" $SUBBRUTELOG
  echo $DNSIP > "${RESOLVERS}"
  python3 /opt/subbrute/subbrute.py ${DOMAIN} -s ${DNSLIST} -r ${RESOLVERS} | tee -a $SUBBRUTELOG
  separator
fi

ask "[enum-dns-internal] run dnsenum for ${DOMAIN} ? (y/N)" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  DNSENUMLOG=${LOGFILE/.log/-dnsenum.txt}
  echo '' > "${DNSENUMLOG}"

  gmsg "dnsenum --dnsserver $DNSIP --enum -p 0 -s 0 -o ${DNSENUMLOG} -f $DNSLIST ${DOMAIN}" ${DNSENUMLOG}
  dnsenum --dnsserver $DNSIP --enum -p 0 -s 0 -o ${DNSENUMLOG} -f $DNSLIST $DOMAIN
  separator
fi

# TODO wrap above to function && prompt to enum additional v/host