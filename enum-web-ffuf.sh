#!/bin/bash

source ./enum.conf

function show_help() {
    echo "Usage: $0 -u <URL> -o <output_directory>"
    echo ""
    echo "Options:"
    echo "  -u        URL (required)"
    echo "  -o        Output directory for results (required)"
    echo "  -h        Show this help message"
}

OUTDIR=""
URL=""

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

if [[ -z "$OUTDIR" ]]; then
    echo "Error: -o <output_directory> is required."
    show_help
    exit 1
fi

if [[ ! -d "${OUTDIR}/logs" ]]; then
  mkdir -p "${OUTDIR}/logs"
fi

ENUMLOGFILE="${OUTDIR}/logs/enum-web-ffuf.log"

BASELINE_OUTFILE="/tmp/autotool/autotool_baseline_out.tmp"
BASELINE_TMP_WRDLST="/tmp/autotool/autotool_baseline_wrdlst.tmp"

parseUrl "$URL" HOST WEB_PORT

if [[ "$WEB_PORT" != "80" && "$WEB_PORT" != "443" ]]; then
  HOST="${HOST}:${WEB_PORT}"
fi

# ======================================================================================================================

function generate_filters() {
  eval "$1 > /dev/null 2>&1"

  declare -A codes
  declare -A sizes
  declare -A words
  declare -A lines

  # get baseline results for filters
  while read -r rslt; do

    # status codes
    status=$(echo $rslt | jq -r '.status')
    [[ -n "${codes[$status]}" ]] && ((codes[$status]++)) || codes[$status]=1

    # sizes
    size=$(echo $rslt | jq -r '.length')
    [[ -n "${sizes[$size]}" ]] && ((sizes[$size]++)) || sizes[$size]=1

    # words
    word=$(echo $rslt | jq -r '.words')
    [[ -n "${words[$word]}" ]] && ((words[$word]++)) || words[$word]=1

    # lines
    line=$(echo $rslt | jq -r '.lines')
    [[ -n "${lines[$line]}" ]] && ((lines[$line]++)) || lines[$line]=1

  done < <(jq -c '.results[]' "$BASELINE_OUTFILE")

  initScanRslts=''

  # Filter for Sizes (-fs) if a size occurs more than 10 times
  fstr=''
  for size in "${!sizes[@]}"; do
    fstr+="${size}[${sizes[$size]}]; "
  done
  if [[ -n $fstr ]]; then
    initScanRslts+=" ${YELLOW}Sizes:${NC} $fstr\n"
  fi

  # Filter for Lines (-fl) if a line count occurs more than 10 times
  fstr=''
  for line in "${!lines[@]}"; do
    fstr+="${line}[${lines[$line]}]; "
  done
  if [[ -n $fstr ]]; then
    initScanRslts+=" ${YELLOW}Lines:${NC} $fstr\n"
  fi

  # Filter for Words (-fw) if a word count occurs more than 10 times
  fstr=''
  for word in "${!words[@]}"; do
    fstr+="${word}[${words[$word]}]; "
  done
  if [[ -n $fstr ]]; then
    initScanRslts+=" ${YELLOW}Words:${NC} $fstr\n"
  fi

  # Filter for Codes (-fc) if a status code occurs more than 10 times and is not 200
  fstr=''
  for code in "${!codes[@]}"; do
    fstr+="${code}[${codes[$code]}]; "
  done
  if [[ -n $fstr ]]; then
    initScanRslts+=" ${YELLOW}Codes:${NC} $fstr\n"
  fi

  if [[ -n $initScanRslts ]]; then
    echo -e "${YELLOW}InitScan results:${NC}"
    echo -e "$initScanRslts"
    ask "Type filters:" FILTERS
  fi
}

function extract_dirs() {
    while IFS= read -r line; do
      path=$(echo "$line" | jq -r '.input.FUZZ')
      furl=$(echo "$line" | jq -r '.url')

      if [[ "$furl" =~ /[^/]+\.[^/]+$ ]]; then
        furl=$(dirname "$furl")
      fi
      furl="${furl%/}"

      [[ "$path" != *.* ]] && FOUND_DIRS+=("$furl")
    done < <(jq -c '.results[]' "$JSON_RSLTS_PATH")
}

# ----------------------------------------------------------------------------------------------------------------------
# enum virtual hosts
echo -e "${GREEN}HOST: $HOST${NC}"
ask "[ffuf] enum VHOSTS ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  separator
  echo -e "${GREEN}-----------> VHOST${NC}"

  # get filters
  tail -n 20 "$FFUF_WLIST_DIRS" > "$BASELINE_TMP_WRDLST"
  cmdstr="ffuf -w $BASELINE_TMP_WRDLST:FUZZ -ic -u $URL -H \"$UA\" -H \"HOST: FUZZ.$HOST\" -o $BASELINE_OUTFILE -of json"
  FILTERS=""
  generate_filters "$cmdstr"

  cmd "ffuf -w $FFUF_WLIST_VHOSTS:FUZZ -c -ic -v -u $URL -H \"$UA\" -H \"HOST: FUZZ.$HOST\" $FILTERS" "${ENUMLOGFILE/.log/-vhosts-${WEB_PORT}.log}"
  cmd "ffuf -w $FFUF_WLIST_VHOSTS_2:FUZZ -c -ic -v -u $URL -H \"$UA\" -H \"HOST: FUZZ.$HOST\" $FILTERS" "${ENUMLOGFILE/.log/-vhosts-2-${WEB_PORT}.log}"
  cmd "ffuf -w $FFUF_WLIST_VHOSTS_3:FUZZ -c -ic -v -u $URL -H \"$UA\" -H \"HOST: FUZZ.$HOST\" $FILTERS" "${ENUMLOGFILE/.log/-vhosts-3-${WEB_PORT}.log}"
  #cmd "gobuster vhost -u $URL -w $FFUF_WLIST_VHOSTS --append-domain" "${ENUMLOGFILE/.log/-vhosts-4-${WEB_PORT}.log}"

  # TODO collect new detected virtual hosts and prompt to add to /etc/hosts if not exist
fi

# ----------------------------------------------------------------------------------------------------------------------
# enum dirs
ask "[ffuf] enum dirs/files ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  separator
  echo -e "${GREEN}-----------> DIRS${NC}"

  # get filters
  tail -n 20 "$FFUF_WLIST_DIRS" > "$BASELINE_TMP_WRDLST"
  cmd="ffuf -w $BASELINE_TMP_WRDLST:FUZZ -u $URL/FUZZ -H \"$UA\" -v -o $BASELINE_OUTFILE -of json"
  FILTERS=""
  generate_filters "$cmd"

  ask "Use recursion ? depth (0..n):" choice
  recursion=""
  if [[ -n $choice && "$choice" -gt 0 ]]; then
    recursion="-recursion -recursion-depth $choice "
  fi

  tip "-e php,html,txt"

  JSON_RSLTS_PATH="${ENUMLOGFILE/.log/-dirs-${WEB_PORT}.json}"
  cmd "ffuf -w $FFUF_WLIST_DIRS:FUZZ -c -ic -v -H \"$UA\" -u $URL/FUZZ $FILTERS $recursion -o $JSON_RSLTS_PATH -of json" "${ENUMLOGFILE/.log/-dirs-${WEB_PORT}.log}"
  separator

  JSON_RSLTS_PATH_2="${ENUMLOGFILE/.log/-dirs-2-${WEB_PORT}.json}"
  cmd "ffuf -w $FFUF_WLIST_DIRS_2:FUZZ -c -ic -v -H \"$UA\" -u $URL/FUZZ $FILTERS $recursion -o $JSON_RSLTS_PATH_2 -of json" "${ENUMLOGFILE/.log/-dirs-2-${WEB_PORT}.log}"
  separator

  # Parse found directories
  ask "Search files in found dirs ? (y/N):" choice
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then

    # collect dirs
    FOUND_DIRS=()
    extract_dirs

    JSON_RSLTS_PATH=$JSON_RSLTS_PATH_2
    extract_dirs

    # rm duplicates
    declare -A unique_dirs
    for dir in "${FOUND_DIRS[@]}"; do
      unique_dirs["$dir"]=1
    done
    FOUND_DIRS=("${!unique_dirs[@]}")  # Convert keys to array

    separator
    for dir in "${FOUND_DIRS[@]}"; do
      dir="${dir%/}"
      echo "-> $dir"
    done
    separator

    FILES_OUTFILE="${ENUMLOGFILE/.log/-files-${WEB_PORT}.log}"
    echo '' > $FILES_OUTFILE
    ffuf -w "$FFUF_WLIST_FILES":FUZZ -u "$URL/FUZZ" -H "$UA" -c -ic -v | tee "$FILES_OUTFILE"

    for dir in "${FOUND_DIRS[@]}"; do

      # skip to check $URL/FUZZ as was checked above
      if [[ "$dir" == "$URL" ]]; then
        continue
      fi

      separator
      dir="${dir%/}"
      echo -e "${GREEN}Searching files in directory: $dir${NC}" | tee -a "$FILES_OUTFILE"
      ffuf -w "$FFUF_WLIST_FILES":FUZZ -u "$dir/FUZZ" -H "$UA" -c -ic -v | tee -a "$FILES_OUTFILE"
    done
  fi

fi

# ----------------------------------------------------------------------------------------------------------------------
# enum parameters
# TODO: $index -> $path
ask "[ffuf] enum $URL/\$index?FUZZ=1 parameter ? (y/N):" choice
if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
  separator
  echo -e "${GREEN}-----------> PARAMS${NC}"
  ask "\$index path: e.g. index.php; default is empty" index

  # get filters
  tail -n 20 "$FFUF_WLIST_PARAMS" > "$BASELINE_TMP_WRDLST"
  cmdstr="ffuf -w $BASELINE_TMP_WRDLST:FUZZ -u \"$URL/$index?FUZZ=1\" -ic -H \"$UA\" -o $BASELINE_OUTFILE -of json"
  FILTERS=""
  generate_filters "$cmdstr"

  cmd "ffuf -w $FFUF_WLIST_PARAMS:FUZZ -u \"${URL}/${index}?FUZZ=1\" -c -ic -v -H \"$UA\" $FILTERS" "${ENUMLOGFILE/.log/-params-${WEB_PORT}.log}"
fi

# TODO detect api url or virtualhost from results above and enumerate API endpoints
#API_WLIST="/usr/share/seclists/Discovery/Web-Content/api-endpoints.txt"
#read -p "ffuf: enum API endpoints? (y/N): " choice
#if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
#    ffuf -w "$API_WLIST":FUZZ -u "$URL/api/FUZZ" -H "$UA" -o "$OUTDIR/enum_ffuf_api_output.log"
#fi

# TODO collect detected parameters from results above and check for LFI or/and RFI
#ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u "$URL/ilf_admin/index.php?log=FUZZ" -fs 2046

tip "check for $URL/.git and other subdomains AND use 'git-dumper <URL> <DIR>'"
tip "fuzz HTTP Headers"
