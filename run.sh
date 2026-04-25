#!/bin/bash
# ============================================================
#  run.sh
#  Live WebRTC/STUN capture - extracts PEER IPs in real time,
#  auto-skips STUN servers and our own public IP (detected at
#  startup via ipinfo.io), then queries ipinfo.io for each new
#  peer found.
#
#  Usage:
#    sudo ./run.sh [OPTIONS]
#
#  Options:
#    -i <iface>   Network interface to capture on  (default: eth0)
#    -e <file>    Exclusion list (.txt or .json)   (optional)
#    -t <sec>     Auto-stop after N seconds        (default: 0 = forever)
#    -h           Show this help
#
#  Fields used from tshark:
#    ip.src        - source IP of each STUN packet
#    ip.dst        - destination IP of each STUN packet
#    stun.att.ipv4 - mapped-address attribute (peer reflexive candidate)
#
#  NOTE: stun.xor_mapped_address and stun.att.xor_mapped_address are NOT
#        valid tshark field names. Our public IP is detected via ipinfo.io
#        at startup instead.
#
#  Exclusion file formats
#  ----------------------
#  TXT  - one IP or prefix per line; lines starting with # are comments
#    # Google STUN servers
#    74.125.
#    8.8.8.8
#
#  JSON - array under the key "excluded"
#    { "excluded": ["74.125.", "8.8.8.8"] }
# ============================================================

# ── Defaults ─────────────────────────────────────────────────
INTERFACE="eth0"
EXCL_FILE=""
CAPTURE_DURATION=0

# ── Built-in exclusions (private/reserved ranges) ─────────────
BUILTIN_EXCLUDED=(
    "0.0.0.0"
    "127."
    "10."
    "172.16."  "172.17."  "172.18."  "172.19."
    "172.20."  "172.21."  "172.22."  "172.23."
    "172.24."  "172.25."  "172.26."  "172.27."
    "172.28."  "172.29."  "172.30."  "172.31."
    "192.168."
    "169.254."
    "224."  "225."  "226."  "227."  "228."  "229."
    "230."  "231."  "232."  "233."  "234."  "235."
    "255.255.255.255"
    "::1"
)

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

# ── Help ─────────────────────────────────────────────────────
usage() {
cat <<EOF
run.sh - Live WebRTC peer IP extractor + ipinfo lookup

Usage:
  sudo $0 [OPTIONS]

Options:
  -i <iface>   Interface to capture on           (default: eth0)
  -e <file>    Exclusion list (.txt or .json)     (optional)
  -t <sec>     Auto-stop after N seconds          (default: 0 = unlimited)
  -h           Show this help

How exclusions work (layered):
  1. Built-in : all private/loopback/multicast ranges - always applied
  2. File     : your -e file (prefixes or exact IPs)
  3. Auto     : our public IP detected via ipinfo.io at startup - excluded
  4. Auto     : destination of our first STUN packet - STUN server, excluded

Exclusion file - TXT:
  # comment
  74.125.         <- prefix match (entire range)
  8.8.8.8         <- exact match

Exclusion file - JSON:
  { "excluded": ["74.125.", "8.8.8.8"] }
EOF
exit 0
}

# ── Parse arguments ───────────────────────────────────────────
while getopts ":i:e:t:h" opt; do
    case $opt in
        i) INTERFACE="$OPTARG" ;;
        e) EXCL_FILE="$OPTARG" ;;
        t) CAPTURE_DURATION="$OPTARG" ;;
        h) usage ;;
        :) err "Option -$OPTARG requires an argument."; exit 1 ;;
       \?) err "Unknown option: -$OPTARG"; exit 1 ;;
    esac
done

# ── Load exclusion file ───────────────────────────────────────
FILE_EXCLUDED=()

load_exclusion_file() {
    local file="$1"
    [[ ! -f "$file" ]] && { err "Exclusion file not found: $file"; exit 1; }

    case "${file,,}" in
        *.json)
            command -v python3 &>/dev/null || { err "python3 required for JSON parsing."; exit 1; }
            mapfile -t FILE_EXCLUDED < <(
                python3 -c "
import json, sys
try:
    data = json.load(open('$file'))
    for ip in data.get('excluded', []):
        print(ip)
except Exception as ex:
    sys.exit(str(ex))
"
            )
            ;;
        *)
            while IFS= read -r line; do
                line="${line%%#*}"
                line="${line//[[:space:]]/}"
                [[ -n "$line" ]] && FILE_EXCLUDED+=("$line")
            done < "$file"
            ;;
    esac

    log "Loaded ${#FILE_EXCLUDED[@]} exclusion entries from: $file"
}

[[ -n "$EXCL_FILE" ]] && load_exclusion_file "$EXCL_FILE"

ALL_EXCLUDED=("${BUILTIN_EXCLUDED[@]}" "${FILE_EXCLUDED[@]}")

# ── Runtime state ─────────────────────────────────────────────
SEEN_PEERS=()
STUN_SERVERS=()
MY_PUBLIC_IP=""

# Used for stderr deduplication - associative array acts as a set
declare -A SEEN_ERR_LINES

# ── Dependency check ──────────────────────────────────────────
for cmd in tshark curl; do
    command -v "$cmd" &>/dev/null || {
        err "$cmd not found. Install: sudo apt install $cmd"
        exit 1
    }
done

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  +=========================================+"
echo "  |   WebRTC / STUN Live Peer IP Scanner   |"
echo "  +=========================================+"
echo -e "${NC}"
log "Interface        : ${YELLOW}${INTERFACE}${NC}"
log "Exclusion entries: ${#ALL_EXCLUDED[@]}  (built-in + file)"
log "Auto-stop        : ${CAPTURE_DURATION}s  (0 = unlimited)"
echo "================================================"
echo ""

# ── Step 1: Detect our own public IP via ipinfo.io ────────────
# We do this BEFORE starting the capture so our public IP is
# excluded from the very first packet.
#
# Why is this needed?
#   STUN Binding Responses contain our public IP in the
#   mapped-address field. That response has:
#     ip.src = STUN server
#     ip.dst = OUR public IP  <-- would be mistaken for a peer
#   By knowing our public IP upfront we exclude it immediately.

log "Detecting this machine's public IP via ipinfo.io..."

MY_INFO=$(curl -s --max-time 6 "https://ipinfo.io/json")

if [[ -n "$MY_INFO" ]]; then
    MY_PUBLIC_IP=$(echo "$MY_INFO" | grep -oP '"ip"\s*:\s*"\K[^"]+')
    MY_CITY=$(     echo "$MY_INFO" | grep -oP '"city"\s*:\s*"\K[^"]+')
    MY_COUNTRY=$(  echo "$MY_INFO" | grep -oP '"country"\s*:\s*"\K[^"]+')
    MY_ORG=$(      echo "$MY_INFO" | grep -oP '"org"\s*:\s*"\K[^"]+')
    ok "My public IP : ${YELLOW}${MY_PUBLIC_IP}${NC} (${MY_CITY}, ${MY_COUNTRY}) - excluded"
    ok "My org       : ${MY_ORG}"
else
    warn "Could not reach ipinfo.io to detect public IP."
    warn "Your public IP may appear in results - add it manually via -e exclusion file."
fi

echo ""

# ── Cleanup / summary ─────────────────────────────────────────
cleanup() {
    echo ""
    warn "Stopping capture..."
    kill "$TSHARK_PID" 2>/dev/null
    wait "$TSHARK_PID" 2>/dev/null
    rm -f "$FIFO" "$TSHARK_STDERR"
    echo ""
    echo -e "${BOLD}============= Session summary ===============${NC}"
    echo -e "  My public IP (excluded) : ${CYAN}${MY_PUBLIC_IP:-not detected}${NC}"
    echo -e "  STUN servers (excluded) : ${#STUN_SERVERS[@]}"
    for s in "${STUN_SERVERS[@]}"; do echo "    - $s"; done
    echo -e "  Peers discovered        : ${#SEEN_PEERS[@]}"
    for p in "${SEEN_PEERS[@]}"; do echo "    - $p"; done
    echo -e "${BOLD}=============================================${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Helpers ───────────────────────────────────────────────────

# Return 0 (true) if IP matches any built-in private range
is_private_ip() {
    local ip="$1"
    for excl in "${BUILTIN_EXCLUDED[@]}"; do
        [[ "$ip" == "$excl"* ]] && return 0
    done
    return 1
}

# Return 0 (true) if IP should be excluded entirely
is_excluded() {
    local ip="$1"
    for excl in "${ALL_EXCLUDED[@]}"; do
        [[ "$ip" == "$excl"* ]] && return 0
    done
    [[ -n "$MY_PUBLIC_IP" && "$ip" == "$MY_PUBLIC_IP" ]] && return 0
    for srv in "${STUN_SERVERS[@]}"; do
        [[ "$ip" == "$srv" ]] && return 0
    done
    return 1
}

already_seen() {
    local ip="$1"
    for p in "${SEEN_PEERS[@]}"; do [[ "$ip" == "$p" ]] && return 0; done
    return 1
}

already_stun() {
    local ip="$1"
    for s in "${STUN_SERVERS[@]}"; do [[ "$ip" == "$s" ]] && return 0; done
    return 1
}

is_valid_ipv4() {
    [[ "$1" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

# ── ipinfo.io lookup ──────────────────────────────────────────
lookup_ip() {
    local ip="$1"
    SEEN_PEERS+=("$ip")

    echo ""
    ok "Peer found -> ${YELLOW}${BOLD}${ip}${NC}"

    local response
    response=$(curl -s --max-time 6 "https://ipinfo.io/${ip}/json")

    if [[ -z "$response" ]]; then
        warn "ipinfo.io returned no data for ${ip}"
        return
    fi

    local org city region country hostname bogon
    org=$(     echo "$response" | grep -oP '"org"\s*:\s*"\K[^"]+')
    city=$(    echo "$response" | grep -oP '"city"\s*:\s*"\K[^"]+')
    region=$(  echo "$response" | grep -oP '"region"\s*:\s*"\K[^"]+')
    country=$( echo "$response" | grep -oP '"country"\s*:\s*"\K[^"]+')
    hostname=$(echo "$response" | grep -oP '"hostname"\s*:\s*"\K[^"]+')
    bogon=$(   echo "$response" | grep -oP '"bogon"\s*:\s*\K(true|false)')

    echo -e "  IP       : ${YELLOW}${ip}${NC}"
    [[ "$bogon" == "true" ]] && echo -e "  ${RED}WARNING: BOGON (private/reserved)${NC}"
    [[ -n "$hostname" ]] && echo "  Hostname : $hostname"
    [[ -n "$org"      ]] && echo "  Org      : $org"
    [[ -n "$city"     ]] && echo "  Location : ${city}, ${region}, ${country}"
    echo    "  Raw JSON : $response"
    echo    "------------------------------------------------"
}

# ── Process one line of tshark output ─────────────────────────
# tshark outputs 3 pipe-separated fields per line:
#   ip.src | ip.dst | stun.att.ipv4
#
# STUN server detection logic:
#   A STUN Binding Request goes FROM us (private IP) TO the STUN server.
#   So when src is a private IP and dst is a new public IP,
#   that dst is the STUN server.
process_line() {
    local src="$1" dst="$2" stun_att="$3"

    # STUN server detection:
    # If src is our private IP and dst is a new public IP we haven't
    # seen yet, we are sending a Binding Request -> dst is the STUN server.
    if [[ -n "$src" && -n "$dst" ]]; then
        if is_private_ip "$src" && is_valid_ipv4 "$dst" && \
           ! already_stun "$dst" && ! is_excluded "$dst"; then
            STUN_SERVERS+=("$dst")
            log "STUN server identified: ${CYAN}${dst}${NC} (we sent a request to it) - excluded"
        fi
    fi

    # Peer IP candidates:
    #   stun.att.ipv4 first (explicit peer-reflexive attribute)
    #   then ip.src and ip.dst (actual packet endpoints)
    local candidates=()
    [[ -n "$stun_att" ]] && candidates+=("$stun_att")
    [[ -n "$src"      ]] && candidates+=("$src")
    [[ -n "$dst"      ]] && candidates+=("$dst")

    for ip in "${candidates[@]}"; do
        is_valid_ipv4 "$ip" || continue
        is_excluded   "$ip" && continue
        already_seen  "$ip" && continue
        lookup_ip "$ip"
    done
}

# ── Print tshark stderr - deduplicated ────────────────────────
# tshark writes "Capturing on 'eth0'" repeatedly to stderr.
# We use an associative array as a set to track lines we have
# already printed and silently drop any repeat.
# Real errors (bad field names, permission issues) are always
# new lines so they still get through.
print_stderr_once() {
    local line
    # Read all available lines from the stderr temp file without blocking
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Only print if we have never seen this exact line before
        if [[ -z "${SEEN_ERR_LINES[$line]+x}" ]]; then
            SEEN_ERR_LINES["$line"]=1
            echo -e "${CYAN}[tshark]${NC} $line"
        fi
    done < "$TSHARK_STDERR"
    # Clear the file so we don't re-read old lines next poll
    > "$TSHARK_STDERR"
}

# ── Launch tshark ─────────────────────────────────────────────
FIFO="/tmp/stun_fifo_$$"
TSHARK_STDERR="/tmp/stun_stderr_$$"
mkfifo "$FIFO"
touch "$TSHARK_STDERR"

DURATION_FLAG=()
(( CAPTURE_DURATION > 0 )) && DURATION_FLAG=(-a "duration:${CAPTURE_DURATION}")

# Only 3 fields - all confirmed valid in the Wireshark field reference:
#   ip.src, ip.dst, stun.att.ipv4
tshark \
    -i  "$INTERFACE" \
    -l \
    "${DURATION_FLAG[@]}" \
    -Y  "stun" \
    -T  fields \
    -e  ip.src \
    -e  ip.dst \
    -e  stun.att.ipv4 \
    -E  separator="|" \
    > "$FIFO" 2>"$TSHARK_STDERR" &

TSHARK_PID=$!

# Give tshark a moment to start and fail fast if something is wrong
sleep 0.8

if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
    err "tshark exited immediately."
    err "tshark said: $(cat "$TSHARK_STDERR")"
    rm -f "$FIFO" "$TSHARK_STDERR"
    exit 1
fi

log "tshark running (PID ${TSHARK_PID})"
log "Capture running - start your WebRTC call now..."
echo ""

# ── Main loop ─────────────────────────────────────────────────
while IFS='|' read -r src dst stun_att; do

    # Print any new tshark stderr lines (deduplicated)
    print_stderr_once

    process_line "$src" "$dst" "$stun_att"

done < "$FIFO"

# tshark exited naturally (duration flag)
cleanup