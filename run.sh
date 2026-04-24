#!/bin/bash
# ============================================================
#  run.sh
#  Live WebRTC/STUN capture — extracts PEER IPs in real time,
#  auto-skips STUN servers and XOR-MAPPED-ADDRESS (your own
#  public IP), then queries ipinfo.io for each new peer found.
#
#  Usage:
#    ./run.sh [OPTIONS]
#
#  Options:
#    -i <iface>    Network interface to capture on  (default: eth0)
#    -e <file>     Exclusion list (.txt or .json)   (optional)
#    -t <sec>      Auto-stop after N seconds        (default: 0 = forever)
#    -h            Show this help
#
#  Exclusion file formats
#  ──────────────────────
#  TXT  — one IP or prefix per line; lines starting with # are comments
#    # Google STUN servers
#    74.125.
#    8.8.8.8
#
#  JSON — array under the key "excluded"
#    { "excluded": ["74.125.", "8.8.8.8"] }
# ============================================================

# ── Defaults ─────────────────────────────────────────────────
INTERFACE="eth0"
EXCL_FILE=""
CAPTURE_DURATION=0

# Always-excluded prefixes (RFC-1918, loopback, multicast …)
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
${BOLD}run.sh${NC} — Live WebRTC peer IP extractor + ipinfo lookup

Usage:
  ./run.sh [OPTIONS]

Options:
  -i <iface>   Interface to capture on           (default: eth0)
  -e <file>    Exclusion list (.txt or .json)     (optional)
  -t <sec>     Auto-stop after N seconds          (default: 0 = unlimited)
  -h           Show this help

How exclusions work (layered):
  1. Built-in : all private/loopback/multicast ranges — always applied
  2. File     : your -e file (prefixes or exact IPs)
  3. Auto     : XOR-MAPPED-ADDRESS = your own public IP  → excluded
  4. Auto     : destination of your first STUN packet    → STUN server, excluded

Exclusion file — TXT:
  # comment
  74.125.         <- prefix match (entire range)
  8.8.8.8         <- exact match

Exclusion file — JSON:
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
        *)  # .txt or anything else
            while IFS= read -r line; do
                line="${line%%#*}"       # strip inline comments
                line="${line//[[:space:]]/}"  # strip whitespace
                [[ -n "$line" ]] && FILE_EXCLUDED+=("$line")
            done < "$file"
            ;;
    esac

    log "Loaded ${#FILE_EXCLUDED[@]} exclusion entries from: $file"
}

[[ -n "$EXCL_FILE" ]] && load_exclusion_file "$EXCL_FILE"

# Merge built-in + file exclusions
ALL_EXCLUDED=("${BUILTIN_EXCLUDED[@]}" "${FILE_EXCLUDED[@]}")

# ── Runtime state ─────────────────────────────────────────────
SEEN_PEERS=()           # IPs we have already queried
STUN_SERVERS=()         # Auto-detected STUN server IPs
MY_PUBLIC_IP=""         # XOR-MAPPED-ADDRESS = our own external IP

FIFO="/tmp/stun_fifo_$$"
mkfifo "$FIFO"

# ── Cleanup / summary ─────────────────────────────────────────
cleanup() {
    echo ""
    warn "Stopping capture…"
    kill "$TSHARK_PID" 2>/dev/null
    rm -f "$FIFO"
    echo ""
    echo -e "${BOLD}══════════════ Session summary ══════════════${NC}"
    echo -e "  My public IP (excluded) : ${CYAN}${MY_PUBLIC_IP:-not seen}${NC}"
    echo -e "  STUN servers (excluded) : ${#STUN_SERVERS[@]}"
    for s in "${STUN_SERVERS[@]}"; do echo "    • $s"; done
    echo -e "  Peers discovered        : ${#SEEN_PEERS[@]}"
    for p in "${SEEN_PEERS[@]}"; do echo "    • $p"; done
    echo -e "${BOLD}═════════════════════════════════════════════${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Dependency check ──────────────────────────────────────────
for cmd in tshark curl; do
    command -v "$cmd" &>/dev/null || {
        err "$cmd not found. Install: sudo apt install $cmd"
        exit 1
    }
done

# ── Exclusion helpers ─────────────────────────────────────────

# Return 0 (true) if $1 should be skipped
is_excluded() {
    local ip="$1"
    # Static list
    for excl in "${ALL_EXCLUDED[@]}"; do
        [[ "$ip" == "$excl"* ]] && return 0
    done
    # Our own public IP
    [[ -n "$MY_PUBLIC_IP" && "$ip" == "$MY_PUBLIC_IP" ]] && return 0
    # Auto-detected STUN servers
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

# ── ipinfo.io lookup ──────────────────────────────────────────
lookup_ip() {
    local ip="$1"
    SEEN_PEERS+=("$ip")

    echo ""
    ok "Peer found → ${YELLOW}${BOLD}${ip}${NC}"

    # ----- the curl that is the point of the exercise -----
    local response
    response=$(curl -s --max-time 6 "https://ipinfo.io/${ip}/json")
    # ------------------------------------------------------

    if [[ -z "$response" ]]; then
        warn "ipinfo.io returned no data for ${ip}"
        return
    fi

    # Parse fields with grep (no jq needed)
    local org city region country hostname bogon
    org=$(     echo "$response" | grep -oP '"org"\s*:\s*"\K[^"]+')
    city=$(    echo "$response" | grep -oP '"city"\s*:\s*"\K[^"]+')
    region=$(  echo "$response" | grep -oP '"region"\s*:\s*"\K[^"]+')
    country=$( echo "$response" | grep -oP '"country"\s*:\s*"\K[^"]+')
    hostname=$(echo "$response" | grep -oP '"hostname"\s*:\s*"\K[^"]+')
    bogon=$(   echo "$response" | grep -oP '"bogon"\s*:\s*\K(true|false)')

    echo -e "  IP       : ${YELLOW}${ip}${NC}"
    [[ "$bogon" == "true" ]] \
        && echo -e "  ${RED}⚠  BOGON (private/reserved — shouldn't appear here)${NC}"
    [[ -n "$hostname" ]] && echo "  Hostname : $hostname"
    [[ -n "$org"      ]] && echo "  Org      : $org"
    [[ -n "$city"     ]] && echo "  Location : ${city}, ${region}, ${country}"
    echo    "  Raw JSON : $response"
    echo    "────────────────────────────────────────────────"
}

# ── Banner ────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ╔═════════════════════════════════════════╗"
echo "  ║   WebRTC / STUN Live Peer IP Scanner    ║"
echo "  ╚═════════════════════════════════════════╝"
echo -e "${NC}"
log "Interface        : ${YELLOW}${INTERFACE}${NC}"
log "Exclusion entries: ${#ALL_EXCLUDED[@]}  (built-in + file)"
log "Auto-stop        : ${CAPTURE_DURATION}s  (0 = unlimited)"
log "Waiting for STUN traffic — start your WebRTC call now…"
echo "═══════════════════════════════════════════════"

# ── Launch tshark ─────────────────────────────────────────────
#
#  Fields:
#    ip.src                — source IP of every matched packet
#    ip.dst                — destination IP
#    stun.xor_mapped_address — the XOR-MAPPED-ADDRESS attribute:
#                             = our own public IP echoed by the STUN server
#                             NOT the peer; we exclude this
#    stun.att.ipv4         — raw MAPPED-ADDRESS or PEER-ADDRESS attribute:
#                             may contain peer reflexive candidate IP
#
#  Filter: only STUN packets (covers Binding Request/Response,
#          which is the entire ICE/STUN negotiation phase).
#          Once media flows over DTLS/SRTP we already have the peer IP.

DURATION_FLAG=()
(( CAPTURE_DURATION > 0 )) && DURATION_FLAG=(-a "duration:${CAPTURE_DURATION}")

tshark \
    -i "$INTERFACE" \
    -l \
    "${DURATION_FLAG[@]}" \
    -Y  "stun" \
    -T  fields \
    -e  ip.src \
    -e  ip.dst \
    -e  stun.xor_mapped_address \
    -e  stun.att.ipv4 \
    -E  separator="|" \
    > "$FIFO" 2>/dev/null &

TSHARK_PID=$!
log "tshark running (PID ${TSHARK_PID})"
echo ""

# ── Main loop ─────────────────────────────────────────────────
while IFS='|' read -r src dst xor_mapped stun_att; do

    # ── 1. Capture our own public IP from XOR-MAPPED-ADDRESS ──────
    #       The STUN server puts our external IP here in its
    #       Binding Response. Save it once; exclude from peer lookups.
    if [[ -n "$xor_mapped" && -z "$MY_PUBLIC_IP" ]]; then
        MY_PUBLIC_IP="$xor_mapped"
        log "My public IP detected (XOR-MAPPED): ${CYAN}${MY_PUBLIC_IP}${NC} — excluded"
    fi

    # ── 2. Auto-detect STUN server IP ────────────────────────────
    #       Heuristic: the dst of a packet whose src matches our
    #       public IP (or before we know it, the first external dst
    #       we send a STUN Binding Request to) is the STUN server.
    if [[ -n "$dst" ]] && ! already_stun "$dst"; then
        # If src is our public IP, dst is definitely the STUN server
        if [[ "$src" == "$MY_PUBLIC_IP" ]]; then
            STUN_SERVERS+=("$dst")
            log "STUN server identified: ${CYAN}${dst}${NC} — excluded"
        fi
    fi

    # ── 3. Collect peer IP candidates ────────────────────────────
    #       Priority:
    #         • stun.att.ipv4  — explicit mapped/peer-reflexive attribute
    #         • ip.src / ip.dst — actual packet endpoints
    #
    #       We do NOT use xor_mapped (= our own IP, already excluded).

    candidates=()
    [[ -n "$stun_att" ]] && candidates+=("$stun_att")
    [[ -n "$src"      ]] && candidates+=("$src")
    [[ -n "$dst"      ]] && candidates+=("$dst")

    for ip in "${candidates[@]}"; do
        # Basic IPv4 sanity check
        [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || continue

        is_excluded  "$ip" && continue
        already_seen "$ip" && continue

        # new, public, non-STUN-server IP → this is the peer
        lookup_ip "$ip"
    done

done < "$FIFO"

# tshark exited naturally (duration flag)
cleanup