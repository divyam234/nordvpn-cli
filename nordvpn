#!/bin/bash

# nordlynx-nordvpn.sh - A script to manage NordVPN (NordLynx/WireGuard) connection on a host system
# based on the docker-nordlynx entrypoint and down scripts, with Tailscale support.
#
# Features:
# - CLI interface (up, down, reset, status)
# - Reads configuration ONLY from JSON file (~/.config/nordlynx-cli/config.json or /etc/nordlynx-cli/config.json)
# - Supports command-line flags to override config file settings.
# - Server selection via API based on country_code and category (country_code takes precedence)
# - Disables IPv6 handling and firewall rules
# - Manages necessary routes and IPTables firewall rules (IPv4 kill-switch)
# - Cleans up rules and temporary hook scripts on disconnection.
# - Enhanced 'status' command with less verbosity and color.
# - Removed temporary network rules for API access (Potential issues if firewall blocks API on host).
#
# Dependencies: curl, jq, wg, wg-quick, ip, iptables, dig
# Requires root privileges.

# --- Configuration File Paths ---
USER_CONFIG_FILE="$HOME/.config/nordlynx-cli/config.json"
SYSTEM_CONFIG_FILE="/etc/nordlynx-cli/config.json"

# --- Default WireGuard settings (used if not specified in config file or CLI flags) ---
DEFAULT_ADDRESS="10.5.0.2/32"
DEFAULT_DNS="103.86.96.100, 103.86.99.100" # NordVPN DNS servers (IPv4)
DEFAULT_ALLOWED_IPS="0.0.0.0/0"      # Route all IPv4 traffic through VPN (full tunnel)
DEFAULT_PERSISTENT_KEEPALIVE="25"
DEFAULT_LISTEN_PORT="51820"
DEFAULT_PHYS_IFACE="eth0"
DEFAULT_WG_IFACE="wg0"

# --- Variables to hold configuration values (will be loaded from config file, overridden by CLI) ---
# Basic Configuration
PRIVATE_KEY=""
FILE__PRIVATE_KEY=""
TOKEN=""
COUNTRY_CODE=""
CATEGORY=""
RECONNECT="infinity" # Default from original script, though not fully implemented in this host version
FIX_TAILSCALE="false" # New flag for conditional Tailscale support

# Advanced Configuration
PHYS_IFACE="" # Will be populated from config or default
WG_IFACE="" # Will be populated from config or default
NET_LOCAL="" # Will be loaded from config, potentially modified for Tailscale
ALLOW_LIST="" # Not implemented in this version's routing/firewall logic

# WireGuard Parameters
LISTEN_PORT=""
ADDRESS=""
DNS=""
MTU=""
TABLE=""
PRE_UP=""
POST_UP=""
PRE_DOWN=""
POST_DOWN=""
ALLOWED_IPS=""
PERSISTENT_KEEPALIVE=""

# Manual Server Configuration (overrides API selection if both set via config or CLI)
ENDPOINT=""
PUBLIC_KEY=""


# Server Selection Results (populated during 'up' if API is used)
API_SELECTED_ENDPOINT=""
API_SELECTED_PUBLIC_KEY=""

# --- Temporary Hook Script Paths ---
# Stored globally so they can be cleaned up on down
TEMP_POST_UP_SCRIPT=""
TEMP_PRE_DOWN_SCRIPT=""


# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Helper Functions ---

usage() {
    echo -e "${BLUE}Usage: $(basename "$0") <command> [options]${NC}"
    echo ""
    echo -e "${BLUE}Commands:${NC}"
    echo "  up      Connect to NordVPN using NordLynx/WireGuard"
    echo "  down    Disconnect from NordVPN and clean up rules"
    echo "  reset   Disconnect and then reconnect"
    echo "  status  Show the current connection status and firewall rules"
    echo ""
    echo -e "${BLUE}Configuration is loaded from JSON file, overridden by CLI flags:${NC}"
    echo "  Config Files: 1. ${USER_CONFIG_FILE} 2. ${SYSTEM_CONFIG_FILE}"
    echo ""
    echo -e "${BLUE}CLI Options (override config file settings):${NC}"
    echo "  --private-key <key>       : Your WireGuard private key"
    echo "  --file-private-key <path> : Path to a file containing your private key"
    echo "  --token <token>           : Your NordVPN API token"
    echo "  --country-code <code>     : NordVPN country code (e.g., us, gb)"
    echo "  --category <cat>          : NordVPN server category (standard, p2p, double, obfuscated, onion)"
    echo "  --interface <iface>       : Physical network interface (default: ${DEFAULT_PHYS_IFACE})"
    echo "  --wg-interface <iface>    : WireGuard interface name (default: ${DEFAULT_WG_IFACE})"
    echo "  --net-local <cidrs>       : Comma/semicolon separated local networks (e.g., 192.168.1.0/24;10.0.0.0/8)"
    echo "  --listen-port <port>      : WireGuard listen port (default: ${DEFAULT_LISTEN_PORT})"
    echo "  --address <ip/cidr>       : Client tunnel IP address(es) (default: ${DEFAULT_ADDRESS})"
    echo "  --dns <ips>               : DNS server IP(s) (default: ${DEFAULT_DNS})"
    echo "  --mtu <value>             : WireGuard MTU"
    echo "  --table <table>           : WireGuard routing table"
    echo "  --pre-up <cmd>            : wg-quick PreUp command/script"
    echo "  --post-up <cmd>           : wg-quick PostUp command/script"
    echo "  --pre-down <cmd>          : wg-quick PreDown command/script"
    echo "  --post-down <cmd>         : wg-quick PostDown command/script"
    echo "  --allowed-ips <cidrs>     : WireGuard AllowedIPs (default: ${DEFAULT_ALLOWED_IPS})"
    echo "  --persistent-keepalive <sec>: WireGuard persistent keepalive (default: ${DEFAULT_PERSISTENT_KEEPALIVE})"
    echo "  --endpoint <ip:port>      : Manual server endpoint"
    echo "  --public-key <key>        : Manual server public key"
    echo ""
    echo -e "${BLUE}Examples:${NC}"
    echo "  # Connect using config file"
    echo "  sudo $(basename "$0") up"
    echo ""
    echo "  # Connect to a German server, overriding config"
    echo "  sudo $(basename "$0") up --country-code de"
    echo ""
    echo "  # Connect using a token and enable Tailscale fixes"
    echo "  sudo $(basename "$0") up --token \"your_token\""
    echo ""
    echo "  # Disconnect"
    echo "  sudo $(basename "$0") down"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] This script must be run as root${NC}" >&2
        exit 1
    fi
}

check_dependencies() {
    local deps=("curl" "jq" "wg" "wg-quick" "ip" "iptables" "dig")
    local missing_deps=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing_deps[*]}${NC}" >&2
        echo -e "${RED}[ERROR] Please install them using your distribution's package manager (e.g., apt, dnf, pacman)${NC}" >&2
        exit 1
    fi
}

# Function to load configuration from file (JSON format)
load_config() {
    local config_file=""
    if [[ -f "${USER_CONFIG_FILE}" ]]; then
        config_file="${USER_CONFIG_FILE}"
        # echo -e "${BLUE}[INFO] Loading configuration from user file: ${config_file}${NC}"
    elif [[ -f "${SYSTEM_CONFIG_FILE}" ]]; then
        config_file="${SYSTEM_CONFIG_FILE}"
        # echo -e "${BLUE}[INFO] Loading configuration from system file: ${config_file}${NC}"
    else
        # echo -e "${YELLOW}[INFO] No configuration file found at ${USER_CONFIG_FILE} or ${SYSTEM_CONFIG_FILE}. Using defaults and CLI flags.${NC}"
        # Set defaults if no config file is found
        PHYS_IFACE="${DEFAULT_PHYS_IFACE}"
        WG_IFACE="${DEFAULT_WG_IFACE}"
        return 0 # No config file found, proceed with defaults and CLI parsing
    fi

    # Use jq to read values and populate global variables
    # Use `.` for object access and `// ""` for default empty string if key is missing
    # Basic Configuration
    PRIVATE_KEY=$(jq -r '.nordlynx.private_key // ""' "${config_file}")
    FILE__PRIVATE_KEY=$(jq -r '.nordlynx.file_private_key // ""' "${config_file}")
    TOKEN=$(jq -r '.nordlynx.token // ""' "${config_file}")
    COUNTRY_CODE=$(jq -r '.nordlynx.country_code // ""' "${config_file}")
    CATEGORY=$(jq -r '.nordlynx.category // ""' "${config_file}")
    RECONNECT=$(jq -r '.nordlynx.reconnect // "infinity"' "${config_file}")
    # Advanced Configuration
    PHYS_IFACE=$(jq -r '.nordlynx.interface // "'"${DEFAULT_PHYS_IFACE}"'"' "${config_file}")
    WG_IFACE=$(jq -r '.nordlynx.wg_interface // "'"${DEFAULT_WG_IFACE}"'"' "${config_file}")
    NET_LOCAL=$(jq -r '.nordlynx.net_local // ""' "${config_file}")
    ALLOW_LIST=$(jq -r '.nordlynx.allow_list // ""' "${config_file}") # Note: ALLOW_LIST not used in current firewall logic

    # WireGuard Parameters
    LISTEN_PORT=$(jq -r '.nordlynx.listen_port // ""' "${config_file}")
    ADDRESS=$(jq -r '.nordlynx.address // ""' "${config_file}")
    DNS=$(jq -r '.nordlynx.dns // ""' "${config_file}")
    MTU=$(jq -r '.nordlynx.mtu // ""' "${config_file}")
    TABLE=$(jq -r '.nordlynx.table // ""' "${config_file}")
    PRE_UP=$(jq -r '.nordlynx.pre_up // ""' "${config_file}")
    POST_UP=$(jq -r '.nordlynx.post_up // ""' "${config_file}")
    PRE_DOWN=$(jq -r '.nordlynx.pre_down // ""' "${config_file}")
    POST_DOWN=$(jq -r '.nordlynx.post_down // ""' "${config_file}")
    ALLOWED_IPS=$(jq -r '.nordlynx.allowed_ips // ""' "${config_file}")
    PERSISTENT_KEEPALIVE=$(jq -r '.nordlynx.persistent_keepalive // ""' "${config_file}")

    # Manual Server Configuration (overrides API selection if both set)
    ENDPOINT=$(jq -r '.nordlynx.endpoint // ""' "${config_file}")
    PUBLIC_KEY=$(jq -r '.nordlynx.public_key // ""' "${config_file}")

    echo -e "${GREEN}[SUCCESS] Configuration loaded from ${config_file}${NC}."
}

# Function to parse CLI flags and override config
parse_cli_flags() {
    echo -e "${BLUE}[INFO] Parsing command-line flags...${NC}"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --private-key)
                if [[ -n "$2" ]]; then PRIVATE_KEY="$2"; shift; fi; shift ;;
            --file-private-key)
                if [[ -n "$2" ]]; then FILE__PRIVATE_KEY="$2"; shift; fi; shift ;;
            --token)
                if [[ -n "$2" ]]; then TOKEN="$2"; shift; fi; shift ;;
            --country-code)
                if [[ -n "$2" ]]; then COUNTRY_CODE="$2"; shift; fi; shift ;;
            --category)
                if [[ -n "$2" ]]; then CATEGORY="$2"; shift; fi; shift ;;
            --interface)
                if [[ -n "$2" ]]; then PHYS_IFACE="$2"; shift; fi; shift ;;
            --wg-interface)
                if [[ -n "$2" ]]; then WG_IFACE="$2"; shift; fi; shift ;;
            --net-local)
                if [[ -n "$2" ]]; then NET_LOCAL="$2"; shift; fi; shift ;;
            --listen-port)
                if [[ -n "$2" ]]; then LISTEN_PORT="$2"; shift; fi; shift ;;
            --address)
                if [[ -n "$2" ]]; then ADDRESS="$2"; shift; fi; shift ;;
            --dns)
                if [[ -n "$2" ]]; then DNS="$2"; shift; fi; shift ;;
            --mtu)
                if [[ -n "$2" ]]; then MTU="$2"; shift; fi; shift ;;
            --table)
                if [[ -n "$2" ]]; then TABLE="$2"; shift; fi; shift ;;
            --pre-up)
                if [[ -n "$2" ]]; then PRE_UP="$2"; shift; fi; shift ;;
            --post-up)
                if [[ -n "$2" ]]; then POST_UP="$2"; shift; fi; shift ;;
            --pre-down)
                if [[ -n "$2" ]]; then PRE_DOWN="$2"; shift; fi; shift ;;
            --post-down)
                if [[ -n "$2" ]]; then POST_DOWN="$2"; shift; fi; shift ;;
            --allowed-ips)
                if [[ -n "$2" ]]; then ALLOWED_IPS="$2"; shift; fi; shift ;;
            --persistent-keepalive)
                if [[ -n "$2" ]]; then PERSISTENT_KEEPALIVE="$2"; shift; fi; shift ;;
            --endpoint)
                if [[ -n "$2" ]]; then ENDPOINT="$2"; shift; fi; shift ;;
            --public-key)
                if [[ -n "$2" ]]; then PUBLIC_KEY="$2"; shift; fi; shift ;;
            *)
                echo -e "${RED}[ERROR] Unknown option: $1${NC}" >&2
                usage
                ;;
        esac
    done
     echo -e "${GREEN}[SUCCESS] Command-line flags parsed.${NC}"
}


# Function to add temporary firewall rules allowing NordVPN API calls (IPv4 only)
# These are added *before* the main kill-switch and removed afterwards.
# NOTE: Removed as per user request. Potential issues if firewall blocks API access.
# add_tmp_net_rules() { ... }

# Function to remove temporary firewall rules (IPv4 only)
# NOTE: Removed as per user request. Potential issues if firewall blocks API access.
# del_tmp_net_rules() { ... }


# Function to set up persistent firewall rules (kill switch and necessary allows) (IPv4 only)
setup_firewall_rules() {
    echo -e "${BLUE}[INFO] Setting up IPTables firewall rules (IPv4 kill switch)${NC}"

    # Get the IP of the WireGuard server endpoint
    local wg_server_ip="${ENDPOINT%:*}" # Remove port
    if [[ -z "$wg_server_ip" ]]; then
         echo -e "${RED}[ERROR] WireGuard server IP is not set. Cannot set up firewall rules.${NC}" >&2
         return 1
    fi

    # --- IPTables (IPv4) ---
    echo -e "${BLUE}[INFO] Configuring iptables (IPv4)${NC}"

    # Create custom chains if they don't exist
    iptables -N NORDLYNX_OUT &>/dev/null || true
    iptables -N NORDLYNX_FWD &>/dev/null || true

    # Jump from OUTPUT and FORWARD chains to our custom chains (only if not already present)
    iptables -C OUTPUT -j NORDLYNX_OUT &>/dev/null || iptables -A OUTPUT -j NORDLYNX_OUT
    iptables -C FORWARD -j NORDLYNX_FWD &>/dev/null || iptables -A FORWARD -j NORDLYNX_FWD

    # Rules inside NORDLYNX_OUT chain
    # 1. Allow loopback traffic
    iptables -C NORDLYNX_OUT -o lo -j ACCEPT &>/dev/null || iptables -A NORDLYNX_OUT -o lo -j ACCEPT
    # 2. Allow traffic out the WG interface
    iptables -C NORDLYNX_OUT -o "${WG_IFACE}" -j ACCEPT &>/dev/null || iptables -A NORDLYNX_OUT -o "${WG_IFACE}" -j ACCEPT
    # 3. Allow traffic out the physical interface to the WG server endpoint (UDP 51820)
    iptables -C NORDLYNX_OUT -o "${PHYS_IFACE}" -d "${wg_server_ip}" -p udp --dport 51820 -j ACCEPT &>/dev/null || iptables -A NORDLYNX_OUT -o "${PHYS_IFACE}" -d "${wg_server_ip}" -p udp --dport 51820 -j ACCEPT
    # 4. Allow traffic out the physical interface to specified local networks
    if [[ -n "${NET_LOCAL}" ]]; then
         # Remove surrounding quotes if they exist
        local net_local_cleaned="${NET_LOCAL#\"}" # Remove leading quote
        net_local_cleaned="${net_local_cleaned%\"}" # Remove trailing quote
        for inet in ${net_local_cleaned//[;,]/ }; do
            echo -e "${BLUE}[INFO]   Allowing OUTPUT to local network ${inet} on ${PHYS_IFACE}${NC}"
            iptables -C NORDLYNX_OUT -o "${PHYS_IFACE}" -d "${inet}" -j ACCEPT &>/dev/null || iptables -A NORDLYNX_OUT -o "${PHYS_IFACE}" -d "${inet}" -j ACCEPT
        done
    fi
    # 5. Drop all other OUTPUT traffic (Kill Switch) - Add this as the last rule
    echo -e "${BLUE}[INFO]   Adding final DROP rule in NORDLYNX_OUT (Kill Switch)${NC}"
    # Check if the DROP rule exists, but be careful as position matters.
    # A simple check might not be enough. Flush and re-add is safer if this chain is only managed by this script.
    # For idempotency without flushing, we rely on the fact that appending adds to the end.
    # Let's just append if it's not there.
     if ! iptables -L NORDLYNX_OUT -n --line-numbers | grep -q "DROP"; then
         iptables -A NORDLYNX_OUT -j DROP
     fi


    # Rules inside NORDLYNX_FWD chain (for routing traffic originating elsewhere)
    # 1. Allow forwarding from WG interface to anywhere
    iptables -C NORDLYNX_FWD -i "${WG_IFACE}" -j ACCEPT &>/dev/null || iptables -A NORDLYNX_FWD -i "${WG_IFACE}" -j ACCEPT
     # 2. Allow forwarding from physical interface to local networks (if host is a router)
     if [[ -n "${NET_LOCAL}" ]]; then
         local net_local_cleaned="${NET_LOCAL#\"}"
        net_local_cleaned="${net_local_cleaned%\"}"
        for inet in ${net_local_cleaned//[;,]/ }; do
             echo -e "${BLUE}[INFO]   Allowing FORWARD to local network ${inet} on ${PHYS_IFACE}${NC}"
             iptables -C NORDLYNX_FWD -o "${PHYS_IFACE}" -d "${inet}" -j ACCEPT &>/dev/null || iptables -A NORDLYNX_FWD -o "${PHYS_IFACE}" -d "${inet}" -j ACCEPT
             echo -e "${BLUE}[INFO]   Allowing FORWARD from local network ${inet} on ${PHYS_IFACE}${NC}"
             iptables -C NORDLYNX_FWD -i "${PHYS_IFACE}" -s "${inet}" -j ACCEPT &>/dev/null || iptables -A NORDLYNX_FWD -i "${PHYS_IFACE}" -s "${inet}" -j ACCEPT
        done
    fi
    # 3. Drop all other FORWARD traffic (Kill Switch)
     echo -e "${BLUE}[INFO]   Adding final DROP rule in NORDLYNX_FWD (Kill Switch)${NC}"
     if ! iptables -L NORDLYNX_FWD -n --line-numbers | grep -q "DROP"; then
         iptables -A NORDLYNX_FWD -j DROP
     fi

    echo -e "${GREEN}[SUCCESS] IPTables firewall rules applied.${NC}"
}

# Function to add necessary routes (WG server, local networks) (IPv4 only)
setup_routes() {
    echo -e "${BLUE}[INFO] Setting up IPv4 routes${NC}"

    # Get default gateway on specified physical interface
    local gateway
    gateway="$(ip route show dev "${PHYS_IFACE}" | awk '/default/ { print $3; exit }')"

    if [[ -z "${gateway}" ]]; then
        echo -e "${RED}[ERROR] No default gateway found on interface ${PHYS_IFACE}. Cannot add static routes.${NC}" >&2
        return 1
    fi

    # Add route to WireGuard server IP via original gateway (prevents routing loop)
    local wg_server_ip="${ENDPOINT%:*}"
    if [[ -n "$wg_server_ip" ]]; then
         # Check if the route already exists
         if ! ip route show | grep -q "${wg_server_ip}.* via ${gateway}"; then
            echo -e "${BLUE}[INFO] Adding route to WireGuard server ${wg_server_ip} via ${gateway} on ${PHYS_IFACE}${NC}"
            ip route add "${wg_server_ip}" via "${gateway}" dev "${PHYS_IFACE}"
         else
             echo -e "${BLUE}[INFO] Route to WireGuard server ${wg_server_ip} already exists.${NC}"
         fi
    else
         echo -e "${YELLOW}[WARNING] WireGuard server IP not available. Cannot add specific route.${NC}" >&2
    fi


    # Add routes for specified local networks via original gateway
    if [[ -n "${NET_LOCAL}" ]]; then
        # Remove surrounding quotes if they exist
        local net_local_cleaned="${NET_LOCAL#\"}"
        net_local_cleaned="${net_local_cleaned%\"}"

        for inet in ${net_local_cleaned//[;,]/ }; do
            # Check if route already exists
            if ! ip route show | grep -q "${inet}.* via ${gateway}"; then
                echo -e "${BLUE}[INFO] Adding route to local network ${inet} via ${gateway} on ${PHYS_IFACE}${NC}"
                ip route add "${inet}" via "${gateway}" dev "${PHYS_IFACE}"
            else
                 echo -e "${BLUE}[INFO] Route to local network ${inet} already exists.${NC}"
            fi
        done
    fi
    echo -e "${GREEN}[SUCCESS] IPv4 routes applied.${NC}"
}


# Function to clean up all rules and routes added by this script (IPv4 only)
cleanup_rules() {
    echo -e "${BLUE}[INFO] Cleaning up firewall rules and routes...${NC}"

    # --- IPTables (IPv4) Cleanup ---
    echo -e "${BLUE}[INFO] Cleaning up iptables (IPv4)${NC}"
    # Remove jump rules first
    iptables -D OUTPUT -j NORDLYNX_OUT 2>/dev/null || true
    iptables -D FORWARD -j NORDLYNX_FWD 2>/dev/null || true

    # Flush custom chains
    iptables -F NORDLYNX_OUT 2>/dev/null || true
    iptables -F NORDLYNX_FWD 2>/dev/null || true

    # Delete custom chains
    iptables -X NORDLYNX_OUT 2>/dev/null || true
    iptables -X NORDLYNX_FWD 2>/dev/null || true

    # --- Route Cleanup ---
    echo -e "${BLUE}[INFO] Cleaning up routes${NC}"

    # Get default gateway (needed to specify the route to delete)
    local gateway
    gateway="$(ip route show dev "${PHYS_IFACE}" | awk '/default/ { print $3; exit }')"

    # Remove route to WireGuard server IP
    local wg_server_ip="${ENDPOINT%:*}"
     if [[ -n "$wg_server_ip" && -n "$gateway" ]]; then
         echo -e "${BLUE}[INFO] Removing route to WireGuard server ${wg_server_ip}${NC}"
        ip route del "${wg_server_ip}" via "${gateway}" dev "${PHYS_IFACE}" 2>/dev/null || true
     fi

    # Remove routes for local networks
    if [[ -n "${NET_LOCAL}" ]]; then # Check if NET_LOCAL was set at all
        local net_local_cleaned="${NET_LOCAL#\"}"
        net_local_cleaned="${net_local_cleaned%\"}"
        for inet in ${net_local_cleaned//[;,]/ }; do
            echo -e "${BLUE}[INFO] Removing route to local network ${inet}${NC}"
            ip route del "${inet}" via "${gateway}" dev "${PHYS_IFACE}" 2>/dev/null || true
        done
    fi

    echo -e "${GREEN}[SUCCESS] Firewall rules and routes cleaned up.${NC}"
}

# --- Main Commands ---

do_up() {
    check_root
    check_dependencies
    load_config # Load configuration from JSON file
    parse_cli_flags "$@" # Parse CLI flags and override loaded config

    echo -e "${BLUE}[INFO] Starting NordLynx connection process...${NC}"

    #==========================================
    # Apply defaults if not set by config or CLI
    #==========================================
    PHYS_IFACE="${PHYS_IFACE:-$DEFAULT_PHYS_IFACE}"
    WG_IFACE="${WG_IFACE:-$DEFAULT_WG_IFACE}"
    LISTEN_PORT="${LISTEN_PORT:-$DEFAULT_LISTEN_PORT}"
    ADDRESS="${ADDRESS:-$DEFAULT_ADDRESS}"
    DNS="${DNS:-$DEFAULT_DNS}"
    ALLOWED_IPS="${ALLOWED_IPS:-$DEFAULT_ALLOWED_IPS}"
    PERSISTENT_KEEPALIVE="${PERSISTENT_KEEPALIVE:-$DEFAULT_PERSISTENT_KEEPALIVE}"

    #==========================================
    # Private key
    #==========================================
    local current_private_key="${PRIVATE_KEY}" # Use local var for logic

    if [[ -z "${current_private_key}" ]] && [[ -n "${FILE__PRIVATE_KEY}" ]]; then
        echo -e "${BLUE}[INFO] Reading private key from file: ${FILE__PRIVATE_KEY}${NC}"
        if [[ ! -f "${FILE__PRIVATE_KEY}" ]]; then
            echo -e "${RED}[ERROR] File ${FILE__PRIVATE_KEY} does not exists${NC}" >&2
            exit 1
        fi
        current_private_key="$(head -n 1 "${FILE__PRIVATE_KEY}")" || {
            echo -e "${RED}[ERROR] Failed to read private key from file: ${FILE__PRIVATE_KEY}. Please check file permissions${NC}" >&2
            exit 1
        }
        if [[ -z "${current_private_key}" ]]; then
            echo -e "${RED}[ERROR] Failed to read private key from file: ${FILE__PRIVATE_KEY}. Please check file content (private key must be on the first line)${NC}" >&2
            exit 1
        fi
        echo -e "${GREEN}[SUCCESS] Private key loaded from file ${FILE__PRIVATE_KEY}${NC}"
    fi

    if [[ -z "${current_private_key}" ]] && [[ -n "${TOKEN}" ]]; then
        # Removed add_tmp_net_rules call
        echo -e "${BLUE}[INFO] Attempting to retrieve private key using NordVPN token${NC}"
        local credentials
        credentials="$(curl -Lsf -u token:"${TOKEN}" "https://api.nordvpn.com/v1/users/services/credentials")" || {
            echo -e "${RED}[ERROR] Failed to retrieve credentials from NordVPN API. Please make sure:${NC}" >&2
            echo "        - Your token is valid" >&2
            echo "        - You have internet connectivity" >&2
            echo "        - NordVPN API is accessible" >&2
            # Removed del_tmp_net_rules call
            exit 1
        }
        current_private_key="$(echo "${credentials}" | jq -r '.nordlynx_private_key')" || {
            echo -e "${RED}[ERROR] Failed to extract private key from API response${NC}" >&2
            # Removed del_tmp_net_rules call
            exit 1
        }
        echo -e "${GREEN}[SUCCESS] Private key retrieved from NordVPN API${NC}"
        # Removed del_tmp_net_rules call
    fi

    # Check if private key is available from any source (config, file, token)
    if [[ -z "${current_private_key}" ]]; then
        echo -e "${RED}[ERROR] No private key available. Please provide one of the following in your config file or via CLI:${NC}" >&2
        echo "        - private_key (--private-key)" >&2
        echo "        - file_private_key (--file-private-key)" >&2
        echo "        - token (--token)" >&2
        exit 1
    fi

    echo "${current_private_key}" | wg pubkey &>/dev/null || {
        echo -e "${RED}[ERROR] Private key is not the correct length or format${NC}" >&2
        exit 1
    }

    #==========================================
    # Server selection
    #==========================================
    local current_endpoint="${ENDPOINT}" # Use local var for logic
    local current_public_key="${PUBLIC_KEY}" # Use local var for logic

    # If manual endpoint and public key are NOT provided (via config or CLI), use API
    if [[ -z "${current_endpoint}" || -z "${current_public_key}" ]]; then
        # Removed add_tmp_net_rules call

        # Building up API query
        local api_query="https://api.nordvpn.com/v1/servers/recommendations?limit=1"
        api_query="${api_query}&filters\[servers_technologies\]\[identifier\]=wireguard_udp"

        # Selecting filters (optional) - Apply precedence: COUNTRY_CODE > CATEGORY
        local country_filter=""
        if [[ -n "${COUNTRY_CODE}" ]]; then
            echo -e "${BLUE}[INFO] Looking up country: ${COUNTRY_CODE^^}${NC}"
            local country
            country="$(curl -Lsf "https://api.nordvpn.com/v1/servers/countries" | jq -r ".[] | select(.code == \"${COUNTRY_CODE^^}\")")" || {
                echo -e "${RED}[ERROR] Failed to reach NordVPN API during country lookup. Please make sure:${NC}" >&2
                echo "        - You have internet connectivity" >&2
                echo "        - NordVPN API is accessible" >&2
                # Removed del_tmp_net_rules call
                exit 1
            }
            if [[ -n "${country}" && "${country}" != "null" ]]; then
                echo -e "${GREEN}[SUCCESS] Country found: $(echo "${country}" | jq -r '.name') ($(echo "${country}" | jq -r '.code'))${NC}"
                local country_id="$(echo "${country}" | jq -r '.id')"
                country_filter="&filters\[country_id\]=${country_id}"
            else
                echo -e "${YELLOW}[WARNING] Country code '${COUNTRY_CODE}' not found in NordVPN database (filter ignored)${NC}" >&2
            fi
             # If country is set, ignore category
             if [[ -n "${CATEGORY}" ]]; then
                echo -e "${YELLOW}[WARNING] COUNTRY_CODE filter takes precedence. CATEGORY filter will be ignored.${NC}" >&2
                # Do not unset global variable, just don't use it in the API query string
            fi
        fi

        local category_filter=""
        # Only apply category if no country filter was set
        if [[ -z "${country_filter}" && -n "${CATEGORY}" ]]; then
            echo -e "${BLUE}[INFO] Processing category filter: ${CATEGORY}${NC}"
            local category_id
            category_id="$(case "${CATEGORY,,}" in
                *standard*) echo "legacy_standard" ;;
                *p2p*) echo "legacy_p2p" ;;
                *double*) echo "legacy_double_vpn" ;;
                *obfuscated*) echo "legacy_obfuscated_servers" ;;
                *onion*) echo "legacy_onion_over_vpn" ;;
                *) echo "" ;; # Unknown category
                esac)"
            if [[ -n "${category_id}" ]]; then
                echo -e "${GREEN}[SUCCESS] Category matched: ${category_id}${NC}"
                category_filter="&filters\[servers_groups\]\[identifier\]=${category_id}"
            else
                echo -e "${YELLOW}[WARNING] Category '${CATEGORY}' not recognized (filter ignored)${NC}" >&2
                echo -e "${YELLOW}[INFO] Available categories: standard, p2p, double, obfuscated, onion${NC}" >&2
            fi
        fi

        api_query="${api_query}${country_filter}${category_filter}"

        # Selecting a server
        echo -e "${BLUE}[INFO] Querying NordVPN API for server recommendations: ${api_query}${NC}"
        local server
        server="$(curl --retry 3 -Lsf "${api_query}" | jq -r '.[0]')" || {
            echo -e "${RED}[ERROR] Failed to reach NordVPN API during server lookup. Please make sure:${NC}" >&2
            echo "        - You have internet connectivity" >&2
            echo "        - NordVPN API is accessible" >&2
            # Removed del_tmp_net_rules call
            exit 1
        }
        if [[ -z "${server}" || "${server}" == "null" ]]; then
            echo -e "${RED}[ERROR] No servers found matching your criteria. Check your filter settings (config file/cli):${NC}" >&2
            echo "        - COUNTRY_CODE: ${COUNTRY_CODE:-not set}" >&2
            echo "        - CATEGORY: ${CATEGORY:-not set}" >&2
            # Removed del_tmp_net_rules call
            exit 1
        fi
        echo -e "${GREEN}[SUCCESS] Server selected: $(echo "${server}" | jq -r '.hostname') ($(echo "${server}" | jq -r '.station'))${NC}"

        API_SELECTED_PUBLIC_KEY="$(echo "${server}" | jq -r '.technologies[] | select( .identifier == "wireguard_udp" ) | .metadata[] | select( .name == "public_key" ) | .value')"
        API_SELECTED_ENDPOINT="$(echo "${server}" | jq -r '.station'):51820"

        if [[ -z "${API_SELECTED_PUBLIC_KEY}" || -z "${API_SELECTED_ENDPOINT%:*}" ]]; then
            echo -e "${RED}[ERROR] Failed to extract public key or endpoint from API response.${NC}" >&2
            # Removed del_tmp_net_rules call
            exit 1
        fi

        # Use API selected details
        current_endpoint="${API_SELECTED_ENDPOINT}"
        current_public_key="${API_SELECTED_PUBLIC_KEY}"

        # Removed del_tmp_net_rules call
    fi # End of API server selection block

    # If we reached here and still don't have endpoint/public key (meaning manual config/CLI was empty/invalid AND API selection failed)
    if [[ -z "${current_endpoint}" || -z "${current_public_key}" ]]; then
         echo -e "${RED}[ERROR] No server endpoint or public key available from API or manual configuration.${NC}" >&2
         echo -e "${RED}[ERROR] Please ensure your config file or CLI provides a valid token/key or manual endpoint/public_key.${NC}" >&2
         exit 1
    fi


    #==========================================
    # WireGuard configuration
    #==========================================
    local wg_conf_dir="/etc/wireguard"
    local wg_conf_file="${wg_conf_dir}/${WG_IFACE}.conf"

    echo -e "${BLUE}[INFO] Generating WireGuard configuration file: ${wg_conf_file}${NC}"
    mkdir -p "${wg_conf_dir}" || { echo -e "${RED}[ERROR] Failed to create config directory ${wg_conf_dir}${NC}"; exit 1; }
    
    (umask 077 && {
        cat >"${wg_conf_file}" <<-EOF
[Interface]
PrivateKey = ${current_private_key}
ListenPort = ${LISTEN_PORT}
Address = ${ADDRESS}
DNS = ${DNS}
$( [[ -n "$MTU" ]] && echo "MTU = ${MTU}" )
$( [[ -n "$TABLE" ]] && echo "Table = ${TABLE}" )
$( [[ -n "$POST_UP" ]] && echo "PreUp = ${POST_UP}" )
$( [[ -n "$PRE_DOWN" ]] && echo "PostUp = ${PRE_DOWN}" )
$( [[ -n "$PRE_UP" ]] && echo "PreDown = ${PRE_UP}" )
$( [[ -n "$POST_DOWN" ]] && echo "PostDown = ${POST_DOWN}" )

[Peer]
PublicKey = ${current_public_key}
Endpoint = ${current_endpoint}
AllowedIPs = ${ALLOWED_IPS}
PersistentKeepalive = ${PERSISTENT_KEEPALIVE}
EOF
    }) || { echo -e "${RED}[ERROR] Failed to write WireGuard config file${NC}"; exit 1; }
    sync
    echo -e "${GREEN}[SUCCESS] WireGuard configuration file created.${NC}"

    #==========================================
    # Routing and Firewall (IPv4 only)
    #==========================================

    # Clean up any previous runs' rules first, just in case
    cleanup_rules

    # Set up necessary routes and the kill switch firewall rules
    # Pass endpoint to setup_firewall_rules and setup_routes as they need it
    # Update global vars for cleanup/status
    ENDPOINT="${current_endpoint}"
    PUBLIC_KEY="${current_public_key}" # Keep public key too, though not strictly needed for cleanup/status

    setup_routes || { cleanup_rules; exit 1; }
    setup_firewall_rules || { cleanup_rules; exit 1; }

    #==========================================
    # Bring up WireGuard Interface
    #==========================================

    echo -e "${BLUE}[INFO] Bringing up WireGuard interface ${WG_IFACE} using ${wg_conf_file}${NC}"
    if wg-quick up "${wg_conf_file}"; then
        echo -e "
    ${GREEN}╔═══════════════════════════════════╗${NC}
    ${GREEN}║                                   ║${NC}
    ${GREEN}║     **** NordLynx is up! **** ║${NC}
    ${GREEN}║                                   ║${NC}
    ${GREEN}╚═══════════════════════════════════╝${NC}
    "
        do_status # Show status after connecting
    else
        echo -e "${RED}[ERROR] Failed to bring up WireGuard interface ${WG_IFACE}${NC}" >&2
        # Clean up routes and firewall rules on failure
        cleanup_rules
        # Clean up config file? Maybe leave it for debugging.
        # rm -f "${wg_conf_file}"
        exit 1
    fi
}

do_down() {
    check_root
    # Load config to get interface names and potentially endpoint for cleanup
    load_config

    parse_cli_flags "$@"

    # Apply defaults for interface names if not set by config or CLI
    PHYS_IFACE="${PHYS_IFACE:-$DEFAULT_PHYS_IFACE}"
    WG_IFACE="${WG_IFACE:-$DEFAULT_WG_IFACE}"

    # Note: ENDPOINT and PUBLIC_KEY might not be set here if not in config,
    # but cleanup_rules is designed to handle this gracefully.

    local wg_conf_dir="/etc/wireguard"
    local wg_conf_file="${wg_conf_dir}/${WG_IFACE}.conf"

    echo -e "${BLUE}[INFO] Stopping NordLynx connection...${NC}"

    if ip link show "${WG_IFACE}" &>/dev/null; then
        echo -e "${BLUE}[INFO] WireGuard interface ${WG_IFACE} is up. Bringing it down...${NC}"
        echo -e "${BLUE}[INFO] Connection summary:${NC}"
        wg show "${WG_IFACE}" 2>/dev/null || echo "Could not get wg summary."

        # wg-quick down removes the interface and the rules/routes it added from the config file
        if ! wg-quick down "${wg_conf_file}"; then
            echo -e "${YELLOW}[WARNING] wg-quick down failed for ${WG_IFACE}. Interface might be gone already or config file missing.${NC}" >&2
            # Proceed with cleanup anyway
        fi
    else
        echo -e "${BLUE}[INFO] WireGuard interface ${WG_IFACE} is not currently up.${NC}"
    fi

    # Clean up rules and routes added manually by the script
    cleanup_rules
    
    echo -e "${BLUE}[INFO] Removing configuration file ${wg_conf_file}${NC}"
    rm -f "${wg_conf_file}"

    echo -e "${GREEN}[INFO] NordLynx is down${NC}"
}

do_reset() {
    echo -e "${BLUE}[INFO] Resetting NordLynx connection...${NC}"
    do_down "$@" # Pass arguments to down in case interface name is specified
    do_up "$@" # Pass arguments to up
}

do_status() {
    # Load config and parse CLI flags to get interface names
    load_config
    parse_cli_flags "$@"

    # Apply defaults for interface names if not set by config or CLI
    PHYS_IFACE="${PHYS_IFACE:-$DEFAULT_PHYS_IFACE}"
    WG_IFACE="${WG_IFACE:-$DEFAULT_WG_IFACE}"


    echo -e "${BLUE}--- NordLynx Status ---${NC}"

    # Check WireGuard interface status
    if ip link show "${WG_IFACE}" &>/dev/null; then
        echo -e "${GREEN}Status: Up${NC}"

        # Get connected server endpoint from the generated config file
        local wg_conf_file="/etc/wireguard/${WG_IFACE}.conf"
        local connected_endpoint=""
        if [[ -f "$wg_conf_file" ]]; then
            connected_endpoint=$(grep "^Endpoint" "$wg_conf_file" | awk '{print $3}')
        fi

        if [[ -n "$connected_endpoint" ]]; then
            echo -e "${GREEN}Connected Server: ${connected_endpoint}${NC}"
        else
            echo -e "${YELLOW}Connected Server: Unknown (Could not read from config file)${NC}"
        fi

        # Optionally show interface IP (less verbose than full 'ip addr show')
        local interface_ip=$(ip address show dev "${WG_IFACE}" | awk '/inet / {print $2}' | head -n 1)
        if [[ -n "$interface_ip" ]]; then
             echo -e "${GREEN}Interface IP: ${interface_ip}${NC}"
        else
             echo -e "${YELLOW}Interface IP: Unknown${NC}"
        fi


        # Show basic wg status (transfer, latest handshake)
        echo -e "${BLUE}WireGuard Interface (${WG_IFACE}):${NC}"
        wg show "${WG_IFACE}" 2>/dev/null | grep -E 'transfer:|latest handshake:' --color=never || echo "Could not get basic wg stats."

    else
        echo -e "${RED}Status: Down${NC}"
        echo -e "${YELLOW}WireGuard interface ${WG_IFACE} is not up.${NC}"
        echo "Run '${GREEN}sudo $(basename "$0") up${NC}' to connect."
    fi

    # Keep minimal checks for kill switch chains without verbose rule listing
    echo ""
    echo -e "${BLUE}Firewall (Kill Switch) Status (IPv4):${NC}"
    if iptables -L NORDLYNX_OUT &>/dev/null && iptables -L NORDLYNX_FWD &>/dev/null; then
        echo -e "${GREEN}Status: Chains Present${NC}"
        echo "  (Kill switch chains NORDLYNX_OUT, NORDLYNX_FWD are in place)"
    else
        echo -e "${RED}Status: Chains NOT Present${NC}"
        echo "  (Kill switch may NOT be active. Run '${GREEN}sudo $(basename "$0") up${NC}' to apply rules.)"
    fi
    
    echo -e "${BLUE}--- End Status ---${NC}"
}

# --- Main Script Logic ---

if [[ $# -eq 0 ]]; then
    usage
fi

command="$1"
shift

# Store remaining arguments to pass to functions after parsing command
remaining_args=("$@")

case "$command" in
    up)
        do_up "${remaining_args[@]}"
        ;;
    down)
        do_down "${remaining_args[@]}"
        ;;
    reset)
        do_reset "${remaining_args[@]}"
        ;;
    status)
        do_status "${remaining_args[@]}"
        ;;
    *)
        echo -e "${RED}[ERROR] Invalid command: $command${NC}" >&2
        usage
        ;;
esac

exit 0