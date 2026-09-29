#!/usr/bin/env bash
# ==============================================================================
# NetShield-LKM: Load and Configuration Automation Script
# ==============================================================================

set -eo pipefail

MODULE_NAME="netshield"
MODULE_FILE="${MODULE_NAME}.ko"

# Styling and Color Palette
COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"
COLOR_BLUE="\033[1;34m"
COLOR_CYAN="\033[1;36m"

log_info()    { echo -e "${COLOR_CYAN}[*]${COLOR_RESET} $*"; }
log_success() { echo -e "${COLOR_GREEN}[+]${COLOR_RESET} $*"; }
log_warn()    { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $*"; }
log_err()     { echo -e "${COLOR_RED}[-]${COLOR_RESET} $*" >&2; }

# Locate project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default parameter configurations
PARAM_PORT=0
PARAM_ICMP=1
PARAM_IP=""
PARAM_LOOPBACK=0
ACTION="load"

print_usage() {
    echo -e "${COLOR_BOLD}NetShield-LKM Module Loader and Management Utility${COLOR_RESET}"
    echo -e "${COLOR_BOLD}USAGE:${COLOR_RESET}"
    echo -e "    sudo $0 [OPTIONS]\n"
    echo -e "${COLOR_BOLD}OPTIONS:${COLOR_RESET}"
    echo -e "    -p, --port <port>       Destination TCP port to block (default: 0 = disabled)"
    echo -e "    -i, --icmp <0|1>        Drop incoming ICMP echo requests / ping (default: 1 = true)"
    echo -e "    -b, --ip <ip_address>   Source IPv4 address to block (default: \"\" = none)"
    echo -e "    -l, --loopback <0|1>    Enable filtering on loopback 'lo' (default: 0 = disabled for anti-lockout)"
    echo -e "    -r, --reload            Safely unload existing instance and reload with new parameters"
    echo -e "    -u, --unload            Safely remove the module from the kernel"
    echo -e "    -s, --status            Inspect current module load state and sysfs parameters"
    echo -e "    -h, --help              Display this guidance information\n"
    echo -e "${COLOR_BOLD}EXAMPLES:${COLOR_RESET}"
    echo -e "    # Load with default parameters (drops ping, port blocking disabled)"
    echo -e "    sudo $0\n"
    echo -e "    # Block incoming TCP port 8080 and drop ping"
    echo -e "    sudo $0 --port 8080 --icmp 1\n"
    echo -e "    # Blacklist traffic from IP 192.168.1.100 and allow loopback testing"
    echo -e "    sudo $0 --ip \"192.168.1.100\" --loopback 1\n"
    echo -e "    # Reload with updated port rule"
    echo -e "    sudo $0 --reload --port 4444"
}

# Ensure root privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        log_err "Root privileges required. Please execute with sudo."
        exit 1
    fi
}

# Unload module routine
do_unload() {
    if lsmod | grep -q "^${MODULE_NAME} "; then
        log_info "Unloading module '${MODULE_NAME}'..."
        rmmod "${MODULE_NAME}"
        log_success "Successfully unloaded '${MODULE_NAME}'."
    else
        log_warn "Module '${MODULE_NAME}' is not currently loaded."
    fi
}

# Status inspection routine
do_status() {
    echo -e "${COLOR_BOLD}${COLOR_BLUE}[NetShield-LKM Status Inspection]${COLOR_RESET}"
    if lsmod | grep -q "^${MODULE_NAME} "; then
        echo -e "Module State: ${COLOR_GREEN}LOADED${COLOR_RESET}"
        lsmod | grep "^${MODULE_NAME} "
        echo -e "\n${COLOR_BOLD}Active Sysfs Parameters (/sys/module/${MODULE_NAME}/parameters/):${COLOR_RESET}"
        if [[ -d "/sys/module/${MODULE_NAME}/parameters" ]]; then
            for p in "/sys/module/${MODULE_NAME}/parameters/"*; do
                pname=$(basename "$p")
                pval=$(cat "$p" 2>/dev/null || echo "N/A")
                echo -e "  • ${pname}: ${COLOR_CYAN}${pval}${COLOR_RESET}"
            done
        fi
        echo -e "\n${COLOR_BOLD}Recent Kernel Messages:${COLOR_RESET}"
        dmesg | grep "\[NetShield-LKM\]" | tail -n 8 || true
    else
        echo -e "Module State: ${COLOR_RED}NOT LOADED${COLOR_RESET}"
    fi
}

# Parse command-line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            PARAM_PORT="$2"
            shift 2
            ;;
        -i|--icmp)
            PARAM_ICMP="$2"
            shift 2
            ;;
        -b|--ip)
            PARAM_IP="$2"
            shift 2
            ;;
        -l|--loopback)
            PARAM_LOOPBACK="$2"
            shift 2
            ;;
        -r|--reload)
            ACTION="reload"
            shift
            ;;
        -u|--unload)
            ACTION="unload"
            shift
            ;;
        -s|--status)
            ACTION="status"
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            log_err "Unknown argument: $1"
            print_usage
            exit 1
            ;;
    esac
done

check_privileges

case "$ACTION" in
    unload)
        do_unload
        exit 0
        ;;
    status)
        do_status
        exit 0
        ;;
    reload)
        if lsmod | grep -q "^${MODULE_NAME} "; then
            do_unload
            sleep 1
        fi
        ;;
    load)
        if lsmod | grep -q "^${MODULE_NAME} "; then
            log_warn "Module '${MODULE_NAME}' is already loaded. Use --reload to apply new parameters."
            do_status
            exit 0
        fi
        ;;
esac

# Locate compiled .ko module file
MODULE_PATH=""
if [[ -f "${PROJECT_ROOT}/${MODULE_FILE}" ]]; then
    MODULE_PATH="${PROJECT_ROOT}/${MODULE_FILE}"
elif [[ -f "${SCRIPT_DIR}/${MODULE_FILE}" ]]; then
    MODULE_PATH="${SCRIPT_DIR}/${MODULE_FILE}"
elif [[ -f "${PROJECT_ROOT}/src/${MODULE_FILE}" ]]; then
    MODULE_PATH="${PROJECT_ROOT}/src/${MODULE_FILE}"
else
    log_err "Module binary '${MODULE_FILE}' not found."
    log_info "Please compile the module first by running 'make' in ${PROJECT_ROOT}."
    exit 1
fi

log_info "Target module binary: ${MODULE_PATH}"

# Prepare insmod parameter string
INSMOD_PARAMS=()
INSMOD_PARAMS+=("block_port=${PARAM_PORT}")
INSMOD_PARAMS+=("drop_icmp=${PARAM_ICMP}")
INSMOD_PARAMS+=("allow_loopback_filter=${PARAM_LOOPBACK}")
if [[ -n "${PARAM_IP}" ]]; then
    INSMOD_PARAMS+=("blacklist_ip=${PARAM_IP}")
fi

log_info "Loading module with parameters: ${INSMOD_PARAMS[*]}"

# Execute insertion
if insmod "${MODULE_PATH}" "${INSMOD_PARAMS[@]}"; then
    log_success "Kernel module inserted successfully."
else
    log_err "Failed to insert kernel module '${MODULE_PATH}'."
    dmesg | tail -n 5 >&2
    exit 1
fi

# Verification and parameter inspection
sleep 0.5
if lsmod | grep -q "^${MODULE_NAME} "; then
    log_success "Verified: '${MODULE_NAME}' is active in kernel space."
    do_status
else
    log_err "Verification failed: '${MODULE_NAME}' was not detected in active module list."
    exit 1
fi