# Capstone Design 4: WiFi and BLE Tools

This repository contains two powerful scripts designed for wireless security testing and Bluetooth Low Energy (BLE) operations. These tools are intended for **educational purposes** and **authorized security testing** only.

---

## Table of Contents

- [Capstone Design 4: WiFi and BLE Tools](#capstone-design-4-wifi-and-ble-tools)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [WiFi Attack Script (`wifiacttack.sh`)](#wifi-attack-script-wifiacttacksh)
    - [Features](#features)
    - [Usage](#usage)
    - [Prerequisites](#prerequisites)
    - [Disclaimer](#disclaimer)
  - [BLE Tool (`bluen.py`)](#ble-tool-bluenpy)
    - [Features](#features-1)
    - [Usage](#usage-1)
    - [Disclaimer](#disclaimer-1)
  - [License](#license)

---

## Overview

This repository includes:

1. **`wifiacttack.sh`**: A Bash script for automating WiFi penetration testing tasks such as dependency checks, wordlist creation, monitor mode activation, network scanning, and WPA handshake capture.
2. **`bluen.py`**: A Python script for Bluetooth Low Energy (BLE) operations, including device scanning, characteristic enumeration, data writing, and BLE signal advertising.

Both scripts are designed for advanced users with knowledge of wireless security and BLE protocols.

---

## WiFi Attack Script (`wifiacttack.sh`)

This script automates various WiFi penetration testing tasks, making it easier to perform network reconnaissance and WPA handshake cracking.

### Features

- **Dependency Check**: Ensures all required tools are installed.
- **Custom Wordlist Creation**: Generates wordlists using `crunch` with user-defined patterns.
- **Monitor Mode Activation**: Enables monitor mode on a wireless interface.
- **Network Scanning**: Scans for nearby WiFi networks and displays available access points.
- **Handshake Capture**: Captures WPA handshakes and attempts to crack them using a wordlist.
- **Deauthentication Attack**: Sends deauthentication packets to force reconnections, aiding in handshake capture.

### Usage

1. Clone the repository and navigate to the script directory.
2. Make the script executable:
   ```bash
   chmod +x wifiacttack.sh
   ```
3. Run the script:
   ```bash
   ./wifiacttack.sh
   ```
4. Follow the menu options to perform desired tasks.

### Prerequisites

The script requires the following tools to be installed:
- `airmon-ng`, `airodump-ng`, `aireplay-ng`, `iw`
- `crunch`, `hcxpcapngtool`, `wpapcap2john`, `john`

The script can install missing dependencies on Debian-based systems.

### Disclaimer

This script is intended for **educational purposes** and **authorized security testing** only. Unauthorized use is illegal and unethical.

---

## BLE Tool (`bluen.py`)

This Python script provides tools for Bluetooth Low Energy (BLE) operations, enabling users to interact with BLE devices for scanning, characteristic enumeration, data writing, and signal advertising.

### Features

- **Device Scanning**: Scans for nearby BLE devices and displays their details.
- **Characteristic Enumeration**: Lists services and characteristics of a BLE device.
- **Data Writing**: Writes data to a specific BLE characteristic.
- **BLE Advertising**: Simulates a BLE device by advertising a signal.

### Usage

1. Install dependencies:
   ```bash
   pip install bleak
   ```
2. Run the script with the following commands:
   - **Scan for devices**:
     ```bash
     python bluen.py scan
     ```
   - **Enumerate characteristics**:
     ```bash
     python bluen.py enum <MAC_ADDRESS>
     ```
   - **Write to a characteristic**:
     ```bash
     python bluen.py write <MAC_ADDRESS> <CHAR_UUID> <HEXDATA>
     ```
   - **Advertise a BLE signal**:
     ```bash
     python bluen.py advertise <MAC_ADDRESS> <SERVICE_UUID>
     ```

### Disclaimer

This script is intended for **educational purposes** and **authorized security testing** only. Unauthorized use is illegal and unethical.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Note**: Ensure you have proper authorization before using these tools in any environment. Misuse of these tools is illegal and unethical.