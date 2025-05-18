# Capstone Design 4: WiFi and BLE Tools

This repository contains two scripts designed for wireless security testing and Bluetooth Low Energy (BLE) operations. These tools are intended for educational purposes and authorized security testing only.

---

## Table of Contents

- [WiFi Attack Script (`wifiacttack.sh`)](#wifi-attack-script-wifiacttacksh)
  - [Features](#features)
  - [Usage](#usage)
  - [Disclaimer](#disclaimer)
- [BLE Tool (`bluen.py`)](#ble-tool-bluenpy)
  - [Features](#features-1)
  - [Usage](#usage-1)
  - [Disclaimer](#disclaimer-1)

---

## WiFi Attack Script (`wifiacttack.sh`)

This Bash script automates WiFi penetration testing tasks, including dependency checks, wordlist creation, monitor mode activation, network scanning, and WPA handshake capture.

### Features

- **Dependency Check**: Verifies required tools are installed.
- **Custom Wordlist Creation**: Generates wordlists using `crunch`.
- **Monitor Mode Activation**: Enables monitor mode on a wireless interface.
- **Network Scanning**: Scans for nearby WiFi networks.
- **Handshake Capture**: Captures WPA handshakes and attempts to crack them using a wordlist.
- **Deauthentication Attack**: Sends deauthentication packets to force reconnections.

### Usage

1. Make the script executable:
   ```bash
   chmod +x wifiacttack.sh