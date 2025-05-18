# Capstone Design 4: WiFi and BLE Tools

This repository contains two powerful scripts designed for wireless security testing and Bluetooth Low Energy (BLE) operations. These tools are intended for **educational purposes** and **authorized security testing** only.

---

## Table of Contents

* [Overview](#overview)
* [Installation on Raspberry Pi 4](#installation-on-raspberry-pi-4)
* [WiFi Attack Script (`wifipen`)](#wifi-attack-script-wifipen)

  * [Features](#features)
  * [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Disclaimer](#disclaimer)
* [BLE Tool (`blue.py`)](#ble-tool-bluepy)

  * [Features](#features-1)
  * [Usage](#usage-1)
  * [Disclaimer](#disclaimer-1)
* [License](#license)

---

## Overview

This repository includes:

1. **`wifipen`**: A Bash script that automates WiFi penetration testing tasks including dependency checks, wordlist creation, monitor mode activation, network scanning, and WPA handshake capture.
2. **`blue.py`**: A Python script for performing Bluetooth Low Energy (BLE) operations such as scanning devices, enumerating characteristics, writing data, and simulating BLE advertisements.

These tools are intended to be used on Kali Linux running on Raspberry Pi 4 for an integrated IoT penetration testing setup.

---

## Installation on Raspberry Pi 4

1. **Download Kali Linux ARM64**
   Get the official Kali Linux image for Raspberry Pi 4:
   👉 [https://www.kali.org/get-kali/#kali-arm](https://www.kali.org/get-kali/#kali-arm)

2. **Flash to microSD Card**
   Use tools like **Raspberry Pi Imager** or **balenaEtcher** to flash the image to a microSD card.

3. **Boot Kali on Raspberry Pi 4**
   Insert the flashed card into the Raspberry Pi, power it on, and complete initial setup.

4. **Update the System**
   Open a terminal and run:

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

5. **Clone the Repository**

   ```bash
   git clone https://github.com/trefeon/Capstone-Design-4.git
   cd Capstone-Design-4
   ```

6. **Create and Activate Python Virtual Environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

7. **Install Python Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

8. **Install System Dependencies**
   Run the WiFi setup script:

   ```bash
   chmod +x wifipen
   ./wifipen
   ```

   Choose **option 1** to automatically install all required system tools.

---

## WiFi Attack Script (`wifipen`)

This script automates WiFi penetration testing workflows, allowing users to conduct network reconnaissance, handshake capturing, and password cracking with ease.

### Features

* ✅ **Dependency Check**: Verifies required tools are installed.
* 🔤 **Wordlist Generation**: Uses `crunch` to create custom dictionaries.
* 📡 **Monitor Mode**: Activates monitor mode on supported wireless interfaces.
* 🌐 **Network Scanning**: Lists nearby WiFi access points.
* 🤝 **Handshake Capture**: Captures WPA handshakes for cracking.
* 🔥 **Deauthentication Attack**: Forces clients to reconnect to trigger handshakes.

### Usage

```bash
chmod +x wifiacttack.sh
./wifiacttack.sh
```

Follow the on-screen menu options to execute desired tasks.

### Prerequisites

Make sure the following tools are installed (auto-installed by `wifipen`):

* `airmon-ng`, `airodump-ng`, `aireplay-ng`, `iw`
* `crunch`, `hcxpcapngtool`, `wpapcap2john`, `john`

### Disclaimer

This script is for **educational and authorized use only**. Unauthorized use of these tools is strictly prohibited and may violate laws and ethical standards.

---

## BLE Tool (`blue.py`)

This Python-based tool provides a command-line interface for interacting with Bluetooth Low Energy (BLE) devices.

### Features

* 📡 **Device Scanning**: Discover nearby BLE devices.
* 🔍 **Characteristic Enumeration**: Inspect services and characteristics.
* ✍️ **Data Writing**: Send custom data to writable characteristics.

### Usage

Activate your virtual environment first:

```bash
source venv/bin/activate
```

Then, run commands such as:

```bash
python3 blue.py
```

### Disclaimer

This script is intended solely for **educational** and **authorized** testing purposes. Unauthorized usage is illegal.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for full details.

---

> ⚠️ **Note**: Always ensure you have permission before testing any network or device. These tools are meant to aid in education and responsible security auditing only.
