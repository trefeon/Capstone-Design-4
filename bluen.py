import asyncio
from bleak import BleakScanner, BleakClient
from bleak.exc import BleakError
import sys

# Placeholder for _bt_adapter. Replace with actual implementation.
_bt_adapter = None

async def scan_devices():
    """
    Scans for BLE devices for 5 seconds and prints their details.
    """
    print("[*] Scanning for BLE devices (5 seconds)...")

    def detection_callback(device, adv_data):
        print(f"{device.address} | RSSI: {adv_data.rssi} | Name: {device.name or 'Unknown'}")

    try:
        scanner = BleakScanner(detection_callback)
        await scanner.start()
        await asyncio.sleep(5.0)
        await scanner.stop()
    except Exception as e:
        print(f"[!] Error during scan: {e}")

async def enumerate_characteristics(mac_address, retries=3, timeout=10):
    """
    Enumerates the characteristics of a BLE device by its MAC address.
    """
    print(f"[*] Scanning for {mac_address} to make sure it's reachable...")
    try:
        devices = await BleakScanner.discover(timeout=5.0)
        target = next((d for d in devices if d.address.upper() == mac_address.upper()), None)

        if not target:
            print(f"[!] Device {mac_address} not found during scan.")
            return

        attempt = 0
        while attempt < retries:
            try:
                print(f"[*] Attempting to connect (Attempt {attempt + 1})...")
                async with BleakClient(mac_address, timeout=timeout) as client:
                    if not client.is_connected:
                        print(f"[!] Could not connect to {mac_address}")
                        return

                    print(f"[*] Connected to {mac_address}")
                    services = await client.get_services()
                    for service in services:
                        print(f"[+] Service: {service.uuid}")
                        for char in service.characteristics:
                            props = ', '.join(char.properties)
                            print(f"    - Char: {char.uuid} | Props: {props}")
                    return  # Successful connection, exit loop
            except asyncio.TimeoutError:
                print(f"[!] Timeout error on attempt {attempt + 1}. Retrying...")
                attempt += 1
                await asyncio.sleep(2)  # Wait before retrying
            except BleakError as e:
                print(f"[!] BLE Error: {e}")
                return
            except Exception as e:
                print(f"[!] Unexpected error: {str(e)}")
                return

        print("[!] Failed to connect after multiple attempts.")
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()  # Full error traceback

async def write_to_characteristic(mac_address, uuid, hex_data):
    """
    Writes data to a specific characteristic of a BLE device.
    """
    try:
        data = bytes.fromhex(hex_data)
    except ValueError:
        print(f"[!] Invalid hex data: '{hex_data}'")
        return

    try:
        async with BleakClient(mac_address) as client:
            if not client.is_connected:
                print(f"[!] Could not connect to {mac_address}")
                return

            print(f"[*] Connected to {mac_address}")
            await client.write_gatt_char(uuid, data)
            print(f"[+] Wrote data to {uuid}: {hex_data}")
    except BleakError as e:
        print(f"[!] BLE Error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

def advertise_ble_signal(mac_address, service_uuid, name="Replicated_Device"):
    """
    Starts advertising a BLE signal with the given MAC address and service UUID.
    """
    if _bt_adapter is None:
        print("[!] BLE adapter is not initialized. Replace `_bt_adapter` with the actual implementation.")
        return

    try:
        print(f"[*] Starting BLE advertisement for {name} with MAC {mac_address} and UUID {service_uuid}")
        # Setup the advertisement data (this is simplified)
        advertisement = (
            "\x02\x01\x06"               # Flags
            "\x03\x03\x00\x18"           # 16-bit service UUID
            "\x09\x09" + name.encode()    # Device name
        )

        # Start advertising
        advertise = _bt_adapter.advertise(advertisement, device_id=mac_address)
        advertise.set_data(advertisement)
        advertise.start_advertising()
        print(f"[+] Advertising as {name} with service {service_uuid}")
    except Exception as e:
        print(f"[!] Error while advertising BLE signal: {e}")

def stop_advertising():
    """
    Stops BLE advertising.
    """
    if _bt_adapter is None:
        print("[!] BLE adapter is not initialized. Replace `_bt_adapter` with the actual implementation.")
        return

    try:
        print("[*] Stopping BLE advertisement.")
        _bt_adapter.stop_advertising()
    except Exception as e:
        print(f"[!] Error while stopping advertisement: {e}")

def usage():
    """
    Prints usage instructions for the script.
    """
    print("Usage:")
    print("  python ble_tool.py scan")
    print("  python ble_tool.py enum <MAC_ADDRESS>")
    print("  python ble_tool.py write <MAC_ADDRESS> <CHAR_UUID> <HEXDATA>")
    print("  python ble_tool.py advertise <MAC_ADDRESS> <SERVICE_UUID>")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    command = sys.argv[1]

    try:
        if command == "scan":
            asyncio.run(scan_devices())
        elif command == "enum" and len(sys.argv) == 3:
            asyncio.run(enumerate_characteristics(sys.argv[2]))
        elif command == "write" and len(sys.argv) == 5:
            asyncio.run(write_to_characteristic(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif command == "advertise" and len(sys.argv) == 4:
            mac_address = sys.argv[2]
            service_uuid = sys.argv[3]
            advertise_ble_signal(mac_address, service_uuid)
        else:
            usage()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Unhandled exception: {e}")