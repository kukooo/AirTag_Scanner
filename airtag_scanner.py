#!/usr/bin/python3

import subprocess
import re
from datetime import datetime
from termcolor import colored

# AirTag detection constants
APPLE_COMPANY_ID = 0x004c
FINDMY_DATA = bytes([0x12, 0x19])
AIR_TAG_STATUSES = bytes([0x10, 0x50, 0x90, 0xd0])

def check_airtag(data_bytes):
    """
    Check if manufacturer data matches AirTag pattern.
    AirTag format: 0x12 0x19 [status] [rest of payload]
    """
    if len(data_bytes) < 3:
        return False, None

    # Check for Find My network advertisement pattern
    # First two bytes should be 0x12 0x19
    # Third byte is the status byte (battery level)
    if data_bytes[0] == FINDMY_DATA[0] and data_bytes[1] == FINDMY_DATA[1]:
        if data_bytes[2] in AIR_TAG_STATUSES:
            return True, data_bytes[2]

    return False, None

def main():
    print("Starting AirTag detection with Ubertooth One...")
    print("Press Ctrl+C to stop\n")

    process = subprocess.Popen(
        ['ubertooth-btle', '-n'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        bufsize=1
    )

    current_packet = {}
    in_apple_packet = False

    try:
        for line in process.stdout:
            line = line.rstrip()

            # Detect start of new packet
            if line.startswith("systime="):
                current_packet = {}
                in_apple_packet = False
                # Extract RSSI
                rssi_match = re.search(r'rssi=(-?\d+)', line)
                if rssi_match:
                    current_packet['rssi'] = rssi_match.group(1)

            # Extract MAC address (AdvA)
            if "AdvA:" in line:
                mac_match = re.search(r'AdvA:\s+([0-9a-f:]+)', line)
                if mac_match:
                    current_packet['mac'] = mac_match.group(1)
                    # Check if it's random or public
                    if "(random)" in line:
                        current_packet['mac_type'] = 'random'
                    elif "(public)" in line:
                        current_packet['mac_type'] = 'public'

            # Check for Apple manufacturer
            if "Company: Apple" in line:
                in_apple_packet = True
                current_packet['company'] = 'Apple'

            # Parse manufacturer data
            if in_apple_packet and line.strip().startswith("Data:"):
                hex_data = line.split("Data:")[1].strip()
                hex_bytes = hex_data.split()

                if len(hex_bytes) >= 3:
                    data_bytes = bytes([int(b, 16) for b in hex_bytes])

                    # Check if this is an AirTag
                    is_airtag, status = check_airtag(data_bytes)

                    if is_airtag:
                        timestamp = datetime.now().strftime('%H:%M:%S')
                        print(f"[{timestamp}] AirTag Detected!")

                        # Print MAC address
                        mac = current_packet.get('mac', 'Unknown')
                        mac_type = current_packet.get('mac_type', '')
                        if mac_type:
                            pm = colored(f"{mac}", "yellow")
                            print(f"  MAC Address: {pm} ({mac_type})")
                        else:
                            print(f"  MAC Address: {pm}")

                        print(f"  Status Byte: 0x{status:02x}", end="")

                        # Decode battery status
                        battery = {
                            0x10: colored("Full","green"),
                            0x50: colored("Medium","yellow"),
                            0x90: colored("Low","light_red"),
                            0xd0: colored("Very Low","red")
                        }.get(status, "Unknown")

                        print(f" (Battery: {battery})")
                        print(f"  RSSI: {current_packet.get('rssi', 'N/A')} dBm")
                        print(f"  Full Payload: {' '.join(hex_bytes)}")
                        print()

                in_apple_packet = False

    except KeyboardInterrupt:
        print("\n\nStopping scan...")
        process.terminate()
        process.wait()
        print("Scan stopped.")

    except Exception as e:
        print(f"Error: {e}")
        process.terminate()

if __name__ == "__main__":
    main()
