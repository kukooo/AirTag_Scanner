#!/usr/bin/python3

import subprocess
import re
import argparse
import sys
from datetime import datetime
from termcolor import colored
from tabulate import tabulate

# AirTag detection constants
APPLE_COMPANY_ID = 0x004c
FINDMY_DATA = bytes([0x12, 0x19])
AIR_TAG_STATUSES = bytes([0x10, 0x50, 0x90, 0xd0])

# Global logger instance
log_file = None

def log_print(*args, **kwargs):
    """Print to stdout and optionally to log file."""
    # Print to stdout
    print(*args, **kwargs)

    # Also write to log file if enabled
    if log_file:
        # Capture the print output
        import io
        buffer = io.StringIO()
        print(*args, **kwargs, file=buffer)
        output = buffer.getvalue()
        log_file.write(output)
        log_file.flush()

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
    global log_file

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AirTag Scanner using Ubertooth One')
    parser.add_argument('--log', nargs='?', const='', default=None,
                        help='Enable logging to file. Optionally specify filename, otherwise uses timestamp')
    args = parser.parse_args()

    # Setup logging if requested
    if args.log is not None:
        if args.log == '':
            # Generate timestamp-based filename
            log_filename = datetime.now().strftime('%Y_%m_%d_%H-%M_airtag_scanner.log')
        else:
            log_filename = args.log

        try:
            log_file = open(log_filename, 'w')
            print(f"Logging to: {log_filename}")
        except Exception as e:
            print(f"Warning: Could not open log file {log_filename}: {e}")
            log_file = None

    log_print("Starting AirTag detection with Ubertooth One...")
    log_print("Press Ctrl+C to stop\n")

    # Dictionary to store detected AirTags: {mac_address: {battery, rssi, time}}
    detected_airtags = {}

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
                        log_print(f"[{timestamp}] AirTag Detected!")

                        # Print MAC address
                        mac = current_packet.get('mac', 'Unknown')
                        mac_type = current_packet.get('mac_type', '')
                        if mac_type:
                            pm = colored(f"{mac}", "yellow")
                            log_print(f"  MAC Address: {pm} ({mac_type})")
                        else:
                            log_print(f"  MAC Address: {pm}")

                        log_print(f"  Status Byte: 0x{status:02x}", end="")

                        # Decode battery status
                        battery_text = {
                            0x10: "Full",
                            0x50: "Medium",
                            0x90: "Low",
                            0xd0: "Very Low"
                        }.get(status, "Unknown")

                        battery_colored = {
                            0x10: colored("Full","green"),
                            0x50: colored("Medium","yellow"),
                            0x90: colored("Low","light_red"),
                            0xd0: colored("Very Low","red")
                        }.get(status, "Unknown")

                        log_print(f" (Battery: {battery_colored})")
                        rssi = current_packet.get('rssi', 'N/A')
                        log_print(f"  RSSI: {rssi} dBm")
                        log_print(f"  Full Payload: {' '.join(hex_bytes)}")
                        log_print()

                        # Save or update AirTag information
                        detected_airtags[mac] = {
                            'battery': battery_text,
                            'rssi': rssi,
                            'time': timestamp
                        }

                in_apple_packet = False

    except KeyboardInterrupt:
        log_print("\n\nStopping scan...")
        process.terminate()
        process.wait()
        log_print("Scan stopped.")

        # Display summary table of detected AirTags
        if detected_airtags:
            log_print("\n" + "="*70)
            log_print("DETECTED AIRTAGS SUMMARY")
            log_print("="*70 + "\n")

            # Prepare table data
            table_data = []
            for mac, info in detected_airtags.items():
                table_data.append([
                    mac,
                    info['battery'],
                    info['rssi'],
                    info['time']
                ])

            # Print table
            headers = ["MAC Address", "Battery", "RSSI (dBm)", "Last Seen"]
            table = tabulate(table_data, headers=headers, tablefmt="grid")
            log_print(table)
            log_print(f"\nTotal unique AirTags detected: {len(detected_airtags)}\n")
        else:
            log_print("\nNo AirTags detected during this scan.\n")

    except Exception as e:
        log_print(f"Error: {e}")
        process.terminate()

    finally:
        # Close log file if it was opened
        if log_file:
            log_file.close()

if __name__ == "__main__":
    main()
