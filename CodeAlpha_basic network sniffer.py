"""
Professional Network Packet Sniffer
Educational tool for analyzing network traffic and understanding protocols.

Usage on Windows:
  python sniff.py                    # Capture 10 packets  
  python sniff.py -c 50 -v          # Capture 50 packets with verbose output

Note: Must be run as Administrator on Windows for raw socket access.
Required: pip install scapy requests
"""

import argparse
import sys
import requests
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy library not found")
    print("Please install it with: pip install scapy")
    sys.exit(1)

class NetworkSniffer:
    """Professional network packet sniffer with clean output format."""
    
    def __init__(self, interface=None, packet_count=10):
        self.interface = interface
        self.packet_count = packet_count
        self.packets_captured = 0
        self.service_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            587: "SMTP", 465: "SMTPS", 119: "NNTP", 161: "SNMP", 162: "SNMP",
            389: "LDAP", 636: "LDAPS", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 
            27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 
            9200: "Elasticsearch", 11211: "Memcached"
        }

    def get_country_from_ip(self, ip_address):
        try:
            if ip_address.startswith(('192.168.', '10.', '172.', '127.', '169.254.')):
                return "Local/Private"
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return f"{data.get('country', 'Unknown')} ({data.get('countryCode', 'XX')})"
            return "Unknown"
        except:
            return "Unknown"

    def get_timezone_from_ip(self, ip_address):
        try:
            if ip_address.startswith(('192.168.', '10.', '172.', '127.', '169.254.')):
                return "Local"
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return data.get('timezone', 'Unknown')
            return "Unknown"
        except:
            return "Unknown"

    def detect_service(self, port):
        return self.service_ports.get(port, f"Unknown ({port})")

    def process_packet(self, pk):
        try:
            mac_src = mac_dst = "Unknown"
            sport = dport = "N/A"
            service_detector = timezone = country = "Unknown"

            if pk.haslayer(Ether):
                mac_src = pk[Ether].src
                mac_dst = pk[Ether].dst

            if pk.haslayer(IP):
                src_ip = pk[IP].src
                dst_ip = pk[IP].dst
                country = self.get_country_from_ip(dst_ip)
                timezone = self.get_timezone_from_ip(dst_ip)

                if pk.haslayer(TCP):
                    sport = pk[TCP].sport
                    dport = pk[TCP].dport
                    service_detector = self.detect_service(dport)
                elif pk.haslayer(UDP):
                    sport = pk[UDP].sport
                    dport = pk[UDP].dport
                    service_detector = self.detect_service(dport)

                print(f"Packet #{self.packets_captured + 1}")
                print(f"{'=' * 40}")
                print(f"Summary       : {pk.summary()}")
                print(f"MAC Source    : {mac_src}")
                print(f"MAC Destination: {mac_dst}")
                print(f"Source Port   : {sport}")
                print(f"Destination Port: {dport}")
                print(f"Service       : {service_detector}")
                print(f"Timezone      : {timezone}")
                print(f"Country       : {country}")
                print(f"{'-' * 40}\n")

                self.packets_captured += 1

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_capture(self):
        print("Starting Network Packet Sniffer")
        print(f"Capturing {self.packet_count} packets")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)

        try:
            sniff(iface=self.interface, prn=self.process_packet, count=self.packet_count, store=0)
        except PermissionError:
            print("Error: Administrator/root privileges required for packet capture")
            sys.exit(1)
        except KeyboardInterrupt:
            print("Capture interrupted by user")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            print("\nCapture Summary")
            print(f"Total packets captured: {self.packets_captured}")
            print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Capture completed.")

def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python sniff.py                    # Capture 10 packets
  python sniff.py -c 50             # Capture 50 packets
  python sniff.py -i eth0 -c 20     # Capture 20 packets on eth0
Note: Requires administrator/root privileges.
"""
    )
    parser.add_argument('-c', '--count', type=int, default=10,
                        help='Number of packets to capture (default: 10)')
    parser.add_argument('-i', '--interface', type=str,
                        help='Network interface to capture from')

    args = parser.parse_args()

    sniffer = NetworkSniffer(interface=args.interface, packet_count=args.count)

    try:
        sniffer.start_capture()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
