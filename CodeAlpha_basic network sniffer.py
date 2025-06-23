import argparse
import sys
import requests
import json
from datetime import datetime
import socket

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy library not found. Please install it with: pip install scapy")
    sys.exit(1)

class NetworkSniffer:
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
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 11211: "Memcached"
        }

    def get_country_from_ip(self, ip_address):
        try:
            if (ip_address.startswith('192.168.') or 
                ip_address.startswith('10.') or 
                ip_address.startswith('172.') or 
                ip_address == '127.0.0.1' or
                ip_address.startswith('169.254.')):
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
            if (ip_address.startswith('192.168.') or 
                ip_address.startswith('10.') or 
                ip_address.startswith('172.') or 
                ip_address == '127.0.0.1' or
                ip_address.startswith('169.254.')):
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
            mac_src = "Unknown"
            mac_dst = "Unknown"
            sport = "N/A"
            dport = "N/A"
            service_detector = "Unknown"
            timezone = "Unknown"
            country = "Unknown"

            if pk.haslayer(Ether):
                mac_src = pk[Ether].src
                mac_dst = pk[Ether].dst

            if pk.haslayer(IP):
                src_ip = pk[IP].src
                dst_ip = pk[IP].dst
                ttl = pk[IP].ttl
                proto = "TCP" if pk.haslayer(TCP) else "UDP" if pk.haslayer(UDP) else "IP"

                # ✅ New formatted output line
                print(f"🌐 IP: {src_ip} → {dst_ip} ({proto}) TTL: {ttl}")

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

            print(f"MAC Source : {mac_src}")
            print(f"MAC Dest   : {mac_dst}")
            print(f"Src Port   : {sport}")
            print(f"Dst Port   : {dport}")
            print(f"Service    : {service_detector}")
            print(f"Timezone   : {timezone}")
            print(f"Country    : {country}")
            print("-" * 50)

            self.packets_captured += 1

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start_capture(self):
        print(f"Starting Network Packet Sniffer")
        print(f"Capturing {self.packet_count} packets...")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)

        try:
            if self.interface:
                sniff(iface=self.interface, prn=self.process_packet, count=self.packet_count, store=0)
            else:
                sniff(prn=self.process_packet, count=self.packet_count, store=0)
        except PermissionError:
            print("Error: Administrator/root privileges required for packet capture.")
            print("Run as administrator (Windows) or with sudo (Linux/Mac)")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nCapture interrupted by user")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            print(f"\nCAPTURE SUMMARY")
            print(f"Total packets captured: {self.packets_captured}")
            print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Capture completed!")

def main():
    parser = argparse.ArgumentParser(
        description="Professional Network Packet Sniffer with Custom Output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python sniff.py                    # Capture 10 packets
  python sniff.py -c 50             # Capture 50 packets
  python sniff.py -i eth0 -c 20     # Capture 20 packets on eth0 interface
Note: Requires administrator/root privileges."""
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
