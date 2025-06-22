"""
Professional Network Packet Sniffer
Educational tool for analyzing network traffic and understanding protocols.

Usage on Windows:
  python sniff.py                    # Capture 10 packets  
  python sniff.py -c 50 -v          # Capture 50 packets with verbose output
  
Note: Must be run as Administrator on Windows for raw socket access.
"""

import socket
import struct
import textwrap
import sys
import argparse
from datetime import datetime
import threading
import time

class NetworkSniffer:
    """
    A professional network packet sniffer for educational purposes.
    Captures and analyzes network packets to understand protocol structures.
    """
    
    def __init__(self, interface=None, packet_count=10, verbose=False):
        self.interface = interface
        self.packet_count = packet_count
        self.verbose = verbose
        self.packets_captured = 0
        self.running = False
        
    def create_socket(self):
        """Create and configure raw socket for packet capture."""
        try:
            # Create raw socket
            if sys.platform.startswith('win'):
                # Windows
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux/Unix
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface:
                    self.sock.bind((self.interface, 0))
                    
        except PermissionError:
            print("❌ Error: Administrator/root privileges required for packet capture")
            print("   Run as administrator (Windows) or with sudo (Linux/Mac)")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error creating socket: {e}")
            sys.exit(1)
    
    def parse_ethernet_header(self, data):
        """Parse Ethernet frame header."""
        eth_header = struct.unpack('!6s6sH', data[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_proto = socket.ntohs(eth_header[2])
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'protocol': eth_proto,
            'header_length': 14
        }
    
    def parse_ip_header(self, data):
        """Parse IP header and extract key information."""
        # Unpack the first 20 bytes of IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        header_length = ihl * 4
        
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_addr = socket.inet_ntoa(ip_header[8])
        dest_addr = socket.inet_ntoa(ip_header[9])
        
        # Protocol mapping
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 2: 'IGMP'}
        protocol_name = protocol_map.get(protocol, f'Unknown({protocol})')
        
        return {
            'version': version,
            'header_length': header_length,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': protocol_name,
            'src_ip': src_addr,
            'dest_ip': dest_addr,
            'total_length': socket.ntohs(ip_header[2])
        }
    
    def parse_tcp_header(self, data):
        """Parse TCP header."""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        
        # Extract flags
        flags = tcp_header[5]
        flag_urg = (flags & 32) >> 5
        flag_ack = (flags & 16) >> 4
        flag_psh = (flags & 8) >> 3
        flag_rst = (flags & 4) >> 2
        flag_syn = (flags & 2) >> 1
        flag_fin = flags & 1
        
        # Build flags string
        flag_list = []
        if flag_fin: flag_list.append('FIN')
        if flag_syn: flag_list.append('SYN')
        if flag_rst: flag_list.append('RST')
        if flag_psh: flag_list.append('PSH')
        if flag_ack: flag_list.append('ACK')
        if flag_urg: flag_list.append('URG')
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': ','.join(flag_list) if flag_list else 'None',
            'header_length': 20
        }
    
    def parse_udp_header(self, data):
        """Parse UDP header."""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        return {
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3],
            'header_length': 8
        }
    
    def format_payload(self, data, max_bytes=50):
        """Format payload data for display."""
        if not data:
            return "No payload data"
        
        # Limit payload display
        display_data = data[:max_bytes]
        
        # Try to decode as text
        try:
            text = display_data.decode('utf-8', errors='ignore')
            if text.isprintable():
                return f"Text: {text[:100]}{'...' if len(text) > 100 else ''}"
        except:
            pass
        
        # Display as hex
        hex_str = ' '.join(f'{b:02x}' for b in display_data)
        return f"Hex: {hex_str}{'...' if len(data) > max_bytes else ''}"
    
    def analyze_packet(self, packet_data):
        """Analyze a captured packet and extract information."""
        try:
            analysis = {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'size': len(packet_data)
            }
            
            offset = 0
            
            # Parse Ethernet header (Linux/Mac)
            if not sys.platform.startswith('win'):
                eth_info = self.parse_ethernet_header(packet_data)
                analysis['ethernet'] = eth_info
                offset = eth_info['header_length']
                
                # Skip non-IP packets
                if eth_info['protocol'] != 0x0800:  # Not IPv4
                    return None
            
            # Parse IP header
            ip_info = self.parse_ip_header(packet_data[offset:])
            analysis['ip'] = ip_info
            offset += ip_info['header_length']
            
            # Parse transport layer
            if ip_info['protocol'] == 6:  # TCP
                tcp_info = self.parse_tcp_header(packet_data[offset:])
                analysis['tcp'] = tcp_info
                offset += tcp_info['header_length']
                
                # Get payload
                payload = packet_data[offset:]
                analysis['payload'] = self.format_payload(payload)
                
            elif ip_info['protocol'] == 17:  # UDP
                udp_info = self.parse_udp_header(packet_data[offset:])
                analysis['udp'] = udp_info
                offset += udp_info['header_length']
                
                # Get payload
                payload = packet_data[offset:]
                analysis['payload'] = self.format_payload(payload)
            
            return analysis
            
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Error analyzing packet: {e}")
            return None
    
    def display_packet(self, analysis):
        """Display packet analysis in a formatted way."""
        if not analysis:
            return
            
        print(f"\n{'='*80}")
        print(f"📦 PACKET #{self.packets_captured} - {analysis['timestamp']} ({analysis['size']} bytes)")
        print(f"{'='*80}")
        
        # Ethernet info (if available)
        if 'ethernet' in analysis:
            eth = analysis['ethernet']
            print(f"🔗 ETHERNET: {eth['src_mac']} → {eth['dest_mac']} (Type: 0x{eth['protocol']:04x})")
        
        # IP info
        ip = analysis['ip']
        print(f"🌐 IP: {ip['src_ip']} → {ip['dest_ip']} ({ip['protocol_name']}) TTL:{ip['ttl']}")
        
        # Transport layer info
        if 'tcp' in analysis:
            tcp = analysis['tcp']
            print(f"🚀 TCP: Port {tcp['src_port']} → {tcp['dest_port']} [Flags: {tcp['flags']}]")
            if self.verbose:
                print(f"    Seq: {tcp['seq_num']}, Ack: {tcp['ack_num']}")
                
        elif 'udp' in analysis:
            udp = analysis['udp']
            print(f"📡 UDP: Port {udp['src_port']} → {udp['dest_port']} (Length: {udp['length']})")
        
        # Payload info
        if 'payload' in analysis and self.verbose:
            print(f"📄 PAYLOAD: {analysis['payload']}")
    
    def start_capture(self):
        """Start packet capture process."""
        print(f"🎯 Starting Network Packet Sniffer")
        print(f"📊 Capturing {self.packet_count} packets...")
        print(f"⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not sys.platform.startswith('win'):
            print(f"🔌 Interface: {self.interface or 'All interfaces'}")
        
        print(f"{'='*80}")
        
        self.create_socket()
        self.running = True
        
        try:
            while self.running and self.packets_captured < self.packet_count:
                # Receive packet
                packet_data, addr = self.sock.recvfrom(65535)
                
                # Analyze packet
                analysis = self.analyze_packet(packet_data)
                
                if analysis:
                    self.packets_captured += 1
                    self.display_packet(analysis)
                    
        except KeyboardInterrupt:
            print(f"\n⏹️  Capture interrupted by user")
        except Exception as e:
            print(f"\n❌ Error during capture: {e}")
        finally:
            self.stop_capture()
    
    def stop_capture(self):
        """Stop packet capture and cleanup."""
        self.running = False
        
        if hasattr(self, 'sock'):
            if sys.platform.startswith('win'):
                # Disable promiscuous mode on Windows
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except:
                    pass
            self.sock.close()
        
        print(f"\n{'='*80}")
        print(f"📈 CAPTURE SUMMARY")
        print(f"{'='*80}")
        print(f"📦 Total packets captured: {self.packets_captured}")
        print(f"⏰ Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"✅ Capture completed successfully!")

def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Professional Network Packet Sniffer - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_sniffer.py                    # Capture 10 packets
  python packet_sniffer.py -c 50 -v          # Capture 50 packets with verbose output
  python packet_sniffer.py -i eth0 -c 20     # Capture 20 packets on eth0 interface
  
Note: Requires administrator/root privileges for packet capture.
        """
    )
    
    parser.add_argument('-c', '--count', type=int, default=10,
                       help='Number of packets to capture (default: 10)')
    parser.add_argument('-i', '--interface', type=str,
                       help='Network interface to capture from (Linux/Mac only)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output (show payloads and details)')
    
    args = parser.parse_args()
    
    # Create and start sniffer
    sniffer = NetworkSniffer(
        interface=args.interface,
        packet_count=args.count,
        verbose=args.verbose
    )
    
    try:
        sniffer.start_capture()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()