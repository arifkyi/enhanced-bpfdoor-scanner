#!/usr/bin/env python3
"""
BPFDoor Simulation Script
Creates a mock infected host that responds to the scanner
FOR EDUCATIONAL/TESTING PURPOSES ONLY
"""

import socket
import threading
import struct
import time
import argparse
import sys

class BPFDoorSimulator:
    def __init__(self, listen_ip='0.0.0.0', listen_ports=[22, 80, 443]):
        self.listen_ip = listen_ip
        self.listen_ports = listen_ports
        self.servers = []
        self.running = True
        
    def parse_magic_packet(self, data):
        """Parse the magic packet structure from scanner"""
        if len(data) < 24:  # minimum packet size
            return None
            
        try:
            # Parse: flag(4) + ip(4) + port(2) + pass(14)
            # Scanner uses: bytes.fromhex('52930000') - this is big endian
            flag = struct.unpack('>I', data[0:4])[0]  # Changed to big endian
            ip_bytes = data[4:8]
            port_bytes = data[8:10]
            
            print(f"[DEBUG] Received packet: {data[:24].hex()}")
            print(f"[DEBUG] Flag: 0x{flag:08x}")
            
            # Check for magic numbers (TCP: 0x52930000, UDP: 0x72550000)
            if flag == 0x52930000:  # TCP magic
                ip = socket.inet_ntoa(ip_bytes)
                port_le = struct.unpack('<H', port_bytes)[0]
                port_be = struct.unpack('>H', port_bytes)[0]
                port = port_be if port_be == 8000 else port_le
                return {'ip': ip, 'port': port, 'protocol': 'TCP'}
            elif flag == 0x72550000:  # UDP/ICMP magic  
                ip = socket.inet_ntoa(ip_bytes)
                port_le = struct.unpack('<H', port_bytes)[0]
                port_be = struct.unpack('>H', port_bytes)[0]
                port = port_be if port_be == 8000 else port_le
                return {'ip': ip, 'port': port, 'protocol': 'UDP/ICMP'}
        except Exception as e:
            print(f"[DEBUG] Parse error: {e}")
            
        return None
    
    def handle_connection(self, conn, addr):
        """Handle incoming scanner connections"""
        try:
            print(f"[*] Connection from {addr[0]}:{addr[1]}")
            
            # Receive potential magic packet
            data = conn.recv(1024)
            if data:
                magic_info = self.parse_magic_packet(data)
                if magic_info:
                    print(f"[!] Magic packet detected from {addr[0]}")
                    print(f"    Protocol: {magic_info['protocol']}")
                    print(f"    Callback IP: {magic_info['ip']}")
                    print(f"    Callback Port: {magic_info['port']}")
                    
                    # Simulate BPFDoor response - send UDP "1" back
                    self.send_response(magic_info['ip'], magic_info['port'])
                else:
                    print(f"[*] Non-magic packet from {addr[0]}")
                    
        except Exception as e:
            print(f"[!] Error handling connection: {e}")
        finally:
            conn.close()
    
    def send_response(self, target_ip, target_port):
        """Send UDP response to scanner (simulates BPFDoor behavior)"""
        try:
            # Create UDP socket and send "1" 
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'1', (target_ip, target_port))
            sock.close()
            print(f"[+] Sent UDP response to {target_ip}:{target_port}")
        except Exception as e:
            print(f"[!] Error sending response: {e}")
    
    def start_server(self, port):
        """Start TCP server on specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.listen_ip, port))
            server.listen(5)
            server.settimeout(1)  # Non-blocking accept
            
            print(f"[*] Mock BPFDoor listening on {self.listen_ip}:{port}")
            
            while self.running:
                try:
                    conn, addr = server.accept()
                    # Handle each connection in a thread
                    thread = threading.Thread(
                        target=self.handle_connection, 
                        args=(conn, addr)
                    )
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except:
                    break
                    
        except Exception as e:
            print(f"[!] Error on port {port}: {e}")
        finally:
            server.close()
    
    def start(self):
        """Start all listening servers"""
        print("=" * 60)
        print("BPFDoor Simulator - FOR TESTING PURPOSES ONLY")
        print("=" * 60)
        
        # Start servers on multiple ports
        for port in self.listen_ports:
            thread = threading.Thread(target=self.start_server, args=(port,))
            thread.daemon = True
            thread.start()
        
        try:
            print(f"[*] Simulating infected host on {self.listen_ip}:{self.listen_ports}")
            print("[*] Waiting for scanner connections...")
            print("[*] Press Ctrl+C to stop")
            
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down simulator...")
            self.running = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='BPFDoor Simulator - FOR TESTING PURPOSES ONLY')
    parser.add_argument(
        '--ip', '-i',
        type=str,
        default='0.0.0.0',
        help='IP address to bind to (default: 0.0.0.0 - all interfaces)'
    )
    parser.add_argument(
        '--ports', '-p',
        type=str,
        default='22,80,443,8080',
        help='Comma-separated list of ports to listen on (default: 22,80,443,8080)'
    )
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("[!] Error: Invalid port list")
        sys.exit(1)
    
    # Start simulator
    simulator = BPFDoorSimulator(listen_ip=args.ip, listen_ports=ports)
    simulator.start()
