# Enhanced BPFDoor Scanner

A comprehensive toolkit for detecting and testing BPFDoor backdoor infections in network environments.

## 🔍 Overview

This repository contains enhanced tools for detecting BPFDoor malware, including both scanner and simulation capabilities for security research and network defense.

**BPFDoor** is a sophisticated backdoor that uses Berkeley Packet Filter (BPF) technology to passively listen for "magic packets" containing specific signatures. Unlike traditional backdoors, BPFDoor doesn't open listening ports, making it extremely difficult to detect with conventional network scanning tools.

## 📁 Repository Contents

- `enhanced_bpfdoor_scanner.py` - Enhanced scanner that detects both TCP and UDP/ICMP magic numbers
- `bpfdoor_sim.py` - BPFDoor simulator for testing and training purposes

## ⚡ Features

### Enhanced Scanner
- ✅ **Dual Magic Number Detection** - Tests both TCP (0x5293) and UDP/ICMP (0x7255) variants
- ✅ **Multi-threaded Scanning** - Fast network-wide detection
- ✅ **Flexible Targeting** - Single IPs or CIDR ranges
- ✅ **Comprehensive Port Coverage** - Customizable port lists and ranges
- ✅ **Verbose Logging** - Detailed scanning progress and results

### BPFDoor Simulator
- ✅ **Realistic Behavior** - Accurately simulates BPFDoor responses
- ✅ **Multi-Protocol Support** - Handles TCP, UDP, and ICMP magic packets
- ✅ **Configurable Binding** - Custom IP addresses and port combinations
- ✅ **Debug Output** - Detailed packet analysis for research

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.6+ required
python3 --version

# No additional dependencies needed - uses standard library only
```

### Basic Usage

#### 1. Start the Simulator (Terminal 1)
```bash
# Run as root for privileged ports
sudo python3 bpfdoor_sim.py --ip 192.168.1.12 --ports 22,80,443
```

#### 2. Run the Scanner (Terminal 2)
```bash
# Scan network for BPFDoor infections
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -p 22,80,443 -i 192.168.1.12 -l 8000 -v
```

## 📖 Detailed Usage

### Enhanced BPFDoor Scanner

```bash
python3 enhanced_bpfdoor_scanner.py <targets> [options]
```

#### Arguments
- `targets` - IP address or CIDR range (e.g., `192.168.1.100` or `10.0.0.0/24`)

#### Options
- `-p, --target-ports` - Comma-separated ports to scan (default: common ports)
- `-i, --ip` - Your IP address for callbacks
- `-l, --listen-port` - Port to listen for responses
- `-v, --verbose` - Enable detailed output
- `-m, --magic-type` - Magic number type: `tcp`, `udp`, or `both` (default: `both`)

#### Examples

**Scan single host:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.100 -i 192.168.1.50 -l 4444
```

**Scan network range with custom ports:**
```bash
python3 enhanced_bpfdoor_scanner.py 10.0.0.0/24 -p 22,80,443,8080 -i 10.0.0.50 -l 4444
```

**Test only TCP magic numbers:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -i 192.168.1.50 -l 4444 -m tcp
```

**Verbose scanning with port ranges:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -p 1-1000 -i 192.168.1.50 -l 4444 -v
```

### BPFDoor Simulator

```bash
python3 bpfdoor_sim.py [options]
```

#### Options
- `-i, --ip` - IP address to bind to (default: `0.0.0.0`)
- `-p, --ports` - Comma-separated ports to listen on (default: `22,80,443,8080`)

#### Examples

**Simulate on all interfaces:**
```bash
python3 bpfdoor_sim.py
```

**Simulate on specific IP:**
```bash
sudo python3 bpfdoor_sim.py --ip 192.168.1.100
```

**Custom ports:**
```bash
sudo python3 bpfdoor_sim.py --ip 192.168.1.100 --ports 22,80,443,3389,5900
```

## 🧪 Testing Scenarios

### Scenario 1: Local Testing
```bash
# Terminal 1: Start local simulator
sudo python3 bpfdoor_sim.py --ip 127.0.0.1 --ports 8022,8080,8443

# Terminal 2: Scan localhost
python3 enhanced_bpfdoor_scanner.py 127.0.0.1 -p 8022,8080,8443 -i 127.0.0.1 -l 9000
```

### Scenario 2: Network Range Testing
```bash
# Terminal 1: Simulate infected host
sudo python3 bpfdoor_sim.py --ip 192.168.1.100 --ports 22,80,443

# Terminal 2: Scan entire subnet
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -p 22,80,443 -i 192.168.1.50 -l 8000 -v
```

### Scenario 3: Magic Number Comparison
```bash
# Test TCP magic only
python3 enhanced_bpfdoor_scanner.py 192.168.1.100 -i 192.168.1.50 -l 8000 -m tcp

# Test UDP magic only  
python3 enhanced_bpfdoor_scanner.py 192.168.1.100 -i 192.168.1.50 -l 8000 -m udp
```

## 🔧 Technical Details

### Magic Numbers
- **TCP Magic**: `0x5293` - Used for TCP-based BPFDoor variants
- **UDP/ICMP Magic**: `0x7255` - Used for UDP and ICMP-based variants

### Packet Structure
```
┌─────────────┬─────────────┬─────────────┬─────────────┐
│ Magic (4B)  │ IP (4B)     │ Port (2B)   │ Pass (14B)  │
├─────────────┼─────────────┼─────────────┼─────────────┤
│ 0x52930000  │ Callback IP │ Callback    │ Password    │
│ or          │             │ Port        │ Field       │
│ 0x72550000  │             │             │             │
└─────────────┴─────────────┴─────────────┴─────────────┘
```

### Detection Process
1. **Port Scanning** - Identify open services
2. **Magic Packet Transmission** - Send crafted packets with magic numbers
3. **Response Monitoring** - Listen for UDP callbacks
4. **Infection Confirmation** - Validate backdoor presence

## ⚠️ Important Considerations

### Security Warning
- **Use only in authorized environments** - These tools can trigger active backdoors
- **Isolated testing recommended** - Use dedicated lab networks
- **Educational purposes** - Designed for security research and defense

### Network Requirements
- **Direct network access** required between scanner and targets
- **Firewall considerations** - Ensure UDP responses can reach scanner
- **Privilege requirements** - Simulator needs root for ports < 1024

### Limitations
- **TCP-based detection only** - Scanner uses TCP connections to send magic packets
- **Active detection** - Tools trigger backdoor responses (not passive)
- **Network dependent** - Requires proper routing between hosts

## 📊 Expected Output

### Successful Detection
```
██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗ ██████╗     
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗    
v2.0 - ENHANCED - By the SnapAttack Research Team

[*] Magic number configuration:
    - TCP Magic: 0x5293 (payload: 52930000)
    - UDP/ICMP Magic: 0x7255 (payload: 72550000)

[-] UDP server started at 192.168.1.50 on port 8000
[-] Scanning 3 ports on 256 targets with 2 magic number(s)
[-] Scanning 192.168.1.100
[+] 192.168.1.100 port 22 open - sending TCP magic
[+] 192.168.1.100 port 22 open - sending UDP magic
[!] 192.168.1.100 has been compromised
[*] Scanning complete! Waiting 5 seconds for any remaining UDP messages...
[*] Uh oh! We found 1 hosts that we believe to be compromised:
192.168.1.100
```

### Clean Network
```
[*] Scanning complete! Waiting 5 seconds for any remaining UDP messages...
[*] Good news! None of the target hosts appear to be compromised!
```

## 🤝 Contributing

Feel free to submit issues, suggestions, or improvements. This project is focused on defensive security research and education.

## ☕ Support Me, Support Rifky The Cyber YouTube Channel

If you find this tool helpful and would like to support its development, you can buy me a coffee!

**[☕ Support on Ko-fi](https://ko-fi.com/rifkythecyber)**

Or scan the QR code below:

<img src="https://github.com/user-attachments/assets/a6529b25-06eb-4072-9077-6682aad0807a" alt="Donate" width="200">

## 🙏 Credits

This project builds upon the excellent work by the SnapAttack Research Team:
- **Original BPFDoor Scanner**: [https://github.com/snapattack/bpfdoor-scanner](https://github.com/snapattack/bpfdoor-scanner)

Special thanks to SnapAttack for their foundational research and open-source contributions to the cybersecurity community.

## 📄 License

This project is intended for educational and defensive security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🔗 References

- [BPFDoor Analysis](https://www.sandflytechnology.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)
- [Berkeley Packet Filter Documentation](https://www.kernel.org/doc/Documentation/networking/filter.txt)
- [Network Security Best Practices](https://www.nist.gov/cybersecurity)

---

**⚠️ Disclaimer**: These tools are provided for educational and authorized security testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
