# Enhanced BPFDoor Scanner

An advanced detection tool for identifying BPFDoor backdoor infections in network environments.

## 🔍 Overview

**BPFDoor** is a sophisticated Linux/Unix backdoor that uses Berkeley Packet Filter (BPF) technology to passively listen for "magic packets" containing specific signatures. Unlike traditional backdoors, BPFDoor doesn't open listening ports, making it extremely difficult to detect with conventional network scanning tools.

This enhanced scanner detects **both TCP and UDP/ICMP variants** of BPFDoor, providing comprehensive coverage against all known magic number combinations.

## ⚡ Key Features

- ✅ **Dual Magic Number Detection** - Tests both TCP (0x5293) and UDP/ICMP (0x7255) variants
- ✅ **Multi-threaded Scanning** - Fast network-wide detection capabilities
- ✅ **Flexible Targeting** - Single IPs, ranges, or CIDR notation support
- ✅ **Comprehensive Port Coverage** - Customizable port lists and ranges
- ✅ **Advanced Options** - Selective magic number testing and verbose logging

## 🚀 Quick Start

### Prerequisites
```bash
# Python 3.6+ required
python3 --version

# No additional dependencies needed - uses standard library only
```

### 📺 Complete Tutorial & Testing Guide

**🎥 Watch the full walkthrough and learn how to test the scanner:**  
**[Enhanced BPFDoor Scanner Tutorial - Rifky The Cyber]([https://www.youtube.com/watch?v=YOUR_VIDEO_LINK_HERE](https://youtu.be/MNeneMz5fZE))**

*The video includes exclusive testing methodology with realistic backdoor simulation - not available in documentation!*

### Basic Usage
```bash
# Scan network for BPFDoor infections
python3 enhanced_bpfdoor_scanner.py <targets> -i <your_ip> -l <listen_port> [options]
```

## 📖 Usage Guide

### Command Syntax
```bash
python3 enhanced_bpfdoor_scanner.py <targets> [options]
```

### Required Arguments
- `targets` - IP address or CIDR range (e.g., `192.168.1.100` or `10.0.0.0/24`)
- `-i, --ip` - Your IP address for callbacks
- `-l, --listen-port` - Port to listen for responses

### Optional Arguments
- `-p, --target-ports` - Comma-separated ports to scan (default: common ports)
- `-v, --verbose` - Enable detailed scanning output
- `-m, --magic-type` - Magic number type: `tcp`, `udp`, or `both` (default: `both`)

### Usage Examples

**Basic network scan:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -i 192.168.1.50 -l 8000
```

**Scan specific host with verbose output:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.100 -i 192.168.1.50 -l 4444 -v
```

**Cross-network scanning (recommended for testing):**
```bash
# Scanner on 192.168.1.10, targeting 192.168.1.20
python3 enhanced_bpfdoor_scanner.py 192.168.1.20 -p 8022,8080,8443 -i 192.168.1.10 -l 9000 -v
```

**Custom ports and TCP magic only:**
```bash
python3 enhanced_bpfdoor_scanner.py 10.0.0.0/24 -p 22,80,443,8080 -i 10.0.0.50 -l 4444 -m tcp
```

**Port range scanning:**
```bash
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -p 1-1000 -i 192.168.1.50 -l 4444 -v
```

**Enterprise network scan:**
```bash
python3 enhanced_bpfdoor_scanner.py 172.16.0.0/16 -p 21,22,23,25,53,80,135,443,445,3389 -i 172.16.1.100 -l 9000
```

## 🧪 Advanced Testing Environment

### BPFDoor Simulator Usage
For comprehensive testing and educational purposes, this repository includes an advanced BPFDoor simulator:

```bash
# Basic simulator usage
python3 advanced_bpfdoor_sim.py --ip <target_ip> --ports <port_list>

# Example with custom IP and ports
python3 advanced_bpfdoor_sim.py --ip 192.168.1.23 --ports 8022,8080,8443
```

#### Simulator Arguments
- `--ip` - IP address to bind the simulator (required)
- `--ports` - Comma-separated list of ports to listen on (required)

#### Available Capabilities
- ✅ **TCP Magic Detection** - Responds to 0x5293 packets
- ✅ **UDP/ICMP Magic Detection** - Responds to 0x7255 packets  
- ✅ **Reverse Shell Simulation** - Establishes backdoor connections
- ✅ **SSH Backdoor Simulation** - Interactive terminal access
- ✅ **Multi-port Listening** - Simultaneous port monitoring

*📺 [Complete simulator setup and usage available in video tutorial](https://www.youtube.com/watch?v=YOUR_VIDEO_LINK_HERE)*

## 🧪 Advanced Testing Environment

### BPFDoor Simulator Usage
For comprehensive testing and educational purposes, this repository includes an advanced BPFDoor simulator:

```bash
# Basic simulator usage
python3 advanced_bpfdoor_sim.py --ip <target_ip> --ports <port_list>

# Example with custom IP and ports
python3 advanced_bpfdoor_sim.py --ip 192.168.1.23 --ports 8022,8080,8443
```

#### Simulator Arguments
- `--ip` - IP address to bind the simulator (required)
- `--ports` - Comma-separated list of ports to listen on (required)

#### Available Capabilities
- ✅ **TCP Magic Detection** - Responds to 0x5293 packets
- ✅ **UDP/ICMP Magic Detection** - Responds to 0x7255 packets  
- ✅ **Reverse Shell Simulation** - Establishes backdoor connections
- ✅ **SSH Backdoor Simulation** - Interactive terminal access
- ✅ **Multi-port Listening** - Simultaneous port monitoring

*📺 [Complete simulator setup and usage available in video tutorial](https://www.youtube.com/watch?v=YOUR_VIDEO_LINK_HERE)*

## 🔧 Technical Details

### Magic Numbers Detected
- **TCP Magic**: `0x5293` - Used for TCP-based BPFDoor variants
- **UDP/ICMP Magic**: `0x7255` - Used for UDP and ICMP-based variants

### Detection Method
1. **Port Discovery** - Identifies open TCP services
2. **Magic Packet Injection** - Sends crafted packets with specific signatures
3. **Response Monitoring** - Listens for UDP callback responses
4. **Infection Confirmation** - Validates active backdoor presence

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

## 📊 Expected Output

### Successful Detection
```
██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗ ██████╗     
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗    
Enhanced BPFDoor Scanner v2.0
Enhanced by Rifky The Cyber - Based on SnapAttack Research Team's work

[*] Magic number configuration:
    - TCP Magic: 0x5293 (payload: 52930000)
    - UDP/ICMP Magic: 0x7255 (payload: 72550000)

[-] UDP server started at 192.168.1.50 on port 9000
[-] Scanning 3 ports on 1 targets with 2 magic number(s)
[+] 192.168.1.100 port 8022 open - sending TCP magic
[+] 192.168.1.100 port 8022 open - sending UDP magic
[!] 192.168.1.100 has been compromised
[*] Uh oh! We found 1 hosts that we believe to be compromised:
192.168.1.100
```

### Clean Network
```
[*] Scanning complete! Waiting 30 seconds for any remaining UDP messages and reverse shells...
[*] Good news! None of the target hosts appear to be compromised!
```

## 🎯 Testing Your Scanner

**Want to verify the scanner works correctly and see actual backdoor behavior?**

### Cross-Network Testing Setup

**Step 1: Set up listener for backdoor connections**
```bash
# On scanner machine - listen for backdoor callbacks
nc -l 9000
```

**Step 2: Run the scanner from another terminal**
```bash
# Scan target network for BPFDoor infections
python3 enhanced_bpfdoor_scanner.py 192.168.1.0/24 -p 8022,8080,8443 -i 192.168.1.50 -l 9000 -v
```

**If BPFDoor is detected, you'll see backdoor connections in your netcat session!**

### Advanced Testing Commands

Once connected via backdoor, try these commands:
```bash
# System information
whoami
uname -a
pwd

# Network reconnaissance  
ip addr show
netstat -an

# File system access
ls -la
cat /etc/passwd

# Process enumeration
ps aux | head -10

# Exit backdoor session
exit
```

🎥 **[Watch the complete testing tutorial](https://www.youtube.com/watch?v=YOUR_VIDEO_LINK_HERE)** to see:
- Advanced testing environments and scenarios
- Realistic backdoor simulation and response
- Professional penetration testing techniques
- Real-world deployment considerations

*The video contains exclusive testing methodologies and simulation setup not available in documentation!*

## ⚠️ Important Security Notes

### Usage Guidelines
- **✅ Authorized testing only** - Use only on networks you own or have explicit permission to test
- **✅ Isolated environments** - Recommended for security labs and research
- **✅ Educational purposes** - Designed for defensive security and awareness

### Network Requirements
- **Direct connectivity** - Scanner and targets must be able to communicate
- **Firewall considerations** - Ensure UDP responses can reach scanner
- **Cross-network testing** - More realistic than localhost testing

### Limitations
- **Active detection method** - Scanner triggers backdoor responses (not passive)
- **Network dependent** - Requires proper routing between hosts
- **UDP response timing** - May need extended wait times for complex scenarios

## ☕ Support Me, Support Rifky The Cyber YouTube Channel

If you find this tool helpful and would like to support its development, you can buy me a coffee!

**[☕ Support on Ko-fi](https://ko-fi.com/rifkythecyber)**

Or scan the QR code below:

<img src="https://github.com/user-attachments/assets/a6529b25-06eb-4072-9077-6682aad0807a" alt="Donate" width="200">

## 🤝 Contributing

Feel free to submit issues, suggestions, or improvements. This project is focused on defensive security research and education.

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

**⚠️ Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
