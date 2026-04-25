# WebRTC / STUN Peer IP Scanner

A pair of scripts (**Bash** + **PowerShell**) that capture live network traffic, extract peer IP addresses from WebRTC/STUN packets, and query **ipinfo.io** for geolocation and organisation info on each newly discovered peer.

> **learning project** — intended to understand how WebRTC peer discovery works at the network level by analysing your own traffic.

---

## Files

| File | Platform |
|---|---|
| `stun_scanner.sh` | Linux / macOS (Bash) |
| `stun_scanner.ps1` | Windows (PowerShell) |

---

## How it works

1. **TShark** sniffs live traffic and filters only `stun` protocol packets
2. The script reads TShark output line by line in real time
3. It automatically identifies and **excludes**:
   - Your own public IP (`stun.xor_mapped_address` — the XOR-MAPPED-ADDRESS the STUN server echoes back)
   - The STUN server IP itself (auto-detected from packet direction)
   - All private/RFC-1918/loopback/multicast ranges
   - Any extra IPs you provide via an exclusion file
4. Every new **public peer IP** is looked up via `curl https://ipinfo.io/<ip>/json`
5. Results (org, location, hostname) are printed to the terminal

---

## Prerequisites

### Linux (Bash)

| Tool | Install |
|---|---|
| `tshark` | `sudo apt install tshark` |
| `curl` | `sudo apt install curl` |
| `python3` | `sudo apt install python3` *(only needed for JSON exclusion files)* |

During TShark installation you will be asked whether non-root users can capture packets. Choose **Yes**, or always run the script with `sudo`.

To verify your install:
```bash
tshark --version
curl --version
```

### Windows (PowerShell)

| Tool | Install |
|---|---|
| **Wireshark** (includes `tshark`) | Download from [wireshark.org](https://www.wireshark.org/download.html) — make sure to tick **TShark** during setup |
| **PowerShell 5.1+** | Built into Windows 10/11 |
| **curl / Invoke-RestMethod** | Built into PowerShell — no extra install needed |

After installing Wireshark, make sure `tshark` is on your PATH. Open a new PowerShell window and run:
```powershell
tshark --version
```

If it says "not recognised", add Wireshark's folder to your PATH:
```
C:\Program Files\Wireshark
```

---

## Finding your network interface

You must tell TShark which interface to listen on.

**Linux:**
```bash
tshark -D
# Example output:
# 1. eth0
# 2. wlan0
# 3. lo (Loopback)
```
Use the name (e.g. `wlan0`) or the number.

**Windows:**
```powershell
tshark -D
# Example output:
# 1. \Device\NPF_{...}  (Wi-Fi)
# 2. \Device\NPF_{...}  (Ethernet)
# 3. \Device\NPF_Loopback
```
Use the **number** (e.g. `6`) that corresponds to your active network adapter (usually Wi-Fi for laptops).

---

## Usage

### Linux — Bash

```bash
# Make the script executable (first time only)
chmod +x stun_scanner.sh

# Basic — capture on wlan0
sudo ./stun_scanner.sh -i wlan0

# With a custom exclusion file
sudo ./stun_scanner.sh -i wlan0 -e excluded.txt

# Auto-stop after 2 minutes
sudo ./stun_scanner.sh -i wlan0 -t 120

# All options together
sudo ./stun_scanner.sh -i wlan0 -e excluded.json -t 120

# Show help
./stun_scanner.sh -h
```

### Windows — PowerShell

```powershell
# Allow local scripts to run (first time only, run as Administrator)
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

# Basic — interface index 6
.\stun_scanner.ps1 -Interface 6

# With a custom exclusion file
.\stun_scanner.ps1 -Interface 6 -ExclFile excluded.txt

# Auto-stop after 2 minutes
.\stun_scanner.ps1 -Interface 6 -Duration 120

# All options together
.\stun_scanner.ps1 -Interface 6 -ExclFile excluded.json -Duration 120

# Show help
.\stun_scanner.ps1 -Help
```

> **Note for Windows:** TShark requires **Npcap** (installed automatically with Wireshark) to capture packets. If you get a permission error, run PowerShell **as Administrator**.

---

## TShark command explained

Both scripts run the following TShark command internally:

```
tshark -i <interface> -l -Y "stun" -T fields
       -e ip.src
       -e ip.dst
       -e stun.xor_mapped_address
       -e stun.att.ipv4
       -E separator=|
```

| Flag | Meaning |
|---|---|
| `-i <interface>` | Which network card to capture from |
| `-l` | Line-buffered output — prints each packet immediately instead of waiting |
| `-Y "stun"` | Display filter — only show STUN protocol packets (covers all ICE/WebRTC negotiation) |
| `-T fields` | Output only specific fields, not full packet info |
| `-e ip.src` | Source IP of each packet |
| `-e ip.dst` | Destination IP of each packet |
| `-e stun.xor_mapped_address` | The XOR-MAPPED-ADDRESS attribute — your own public IP echoed by the STUN server |
| `-e stun.att.ipv4` | Raw MAPPED-ADDRESS or peer-reflexive candidate — may contain peer IP |
| `-E separator=\|` | Separate fields with a pipe character for easy parsing |

---

## Exclusion file format

You can pass a `.txt` or `.json` file to skip specific IPs or ranges.

**TXT format** — one entry per line, `#` for comments:
```
# Google STUN servers
74.125.
# Cloudflare
1.1.1.1
# Specific address
5.6.7.8
```

**JSON format:**
```json
{
  "excluded": [
    "74.125.",
    "1.1.1.1",
    "5.6.7.8"
  ]
}
```

> Entries are **prefix-matched**: `74.125.` will exclude any IP starting with those digits (the entire Google range). Exact IPs also work.

---

## Built-in excluded ranges (always applied)

The following are always excluded regardless of your exclusion file:

- `127.x.x.x` — loopback
- `10.x.x.x` — RFC-1918 private
- `172.16–31.x.x` — RFC-1918 private
- `192.168.x.x` — RFC-1918 private
- `169.254.x.x` — link-local
- `224–235.x.x.x` — multicast
- `0.0.0.0` and `255.255.255.255`
- Your own public IP (auto-detected from XOR-MAPPED-ADDRESS)
- The STUN server IP (auto-detected from packet direction)

---

## Tips

- Start your WebRTC call (Google Meet, Discord, etc.) **after** launching the script so the STUN handshake is captured from the beginning.
- If you only see STUN server IPs and no peer IPs, the call may be using a **TURN relay** — in that case only the relay server's IP is visible in traffic, not the peer's.
- Use `-t 120` to capture a fixed window instead of running indefinitely.
- The script deduplicates: each peer IP is only looked up **once** per session.

---

## License

MIT — free to use, modify, and share.
