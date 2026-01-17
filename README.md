# WiFi MitM Detector (Defensive)

A lightweight **defensive** Python tool that passively sniffs traffic and flags **indicators** of:

- **ARP spoofing / gateway poisoning** (IP → MAC changes in ARP replies)
- **DNS spoofing indicators** (same domain answering to multiple IPs within a short window)
- **802.11 deauth / disassociation floods** (rate-based)

> ⚠️ This is an **indicator** tool (heuristics). CDNs and load balancers can legitimately return multiple IPs for a domain. Always validate alerts using Wireshark and your network topology.

## Requirements

- Linux + wireless card capable of monitor mode (for deauth/disassoc frames)
- Python 3.8+
- `scapy`

### Install

Debian/Ubuntu/Kali:

```bash
sudo apt update
sudo apt install -y aircrack-ng python3-pip
pip3 install --upgrade scapy
```

## Monitor mode (for WiFi management frames)

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0   # creates wlan0mon (often)
```

(Optional) lock to channel for better capture:

```bash
sudo iwconfig wlan0mon channel 6
```

## Run

```bash
sudo python3 wifi_mitm_detector.py wlan0mon
```

Run for a fixed duration (seconds):

```bash
sudo python3 wifi_mitm_detector.py wlan0mon --duration 600
```

### Useful options

- Tighten/loosen DNS window:

```bash
sudo python3 wifi_mitm_detector.py wlan0mon --dns-window 120
```

- Adjust deauth detection:

```bash
sudo python3 wifi_mitm_detector.py wlan0mon --deauth-window 30 --deauth-threshold 25
```

- BPF filter (reduce noise):

```bash
sudo python3 wifi_mitm_detector.py wlan0mon --bpf "arp or udp port 53"
```

## What it detects (how)

### 1) ARP spoofing indicator
If an **ARP reply** (`is-at`) claims an IP belongs to a **new MAC** compared to what was previously observed, it prints an alert.

### 2) DNS spoofing indicator
Tracks a rolling window of A/AAAA answers per domain (`qname`). If the same domain resolves to **multiple IPs** within the window, it prints an alert.

### 3) Deauth/disassoc flood indicator
Counts 802.11 **deauth** and **disassociation** management frames per BSSID in a time window. If the count exceeds the threshold, it prints an alert.

## Tips for real investigations

- Capture a PCAP and validate in Wireshark:

```bash
sudo tcpdump -i wlan0mon -w capture.pcap
```

- Compare alerts against:
  - Your expected gateway MAC
  - Known DNS resolvers in your network
  - AP logs / controller logs

## Legal / Ethics

Use only on networks and devices you own or have explicit permission to monitor.
