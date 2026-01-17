#!/usr/bin/env python3
"""wifi_mitm_detector.py

WiFi MitM Detector (defensive)
- ARP spoofing indicators (IP->MAC changes for ARP replies)
- DNS spoofing indicators (same qname answered by multiple A/AAAA IPs within a short window)
- 802.11 deauth/disassoc flood indicators (rate-based)

Notes
- Requires monitor mode to see 802.11 management frames (deauth/disassoc).
- You may still detect ARP/DNS on normal (managed) mode for your own host/network.

Run (Linux):
  sudo python3 wifi_mitm_detector.py wlan0mon

Dependencies:
  scapy

Optional:
  numpy (not required; kept optional)
"""

from __future__ import annotations

import time
import threading
from collections import defaultdict, Counter, deque
from datetime import datetime

try:
    import numpy as np  # noqa: F401
except Exception:
    np = None  # optional

from scapy.all import sniff, ARP, DNS, DNSQR, DNSRR, Dot11Deauth, Dot11Disas, conf  # type: ignore


class WiFiMitMDetector:
    def __init__(
        self,
        interface: str = "wlan0mon",
        dns_window_s: int = 300,
        deauth_window_s: int = 30,
        deauth_threshold: int = 20,
        stats_interval_s: int = 30,
        bpf_filter: str | None = None,
    ):
        self.interface = interface
        self.dns_window_s = dns_window_s
        self.deauth_window_s = deauth_window_s
        self.deauth_threshold = deauth_threshold
        self.stats_interval_s = stats_interval_s
        self.bpf_filter = bpf_filter

        # state
        self.arp_cache: dict[str, str] = {}  # IP -> MAC
        self.dns_answers: dict[str, deque[tuple[float, str]]] = defaultdict(deque)  # qname -> [(ts, ip), ...]
        self.deauth_events: dict[str, deque[float]] = defaultdict(deque)  # bssid -> [ts, ts, ...]

        self.alert_counts = Counter()
        self.running = False

        # Silence scapy runtime warnings a bit
        conf.verb = 0

    @staticmethod
    def _now() -> float:
        return time.time()

    def _prune_deque(self, dq: deque, window_s: int) -> None:
        cutoff = self._now() - window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def print_banner(self) -> None:
        print("=" * 72)
        print(" WiFi MitM Detector (Defensive) - ARP / DNS / Deauth indicators")
        print("=" * 72)
        print(f"Interface: {self.interface}")
        print(f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 72)

    # --------------------------- detections ---------------------------
    def is_arp_spoof(self, pkt):
        """Detect ARP spoofing by observing IP->MAC changes for ARP replies."""
        if ARP in pkt and pkt[ARP].op == 2:  # is-at (reply)
            sender_ip = str(pkt[ARP].psrc)
            sender_mac = str(pkt[ARP].hwsrc)

            if sender_ip in self.arp_cache and self.arp_cache[sender_ip] != sender_mac:
                old = self.arp_cache[sender_ip]
                self.arp_cache[sender_ip] = sender_mac
                return True, f"{sender_ip} changed MAC {old} -> {sender_mac}"

            self.arp_cache[sender_ip] = sender_mac
        return False, None

    def is_dns_spoof(self, pkt):
        """Detect DNS spoofing by tracking a rolling window of answers per qname.

        Heuristic: if the same qname gets different A/AAAA IPs within dns_window_s,
        raise an alert.
        """
        if DNS in pkt and pkt[DNS].qr == 1 and pkt[DNS].ancount > 0:  # response with answers
            qname = None
            if pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR) and pkt[DNS].qd.qname:
                try:
                    qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".").lower()
                except Exception:
                    qname = str(pkt[DNS].qd.qname).rstrip(".").lower()

            if not qname:
                return False, None

            # collect A/AAAA answers
            ips = []
            for i in range(pkt[DNS].ancount):
                rr = pkt[DNS].an[i]
                if isinstance(rr, DNSRR) and rr.type in (1, 28):  # A=1, AAAA=28
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        try:
                            rdata = rdata.decode(errors="ignore")
                        except Exception:
                            rdata = str(rdata)
                    ips.append(str(rdata))

            if not ips:
                return False, None

            dq = self.dns_answers[qname]
            now = self._now()
            for ip in ips:
                dq.append((now, ip))

            # prune old entries
            cutoff = now - self.dns_window_s
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            uniq = sorted({ip for (_, ip) in dq})
            if len(uniq) > 1:
                # Some domains legitimately rotate IPs (CDNs). This is just an indicator.
                return True, f"{qname} answered by multiple IPs in {self.dns_window_s}s: {uniq}"

        return False, None

    def is_deauth_flood(self, pkt):
        """Detect 802.11 deauth/disassoc floods by rate."""
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            # addr3 is typically BSSID; fall back if missing
            bssid = getattr(pkt, "addr3", None) or getattr(pkt, "addr2", None) or "unknown"
            dq = self.deauth_events[str(bssid)]
            dq.append(self._now())

            cutoff = self._now() - self.deauth_window_s
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) > self.deauth_threshold:
                return True, f"{bssid} seen {len(dq)} deauth/disassoc frames in {self.deauth_window_s}s"
        return False, None

    # --------------------------- runtime ---------------------------
    def packet_handler(self, pkt):
        alerts = []

        arp_alert, arp_msg = self.is_arp_spoof(pkt)
        if arp_alert:
            self.alert_counts["arp"] += 1
            alerts.append(("ARP SPOOF", arp_msg))

        dns_alert, dns_msg = self.is_dns_spoof(pkt)
        if dns_alert:
            self.alert_counts["dns"] += 1
            alerts.append(("DNS SPOOF", dns_msg))

        deauth_alert, deauth_msg = self.is_deauth_flood(pkt)
        if deauth_alert:
            self.alert_counts["deauth"] += 1
            alerts.append(("DEAUTH", deauth_msg))

        for kind, msg in alerts:
            src = getattr(pkt, "src", "?")
            dst = getattr(pkt, "dst", "?")
            print(f"\n[!] [{kind}] {msg}")
            print(f"    Time: {datetime.now().strftime('%H:%M:%S')} | Src: {src} | Dst: {dst}")

    def stats_thread(self):
        while self.running:
            time.sleep(self.stats_interval_s)
            # show top 5 bssids
            deauth_top = sorted(((b, len(dq)) for b, dq in self.deauth_events.items()), key=lambda x: x[1], reverse=True)[:5]
            print(
                f"\n[*] Stats | ARP IPs: {len(self.arp_cache)} | DNS Qnames: {len(self.dns_answers)} | "
                f"Alerts: {dict(self.alert_counts)}"
            )
            if deauth_top:
                print("    Deauth window counts (top): " + ", ".join([f"{b}={c}" for b, c in deauth_top]))

    def run(self, duration: int = 3600):
        self.running = True
        self.print_banner()

        t = threading.Thread(target=self.stats_thread, daemon=True)
        t.start()

        try:
            print(f"[*] Monitoring {self.interface} for {duration}s (Ctrl+C to stop)")
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                timeout=duration,
                filter=self.bpf_filter,
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
        finally:
            self.running = False


def main():
    import argparse

    ap = argparse.ArgumentParser(description="WiFi MitM Detector (defensive indicators)")
    ap.add_argument("iface", nargs="?", default="wlan0mon", help="Interface (e.g., wlan0mon)")
    ap.add_argument("--duration", type=int, default=0, help="Seconds to run (0 = run until Ctrl+C)")
    ap.add_argument("--dns-window", type=int, default=300, help="DNS answer window in seconds")
    ap.add_argument("--deauth-window", type=int, default=30, help="Deauth counting window in seconds")
    ap.add_argument("--deauth-threshold", type=int, default=20, help="Alert threshold within deauth window")
    ap.add_argument("--stats", type=int, default=30, help="Stats print interval in seconds")
    ap.add_argument("--bpf", type=str, default=None, help="Optional BPF filter (e.g., 'arp or udp port 53')")
    args = ap.parse_args()

    duration = args.duration if args.duration and args.duration > 0 else 10**9

    print("WiFi MitM Detector starting...")
    print("Ensure monitor mode for deauth detection (example):")
    print("  sudo airmon-ng check kill && sudo airmon-ng start wlan0")

    detector = WiFiMitMDetector(
        interface=args.iface,
        dns_window_s=args.dns_window,
        deauth_window_s=args.deauth_window,
        deauth_threshold=args.deauth_threshold,
        stats_interval_s=args.stats,
        bpf_filter=args.bpf,
    )
    detector.run(duration=duration)


if __name__ == "__main__":
    main()
