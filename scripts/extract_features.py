"""
extract_features.py

Parses one or more pcap files and computes per-device (per source MAC),
per time-window behavioral features suitable for anomaly detection.
"""

import argparse
import glob
import os
import sys
from collections import defaultdict

import numpy as np
import pandas as pd

try:
    from scapy.all import rdpcap, ARP, IP, Ether, ICMP
except ImportError:
    print("scapy is required: pip install scapy", file=sys.stderr)
    sys.exit(1)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_broadcast_or_multicast(dst_mac: str) -> bool:
    if dst_mac is None:
        return False
    dst_mac = dst_mac.lower()
    if dst_mac == BROADCAST_MAC:
        return True
    try:
        first_octet = int(dst_mac.split(":")[0], 16)
        return bool(first_octet & 0x01)
    except (ValueError, IndexError):
        return False


def collect_pcap_paths(pcap_arg: str):
    if os.path.isdir(pcap_arg):
        paths = sorted(glob.glob(os.path.join(pcap_arg, "*.pcap")) +
                       glob.glob(os.path.join(pcap_arg, "*.pcapng")))
        if not paths:
            print(f"No .pcap/.pcapng files found in {pcap_arg}", file=sys.stderr)
        return paths
    return [pcap_arg]


def parse_packets(paths):
    records = []
    for path in paths:
        print(f"Reading {path} ...")
        packets = rdpcap(path)
        for pkt in packets:
            if not pkt.haslayer(Ether):
                continue
            ts = float(pkt.time)
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst
            length = len(pkt)

            is_arp_req = pkt.haslayer(ARP) and pkt[ARP].op == 1
            is_arp_reply = pkt.haslayer(ARP) and pkt[ARP].op == 2
            is_icmp_req = False
            is_icmp_reply = False
            icmp_id_seq = None
            src_ip = None
            dst_ip = None

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            if pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                if icmp.type == 8:
                    is_icmp_req = True
                    icmp_id_seq = (icmp.id, icmp.seq)
                elif icmp.type == 0:
                    is_icmp_reply = True
                    icmp_id_seq = (icmp.id, icmp.seq)

            records.append(dict(
                ts=ts, src_mac=src_mac, dst_mac=dst_mac, length=length,
                is_arp_req=is_arp_req, is_arp_reply=is_arp_reply, is_icmp_req=is_icmp_req,
                is_icmp_reply=is_icmp_reply, icmp_id_seq=icmp_id_seq,
                src_ip=src_ip, dst_ip=dst_ip,
            ))
    return records


def compute_icmp_latencies(records):
    requests = {}
    latencies_by_mac = defaultdict(list)
    for r in records:
        if r["is_icmp_req"] and r["icmp_id_seq"] is not None:
            requests[r["icmp_id_seq"]] = (r["ts"], r["src_mac"])
        elif r["is_icmp_reply"] and r["icmp_id_seq"] is not None:
            match = requests.get(r["icmp_id_seq"])
            if match is not None:
                req_ts, req_mac = match
                if r["ts"] >= req_ts:
                    latencies_by_mac[req_mac].append(r["ts"] - req_ts)
    return latencies_by_mac


def extract_features(paths, window_seconds):
    records = parse_packets(paths)
    if not records:
        raise ValueError("No packets parsed from input pcap(s).")

    records.sort(key=lambda r: r["ts"])
    t0 = records[0]["ts"]
    t_end = records[-1]["ts"]

    # Bug fix (1b): known device set is fixed up front from the WHOLE capture,
    # so every device gets a row in every window, even windows where it sent
    # nothing at all (this is what makes "silence" a labeled state).
    all_macs = sorted({r["src_mac"] for r in records if r["src_mac"] is not None})

    rows = []
    window_start = t0
    while window_start <= t_end:
        window_end = window_start + window_seconds
        window_records = [r for r in records if window_start <= r["ts"] < window_end]

        # Bug fix (1c): the final window in a capture is often shorter than
        # window_seconds. Use the actual elapsed span for rate denominators
        # instead of the nominal window length.
        actual_duration = min(window_end, t_end) - window_start
        if actual_duration <= 0:
            actual_duration = window_seconds

        by_mac = defaultdict(list)
        for r in window_records:
            by_mac[r["src_mac"]].append(r)

        # Bug fix (1a): ICMP req/reply matching is now restricted to records
        # inside THIS window, so avg_response_latency reflects this window's
        # traffic instead of one global value copied into every row.
        window_icmp_latencies = compute_icmp_latencies(window_records)

        for mac in all_macs:
            pkts = by_mac.get(mac, [])
            pkt_count = len(pkts)

            recv_bytes = sum(
                p["length"] for p in window_records if p["dst_mac"] == mac
            )

            if pkt_count == 0:
                # Bug fix (1b): zero-filled row for an idle window instead of
                # silently dropping this device from the output entirely.
                rows.append(dict(
                    window_start=window_start,
                    device_mac=mac,
                    pkt_count=0,
                    byte_count=0,
                    mean_iat=np.nan,
                    std_iat=np.nan,
                    arp_req_count=0,
                    arp_req_rate=0.0,
                    arp_reply_count=0,
                    arp_reply_rate=0.0,
                    broadcast_ratio=0.0,
                    avg_response_latency=np.nan,
                    send_recv_ratio=0.0,
                ))
                continue

            pkts_sorted = sorted(pkts, key=lambda r: r["ts"])
            timestamps = [p["ts"] for p in pkts_sorted]
            iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([])

            byte_count = sum(p["length"] for p in pkts_sorted)
            mean_iat = float(np.mean(iats)) if len(iats) else np.nan
            std_iat = float(np.std(iats)) if len(iats) else np.nan

            arp_reqs = [p for p in pkts_sorted if p["is_arp_req"]]
            arp_req_count = len(arp_reqs)
            arp_req_rate = arp_req_count / actual_duration

            arp_replies = [p for p in pkts_sorted if p["is_arp_reply"]]
            arp_reply_count = len(arp_replies)
            arp_reply_rate = arp_reply_count / actual_duration

            bcast = sum(1 for p in pkts_sorted if is_broadcast_or_multicast(p["dst_mac"]))
            broadcast_ratio = bcast / pkt_count if pkt_count else 0.0

            lat_list = window_icmp_latencies.get(mac, [])
            avg_latency = float(np.mean(lat_list)) if lat_list else np.nan

            sent_bytes = byte_count
            send_recv_ratio = (sent_bytes / recv_bytes) if recv_bytes > 0 else float(sent_bytes > 0) * 10.0

            rows.append(dict(
                window_start=window_start,
                device_mac=mac,
                pkt_count=pkt_count,
                byte_count=byte_count,
                mean_iat=mean_iat,
                std_iat=std_iat,
                arp_req_count=arp_req_count,
                arp_req_rate=arp_req_rate,
                arp_reply_count=arp_reply_count,
                arp_reply_rate=arp_reply_rate,
                broadcast_ratio=broadcast_ratio,
                avg_response_latency=avg_latency,
                send_recv_ratio=send_recv_ratio,
            ))

        window_start = window_end

    df = pd.DataFrame(rows)
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True, help="pcap file or directory of pcaps")
    ap.add_argument("--window", type=float, default=10.0, help="window size in seconds")
    ap.add_argument("--out", required=True, help="output CSV path")
    args = ap.parse_args()

    paths = collect_pcap_paths(args.pcap)
    if not paths:
        sys.exit(1)

    df = extract_features(paths, args.window)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} feature rows to {args.out}")
    print(df.describe(include="all"))


if __name__ == "__main__":
    main()
