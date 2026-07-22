"""
Generates a synthetic but realistic labelled dataset of network flows.

Each row is one network "flow" (a burst of packets between a source and
destination over a short window) described by numeric features, plus a
label: 0 = benign, 1 = malicious.

Malicious flows are generated from four archetypal attack patterns so the
model learns more than one shape of "bad":
  - port_scan     : many tiny, fast connections to many different ports
  - dos_burst     : huge packet/byte counts in a very short duration
  - brute_force   : many short connections to a single port (e.g. SSH/RDP)
  - exfiltration  : long duration, very high outbound byte count, few packets
"""
import numpy as np
import pandas as pd
import os

RNG = np.random.default_rng(42)

FEATURES = [
    "duration_ms",
    "packet_count",
    "byte_count",
    "packets_per_sec",
    "avg_packet_size",
    "src_port",
    "dst_port",
    "protocol",       # 0=TCP, 1=UDP, 2=ICMP
    "syn_ratio",      # fraction of packets that are SYN (scan/dos signal)
    "unique_ports_touched",
]


def _protocol_col(n, weights=(0.75, 0.20, 0.05)):
    return RNG.choice([0, 1, 2], size=n, p=weights)


def benign_flows(n):
    duration = RNG.normal(800, 400, n).clip(20, 5000)
    packet_count = RNG.normal(40, 20, n).clip(2, 300)
    avg_packet_size = RNG.normal(500, 150, n).clip(40, 1500)
    byte_count = packet_count * avg_packet_size
    packets_per_sec = packet_count / (duration / 1000).clip(min=0.01)
    src_port = RNG.integers(1024, 65535, n)
    dst_port = RNG.choice([80, 443, 22, 53, 25, 3306, 8080], size=n)
    protocol = _protocol_col(n)
    syn_ratio = RNG.uniform(0.0, 0.15, n)
    unique_ports_touched = RNG.integers(1, 3, n)
    label = np.zeros(n, dtype=int)
    return _frame(duration, packet_count, byte_count, packets_per_sec,
                  avg_packet_size, src_port, dst_port, protocol,
                  syn_ratio, unique_ports_touched, label)


def port_scan_flows(n):
    duration = RNG.normal(150, 60, n).clip(5, 500)
    packet_count = RNG.normal(5, 2, n).clip(1, 15)
    avg_packet_size = RNG.normal(60, 15, n).clip(40, 100)
    byte_count = packet_count * avg_packet_size
    packets_per_sec = packet_count / (duration / 1000).clip(min=0.01)
    src_port = RNG.integers(1024, 65535, n)
    dst_port = RNG.integers(1, 65535, n)
    protocol = np.zeros(n, dtype=int)  # mostly TCP SYN scans
    syn_ratio = RNG.uniform(0.85, 1.0, n)
    unique_ports_touched = RNG.integers(20, 500, n)
    label = np.ones(n, dtype=int)
    return _frame(duration, packet_count, byte_count, packets_per_sec,
                  avg_packet_size, src_port, dst_port, protocol,
                  syn_ratio, unique_ports_touched, label)


def dos_burst_flows(n):
    duration = RNG.normal(100, 40, n).clip(5, 400)
    packet_count = RNG.normal(5000, 2000, n).clip(500, 20000)
    avg_packet_size = RNG.normal(80, 20, n).clip(40, 200)
    byte_count = packet_count * avg_packet_size
    packets_per_sec = packet_count / (duration / 1000).clip(min=0.01)
    src_port = RNG.integers(1024, 65535, n)
    dst_port = RNG.choice([80, 443, 53], size=n)
    protocol = _protocol_col(n, weights=(0.5, 0.45, 0.05))
    syn_ratio = RNG.uniform(0.6, 1.0, n)
    unique_ports_touched = RNG.integers(1, 3, n)
    label = np.ones(n, dtype=int)
    return _frame(duration, packet_count, byte_count, packets_per_sec,
                  avg_packet_size, src_port, dst_port, protocol,
                  syn_ratio, unique_ports_touched, label)


def brute_force_flows(n):
    duration = RNG.normal(300, 100, n).clip(20, 1000)
    packet_count = RNG.normal(15, 5, n).clip(4, 40)
    avg_packet_size = RNG.normal(120, 30, n).clip(40, 300)
    byte_count = packet_count * avg_packet_size
    packets_per_sec = packet_count / (duration / 1000).clip(min=0.01)
    src_port = RNG.integers(1024, 65535, n)
    dst_port = RNG.choice([22, 3389, 21, 23], size=n)
    protocol = np.zeros(n, dtype=int)
    syn_ratio = RNG.uniform(0.3, 0.6, n)
    unique_ports_touched = RNG.integers(1, 2, n)
    label = np.ones(n, dtype=int)
    return _frame(duration, packet_count, byte_count, packets_per_sec,
                  avg_packet_size, src_port, dst_port, protocol,
                  syn_ratio, unique_ports_touched, label)


def exfiltration_flows(n):
    duration = RNG.normal(6000, 2000, n).clip(2000, 15000)
    packet_count = RNG.normal(300, 100, n).clip(50, 1000)
    avg_packet_size = RNG.normal(1400, 100, n).clip(800, 1500)
    byte_count = packet_count * avg_packet_size * RNG.uniform(3, 8, n)
    packets_per_sec = packet_count / (duration / 1000).clip(min=0.01)
    src_port = RNG.integers(1024, 65535, n)
    dst_port = RNG.choice([443, 22, 21], size=n)
    protocol = np.zeros(n, dtype=int)
    syn_ratio = RNG.uniform(0.0, 0.1, n)
    unique_ports_touched = RNG.integers(1, 2, n)
    label = np.ones(n, dtype=int)
    return _frame(duration, packet_count, byte_count, packets_per_sec,
                  avg_packet_size, src_port, dst_port, protocol,
                  syn_ratio, unique_ports_touched, label)


def _frame(duration, packet_count, byte_count, packets_per_sec, avg_packet_size,
           src_port, dst_port, protocol, syn_ratio, unique_ports_touched, label):
    return pd.DataFrame({
        "duration_ms": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packets_per_sec": packets_per_sec,
        "avg_packet_size": avg_packet_size,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "syn_ratio": syn_ratio,
        "unique_ports_touched": unique_ports_touched,
        "label": label,
    })


def generate(n_benign=4000, n_each_attack=1000, out_path=None):
    parts = [
        benign_flows(n_benign),
        port_scan_flows(n_each_attack),
        dos_burst_flows(n_each_attack),
        brute_force_flows(n_each_attack),
        exfiltration_flows(n_each_attack),
    ]
    df = pd.concat(parts, ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    if out_path:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        df.to_csv(out_path, index=False)
    return df


if __name__ == "__main__":
    here = os.path.dirname(__file__)
    df = generate(out_path=os.path.join(here, "traffic_dataset.csv"))
    print(f"Generated {len(df)} rows -> {os.path.join(here, 'traffic_dataset.csv')}")
    print(df["label"].value_counts())
