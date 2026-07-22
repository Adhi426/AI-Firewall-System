"""
Generates a random plausible flow (benign or one of a few attack shapes) so
the dashboard has something to show without needing real packet capture.
"""
import random

BENIGN_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
ATTACKER_IPS = [f"203.0.113.{i}" for i in range(1, 20)] + [f"198.51.100.{i}" for i in range(1, 20)]


def _benign():
    return {
        "src_ip": random.choice(BENIGN_IPS),
        "dst_ip": "10.0.0.1",
        "duration_ms": random.gauss(800, 300),
        "packet_count": random.gauss(40, 15),
        "byte_count": random.gauss(20000, 8000),
        "packets_per_sec": random.uniform(10, 80),
        "avg_packet_size": random.gauss(500, 120),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 53]),
        "protocol": "TCP",
        "syn_ratio": random.uniform(0.0, 0.15),
        "unique_ports_touched": 1,
    }


def _port_scan():
    return {
        "src_ip": random.choice(ATTACKER_IPS),
        "dst_ip": "10.0.0.1",
        "duration_ms": random.gauss(150, 50),
        "packet_count": random.gauss(5, 2),
        "byte_count": random.gauss(300, 100),
        "packets_per_sec": random.uniform(20, 60),
        "avg_packet_size": random.gauss(60, 15),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(1, 65535),
        "protocol": "TCP",
        "syn_ratio": random.uniform(0.85, 1.0),
        "unique_ports_touched": random.randint(50, 400),
    }


def _dos_burst():
    return {
        "src_ip": random.choice(ATTACKER_IPS),
        "dst_ip": "10.0.0.1",
        "duration_ms": random.gauss(100, 30),
        "packet_count": random.gauss(6000, 1500),
        "byte_count": random.gauss(500000, 100000),
        "packets_per_sec": random.uniform(2000, 8000),
        "avg_packet_size": random.gauss(80, 20),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443]),
        "protocol": "UDP",
        "syn_ratio": random.uniform(0.6, 1.0),
        "unique_ports_touched": 1,
    }


def random_flow():
    roll = random.random()
    if roll < 0.6:
        return _benign()
    elif roll < 0.8:
        return _port_scan()
    else:
        return _dos_burst()
