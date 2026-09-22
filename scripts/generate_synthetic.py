"""Generate realistic synthetic security logs for testing and demos.

Creates firewall, syslog, and auth log samples that mimic real-world
attack patterns mixed with normal traffic. This lets us test the full
pipeline without needing production data or the full CICIDS dataset.
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

# ── Configuration ──

INTERNAL_IPS = ["192.168.1.10", "192.168.1.25", "192.168.1.50", "10.0.0.5", "10.0.0.12"]
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.22", "45.33.32.156", "185.220.101.1",  # Normal
    "91.240.118.172", "185.156.73.54", "23.129.64.100",                # Known malicious ranges
]
HOSTNAMES = ["web-01", "db-01", "app-01", "fw-01", "mail-01"]
USERS_VALID = ["admin", "deploy", "webadmin", "dbuser", "svc-monitor"]
USERS_INVALID = ["root", "test", "guest", "oracle", "postgres", "user1", "ftpuser"]


def _random_ts(base: datetime, spread_hours: int = 24) -> datetime:
    return base - timedelta(seconds=random.randint(0, spread_hours * 3600))


def generate_firewall_logs(output_dir: Path, count: int = 500) -> Path:
    """Generate synthetic firewall CSV logs."""
    filepath = output_dir / "firewall_traffic.csv"
    base_time = datetime.now()

    rows = []
    for _ in range(count):
        is_attack = random.random() < 0.15  # 15% malicious

        if is_attack:
            src = random.choice(EXTERNAL_IPS[-3:])
            dst = random.choice(INTERNAL_IPS)
            dst_port = random.choice([22, 23, 3389, 445, 1433, 3306, 80, 443, 8080])
            action = random.choice(["deny", "drop", "deny"])
        else:
            src = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:4])
            dst = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:4])
            dst_port = random.choice([80, 443, 8080, 8443, 53, 123])
            action = "allow"

        rows.append({
            "timestamp": _random_ts(base_time).strftime("%Y-%m-%d %H:%M:%S"),
            "Source": src,
            "Source Port": random.randint(1024, 65535),
            "Destination": dst,
            "Destination Port": dst_port,
            "Protocol": random.choice(["TCP", "UDP"]),
            "Action": action,
            "Bytes Sent": random.randint(40, 50000),
            "Bytes Received": random.randint(0, 50000),
            "Application": random.choice(["web-browsing", "ssl", "ssh", "dns", "ms-sql-s", "rdp"]),
        })

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"  Generated {count} firewall events → {filepath.name}")
    return filepath


def generate_auth_logs(output_dir: Path, count: int = 500) -> Path:
    """Generate synthetic auth.log with brute force patterns."""
    filepath = output_dir / "auth.log"
    base_time = datetime.now()
    lines = []

    # Inject a brute force burst (50 rapid failures from same IP)
    attacker_ip = "91.240.118.172"
    brute_force_time = _random_ts(base_time, spread_hours=4)
    for i in range(50):
        ts = (brute_force_time + timedelta(seconds=i * 2)).strftime("%b %d %H:%M:%S")
        user = random.choice(USERS_INVALID)
        lines.append(
            f"{ts} web-01 sshd[{random.randint(1000,9999)}]: "
            f"Failed password for invalid user {user} from {attacker_ip} port {random.randint(40000,60000)} ssh2"
        )

    # Normal auth events
    for _ in range(count - 50):
        ts = _random_ts(base_time).strftime("%b %d %H:%M:%S")
        hostname = random.choice(HOSTNAMES)
        event_type = random.choices(
            ["ssh_ok", "ssh_fail", "sudo_ok", "sudo_fail", "session_open", "session_close"],
            weights=[30, 10, 15, 3, 25, 17],
        )[0]

        match event_type:
            case "ssh_ok":
                user = random.choice(USERS_VALID)
                ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:2])
                line = (
                    f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: "
                    f"Accepted publickey for {user} from {ip} port {random.randint(40000,60000)} ssh2"
                )
            case "ssh_fail":
                user = random.choice(USERS_VALID + USERS_INVALID)
                ip = random.choice(EXTERNAL_IPS)
                line = (
                    f"{ts} {hostname} sshd[{random.randint(1000,9999)}]: "
                    f"Failed password for {user} from {ip} port {random.randint(40000,60000)} ssh2"
                )
            case "sudo_ok":
                user = random.choice(USERS_VALID)
                cmd = random.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update", "/bin/cat /etc/shadow"])
                line = (
                    f"{ts} {hostname} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                    f"USER=root ; COMMAND={cmd}"
                )
            case "sudo_fail":
                user = random.choice(USERS_INVALID[:3])
                line = f"{ts} {hostname} sudo: {user} : NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"
            case "session_open":
                user = random.choice(USERS_VALID)
                line = f"{ts} {hostname} systemd-logind[{random.randint(100,999)}]: session opened for user {user}"
            case "session_close":
                user = random.choice(USERS_VALID)
                line = f"{ts} {hostname} systemd-logind[{random.randint(100,999)}]: session closed for user {user}"

        lines.append(line)

    random.shuffle(lines)
    filepath.write_text("\n".join(lines) + "\n")

    print(f"  Generated {count} auth events → {filepath.name}")
    return filepath


def generate_syslog(output_dir: Path, count: int = 500) -> Path:
    """Generate synthetic syslog messages."""
    filepath = output_dir / "syslog.log"
    base_time = datetime.now()
    lines = []

    message_templates = [
        # Normal
        ("<134>", "CRON[{pid}]: (root) CMD (/usr/lib/sa/sa1 1 1)"),
        ("<134>", "systemd[1]: Started Session {n} of user {user}."),
        ("<134>", "kernel: [UFW AUDIT] IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP"),
        ("<142>", "nginx: {src} - - GET /api/health HTTP/1.1 200"),
        ("<142>", "nginx: {src} - - POST /api/v2/data HTTP/1.1 201"),
        # Suspicious
        ("<131>", "kernel: [UFW BLOCK] IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP SPT={sport} DPT={dport}"),
        ("<131>", "sshd[{pid}]: connection refused from {src}"),
        # Critical
        ("<128>", "kernel: segfault at 0000000000000000 ip 00007f rsp 00007ff err 4"),
        ("<128>", "kernel: possible SYN flooding on port {dport}. Sending cookies."),
    ]

    for _ in range(count):
        ts = _random_ts(base_time).strftime("%b %d %H:%M:%S")
        hostname = random.choice(HOSTNAMES)
        priority, template = random.choices(
            message_templates,
            weights=[15, 15, 10, 15, 10, 12, 8, 3, 2],
        )[0]

        message = template.format(
            pid=random.randint(1000, 9999),
            n=random.randint(1, 500),
            user=random.choice(USERS_VALID),
            src=random.choice(EXTERNAL_IPS),
            dst=random.choice(INTERNAL_IPS),
            sport=random.randint(1024, 65535),
            dport=random.choice([22, 80, 443, 3306, 8080]),
        )

        app = message.split("[")[0].split(":")[0] if "[" in message or ":" in message else "kernel"
        lines.append(f"{priority}{ts} {hostname} {message}")

    filepath.write_text("\n".join(lines) + "\n")

    print(f"  Generated {count} syslog events → {filepath.name}")
    return filepath


def generate_sample_cicids(output_dir: Path, count: int = 500) -> Path:
    """Generate a small sample CICIDS-format CSV for testing."""
    filepath = output_dir / "cicids_sample.csv"
    base_time = datetime.now()

    labels_weights = [
        ("BENIGN", 70),
        ("DDoS", 5),
        ("DoS Hulk", 5),
        ("PortScan", 5),
        ("FTP-Patator", 3),
        ("SSH-Patator", 3),
        ("Bot", 3),
        ("Web Attack Brute Force", 2),
        ("Web Attack XSS", 2),
        ("Web Attack Sql Injection", 1),
        ("Infiltration", 1),
    ]
    labels = [l for l, _ in labels_weights]
    weights = [w for _, w in labels_weights]

    headers = [
        "Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port",
        "Protocol", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Flow Bytes/s", "Flow Packets/s",
        "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Label",
    ]

    rows = []
    for _ in range(count):
        label = random.choices(labels, weights=weights)[0]
        is_attack = label != "BENIGN"

        ts = _random_ts(base_time).strftime("%d/%m/%Y %H:%M")
        src_ip = random.choice(EXTERNAL_IPS if is_attack else INTERNAL_IPS + EXTERNAL_IPS[:3])
        dst_ip = random.choice(INTERNAL_IPS)

        rows.append({
            "Timestamp": ts,
            "Source IP": src_ip,
            "Source Port": random.randint(1024, 65535),
            "Destination IP": dst_ip,
            "Destination Port": random.choice([80, 443, 22, 21, 3306, 8080, 53]),
            "Protocol": random.choice([6, 17]),  # TCP=6, UDP=17
            "Flow Duration": random.randint(0, 120_000_000),
            "Total Fwd Packets": random.randint(1, 500 if is_attack else 50),
            "Total Backward Packets": random.randint(0, 300 if is_attack else 30),
            "Total Length of Fwd Packets": random.randint(40, 100000),
            "Total Length of Bwd Packets": random.randint(0, 80000),
            "Flow Bytes/s": round(random.uniform(0, 1e7), 2),
            "Flow Packets/s": round(random.uniform(0, 5000), 2),
            "Fwd Packet Length Mean": round(random.uniform(20, 1500), 2),
            "Bwd Packet Length Mean": round(random.uniform(0, 1500), 2),
            "Label": label,
        })

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"  Generated {count} CICIDS-format events → {filepath.name}")
    return filepath


def generate_all_samples(output_dir: Path, count: int = 500) -> None:
    """Generate all sample log types."""
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\nGenerating synthetic logs ({count} events each)...")
    generate_firewall_logs(output_dir, count)
    generate_auth_logs(output_dir, count)
    generate_syslog(output_dir, count)
    generate_sample_cicids(output_dir, count)
    print(f"\nAll samples written to {output_dir}/")


if __name__ == "__main__":
    generate_all_samples(Path("data/samples"), count=500)
