#!/usr/bin/env python3
"""Simple multi-threaded TCP connect port scanner (standard library only).

Use only on systems you own or have written permission to test.
"""
import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017]

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb",
}

NOTICE = "Use only on systems you own or are authorized to test."


def parse_ports(spec):
    """Parse '22,80,1-1024' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError(f"bad range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock, port, host):
    """Try to read a short banner. Sends a tiny HTTP request on web ports."""
    try:
        if port in (80, 8000, 8080):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(256)
        return data.decode("utf-8", "replace").strip().splitlines()[0][:100] if data.strip() else ""
    except (OSError, IndexError):
        return ""


def scan_port(host, port, timeout, banner):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            info = {"port": port, "state": "open", "service": service_name(port)}
            if banner:
                info["banner"] = grab_banner(s, port, host)
            return info
    except OSError:
        return None


def scan(host, ports, timeout=1.0, threads=100, banner=False):
    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = ex.map(lambda p: scan_port(host, p, timeout, banner), ports)
    return sorted((r for r in results if r), key=lambda r: r["port"])


def build_parser():
    p = argparse.ArgumentParser(description="Simple TCP connect port scanner. " + NOTICE)
    p.add_argument("host", help="target hostname or IP (e.g. localhost, scanme.nmap.org)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("-p", "--ports", default="1-1024", help="ports, e.g. 22,80,443 or 1-1000 (default 1-1024)")
    g.add_argument("--common", action="store_true", help="scan a list of common ports only")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per connection (default 1.0)")
    p.add_argument("-T", "--threads", type=int, default=100, help="worker threads (default 100)")
    p.add_argument("-b", "--banner", action="store_true", help="try to grab a service banner")
    p.add_argument("-o", "--output", choices=["text", "json"], default="text", help="output format")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        ports = COMMON_PORTS if args.common else parse_ports(args.ports)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"error: cannot resolve {args.host}", file=sys.stderr)
        return 2
    start = time.time()
    open_ports = scan(args.host, ports, args.timeout, args.threads, args.banner)
    elapsed = round(time.time() - start, 2)
    if args.output == "json":
        print(json.dumps({"host": args.host, "ip": ip, "scanned": len(ports),
                          "elapsed_seconds": elapsed, "open_ports": open_ports}, indent=2))
    else:
        print(f"[!] {NOTICE}")
        print(f"Scanning {args.host} ({ip}), {len(ports)} ports")
        print(f"{'PORT':<8}{'STATE':<8}{'SERVICE':<14}BANNER")
        for r in open_ports:
            print(f"{r['port']:<8}{r['state']:<8}{r['service']:<14}{r.get('banner', '')}")
        print(f"Done: {len(open_ports)} open of {len(ports)} scanned in {elapsed}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
