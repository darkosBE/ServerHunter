#!/usr/bin/env python3
# scanner.py — Improved: faster, randomized targets, robust remover & locking
"""
Improved Dark's Minecraft ServerChecker (Subnet scanner)
- Reads ips.txt (IP, IP:PORT, or domain)
- Resolves domains via mcsrvstat (HTTP) and falls back to DNS
- Randomly chooses targets from ips.txt each pass
- Scans /21 subnet (~2,046 IPs) for Minecraft servers in parallel
- Removes each target from ips.txt atomically under a file lock
- Skips MOTDs with forbidden words (case-insensitive)
- Uses multiprocessing to leverage CPU cores; threads per process for I/O
"""

from __future__ import annotations
import base64
import json
import socket
import struct
import time
import concurrent.futures
import ipaddress
import requests
import os
import tempfile
import colorama
from pymongo import MongoClient, errors
from datetime import datetime
from typing import Optional, Tuple, List
import multiprocessing
import sys
import random
import errno
import platform

colorama.init(autoreset=True)

class Color:
    WHITE = colorama.Fore.WHITE
    GREEN = colorama.Fore.LIGHTGREEN_EX
    RED = colorama.Fore.LIGHTRED_EX
    BLUE = colorama.Fore.LIGHTBLUE_EX
    YELLOW = colorama.Fore.LIGHTYELLOW_EX

# === Configuration ===
MONGO_URI = "mongodb URI HERE"
DB_NAME = "mcscanner"
COLLECTION = "servers"
PING_TIMEOUT = 1.6              # slightly lower to speed up scanning
DOMAIN_RESOLVE_TIMEOUT = 6.0
vfilter = ""                    # leave blank for all versions
FORBIDDEN_KEYWORDS = ["protect", "docs", "refer", "invalid", "be"]  # lower-case
IPS_FILE = "ips.txt"
LOCK_RETRY_DELAY = 0.01
LOCK_RETRY_MAX = 300            # ~3 seconds max waiting for lock

# MongoDB client (initialized per process)
client = None
coll = None

# Platform-specific file locking
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    import msvcrt
else:
    import fcntl

def _acquire_lock(f):
    if IS_WINDOWS:
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def _release_lock(f):
    if IS_WINDOWS:
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except Exception:
            pass
    else:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

# === Robust atomic remove with file locking ===
def remove_target_from_file(target: str) -> bool:
    attempts = 0
    while True:
        attempts += 1
        try:
            fd = os.open(IPS_FILE, os.O_RDWR | os.O_CREAT, 0o666)
            with os.fdopen(fd, "r+", encoding="utf-8") as f:
                lock_attempts = 0
                while True:
                    try:
                        _acquire_lock(f)
                        break
                    except IOError as e:
                        lock_attempts += 1
                        if lock_attempts > LOCK_RETRY_MAX:
                            raise
                        time.sleep(LOCK_RETRY_DELAY)

                f.seek(0)
                lines = f.readlines()
                found = False
                new_lines = []
                for line in lines:
                    if not found and line.strip() == target:
                        found = True
                        continue
                    new_lines.append(line)

                if not found:
                    _release_lock(f)
                    return False

                f.seek(0)
                f.truncate(0)
                f.writelines(new_lines)
                f.flush()
                os.fsync(f.fileno())
                _release_lock(f)
                return True
        except Exception as e:
            if attempts > 10:
                print(Color.RED + f"[REMOVE ERROR] Could not remove {target}: {e}")
                return False
            time.sleep(0.01)

# === Ping function (Minecraft handshake/status) ===
def ping(host_ip: str, port: int = 25565) -> Optional[dict]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PING_TIMEOUT)
        sock.connect((host_ip, port))

        def encode_varint(value: int) -> bytes:
            out = b""
            v = value & 0xFFFFFFFF
            while True:
                temp = v & 0x7F
                v >>= 7
                if v != 0:
                    out += bytes([temp | 0x80])
                else:
                    out += bytes([temp])
                    break
            return out

        host_bytes = host_ip.encode("utf-8")
        handshake = b""
        handshake += encode_varint(0)
        handshake += encode_varint(47)
        handshake += encode_varint(len(host_bytes)) + host_bytes
        handshake += struct.pack(">H", port)
        handshake += encode_varint(1)
        packet = encode_varint(len(handshake)) + handshake

        sock.sendall(packet)
        status_req = encode_varint(1) + b"\x00"
        sock.sendall(status_req)

        def read_varint_sock(s):
            num_read = 0
            result = 0
            while True:
                b = s.recv(1)
                if not b:
                    return None
                byte = b[0]
                result |= (byte & 0x7F) << (7 * num_read)
                num_read += 1
                if num_read > 5:
                    raise ValueError("VarInt too big")
                if not (byte & 0x80):
                    break
            return result

        length = read_varint_sock(sock)
        if length is None:
            return None
        _ = read_varint_sock(sock)
        json_len = read_varint_sock(sock)
        if json_len is None:
            return None
        data = b""
        while len(data) < json_len:
            chunk = sock.recv(json_len - len(data))
            if not chunk:
                break
            data += chunk
        if not data:
            return None
        jdata = json.loads(data.decode(errors="ignore"))
        if vfilter:
            version_name = jdata.get("version", {}).get("name", "")
            if version_name != vfilter:
                return None
        return jdata
    except Exception:
        return None
    finally:
        if sock:
            sock.close()

# === Mongo DB helpers ===
def init_mongo():
    global client, coll
    if client is None:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client[DB_NAME]
        coll = db[COLLECTION]

def save_server_to_db(ip: str, port: int, data: dict):
    init_mongo()
    desc = data.get("description", "")
    
    # Normalize description to a plain string
    if isinstance(desc, dict):
        desc_text = desc.get("text", "")
        if not desc_text and "extra" in desc and isinstance(desc["extra"], list):
            parts = []
            for item in desc["extra"]:
                if isinstance(item, dict):
                    parts.append(str(item.get("text", "")))
                elif isinstance(item, str):
                    parts.append(item)
            desc_text = "".join(parts)
        desc = desc_text
    elif not isinstance(desc, str):
        desc = str(desc)

    # Convert MOTD to lowercase for case-insensitive matching
    motd_lower = desc.lower()

    # Check against forbidden keywords (all assumed to be in lowercase)
    if any(word in motd_lower for word in FORBIDDEN_KEYWORDS):
        print(Color.YELLOW + f"[SKIP] {ip}:{port} MOTD contains forbidden keyword.")
        return

    players_data = data.get("players", {})
    online = players_data.get("online", 0)
    max_players = players_data.get("max", 0)
    players_str = f"{online}/{max_players}"

    key = f"{ip}:{port}"
    try:
        coll.update_one(
            {"_id": key},
            {"$set": {
                "ip": ip,
                "port": port,
                "description": desc,
                "version": data.get("version", {}).get("name", "Unknown"),
                "players": players_str,
                "protocol": data.get("version", {}).get("protocol", 0),
                "timestamp": datetime.utcnow()
            }},
            upsert=True
        )
    except errors.PyMongoError as e:
        print(Color.RED + f"[DB ERROR] {e}")

# === Subnet scan (per target) — NOW SCANS /21 (~2,046 IPs) ===
def scan_subnet_task(args) -> int:
    ip, port = args
    try:
        # Use /21 subnet (2,046 usable IPs)
        network = ipaddress.IPv4Network(f"{ip}/21", strict=False)
        ips = [str(host) for host in network.hosts()]
    except Exception as e:
        print(Color.RED + f"[SUBNET ERROR] Invalid IP for /21: {ip} — {e}")
        return 0

    working = 0
    max_threads = min(500, max(32, multiprocessing.cpu_count() * 30))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as exe:
        futures = {exe.submit(ping, ipx, port): ipx for ipx in ips}
        for fut in concurrent.futures.as_completed(futures):
            ipx = futures[fut]
            try:
                result = fut.result()
                if result:
                    working += 1
                    save_server_to_db(ipx, port, result)
                    desc = result.get("description", "")
                    if isinstance(desc, dict):
                        desc_text = desc.get("text", "")
                        if not desc_text and "extra" in desc and isinstance(desc["extra"], list):
                            parts = []
                            for item in desc["extra"]:
                                if isinstance(item, dict):
                                    parts.append(str(item.get("text", "")))
                                elif isinstance(item, str):
                                    parts.append(item)
                            desc = "".join(parts)
                        else:
                            desc = desc_text
                    elif not isinstance(desc, str):
                        desc = str(desc)
                    players_data = result.get("players", {})
                    online = players_data.get("online", 0)
                    max_players = players_data.get("max", 0)
                    players_str = f"{online}/{max_players}"
                    print(Color.GREEN + f"[ONLINE] {ipx}:{port} » {desc} | {players_str}")
            except Exception:
                pass
    return working

# === Domain resolution ===
def resolve_target(target: str) -> Optional[Tuple[str, int]]:
    port = 25565
    try:
        if ":" in target and target.count(":") == 1:
            host_part, ppart = target.rsplit(":", 1)
            if ppart.isdigit():
                port = int(ppart)
                try:
                    ipaddress.ip_address(host_part)
                    ip = host_part
                    if ipaddress.ip_address(ip).version == 6:
                        print(Color.RED + f"[SKIP] IPv6 not supported: {ip}")
                        return None
                    return ip, port
                except Exception:
                    pass
    except Exception:
        pass

    try:
        ipaddress.ip_address(target)
        ip = target
        if ipaddress.ip_address(ip).version == 6:
            print(Color.RED + f"[SKIP] IPv6 not supported: {ip}")
            return None
        return ip, 25565
    except Exception:
        pass

    http_candidates = [
        f"https://fictional-tribble-g4vrv744wrj5h9qpj-5050.app.github.dev/3/{target}",
        f"https://api.mcsrvstat.us/2/{target}"
    ]
    for url in http_candidates:
        try:
            resp = requests.get(url, timeout=DOMAIN_RESOLVE_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            ip = data.get("ip") or data.get("hostname") or data.get("address") or data.get("domain")
            port = int(data.get("port", port))
            if not ip:
                continue
            if ":" in str(ip) and str(ip).count(":") == 1 and "[" not in str(ip):
                host_part, ppart = str(ip).rsplit(":", 1)
                if ppart.isdigit():
                    ip = host_part
                    port = int(ppart)
            try:
                addrs = socket.getaddrinfo(ip, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
                if not addrs:
                    continue
                resolved_ip = addrs[0][4][0]
                return resolved_ip, port
            except Exception:
                try:
                    ipaddress.ip_address(ip)
                    if ipaddress.ip_address(ip).version == 6:
                        print(Color.RED + f"[SKIP] IPv6 not supported: {ip}")
                        return None
                    return ip, port
                except Exception:
                    continue
        except Exception:
            continue

    try:
        infos = socket.getaddrinfo(target, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if infos:
            resolved_ip = infos[0][4][0]
            return resolved_ip, port
    except Exception:
        pass

    return None

# === Resolve and dispatch ===
def process_target(target: str) -> bool:
    resolved = resolve_target(target)
    if not resolved:
        print(Color.RED + f"[RESOLVE FAIL] {target}")
        return False

    ip, port = resolved

    removed = remove_target_from_file(target)
    if not removed:
        print(Color.YELLOW + f"[WARN] Could not remove {target} (maybe removed by another worker). Continuing scan of {ip}:{port}")

    print(Color.BLUE + f"[START] Scanning /21 subnet of {ip}:{port} (~2,046 IPs)")
    working = scan_subnet_task((ip, port))
    print(Color.YELLOW + f"[DONE] {ip}:{port} — {working} online out of ~2,046.")
    return True

# === Main driver ===
def main():
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass
    print(Color.RED + "\nDARK'S Minecraft ServerChecker — /21 SUBNET VERSION (~2K IPs)\n")

    if not os.path.exists(IPS_FILE):
        print(Color.GREEN + f"{IPS_FILE} not found. Exiting.")
        return

    while True:
        targets = []
        try:
            with open(IPS_FILE, "r", encoding="utf-8") as f:
                try:
                    _acquire_lock(f)
                except Exception:
                    pass
                f.seek(0)
                targets = [line.strip() for line in f if line.strip()]
                try:
                    _release_lock(f)
                except Exception:
                    pass
        except FileNotFoundError:
            print(Color.GREEN + f"{IPS_FILE} not found. Exiting.")
            return
        except Exception as e:
            print(Color.RED + f"[ERROR] reading {IPS_FILE}: {e}")
            time.sleep(0.5)
            continue

        if not targets:
            print(Color.GREEN + "No targets left in ips.txt. Exiting.")
            return

        random.shuffle(targets)

        max_workers = min(len(targets), max(1, multiprocessing.cpu_count()))
        print(Color.BLUE + f"Processing {len(targets)} targets using {max_workers} worker processes...")

        completed = []
        try:
            with multiprocessing.Pool(processes=max_workers, initializer=init_mongo) as pool:
                for target in targets:
                    pool.apply_async(process_target, (target,), callback=completed.append)
                pool.close()
                pool.join()
        except KeyboardInterrupt:
            print(Color.YELLOW + "Interrupted by user. Exiting.")
            return
        except Exception as e:
            print(Color.RED + f"[POOL ERROR] {e}")

        time.sleep(0.5)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
