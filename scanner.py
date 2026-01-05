#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import random
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_ip_lines(path):
    ranges = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "/" in line:
                network = ipaddress.ip_network(line, strict=False)
                ranges.append(("cidr", line, list(network.hosts())))
                continue
            if "-" in line:
                start_raw, end_raw = [part.strip() for part in line.split("-", 1)]
                start = ipaddress.ip_address(start_raw)
                end = ipaddress.ip_address(end_raw)
                if start.version != end.version:
                    raise ValueError(f"Range version mismatch: {line}")
                if int(end) < int(start):
                    raise ValueError(f"Range end before start: {line}")
                count = int(end) - int(start) + 1
                items = [ipaddress.ip_address(int(start) + offset) for offset in range(count)]
                ranges.append(("range", line, items))
                continue
            ip = ipaddress.ip_address(line)
            ranges.append(("single", line, [ip]))
    return ranges


def render_config(template_path, ip_value):
    with open(template_path, "r", encoding="utf-8") as handle:
        template = handle.read()
    rendered = template.replace("PLACEHOLDER_IP", str(ip_value))
    json.loads(rendered)
    return rendered


def run_xray(xray_bin, config_text):
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp.write(config_text.encode("utf-8"))
    temp.flush()
    temp.close()
    process = subprocess.Popen(
        [xray_bin, "-c", temp.name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return process, temp.name


def stop_xray(process, config_path):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
    try:
        os.unlink(config_path)
    except FileNotFoundError:
        pass


def run_curl(args, stdin_bytes=None, timeout=30):
    result = subprocess.run(
        args,
        input=stdin_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return result


def test_download(url, proxy, min_kbps):
    args = [
        "curl",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{speed_download}",
        "--proxy",
        proxy,
        "--max-time",
        "20",
        url,
    ]
    result = run_curl(args)
    if result.returncode != 0:
        return False, 0.0
    try:
        speed_bps = float(result.stdout.decode().strip())
    except ValueError:
        return False, 0.0
    speed_kbps = speed_bps / 1024
    if min_kbps and speed_kbps < min_kbps:
        return False, speed_kbps
    return True, speed_kbps


def test_upload(url, proxy, size_kb, min_kbps):
    payload = b"x" * (size_kb * 1024)
    args = [
        "curl",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{speed_upload}",
        "--proxy",
        proxy,
        "--max-time",
        "20",
        "--data-binary",
        "@-",
        url,
    ]
    result = run_curl(args, stdin_bytes=payload)
    if result.returncode != 0:
        return False, 0.0
    try:
        speed_bps = float(result.stdout.decode().strip())
    except ValueError:
        return False, 0.0
    speed_kbps = speed_bps / 1024
    if min_kbps and speed_kbps < min_kbps:
        return False, speed_kbps
    return True, speed_kbps


def scan_ip(ip_value, options):
    config_text = render_config(options.config, ip_value)
    process, config_path = run_xray(options.xray_bin, config_text)
    time.sleep(options.xray_startup_delay)
    success = False
    download_speed = 0.0
    upload_speed = 0.0
    try:
        if options.download:
            success, download_speed = test_download(
                options.download_url,
                options.proxy,
                options.min_kbps,
            )
        if options.upload:
            upload_ok, upload_speed = test_upload(
                options.upload_url,
                options.proxy,
                options.upload_size_kb,
                options.min_kbps,
            )
            success = success or upload_ok
    finally:
        stop_xray(process, config_path)
    return ip_value, success, download_speed, upload_speed


def should_skip(range_size, scanned, success_count, start_time, auto_skip):
    if not auto_skip:
        return False
    if range_size > 0 and scanned / range_size >= 0.10:
        return True
    if success_count >= 5:
        return True
    elapsed = time.time() - start_time
    if elapsed >= 180:
        return True
    return False


def scan_range(label, items, options, output_lock, output_handle):
    range_size = len(items)
    if options.random:
        random.shuffle(items)
    start_time = time.time()
    scanned = 0
    success_count = 0

    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {}
        item_iter = iter(items)

        def submit_next():
            try:
                ip_value = next(item_iter)
            except StopIteration:
                return False
            future = executor.submit(scan_ip, ip_value, options)
            futures[future] = ip_value
            return True

        for _ in range(options.threads):
            if not submit_next():
                break

        while futures:
            for future in as_completed(list(futures.keys()), timeout=None):
                futures.pop(future, None)
                scanned += 1
                try:
                    ip_value, success, download_speed, upload_speed = future.result()
                except Exception:
                    ip_value = None
                    success = False
                    download_speed = 0.0
                    upload_speed = 0.0
                if success:
                    success_count += 1
                    with output_lock:
                        output_handle.write(
                            f"{ip_value},{download_speed:.2f},{upload_speed:.2f}\n"
                        )
                        output_handle.flush()
                if should_skip(range_size, scanned, success_count, start_time, options.auto_skip):
                    return
                if submit_next():
                    continue
            if not futures:
                break


def build_parser():
    parser = argparse.ArgumentParser(description="IP scanner for Xray/V2Ray configs")
    parser.add_argument("--ip-file", required=True, help="Path to IP list file")
    parser.add_argument("--config", required=True, help="Path to Xray JSON template")
    parser.add_argument("--xray-bin", default="xray", help="Path to Xray binary")
    parser.add_argument("--threads", type=int, default=10, help="Parallel threads")
    parser.add_argument("--download", action="store_true", help="Enable download test")
    parser.add_argument("--upload", action="store_true", help="Enable upload test")
    parser.add_argument("--download-url", default="https://speed.hetzner.de/100MB.bin")
    parser.add_argument("--upload-url", default="https://httpbin.org/post")
    parser.add_argument("--upload-size-kb", type=int, default=256)
    parser.add_argument("--speed", type=int, dest="min_kbps", default=0, help="Min speed KB/s")
    parser.add_argument("--random", action="store_true", help="Randomize IP order")
    parser.add_argument("--autoskip", action="store_true", help="Enable auto skip logic")
    parser.add_argument("--proxy", default="socks5h://127.0.0.1:10808")
    parser.add_argument("--xray-startup-delay", type=float, default=0.5)
    parser.add_argument("--out", default="success.txt", help="Output file")
    return parser


def main():
    parser = build_parser()
    options = parser.parse_args()

    if not options.download and not options.upload:
        parser.error("At least one of --download or --upload must be set.")

    ranges = parse_ip_lines(options.ip_file)
    output_lock = threading.Lock()

    with open(options.out, "w", encoding="utf-8") as output_handle:
        for kind, label, items in ranges:
            scan_range(label, items, options, output_lock, output_handle)


if __name__ == "__main__":
    main()
