#!/usr/bin/env python3
import argparse
import http.server
import ipaddress
import json
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.parse
import zipfile
import math
import itertools
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from concurrent.futures import ThreadPoolExecutor, as_completed


XRAY_REPO_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
DEFAULT_TEST_DIR = os.path.join(os.path.expanduser("~"), ".json-scanner", "test-files")
DEFAULT_TEST_FILENAME = "test.bin"
RESULTS_DIRNAME = "result"
RANDOM_SHUFFLE_LIMIT = 100000
CONNECT_TIMEOUT_SECONDS = 5
MAX_TIME_SECONDS = 20
DEFAULT_SOCKS_PORT = 10808
SPEED_LIMIT_MULTIPLIER = 1.1


@dataclass
class IpRange:
    kind: str
    label: str
    count: int
    iter_factory: callable

    def iter_ips(self):
        return self.iter_factory()


def count_network_hosts(network):
    if network.version == 4:
        if network.prefixlen >= 31:
            return int(network.num_addresses)
        return max(int(network.num_addresses) - 2, 0)
    if network.prefixlen == 128:
        return 1
    return max(int(network.num_addresses) - 1, 0)


def parse_ip_lines(path):
    ranges = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "/" in line:
                network = ipaddress.ip_network(line, strict=False)
                count = count_network_hosts(network)
                ranges.append(
                    IpRange(
                        "cidr",
                        line,
                        count,
                        iter_factory=network.hosts,
                    )
                )
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
                ranges.append(
                    IpRange(
                        "range",
                        line,
                        count,
                        iter_factory=lambda start=start, count=count: (
                            ipaddress.ip_address(int(start) + offset) for offset in range(count)
                        ),
                    )
                )
                continue
            ip = ipaddress.ip_address(line)
            ranges.append(
                IpRange(
                    "single",
                    line,
                    1,
                    iter_factory=lambda ip=ip: iter((ip,)),
                )
            )
    return ranges


def load_config_template(template_path):
    with open(template_path, "r", encoding="utf-8") as handle:
        return handle.read()


def render_config(template_text, ip_value, socks_port=None):
    rendered = template_text.replace("PLACEHOLDER_IP", str(ip_value))
    if "PLACEHOLDER_PORT" in rendered:
        if socks_port is None:
            raise ValueError("PLACEHOLDER_PORT is present but no socks port was provided.")
        rendered = rendered.replace("PLACEHOLDER_PORT", str(socks_port))
    json.loads(rendered)
    return rendered


def platform_asset_name():
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in {"x86_64", "amd64"}:
            return "Xray-linux-64.zip"
        if machine in {"aarch64", "arm64"}:
            return "Xray-linux-arm64-v8a.zip"
        if machine in {"armv7l", "armv7"}:
            return "Xray-linux-arm32-v7a.zip"
        if machine in {"armv6l", "armv6"}:
            return "Xray-linux-arm32-v6.zip"
    if system == "darwin":
        if machine in {"x86_64", "amd64"}:
            return "Xray-macos-64.zip"
        if machine in {"arm64", "aarch64"}:
            return "Xray-macos-arm64-v8a.zip"
    if system == "windows":
        if machine in {"x86_64", "amd64"}:
            return "Xray-windows-64.zip"
        if machine in {"arm64", "aarch64"}:
            return "Xray-windows-arm64-v8a.zip"
        if machine in {"x86", "i386", "i686"}:
            return "Xray-windows-32.zip"
    return None


def download_xray(cache_dir):
    asset_name = platform_asset_name()
    if not asset_name:
        raise RuntimeError("Unsupported platform for automatic Xray download.")

    request = urllib.request.Request(XRAY_REPO_API, headers={"User-Agent": "json-scanner"})
    with urllib.request.urlopen(request) as resp:
        release = json.load(resp)
    assets = {item["name"]: item["browser_download_url"] for item in release["assets"]}
    if asset_name not in assets:
        raise RuntimeError(f"Asset {asset_name} not found in latest release.")

    binary_name = "xray.exe" if platform.system().lower() == "windows" else "xray"
    binary_path = os.path.join(cache_dir, binary_name)
    if os.path.exists(binary_path):
        return binary_path

    with tempfile.TemporaryDirectory() as temp_dir:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as temp_zip:
            asset_request = urllib.request.Request(
                assets[asset_name],
                headers={"User-Agent": "json-scanner"},
            )
            with urllib.request.urlopen(asset_request) as resp:
                temp_zip.write(resp.read())
            temp_zip_path = temp_zip.name

        with zipfile.ZipFile(temp_zip_path, "r") as archive:
            archive.extractall(temp_dir)

        os.unlink(temp_zip_path)

        extracted_binary = None
        for root, _dirs, files in os.walk(temp_dir):
            if binary_name in files:
                extracted_binary = os.path.join(root, binary_name)
                break

        if not extracted_binary:
            raise RuntimeError("Downloaded archive did not include xray binary.")

        shutil.move(extracted_binary, binary_path)

    if platform.system().lower() != "windows":
        os.chmod(binary_path, 0o755)

    return binary_path


def resolve_xray_binary(xray_bin):
    if not xray_bin:
        xray_bin = "xray"
    if os.path.isfile(xray_bin):
        return os.path.abspath(xray_bin)
    found = shutil.which(xray_bin)
    if found:
        return found

    search_dirs = [os.getcwd(), os.path.dirname(os.path.abspath(__file__))]
    for directory in dict.fromkeys(search_dirs):
        for filename in ("xray", "xray.exe"):
            candidate = os.path.join(directory, filename)
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

    print("Xray binary not found. Downloading latest release for your platform...")
    return download_xray(os.path.dirname(os.path.abspath(__file__)))


def validate_xray_config(xray_bin, config_text, show_message=True):
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp.write(config_text.encode("utf-8"))
    temp.flush()
    temp.close()
    try:
        result = subprocess.run(
            [xray_bin, "-test", "-c", temp.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    finally:
        try:
            os.unlink(temp.name)
        except FileNotFoundError:
            pass
    if result.returncode == 0:
        if show_message:
            print("config has valid syntax")
        return True
    output = result.stderr.decode(errors="ignore").strip()
    if not output:
        output = result.stdout.decode(errors="ignore").strip()
    if output:
        print(output)
    return False


def run_xray(xray_bin, config_text):
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp.write(config_text.encode("utf-8"))
    temp.flush()
    temp.close()
    log_path = tempfile.NamedTemporaryFile(delete=False, suffix=".log").name
    log_handle = open(log_path, "w", encoding="utf-8")
    process = subprocess.Popen(
        [xray_bin, "-c", temp.name],
        stdout=log_handle,
        stderr=log_handle,
    )
    log_handle.close()
    return process, temp.name, log_path


def stop_xray(process, config_path, log_path):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
    log_text = ""
    if log_path and os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
            log_text = handle.read().strip()
        try:
            os.unlink(log_path)
        except FileNotFoundError:
            pass
    try:
        os.unlink(config_path)
    except FileNotFoundError:
        pass
    return log_text


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


def parse_curl_metrics(raw):
    parts = raw.strip().split()
    if len(parts) != 2:
        return None, None
    try:
        speed_bps = float(parts[0])
    except ValueError:
        return None, None
    http_code = parts[1]
    return speed_bps, http_code


def parse_proxy_host_port(proxy_url):
    if not proxy_url:
        return None, None
    parts = urllib.parse.urlsplit(proxy_url)
    if not parts.hostname:
        return None, None
    port = parts.port
    if not port:
        if parts.scheme.startswith("socks"):
            port = 1080
        elif parts.scheme == "http":
            port = 8080
    return parts.hostname, port


def parse_url_lines(path):
    urls = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line)
    return urls


class PortAllocator:
    def __init__(self):
        self._lock = threading.Lock()
        self._in_use = set()

    def acquire(self):
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            with self._lock:
                if port not in self._in_use:
                    self._in_use.add(port)
                    return port

    def release(self, port):
        if port is None:
            return
        with self._lock:
            self._in_use.discard(port)


def build_proxy_url(proxy_template, socks_port):
    if not proxy_template:
        return proxy_template
    if "{port}" in proxy_template:
        return proxy_template.format(port=socks_port)
    return proxy_template


def wait_for_proxy_ready(proxy_url, timeout):
    host, port = parse_proxy_host_port(proxy_url)
    if not host or not port or timeout <= 0:
        return True
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError as exc:
            last_error = exc
            time.sleep(0.2)
    return False


def is_success_http_code(code):
    return code is not None and code.isdigit() and 200 <= int(code) < 300


def test_download(url, proxy, min_kbps, download_bytes):
    args = [
        "curl",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{speed_download} %{http_code}",
        "--proxy",
        proxy,
        "--connect-timeout",
        str(CONNECT_TIMEOUT_SECONDS),
        "--max-time",
        str(MAX_TIME_SECONDS),
    ]
    if min_kbps and min_kbps > 0:
        limit_bps = int(math.ceil(min_kbps * 1024 * SPEED_LIMIT_MULTIPLIER))
        args.extend(["--limit-rate", str(limit_bps)])
    if download_bytes and download_bytes > 0:
        args.extend(["--range", f"0-{download_bytes - 1}"])
    args.append(url)
    result = run_curl(args)
    stdout = result.stdout.decode(errors="ignore").strip()
    stderr = result.stderr.decode(errors="ignore").strip()
    if result.returncode != 0:
        error = stderr or f"curl exited with {result.returncode}"
        return False, 0.0, None, error
    speed_bps, http_code = parse_curl_metrics(stdout)
    if speed_bps is None:
        error = stderr or f"unexpected curl output: {stdout}"
        return False, 0.0, http_code, error
    if not is_success_http_code(http_code):
        return False, 0.0, http_code, f"HTTP {http_code}"
    speed_kbps = speed_bps / 1024
    if speed_kbps <= 0:
        return False, 0.0, http_code, "speed is zero"
    if min_kbps and speed_kbps < min_kbps:
        return False, speed_kbps, http_code, f"below minimum ({min_kbps} KB/s)"
    return True, speed_kbps, http_code, ""


def test_upload(url, proxy, size_kb, min_kbps):
    payload = b"x" * (size_kb * 1024)
    args = [
        "curl",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{speed_upload} %{http_code}",
        "--proxy",
        proxy,
        "--connect-timeout",
        str(CONNECT_TIMEOUT_SECONDS),
        "--max-time",
        str(MAX_TIME_SECONDS),
        "--data-binary",
        "@-",
        url,
    ]
    result = run_curl(args, stdin_bytes=payload)
    stdout = result.stdout.decode(errors="ignore").strip()
    stderr = result.stderr.decode(errors="ignore").strip()
    if result.returncode != 0:
        error = stderr or f"curl exited with {result.returncode}"
        return False, 0.0, None, error
    speed_bps, http_code = parse_curl_metrics(stdout)
    if speed_bps is None:
        error = stderr or f"unexpected curl output: {stdout}"
        return False, 0.0, http_code, error
    if not is_success_http_code(http_code):
        return False, 0.0, http_code, f"HTTP {http_code}"
    speed_kbps = speed_bps / 1024
    if speed_kbps <= 0:
        return False, 0.0, http_code, "speed is zero"
    if min_kbps and speed_kbps < min_kbps:
        return False, speed_kbps, http_code, f"below minimum ({min_kbps} KB/s)"
    return True, speed_kbps, http_code, ""


def test_real_delay(url, proxy):
    args = [
        "curl",
        "-o",
        "/dev/null",
        "-s",
        "-w",
        "%{time_total} %{http_code}",
        "--proxy",
        proxy,
        "--connect-timeout",
        str(CONNECT_TIMEOUT_SECONDS),
        "--max-time",
        str(MAX_TIME_SECONDS),
        url,
    ]
    result = run_curl(args)
    stdout = result.stdout.decode(errors="ignore").strip()
    stderr = result.stderr.decode(errors="ignore").strip()
    if result.returncode != 0:
        error = stderr or f"curl exited with {result.returncode}"
        return False, 0.0, None, error
    parts = stdout.split()
    if len(parts) != 2:
        error = stderr or f"unexpected curl output: {stdout}"
        return False, 0.0, None, error
    try:
        time_seconds = float(parts[0])
    except ValueError:
        error = stderr or f"unexpected curl output: {stdout}"
        return False, 0.0, None, error
    http_code = parts[1]
    if not is_success_http_code(http_code):
        return False, 0.0, http_code, f"HTTP {http_code}"
    delay_ms = time_seconds * 1000
    return True, delay_ms, http_code, ""


def select_download_bytes(options):
    if options.download_bytes and options.download_bytes > 0:
        return options.download_bytes
    min_bytes = min(options.download_bytes_min, options.download_bytes_max)
    max_bytes = max(options.download_bytes_min, options.download_bytes_max)
    return random.randint(min_bytes, max_bytes)


def ensure_test_file(path, size_mb):
    target_size = max(size_mb, 1) * 1024 * 1024
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    if os.path.exists(path):
        existing = os.path.getsize(path)
        if existing >= target_size:
            return
    with open(path, "wb") as handle:
        handle.truncate(target_size)


def is_loopback_host(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ip_value = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip_value.is_loopback


def detect_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


class LocalTestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def do_POST(self):
        self._discard_body()

    def do_PUT(self):
        self._discard_body()

    def _safe_write(self, data):
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def _discard_body(self):
        length = self.headers.get("Content-Length")
        if length:
            remaining = int(length)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 1024 * 32))
                if not chunk:
                    break
                remaining -= len(chunk)
        else:
            while True:
                chunk = self.rfile.read(1024 * 32)
                if not chunk:
                    break
        self.send_response(200)
        self.end_headers()
        self._safe_write(b"OK")


def start_local_test_server(directory, listen_host, port):
    handler = partial(LocalTestHandler, directory=directory)
    server = http.server.ThreadingHTTPServer((listen_host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def colorize(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}\033[0m"


def format_status_line(label, status_text, status_color, details=""):
    columns = shutil.get_terminal_size((80, 20)).columns
    plain_status = status_text
    status = colorize(status_text, status_color)
    left = label
    if details:
        left = f"{label} - {details}"
    padding_width = max(10, columns - len(plain_status) - 1)
    if len(left) > padding_width:
        if padding_width > 1:
            left = left[: padding_width - 1] + "…"
        else:
            left = left[:padding_width]
    return f"{left:<{padding_width}} {status}"


def format_http_code(code):
    if code is None:
        return "HTTP ?"
    return f"HTTP {code}"


def format_speed(speed_kbps):
    return f"{speed_kbps:.2f} KB/s"


def format_delay(delay_ms):
    return f"{delay_ms:.2f} ms"


def summarize_test(name, result, extra=""):
    if result is None:
        return f"{name}: skipped"
    status = "ok" if result["ok"] else "fail"
    speed = format_speed(result["speed_kbps"]) if result["speed_kbps"] else "0.00 KB/s"
    code = format_http_code(result.get("http_code"))
    message = result.get("error", "").strip()
    detail_bits = [speed, code]
    if extra:
        detail_bits.append(extra)
    detail = ", ".join(bit for bit in detail_bits if bit)
    if message:
        return f"{name}: {status} ({detail}) - {message}"
    return f"{name}: {status} ({detail})"


def summarize_delay_test(name, result, extra=""):
    if result is None:
        return f"{name}: skipped"
    status = "ok" if result["ok"] else "fail"
    delay = format_delay(result["delay_ms"]) if result["delay_ms"] else "0.00 ms"
    code = format_http_code(result.get("http_code"))
    message = result.get("error", "").strip()
    detail_bits = [delay, code]
    if extra:
        detail_bits.append(extra)
    detail = ", ".join(bit for bit in detail_bits if bit)
    if message:
        return f"{name}: {status} ({detail}) - {message}"
    return f"{name}: {status} ({detail})"


def scan_ip(ip_value, options):
    if options.stop_event.is_set():
        return ip_value, False, 0.0, 0.0, {}
    socks_port = options.static_socks_port
    if options.dynamic_proxy:
        socks_port = options.port_allocator.acquire()
    proxy_url = build_proxy_url(options.proxy, socks_port)
    try:
        config_text = render_config(options.config_template, ip_value, socks_port)
        process, config_path, log_path = run_xray(options.xray_bin, config_text)
        if options.xray_startup_delay > 0:
            time.sleep(options.xray_startup_delay)
        if not wait_for_proxy_ready(proxy_url, options.proxy_ready_timeout):
            log_text = stop_xray(process, config_path, log_path)
            details = {
                "xray_error": log_text or "Xray proxy did not become ready in time.",
                "error": "proxy not ready",
            }
            return ip_value, False, 0.0, 0.0, details
        if process.poll() is not None:
            log_text = stop_xray(process, config_path, log_path)
            details = {"xray_error": log_text or "Xray exited early."}
            return ip_value, False, 0.0, 0.0, details
        success = True
        download_speed = 0.0
        upload_speed = 0.0
        delay_ms = 0.0
        details = {}
        try:
            if options.download:
                download_bytes = select_download_bytes(options)
                download_url = options.download_url
                if options.download_url_cycle is not None:
                    with options.download_url_lock:
                        download_url = next(options.download_url_cycle)
                download_ok, download_speed, http_code, error = test_download(
                    download_url,
                    proxy_url,
                    options.min_kbps,
                    download_bytes,
                )
                details["download"] = {
                    "ok": download_ok,
                    "speed_kbps": download_speed,
                    "http_code": http_code,
                    "error": error,
                    "bytes": download_bytes,
                    "url": download_url,
                }
                success = success and download_ok
            if options.upload:
                upload_ok, upload_speed, http_code, error = test_upload(
                    options.upload_url,
                    proxy_url,
                    options.upload_size_kb,
                    options.min_kbps,
                )
                details["upload"] = {
                    "ok": upload_ok,
                    "speed_kbps": upload_speed,
                    "http_code": http_code,
                    "error": error,
                    "size_kb": options.upload_size_kb,
                }
                success = success and upload_ok
            if options.real_delay:
                delay_ok, delay_ms, http_code, error = test_real_delay(
                    options.real_delay_url,
                    proxy_url,
                )
                details["real_delay"] = {
                    "ok": delay_ok,
                    "delay_ms": delay_ms,
                    "http_code": http_code,
                    "error": error,
                    "url": options.real_delay_url,
                }
                success = success and delay_ok
        finally:
            xray_log = stop_xray(process, config_path, log_path)
            if xray_log and not success:
                details["xray_log"] = xray_log
        return ip_value, success, download_speed, upload_speed, delay_ms, details
    finally:
        if options.dynamic_proxy:
            options.port_allocator.release(socks_port)


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


def format_result_line(ip_value, download_speed, upload_speed, delay_ms, options):
    fields = [str(ip_value)]
    if options.download:
        fields.append(format_speed(download_speed))
    if options.upload:
        fields.append(format_speed(upload_speed))
    if options.real_delay:
        fields.append(format_delay(delay_ms))
    return ",".join(fields)


def iter_range_items(range_item, options):
    if options.random and range_item.count <= RANDOM_SHUFFLE_LIMIT:
        items = list(range_item.iter_ips())
        random.shuffle(items)
        return iter(items)
    if options.random and range_item.count > RANDOM_SHUFFLE_LIMIT:
        print(
            f"{range_item.label}: random mode skipped for large range "
            f"({range_item.count} IPs)."
        )
    return range_item.iter_ips()


def scan_range(range_item, options, output_lock, output_handle):
    range_size = range_item.count
    show_progress = range_size != 1
    label = range_item.label
    if range_size:
        if not options.config_validated:
            first_ip = next(range_item.iter_ips(), None)
            if first_ip is None:
                return
            config_text = render_config(
                options.config_template,
                first_ip,
                options.validation_socks_port,
            )
            if not validate_xray_config(options.xray_bin, config_text, show_message=True):
                return
            options.config_validated = True
    start_time = time.time()
    scanned = 0
    success_count = 0
    last_report = 0.0

    def clear_progress_line():
        if not show_progress:
            return
        columns = shutil.get_terminal_size((80, 20)).columns
        print("\r" + (" " * (columns - 1)) + "\r", end="")

    def report_progress():
        nonlocal last_report
        if range_size == 0 or not show_progress:
            return
        now = time.time()
        if now - last_report < 0.5 and scanned < range_size:
            return
        percent = (scanned / range_size) * 100
        print(f"\r{label}: {percent:5.1f}% ({scanned}/{range_size})", end="", flush=True)
        last_report = now

    with ThreadPoolExecutor(max_workers=options.threads) as executor:
        futures = {}
        item_iter = iter_range_items(range_item, options)

        def submit_next():
            if options.stop_event.is_set():
                return False
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

        try:
            while futures and not options.stop_event.is_set():
                for future in as_completed(list(futures.keys()), timeout=None):
                    futures.pop(future, None)
                    scanned += 1
                    try:
                        (
                            ip_value,
                            success,
                            download_speed,
                            upload_speed,
                            delay_ms,
                            details,
                        ) = future.result()
                    except Exception:
                        ip_value = None
                        success = False
                        download_speed = 0.0
                        upload_speed = 0.0
                        delay_ms = 0.0
                        details = {"error": "Unexpected worker failure."}
                    if success:
                        success_count += 1
                        with output_lock:
                            output_handle.write(
                                f"{format_result_line(ip_value, download_speed, upload_speed, delay_ms, options)}\n"
                            )
                            output_handle.flush()
                    if ip_value is not None:
                        clear_progress_line()
                        status_text = "OK" if success else "FAIL"
                        status_color = "\033[32m" if success else "\033[31m"
                        summary_bits = []
                        if options.download:
                            if details.get("download"):
                                summary_bits.append(
                                    f"dl {format_speed(details['download']['speed_kbps'])}"
                                )
                            else:
                                summary_bits.append("dl -")
                        if options.upload:
                            if details.get("upload"):
                                summary_bits.append(
                                    f"ul {format_speed(details['upload']['speed_kbps'])}"
                                )
                            else:
                                summary_bits.append("ul -")
                        if options.real_delay:
                            if details.get("real_delay"):
                                summary_bits.append(
                                    f"delay {format_delay(details['real_delay']['delay_ms'])}"
                                )
                            else:
                                summary_bits.append("delay -")
                        summary = " | ".join(summary_bits)
                        print(
                            format_status_line(
                                str(ip_value),
                                status_text,
                                status_color,
                                summary,
                            )
                        )
                        if details.get("xray_error"):
                            print(f"  xray: fail - {details['xray_error']}")
                        if details.get("error"):
                            print(f"  error: {details['error']}")
                        if details.get("download"):
                            extra = f"bytes {details['download']['bytes']}"
                            print(summarize_test("  download", details["download"], extra=extra))
                        if details.get("upload"):
                            extra = f"size {details['upload']['size_kb']} KB"
                            print(summarize_test("  upload", details["upload"], extra=extra))
                        if details.get("real_delay"):
                            print(summarize_delay_test("  real delay", details["real_delay"]))
                        if details.get("xray_log"):
                            print("  xray log:")
                            for line in details["xray_log"].splitlines():
                                print(f"    {line}")
                    report_progress()
                    if should_skip(range_size, scanned, success_count, start_time, options.auto_skip):
                        print()
                        return
                    if submit_next():
                        continue
                if not futures:
                    break
        except KeyboardInterrupt:
            options.stop_event.set()
            for future in futures:
                future.cancel()
            print("\nScan interrupted by user. Partial results saved.")
            return
    if show_progress:
        print()


def ensure_output_path(out_path):
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        return out_path
    result_dir = os.path.join(os.getcwd(), RESULTS_DIRNAME)
    os.makedirs(result_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    filename = f"{timestamp}.txt"
    candidate = os.path.join(result_dir, filename)
    if not os.path.exists(candidate):
        return candidate
    for suffix in itertools.count(1):
        candidate = os.path.join(result_dir, f"{timestamp}-{suffix}.txt")
        if not os.path.exists(candidate):
            return candidate


def build_parser():
    parser = argparse.ArgumentParser(description="IP scanner for Xray/V2Ray configs")
    parser.add_argument("-i", "--ip-file", help="Path to IP list file")
    parser.add_argument("-c", "--config", help="Path to Xray JSON template")
    parser.add_argument("-x", "--xray-bin", default="xray", help="Path to Xray binary")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Parallel threads")
    parser.add_argument("-d", "--download", action="store_true", help="Enable download test")
    parser.add_argument("-u", "--upload", action="store_true", help="Enable upload test")
    parser.add_argument(
        "--real-delay",
        action="store_true",
        help="Enable real delay test (skips download test)",
    )
    parser.add_argument("-D", "--download-url")
    parser.add_argument(
        "--download-url-list",
        help="Path to a file with one download URL per line (round-robin)",
    )
    parser.add_argument(
        "--real-delay-url",
        default="https://www.gstatic.com/generate_204",
        help="URL to use for real delay test",
    )
    parser.add_argument("-U", "--upload-url")
    parser.add_argument("-S", "--upload-size-kb", type=int, default=256)
    parser.add_argument(
        "-s",
        "--speed",
        type=int,
        dest="min_kbps",
        default=0,
        help="Min speed KB/s",
    )
    parser.add_argument(
        "--download-bytes",
        type=int,
        default=1024 * 256,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--download-bytes-min",
        type=int,
        default=10 * 1024,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--download-bytes-max",
        type=int,
        default=1000 * 1024,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--local-test-server",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--local-test-host",
        default="127.0.0.1",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--local-test-listen",
        default="0.0.0.0",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--local-test-port",
        type=int,
        default=18080,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--test-file-path",
        default=None,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--test-file-size-mb",
        type=int,
        default=20,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("-r", "--random", action="store_true", help="Randomize IP order")
    parser.add_argument(
        "-a",
        "--autoskip",
        dest="auto_skip",
        action="store_true",
        help="Enable auto skip logic",
    )
    parser.add_argument(
        "-p",
        "--proxy",
        default="socks5h://127.0.0.1:{port}",
        help="Proxy URL template (use {port} to inject the socks port)",
    )
    parser.add_argument("-w", "--xray-startup-delay", type=float, default=0.0, help=argparse.SUPPRESS)
    parser.add_argument(
        "--proxy-ready-timeout",
        type=float,
        default=6.0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("-o", "--out", default=None, help="Output file")
    return parser


def prompt_text(prompt, default=None, required=False, validator=None):
    while True:
        suffix = f" [{default}]" if default not in (None, "") else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if value == "" and default not in (None, ""):
            value = str(default)
        if value == "" and required:
            print("Value is required.")
            continue
        if value != "" and validator:
            try:
                validator(value)
            except ValueError as exc:
                print(exc)
                continue
        return value


def prompt_int(prompt, default):
    while True:
        value = prompt_text(prompt, default=str(default))
        try:
            return int(value)
        except ValueError:
            print("Please enter a valid number.")


def prompt_float(prompt, default):
    while True:
        value = prompt_text(prompt, default=str(default))
        try:
            return float(value)
        except ValueError:
            print("Please enter a valid number.")


def prompt_bool(prompt, default=False):
    default_label = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} [{default_label}]: ").strip().lower()
        if value == "":
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please enter yes or no.")


def configure_interactive(options):
    print("Interactive setup:")
    if not options.ip_file:
        options.ip_file = prompt_text("IP list file path", required=True)
    if not options.config:
        options.config = prompt_text("Xray JSON template path", required=True)

    if not options.download and not options.upload and not options.real_delay:
        options.download = prompt_bool("Enable download test?", default=True)
        options.upload = prompt_bool("Enable upload test?", default=False)
        options.real_delay = prompt_bool("Enable real delay test?", default=False)
        if not options.download and not options.upload and not options.real_delay:
            print("At least one test must be enabled.")
            options.download = True

    if options.real_delay:
        options.download = False

    if options.download and not options.download_url:
        options.download_url = prompt_text(
            "Download test URL (leave blank to use local server)",
            default="",
        )

    if options.upload and not options.upload_url:
        options.upload_url = prompt_text(
            "Upload test URL (leave blank to use local server)",
            default="",
        )

    options.local_test_server = options.local_test_server or (
        (options.download and not options.download_url)
        or (options.upload and not options.upload_url)
    )

    if options.local_test_server:
        options.local_test_host = prompt_text(
            "Local test host for generated URLs",
            default=options.local_test_host,
        )
        options.local_test_listen = prompt_text(
            "Local test listen address",
            default=options.local_test_listen,
        )
        options.local_test_port = prompt_int(
            "Local test server port",
            options.local_test_port,
        )
        if not options.test_file_path:
            options.test_file_path = prompt_text(
                "Local test file path",
                default=os.path.join(DEFAULT_TEST_DIR, DEFAULT_TEST_FILENAME),
            )
        min_size_mb = math.ceil(options.download_bytes_max / (1024 * 1024))
        options.test_file_size_mb = max(options.test_file_size_mb, min_size_mb)

    options.xray_bin = prompt_text("Xray binary path", default=options.xray_bin)
    options.threads = prompt_int("Parallel threads", options.threads)
    options.proxy = prompt_text("Proxy URL", default=options.proxy)
    options.min_kbps = prompt_int("Minimum speed (KB/s)", options.min_kbps)
    if options.upload:
        options.upload_size_kb = prompt_int("Upload size (KB)", options.upload_size_kb)
    if options.real_delay:
        options.real_delay_url = prompt_text(
            "Real delay URL",
            default=options.real_delay_url,
        )
    options.download_bytes = 0
    options.random = options.random or prompt_bool("Randomize IP order?", default=options.random)
    options.auto_skip = options.auto_skip or prompt_bool("Enable auto skip?", default=options.auto_skip)
    return options


def main():
    parser = build_parser()
    options = parser.parse_args()
    options.stop_event = threading.Event()
    options.config_validated = False
    if len(sys.argv) == 1 or not options.ip_file or not options.config:
        options = configure_interactive(options)
    options.config_template = load_config_template(options.config)
    proxy_template_uses_port = "{port}" in options.proxy
    config_uses_port = "PLACEHOLDER_PORT" in options.config_template
    if proxy_template_uses_port and not config_uses_port:
        parser.error("Proxy template uses {port} but config is missing PLACEHOLDER_PORT.")
    static_host = None
    static_port = None
    if not proxy_template_uses_port:
        static_host, static_port = parse_proxy_host_port(options.proxy)
        if config_uses_port and static_port is None:
            parser.error("Config uses PLACEHOLDER_PORT but --proxy does not include a port.")
    options.static_socks_port = static_port or DEFAULT_SOCKS_PORT
    options.dynamic_proxy = proxy_template_uses_port
    options.port_allocator = PortAllocator() if options.dynamic_proxy else None
    options.validation_socks_port = options.static_socks_port or DEFAULT_SOCKS_PORT
    options.xray_bin = resolve_xray_binary(options.xray_bin)
    options.out = ensure_output_path(options.out)
    options.download_urls = []
    options.download_url_cycle = None
    options.download_url_lock = threading.Lock()
    if options.real_delay:
        options.download = False
    if options.download_url and options.download_url_list:
        parser.error("Use either --download-url or --download-url-list, not both.")
    if options.download_url_list:
        options.download_urls = parse_url_lines(options.download_url_list)
        if not options.download_urls:
            parser.error("Download URL list is empty.")
        options.download_url = options.download_urls[0]
        options.download_url_cycle = itertools.cycle(options.download_urls)

    if not options.download and not options.upload and not options.real_delay:
        parser.error("At least one of --download, --upload, or --real-delay must be set.")

    server = None
    try:
        use_local_server = options.local_test_server or (
            (options.download and not options.download_url)
            or (options.upload and not options.upload_url)
        )
        if use_local_server and is_loopback_host(options.local_test_host) and options.proxy:
            detected_ip = detect_local_ip()
            if detected_ip and not is_loopback_host(detected_ip):
                print(
                    "Local test host was loopback; using detected IP "
                    f"{detected_ip} for proxy tests. Use --local-test-host to override."
                )
                options.local_test_host = detected_ip
            else:
                raise RuntimeError(
                    "Local test host is loopback but proxy tests need a reachable host. "
                    "Set --local-test-host to your public IP or use --download-url/--upload-url."
                )
        if use_local_server:
            test_file_path = options.test_file_path
            if not test_file_path:
                test_file_path = os.path.join(DEFAULT_TEST_DIR, DEFAULT_TEST_FILENAME)
            ensure_test_file(test_file_path, options.test_file_size_mb)
            file_size_mb = os.path.getsize(test_file_path) / (1024 * 1024)
            server_directory = os.path.dirname(test_file_path) or "."
            server = start_local_test_server(
                server_directory,
                options.local_test_listen,
                options.local_test_port,
            )
            print(
                "Local test server running "
                f"on {options.local_test_listen}:{options.local_test_port} "
                f"(file: {test_file_path}, {file_size_mb:.1f} MB)"
            )
            if options.download and not options.download_url:
                options.download_url = (
                    f"http://{options.local_test_host}:{options.local_test_port}/"
                    f"{os.path.basename(test_file_path)}"
                )
            if options.upload and not options.upload_url:
                options.upload_url = (
                    f"http://{options.local_test_host}:{options.local_test_port}/upload"
                )

        if options.download and not options.download_url:
            parser.error("Download test enabled but no download URL provided.")
        if options.upload and not options.upload_url:
            parser.error("Upload test enabled but no upload URL provided.")
        if options.download:
            print(f"Download URL: {options.download_url}")
            if options.download_url_cycle is not None:
                print(
                    f"Download URL list: {options.download_url_list} "
                    f"({len(options.download_urls)} entries)"
                )
        if options.upload:
            print(f"Upload URL: {options.upload_url}")
        if options.real_delay:
            print(f"Real delay URL: {options.real_delay_url}")
        if options.dynamic_proxy:
            print(f"Proxy template: {options.proxy}")
        else:
            print(f"Proxy: {options.proxy}")
        print(f"Output: {options.out}")

        ranges = parse_ip_lines(options.ip_file)
        output_lock = threading.Lock()
        with open(options.out, "w", encoding="utf-8") as output_handle:
            for range_item in ranges:
                if options.stop_event.is_set():
                    break
                scan_range(range_item, options, output_lock, output_handle)
    except KeyboardInterrupt:
        options.stop_event.set()
        print("\nScan interrupted by user. Partial results saved.")
    finally:
        if server:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
