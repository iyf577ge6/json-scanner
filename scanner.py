#!/usr/bin/env python3
import argparse
import http.server
import ipaddress
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
import math
from functools import partial
from concurrent.futures import ThreadPoolExecutor, as_completed


XRAY_REPO_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
DEFAULT_TEST_DIR = os.path.join(os.path.expanduser("~"), ".json-scanner", "test-files")
DEFAULT_TEST_FILENAME = "test.bin"


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
    if os.path.isfile(xray_bin):
        return xray_bin
    found = shutil.which(xray_bin)
    if found:
        return found

    cwd = os.getcwd()
    for filename in ("xray", "xray.exe"):
        candidate = os.path.join(cwd, filename)
        if os.path.isfile(candidate):
            return candidate

    print("Xray binary not found. Downloading latest release for your platform...")
    return download_xray(cwd)


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
        "5",
        "--max-time",
        "8",
    ]
    if download_bytes and download_bytes > 0:
        args.extend(["--range", f"0-{download_bytes - 1}"])
    args.append(url)
    result = run_curl(args)
    if result.returncode != 0:
        return False, 0.0
    speed_bps, http_code = parse_curl_metrics(result.stdout.decode())
    if speed_bps is None or not is_success_http_code(http_code):
        return False, 0.0
    speed_kbps = speed_bps / 1024
    if speed_kbps <= 0:
        return False, 0.0
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
        "%{speed_upload} %{http_code}",
        "--proxy",
        proxy,
        "--connect-timeout",
        "5",
        "--max-time",
        "8",
        "--data-binary",
        "@-",
        url,
    ]
    result = run_curl(args, stdin_bytes=payload)
    if result.returncode != 0:
        return False, 0.0
    speed_bps, http_code = parse_curl_metrics(result.stdout.decode())
    if speed_bps is None or not is_success_http_code(http_code):
        return False, 0.0
    speed_kbps = speed_bps / 1024
    if speed_kbps <= 0:
        return False, 0.0
    if min_kbps and speed_kbps < min_kbps:
        return False, speed_kbps
    return True, speed_kbps


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


class LocalTestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        self._discard_body()

    def do_PUT(self):
        self._discard_body()

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
        self.wfile.write(b"OK")


def start_local_test_server(directory, listen_host, port):
    handler = partial(LocalTestHandler, directory=directory)
    server = http.server.ThreadingHTTPServer((listen_host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def scan_ip(ip_value, options):
    if options.stop_event.is_set():
        return ip_value, False, 0.0, 0.0
    config_text = render_config(options.config, ip_value)
    process, config_path = run_xray(options.xray_bin, config_text)
    if options.xray_startup_delay > 0:
        time.sleep(options.xray_startup_delay)
    success = True
    download_speed = 0.0
    upload_speed = 0.0
    try:
        if options.download:
            download_bytes = select_download_bytes(options)
            download_ok, download_speed = test_download(
                options.download_url,
                options.proxy,
                options.min_kbps,
                download_bytes,
            )
            success = success and download_ok
        if options.upload:
            upload_ok, upload_speed = test_upload(
                options.upload_url,
                options.proxy,
                options.upload_size_kb,
                options.min_kbps,
            )
            success = success and upload_ok
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
    show_progress = range_size != 1
    if options.random:
        random.shuffle(items)
    if items:
        if not options.config_validated:
            config_text = render_config(options.config, items[0])
            if not validate_xray_config(options.xray_bin, config_text, show_message=True):
                return
            options.config_validated = True
    start_time = time.time()
    scanned = 0
    success_count = 0
    last_report = 0.0

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
        item_iter = iter(items)

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
                    if not show_progress and ip_value is not None:
                        if success:
                            if options.download:
                                print(f"{label}: ok - {download_speed:.2f} KB/s")
                            else:
                                print(f"{label}: ok")
                        else:
                            print(f"{label}: fail")
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


def build_parser():
    parser = argparse.ArgumentParser(description="IP scanner for Xray/V2Ray configs")
    parser.add_argument("-i", "--ip-file", help="Path to IP list file")
    parser.add_argument("-c", "--config", help="Path to Xray JSON template")
    parser.add_argument("-x", "--xray-bin", default="xray", help="Path to Xray binary")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Parallel threads")
    parser.add_argument("-d", "--download", action="store_true", help="Enable download test")
    parser.add_argument("-u", "--upload", action="store_true", help="Enable upload test")
    parser.add_argument("-D", "--download-url")
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
        default=1024 * 512,
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
    parser.add_argument("-p", "--proxy", default="socks5h://127.0.0.1:10808")
    parser.add_argument("-w", "--xray-startup-delay", type=float, default=0.0, help=argparse.SUPPRESS)
    parser.add_argument("-o", "--out", default="success.txt", help="Output file")
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

    if not options.download and not options.upload:
        options.download = prompt_bool("Enable download test?", default=True)
        options.upload = prompt_bool("Enable upload test?", default=False)
        if not options.download and not options.upload:
            print("At least one test must be enabled.")
            options.download = True

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
    options.download_bytes = 0
    options.random = options.random or prompt_bool("Randomize IP order?", default=options.random)
    options.auto_skip = options.auto_skip or prompt_bool("Enable auto skip?", default=options.auto_skip)
    options.out = prompt_text("Output file", default=options.out)
    return options


def main():
    parser = build_parser()
    options = parser.parse_args()
    options.stop_event = threading.Event()
    options.config_validated = False
    if len(sys.argv) == 1 or not options.ip_file or not options.config:
        options = configure_interactive(options)
    options.xray_bin = resolve_xray_binary(options.xray_bin)

    if not options.download and not options.upload:
        parser.error("At least one of --download or --upload must be set.")

    server = None
    try:
        use_local_server = options.local_test_server or (
            (options.download and not options.download_url)
            or (options.upload and not options.upload_url)
        )
        if use_local_server:
            test_file_path = options.test_file_path
            if not test_file_path:
                test_file_path = os.path.join(DEFAULT_TEST_DIR, DEFAULT_TEST_FILENAME)
            ensure_test_file(test_file_path, options.test_file_size_mb)
            server_directory = os.path.dirname(test_file_path) or "."
            server = start_local_test_server(
                server_directory,
                options.local_test_listen,
                options.local_test_port,
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

        ranges = parse_ip_lines(options.ip_file)
        output_lock = threading.Lock()
        with open(options.out, "w", encoding="utf-8") as output_handle:
            for kind, label, items in ranges:
                if options.stop_event.is_set():
                    break
                scan_range(label, items, options, output_lock, output_handle)
    except KeyboardInterrupt:
        options.stop_event.set()
        print("\nScan interrupted by user. Partial results saved.")
    finally:
        if server:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
