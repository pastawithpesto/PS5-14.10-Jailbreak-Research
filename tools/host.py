#!/usr/bin/env python3
"""PS5 WebKit Remote Loader -- DNS spoofer + HTTPS server.

    sudo python3 host.py
    sudo python3 host.py --http-port 8080

Point the console DNS at this PC, then open Settings -> User's Guide.
TLS certificate generation uses openssl unless a certificate is supplied.
"""

import argparse
import base64
import binascii
import datetime
import errno
import io
import json
import mimetypes
import os
import posixpath
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from collections import defaultdict, deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


# ===========================================================================
# Build Placeholders  (replaced by tools/build_host.py for release bundles)
# ===========================================================================

# [[VERSION_PLACEHOLDER]]
VERSION = "0.2.0"
HOST_NAME = "PS5 WEBKIT REMOTE LOADER"

# [[BUILD_TIME_PLACEHOLDER]]
BUILD_TIME = "dev"

# [[SSL_CERT_PLACEHOLDER]]
SSL_CERT_PEM = ""

# [[SSL_KEY_PLACEHOLDER]]
SSL_KEY_PEM = ""

# [[EMBEDDED_ZIP]]
EMBEDDED_ZIP_B64 = ""

DEFAULT_TARGET = "manuals.playstation.net"
DEFAULT_TTL = 300
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
BEACON_LOG = os.path.join(REPO_ROOT, "host-beacons.log")


# ===========================================================================
# Embedded Zip  (standalone release mode)
# ===========================================================================

_embedded_zip_cache = None
_embedded_zip_loaded = False


def get_embedded_zip():
    """Lazily decode EMBEDDED_ZIP_B64 into an in-memory zipfile.ZipFile."""
    global _embedded_zip_cache, _embedded_zip_loaded
    if not _embedded_zip_loaded:
        _embedded_zip_loaded = True
        if EMBEDDED_ZIP_B64:
            try:
                _embedded_zip_cache = zipfile.ZipFile(
                    io.BytesIO(base64.b64decode(EMBEDDED_ZIP_B64))
                )
            except (binascii.Error, zipfile.BadZipFile):
                _embedded_zip_cache = None
    return _embedded_zip_cache


# ===========================================================================
# Terminal Output
# ===========================================================================

COLOR = sys.stdout.isatty()


def style(text, *codes):
    """ANSI styling wrapper.  No-op when output is not a terminal."""
    if not COLOR:
        return text
    return "\033[" + ";".join(str(c) for c in codes) + "m" + text + "\033[0m"


def say(text):
    print(text, flush=True)


def good(text):
    say(style("[+]", 32) + " " + text)


def bad(text):
    say(style("[-]", 31) + " " + text)


def note(text):
    say(style("    " + text, 2))


def bind_hint(service, port, exc):
    """User-facing explanation for a failed bind."""
    if isinstance(exc, PermissionError):
        return (
            f"{service} port {port} is privileged. On Linux and macOS you "
            f"probably need to run this with sudo."
        )
    if getattr(exc, "errno", None) == errno.EADDRINUSE:
        return (
            f"{service} port {port} is already in use. Find the holder with "
            f"`lsof -i :{port}` and stop it, or pass a different port "
            f"(e.g. --dns-port 1053 / --https-port 8443) and set the PS5 DNS "
            f"port to match."
        )
    return ""


# ===========================================================================
# Beacon Store -- structured in-memory log with rich terminal display
# ===========================================================================

# Beacon event classification for color-coded output.
# Color codes: 32=green (success), 35=magenta (corruption/hit), 33=yellow
# (progress), 36=cyan (diagnostic), 31=red (failure/error).
_BEACON_COLORS = {
    # Success / completion
    "COMPILED": 32, "DONE": 32, "OK": 32, "MARKER-OK": 32, "READY": 32,
    "ALIVE": 32, "W-READY": 32, "W-ALIVE": 32,
    # Corruption / hit -- the money events
    "CORRUPT": 35, "W-CORRUPT": 35, "HIT": 35, "LEAK": 35, "DIRTY": 35,
    "DIRTY-BYTES": 35, "UAF": 35, "SPRAY-HIT": 35, "JSCORRUPT": 35,
    # Progress
    "BOOT": 33, "INIT": 33, "GC": 33, "GC-DONE": 33, "GC-FREED": 33,
    "BLOB": 33, "BAITS": 33, "VIEWS": 33, "INIT-CHECK": 33, "GROOM": 33,
    "GROOM-DONE": 33, "SPRAY": 33,
    # Data / diagnostic
    "SCAN": 36, "NO-HIT": 36, "W-GOT": 36, "W-WATCHING": 36,
    "CALLED": 36, "CALLING": 36,
    # Failure
    "DEAD": 31, "CRASH": 31, "ERR": 31, "FAIL": 31, "OOM": 31,
}

_BEACON_PATH_RE = re.compile(r"^/beacon/(?:([A-Za-z]\d+)-)?(.+)$")


def _classify_beacon(event_name):
    """Return ANSI color code for a beacon event name."""
    upper = event_name.upper()
    if upper in _BEACON_COLORS:
        return _BEACON_COLORS[upper]
    for key, color in _BEACON_COLORS.items():
        if upper.startswith(key):
            return color
    return 0


def _parse_beacon_path(path):
    """Extract (probe_id, event_name) from a path like /beacon/V475-BOOT.

    Returns (probe_id_or_None, event_name).  Non-versioned beacons like
    /beacon/noop-check return (None, "noop-check").
    """
    m = _BEACON_PATH_RE.match(path)
    if m:
        return m.group(1), m.group(2)
    rest = path[len("/beacon/"):] if path.startswith("/beacon/") else path
    return None, rest


class BeaconStore:
    """Thread-safe beacon ring buffer with structured logging and display.

    Replaces the old duplicated _log_beacon / do_POST beacon code with one
    unified sink.  Backward-compatible JSON-lines output (old fields preserved),
    plus new fields: ts (ISO), seq, method, probe, event.
    """

    def __init__(self, max_recent=500, log_path=BEACON_LOG):
        self._lock = threading.Lock()
        self._recent = deque(maxlen=max_recent)
        self._seq = 0
        self._by_probe = defaultdict(list)
        self._active_probe = None
        self._log_path = log_path
        self._log_fh = None

    def record(self, method, path, body="", origin="", ua=""):
        """Record a beacon from GET or POST.  Logs to disk, displays to tty."""
        stamp = time.strftime("%H:%M:%S")
        iso_stamp = datetime.datetime.now().isoformat(timespec="milliseconds")
        probe, event = _parse_beacon_path(path)

        with self._lock:
            self._seq += 1
            seq = self._seq
            if probe:
                self._active_probe = probe

            entry = {
                # Original fields (backward-compatible)
                "t": stamp, "path": path, "ua": ua[:70],
                "body": body[:800], "origin": origin,
                # New fields
                "ts": iso_stamp, "seq": seq, "method": method,
                "probe": probe, "event": event,
            }

            self._recent.append(entry)
            if probe:
                self._by_probe[probe].append(entry)

            # Persist in sequence order (line-buffered).
            try:
                line = json.dumps(entry)
                if self._log_fh is None:
                    self._log_fh = open(
                        self._log_path, "a", encoding="utf-8", buffering=1
                    )
                self._log_fh.write(line + "\n")
            except OSError:
                pass

        self._display(entry)
        return entry

    def _display(self, entry):
        """Print a color-coded beacon line to the terminal."""
        probe = entry.get("probe") or "---"
        event = entry["event"]
        body = entry["body"]
        origin = entry["origin"]
        color = _classify_beacon(event)

        tag = style("[BEACON]", 1, 33)
        probe_s = style(probe, 1, 36) if entry.get("probe") else style(probe, 2)
        event_s = style(event, 1, color) if color else style(event, 1)

        parts = [tag, probe_s, event_s]
        if body:
            display_body = body if len(body) <= 80 else body[:77] + "..."
            parts.append(style(display_body, 2))
        parts.append(style(f"({origin})", 2))

        say(" ".join(parts))

    @property
    def active_probe(self):
        with self._lock:
            return self._active_probe

    @property
    def count(self):
        with self._lock:
            return self._seq

    def recent(self, n=20):
        with self._lock:
            items = list(self._recent)
        return items[-n:]

    def for_probe(self, probe_id):
        with self._lock:
            return list(self._by_probe.get(probe_id, []))

    def close(self):
        if self._log_fh:
            try:
                self._log_fh.close()
            except OSError:
                pass


# ===========================================================================
# Statistics Tracker
# ===========================================================================

class Stats:
    """Thread-safe counters for DNS, HTTP, TLS, and connection tracking."""

    def __init__(self):
        self._lock = threading.Lock()
        self.dns_total = 0
        self.dns_spoofed = 0
        self.dns_blocked = 0
        self.http_total = 0
        self.http_by_code = defaultdict(int)
        self.tls_ok = 0
        self.tls_fail = 0
        self.beacon_count = 0
        self.client_ips = set()
        self.start_time = time.monotonic()
        self._milestones = {"dns": False, "http": False, "document": False}

    def dns_query(self, spoofed=True, client_ip=None):
        with self._lock:
            self.dns_total += 1
            if spoofed:
                self.dns_spoofed += 1
            else:
                self.dns_blocked += 1
            if client_ip:
                self.client_ips.add(client_ip)

    def http_request(self, status_code=200, client_ip=None):
        with self._lock:
            self.http_total += 1
            self.http_by_code[status_code] += 1
            if client_ip:
                self.client_ips.add(client_ip)

    def tls_handshake(self, success=True, client_ip=None):
        with self._lock:
            if success:
                self.tls_ok += 1
            else:
                self.tls_fail += 1
            if client_ip:
                self.client_ips.add(client_ip)

    def beacon(self):
        with self._lock:
            self.beacon_count += 1

    def milestone(self, name):
        """Return True exactly once per milestone name."""
        with self._lock:
            if self._milestones.get(name, True):
                return False
            self._milestones[name] = True
            return True

    def summary(self):
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            return {
                "uptime": f"{mins}m{secs:02d}s",
                "dns": self.dns_total,
                "dns_spoofed": self.dns_spoofed,
                "dns_blocked": self.dns_blocked,
                "http": self.http_total,
                "tls_ok": self.tls_ok,
                "tls_fail": self.tls_fail,
                "beacons": self.beacon_count,
                "clients": len(self.client_ips),
                "client_ips": sorted(self.client_ips),
            }


# ===========================================================================
# File Watcher -- detect probe/HTML changes on disk
# ===========================================================================

class FileWatcher:
    """Monitors the repo root for HTML/JS file changes and logs them."""

    WATCH_EXTENSIONS = (".html", ".htm", ".js", ".mjs")

    def __init__(self, root, interval=3.0):
        self._root = root
        self._interval = interval
        self._mtimes = {}
        self._stop = threading.Event()
        self._scan()  # baseline snapshot

    def _scan(self):
        """Snapshot mtimes of watched files in the repo root."""
        mtimes = {}
        try:
            for entry in os.scandir(self._root):
                if not entry.is_file():
                    continue
                name = entry.name
                if name.startswith(".") or name == "host-beacons.log":
                    continue
                if any(name.endswith(ext) for ext in self.WATCH_EXTENSIONS):
                    try:
                        mtimes[name] = entry.stat().st_mtime
                    except OSError:
                        pass
        except OSError:
            pass
        return mtimes

    def start(self):
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        while not self._stop.wait(self._interval):
            current = self._scan()
            for name, mtime in current.items():
                old = self._mtimes.get(name)
                if old is not None and mtime != old:
                    say(style(f"[FILE] {name} modified", 1, 33))
                elif old is None:
                    say(style(f"[FILE] {name} added", 1, 32))
            for name in set(self._mtimes) - set(current):
                say(style(f"[FILE] {name} removed", 2, 31))
            self._mtimes = current

    def stop(self):
        self._stop.set()


# ===========================================================================
# Local IP Detection
# ===========================================================================

def detect_local_ip():
    """Best-effort LAN IP via UDP socket probe (no traffic transmitted)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "127.0.0.1"


def validate_ip(value):
    socket.inet_aton(value)
    return value


# ===========================================================================
# DNS Server
# ===========================================================================

def parse_dns_query(data):
    """Parse the first question of a DNS query.

    Returns (qid, question_bytes, name) with question_bytes being the raw
    question section to echo back, or None if the packet is malformed.
    """
    if len(data) < 12:
        return None
    qid, _flags, qdcount = struct.unpack(">HHH", data[:6])
    if qdcount < 1:
        return None

    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:  # compression pointer or reserved bits
            return None
        offset += 1
        if offset + length > len(data):
            return None
        try:
            labels.append(data[offset:offset + length].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += length
    else:
        return None  # ran off end without a zero label

    if offset + 4 > len(data):  # need QTYPE + QCLASS
        return None
    return qid, data[12:offset + 4], ".".join(labels).lower()


def build_dns_response(qid, question_bytes, ip=None, ttl=DEFAULT_TTL):
    """Build a DNS response.  With ip -> one A record; without -> NXDOMAIN."""
    if ip is None:
        flags = 0x8183  # QR + RD + RA + NXDOMAIN
        answer = b""
        ancount = 0
    else:
        flags = 0x8180  # QR + RD + RA
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 1, 1, ttl, 4)
            + socket.inet_aton(ip)
        )
        ancount = 1
    header = struct.pack(">HHHHHH", qid, flags, 1, ancount, 0, 0)
    return header + question_bytes + answer


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        parsed = parse_dns_query(data)
        if parsed is None:
            return
        qid, question_bytes, name = parsed
        srv = self.server
        client_ip = self.client_address[0]

        if name == srv.target:
            srv.stats.dns_query(spoofed=True, client_ip=client_ip)
            if srv.verbose:
                say(style(f"[DNS]  {name} -> {srv.ip}", 36))
            sock.sendto(
                build_dns_response(qid, question_bytes, srv.ip),
                self.client_address,
            )
            if srv.stats.milestone("dns"):
                say("")
                good("PS5 is talking to us (DNS).")
                note("On the PS5: Settings -> User's Guide")
                note("If the DNS is not set yet:")
                note("Settings -> Network -> Set Up Internet Connection")
                note("-> Set Up Manually -> DNS Settings")
                say("")
        else:
            srv.stats.dns_query(spoofed=False, client_ip=client_ip)
            if srv.verbose:
                say(style(f"[DNS]  {name} -> NXDOMAIN", 33))
            sock.sendto(
                build_dns_response(qid, question_bytes),
                self.client_address,
            )


class DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, target, ip, stats, verbose=False):
        self.target = target
        self.ip = ip
        self.stats = stats
        self.verbose = verbose
        super().__init__(address, DNSHandler)


# ===========================================================================
# Route Resolution -- firmware routing + file lookup
# ===========================================================================

_FW_RE = re.compile(r"PlayStation 5/(\d+\.\d+)")
_POOPS_FIRMWARES = {9.05, 11.40}


def detect_firmware(user_agent):
    """Extract PS5 firmware version from User-Agent, or None."""
    m = _FW_RE.search(user_agent)
    return float(m.group(1)) if m else None


def choose_index_page(firmware, query_exploit):
    """Determine which index page to serve based on firmware and query params.

    Flag-file routing: if deploy/<name>.on exists, serve <name> as the index.
    Swap probes with: touch deploy/v576.html.on  (rm others first)
    This avoids editing index.html for every deploy.

    Returns the preferred filename to try first, or None for default behavior.
    """
    # Flag-file routing (cobra harness pattern): check deploy/*.on
    deploy_dir = os.path.join(REPO_ROOT, "deploy")
    try:
        for fn in os.listdir(deploy_dir):
            if fn.endswith(".on"):
                target = fn[:-3]  # strip .on
                if os.path.isfile(os.path.join(REPO_ROOT, target)):
                    return target
    except OSError:
        pass

    if query_exploit == "poops":
        return "poops.html"
    if query_exploit == "relapse":
        return "relapse.html"
    if firmware is not None and round(firmware, 2) in _POOPS_FIRMWARES:
        return "poops.html"
    return None


def normalize_request_path(raw_path):
    """Normalize a request path, rewriting the User's Guide doc path to root.

    /document/XX/ps5/foo.html -> foo.html
    /whatever/path            -> whatever/path  (no leading slash)
    """
    path = raw_path.split("?", 1)[0].split("#", 1)[0]

    # Rewrite /document/XX/ps5/... to root
    if path.startswith("/document/") and "/ps5/" in path:
        path = "/" + path.split("/ps5/", 1)[1]

    try:
        path = urllib.parse.unquote(path, errors="surrogatepass")
    except UnicodeDecodeError:
        path = urllib.parse.unquote(path)

    path = posixpath.normpath(path)
    parts = [
        w for w in path.split("/")
        if w and not (os.path.dirname(w) or w in (os.curdir, os.pardir))
    ]
    return "/".join(parts)


def resolve_file(rel_path, firmware=None, query_exploit=None):
    """Resolve a relative path to file content.

    Returns (kind, full_path, shown_name, data, mtime) or None.
    kind: "zip" (embedded bundle) or "file" (local filesystem).
    For "file", data is None -- the caller reads it.
    """
    candidates = [rel_path]

    is_index = not rel_path or rel_path.endswith("/")
    if is_index:
        preferred = choose_index_page(firmware, query_exploit)
        if preferred:
            candidates = [preferred, rel_path + "index.html", rel_path + "index.htm"]
        else:
            candidates = [rel_path + "index.html", rel_path + "index.htm"]
    elif rel_path == "relapse.html":
        candidates.append("index.html")

    # 1. Embedded zip archive (standalone bundled release mode)
    z = get_embedded_zip()
    if z is not None:
        names = set(z.namelist())
        for candidate in candidates:
            clean = candidate.lstrip("/")
            if clean in names:
                info = z.getinfo(clean)
                data = z.read(info)
                mtime = datetime.datetime(*info.date_time[:6]).timestamp()
                return "zip", None, candidate, data, mtime
        return None

    # 2. Local filesystem (development mode from source checkout)
    for candidate in candidates:
        full = os.path.join(REPO_ROOT, candidate)
        try:
            real = os.path.abspath(full)
            if (os.path.commonpath([real, REPO_ROOT]) == REPO_ROOT
                    and os.path.isfile(full)):
                return "file", full, candidate, None, os.path.getmtime(full)
        except (ValueError, OSError):
            pass

    return None


# ===========================================================================
# HTTP Handler
# ===========================================================================

class GuideHandler(SimpleHTTPRequestHandler):
    """Serves the repo with User's Guide path rewriting and beacon collection.

    All POST requests are treated as beacons (crash-safe: whatever the probe
    sends gets logged, no matter the path).  GET /beacon/* is also a beacon.
    """

    server_version = "PS5WebKitLoaderHost/2.0"

    def __init__(self, *args, allowed_host=None, **kwargs):
        self.allowed_host = allowed_host.lower() if allowed_host else None
        super().__init__(*args, directory=REPO_ROOT, **kwargs)

    # -- Logging (suppress stdlib, do our own) ----------------------------

    def log_message(self, fmt, *args):
        pass

    def log_request(self, code="-", size="-"):
        """Always log the request line, even when not verbose.

        A silent server is the worst thing to debug: if the User's Guide shows
        a cert error or a blank page you need to know whether the request
        arrived at all.
        """
        agent = self.headers.get("User-Agent", "-")
        say(style(
            f"[HTTP] {self.command} {self.path} -> {code}  "
            f"UA: {agent[:60]}",
            36,
        ))
        try:
            code_int = int(code) if str(code).isdigit() else 0
            self.server.stats.http_request(code_int, self.client_address[0])
        except (AttributeError, ValueError):
            pass

    def _host_allowed(self):
        if self.allowed_host is None:
            return True
        host = self.headers.get("Host", "").split(":", 1)[0].strip().lower()
        return host == self.allowed_host

    # -- Unified Beacon Handler -------------------------------------------

    def _handle_beacon(self, method="GET"):
        """Single beacon sink for both GET /beacon/* and all POSTs.

        Replaces the old duplicated _log_beacon (GET) and do_POST logic.
        """
        raw = self.path.split("#", 1)[0]  # strip fragment (never sent, but safe)
        body = ""
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                length = max(0, min(length, 1 << 20))  # cap at 1 MB
                if length > 0:
                    body = self.rfile.read(length).decode("utf-8", "replace")
            except (ValueError, OSError):
                pass

        ua = (self.headers.get("User-Agent", "-"))[:70]
        origin = self.client_address[0]

        try:
            self.server.beacons.record(method, raw, body, origin, ua)
            self.server.stats.beacon()
        except Exception:
            pass

        self.log_request(204)
        try:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- Special Endpoints ------------------------------------------------

    def _handle_ftp_redir(self):
        """CVE-2023-42890 trigger: 302 redirect to FTP URL."""
        self.send_response(302)
        self.send_header("Location", "ftp://exploit.test/pwn")
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _handle_slow_response(self):
        """Slow chunked response for heap spray timing."""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for _ in range(10):
            chunk = b"A" * 1024
            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            self.wfile.flush()
            time.sleep(0.5)
        self.wfile.write(b"0\r\n\r\n")

    def _handle_slow_xhtml(self):
        """Streaming XHTML for CE injection timing attack (V417).

        Sends XHTML in two chunks with 5s delay between them.  First chunk:
        valid XHTML head+body with safe elements.  Second chunk: custom element
        tags that XMLDocumentParser should find in the registry.
        """
        self.send_response(200)
        self.send_header("Content-Type", "application/xhtml+xml")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        chunk1 = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<html xmlns="http://www.w3.org/1999/xhtml">'
            b'<head><title>V417-STREAM</title></head>'
            b'<body>'
            b'<div id="host">streaming-target</div>'
            b'<div id="sink">streaming-sink</div>'
        )
        self.wfile.write(f"{len(chunk1):x}\r\n".encode() + chunk1 + b"\r\n")
        self.wfile.flush()
        time.sleep(5)

        chunk2 = (
            b'<pwn-stream id="ps1">payload1</pwn-stream>'
            b'<pwn-stream id="ps2">payload2</pwn-stream>'
            b'</body></html>'
        )
        self.wfile.write(f"{len(chunk2):x}\r\n".encode() + chunk2 + b"\r\n")
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _handle_status_api(self):
        """GET /api/status -- JSON session stats for external monitors."""
        try:
            data = self.server.stats.summary()
            data["active_probe"] = self.server.beacons.active_probe
            data["recent_beacons"] = self.server.beacons.recent(10)
            body = json.dumps(data).encode("utf-8")
        except Exception:
            body = b'{"error": "stats unavailable"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # -- Request Routing --------------------------------------------------

    def _handle_hold(self):
        """Kernel-level liveness socket: never finishes the response.
        The host logs OPEN immediately; when the console process dies its
        kernel closes the TCP connection and the next recv/write observes it,
        logging CLOSE with the death timestamp. No JS cooperation needed."""
        peer = self.client_address[0]
        tag = self.path.split("?", 1)[1][:120] if "?" in self.path else ""
        hold_log = "/tmp/opencode/hold.log"

        def _hlog(kind, extra=""):
            try:
                with open(hold_log, "a") as f:
                    f.write("%s %-5s %s %s\n" % (
                        datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        kind, peer, extra))
            except Exception:
                pass

        _hlog("OPEN", tag)
        reason = "unknown"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                self.wfile.flush()
            except Exception:
                pass
            self.connection.settimeout(0.25)
            last_ka = time.time()
            while True:
                try:
                    data = self.connection.recv(1024)
                    if data == b"":
                        reason = "EOF"
                        break
                except socket.timeout:
                    pass
                except OSError as e:
                    reason = "RST" if e.errno in (104, 32, 54) else ("ERR:" + str(e))
                    break
                if time.time() - last_ka >= 5.0:
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError) as e:
                        reason = "WRITE-" + type(e).__name__
                        break
                    except OSError as e:
                        reason = "WRITE-ERR:" + str(e)
                        break
                    last_ka = time.time()
        finally:
            _hlog("CLOSE", reason)

    # path -> (handler_method_name, logged_status_code)
    _SPECIAL_ROUTES = {
        "/hold":           ("_handle_hold", 200),
        "/ftp-redir":      ("_handle_ftp_redir", 302),
        "/slow-response":  ("_handle_slow_response", 200),
        "/slow-xhtml":     ("_handle_slow_xhtml", 200),
        "/api/status":     ("_handle_status_api", 200),
    }

    def do_GET(self):
        raw = self.path.split("?", 1)[0]

        # Beacon paths
        if raw.startswith("/beacon/"):
            self._handle_beacon("GET")
            return

        # Special routes
        route = self._SPECIAL_ROUTES.get(raw)
        if route:
            handler_name, code = route
            self.log_request(code)
            try:
                getattr(self, handler_name)()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # Normal file serving
        f = self.send_head()
        if f:
            try:
                self.wfile.write(f.read())
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                f.close()

    def do_POST(self):
        """Every POST is a beacon.  Crash-safe: whatever the probe sends,
        it gets logged regardless of the path."""
        self._handle_beacon("POST")

    def do_OPTIONS(self):
        """CORS preflight for beacon POSTs from cross-origin contexts."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "86400")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_head(self):
        """Resolve and serve a file with appropriate headers."""
        raw_path = self.path.split("?", 1)[0].split("#", 1)[0]

        if not self._host_allowed():
            self.send_error(403, "Host not allowed")
            say(style(
                f"[HTTP] {self.command} {raw_path} -> REJECTED (host mismatch)",
                31,
            ))
            return None

        # Firmware detection + query param routing
        ua = self.headers.get("User-Agent", "")
        firmware = detect_firmware(ua)
        query_exploit = None
        if "?" in self.path:
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1])
            query_exploit = qs.get("exploit", [None])[0]

        rel = normalize_request_path(self.path)
        resolved = resolve_file(rel, firmware, query_exploit)

        if resolved is None:
            self.send_error(404, "File not found")
            say(style(f"[HTTP] {self.command} {raw_path} -> 404", 31))
            return None

        kind, full, shown, data, mtime = resolved

        if kind == "file":
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError as exc:
                self.send_error(500, str(exc))
                say(style(
                    f"[HTTP] {self.command} {raw_path} -> 500 ({exc})", 31
                ))
                return None

        # Template substitution for build placeholders
        if data and (b"[[VERSION_PLACEHOLDER]]" in data
                     or b"[[BUILD_TIME_PLACEHOLDER]]" in data):
            data = data.replace(
                b"[[VERSION_PLACEHOLDER]]", VERSION.encode("utf-8")
            )
            data = data.replace(
                b"[[BUILD_TIME_PLACEHOLDER]]", BUILD_TIME.encode("utf-8")
            )

        # Content type
        ctype = mimetypes.guess_type(shown)[0] or "application/octet-stream"
        if shown.endswith((".js", ".mjs")):
            ctype = "application/javascript"
        elif shown.endswith((".html", ".htm")):
            ctype = "text/html; charset=utf-8"

        # Response headers -- never cache (stale JS/offsets waste a reload cycle)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Last-Modified", self.date_time_string(mtime))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

        # Detail logging with routing info
        detail = shown
        is_poops_fw = (firmware is not None
                       and round(firmware, 2) in _POOPS_FIRMWARES)
        if shown == "poops.html" and is_poops_fw and query_exploit is None:
            detail = f"{shown} (PS5 FW {firmware:.2f} -> Poops)"
        elif query_exploit:
            detail = f"{shown} (exploit={query_exploit})"
        say(style(f"[HTTP] {self.command} {raw_path} -> {detail}", 34))

        # Document-served milestone
        if raw_path.startswith("/document/"):
            if self.server.stats.milestone("document"):
                say("")
                good("User's Guide document served.")
                note("The WebKit exploit should be running on the PS5 now.")
                note("Reload the User's Guide if the browser stalls.")
                note("")
                note("When done, set the PS5 DNS back to automatic,")
                note("otherwise it has no internet.")
                say("")

        return io.BytesIO(data)


# ===========================================================================
# TLS
# ===========================================================================

class LoggingSSLContext(ssl.SSLContext):
    """TLS context that reports each handshake outcome.

    This is the most useful diagnostic line when the PS5 is not cooperating:
    it separates "the PS5 never reached us" (no line at all) from "the PS5
    connected and the handshake failed" from "TLS completed and the problem
    is elsewhere."
    """

    stats = None  # set externally after construction

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
                    suppress_ragged_eofs=True, server_hostname=None,
                    session=None):
        peer_ip = "?"
        try:
            peer = sock.getpeername()
            peer_ip = peer[0] if peer else "?"
        except (OSError, AttributeError):
            pass

        try:
            wrapped = super().wrap_socket(
                sock, server_side, do_handshake_on_connect,
                suppress_ragged_eofs, server_hostname, session,
            )
        except ssl.SSLError as exc:
            say(style(
                f"[TLS]  handshake FAILED from {peer_ip} -> {exc}", 31
            ))
            if self.stats:
                self.stats.tls_handshake(success=False, client_ip=peer_ip)
            raise

        try:
            peer = wrapped.getpeername()
            say(style(
                f"[TLS]  handshake ok from {peer[0]}: "
                f"{wrapped.version()} {wrapped.cipher()[0]}",
                32,
            ))
            if self.stats:
                self.stats.tls_handshake(success=True, client_ip=peer[0])
        except OSError:
            pass
        return wrapped


def make_cert(target):
    """Self-signed cert for the spoofed hostname, via openssl.

    Includes a subjectAltName because CN-only certificates are rejected by
    current TLS stacks.  Returns (cert_pem, key_pem) or (None, None).
    """
    with tempfile.TemporaryDirectory(prefix="ps5-wkl-") as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        conf = os.path.join(tmp, "openssl.cnf")
        with open(conf, "w") as f:
            f.write(
                "[req]\n"
                "distinguished_name = dn\n"
                "x509_extensions = ext\n"
                "prompt = no\n"
                "[dn]\n"
                f"CN = {target}\n"
                "[ext]\n"
                f"subjectAltName = DNS:{target}, IP:127.0.0.1\n"
                "basicConstraints = critical, CA:FALSE\n"
            )
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "825", "-sha256",
                    "-keyout", key_path, "-out", cert_path,
                    "-config", conf,
                ],
                check=True, capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None, None
        with open(cert_path) as f:
            cert = f.read()
        with open(key_path) as f:
            key = f.read()
    return cert, key


def setup_tls(httpsd, args, stats):
    """Configure TLS on the HTTPS server.  Returns True on success."""
    if args.cert and args.key:
        try:
            with open(args.cert) as f:
                cert_pem = f.read()
            with open(args.key) as f:
                key_pem = f.read()
        except OSError as exc:
            bad(f"Could not read --cert/--key: {exc}")
            return False
        good(f"Using pinned certificate {args.cert}")
    elif SSL_CERT_PEM and SSL_KEY_PEM:
        cert_pem = SSL_CERT_PEM
        key_pem = SSL_KEY_PEM
        if args.verbose:
            good("Using pre-built embedded TLS certificate")
    else:
        cert_pem, key_pem = make_cert(args.target)
        if cert_pem is None:
            bad("Could not generate an HTTPS certificate (openssl missing?).")
            note("Install openssl, or use --http-port 8080 for desktop testing.")
            return False

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert_pem.encode("ascii"))
    cert_file.close()
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(key_pem.encode("ascii"))
    key_file.close()

    ctx = LoggingSSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.stats = stats
    ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

    # An older WebKit may offer only legacy versions/ciphers.  macOS ships
    # LibreSSL, which rejects OpenSSL's "@SECLEVEL" syntax outright, so try
    # the permissive forms in order and keep the default if none apply.
    for spec in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
        try:
            ctx.set_ciphers(spec)
            break
        except ssl.SSLError:
            continue
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, ssl.SSLError):
        pass  # LibreSSL will not go below its own floor

    httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)

    # Cert is loaded into the context; temp files are safe to remove.
    for name in (cert_file.name, key_file.name):
        try:
            os.unlink(name)
        except OSError:
            pass

    return True


# ===========================================================================
# Server Builder
# ===========================================================================

def build_server(host, port, allowed_host, stats, beacons, quiet=False):
    """Create a ThreadingHTTPServer with the GuideHandler and shared state."""
    handler = lambda *a, **kw: GuideHandler(
        *a, allowed_host=allowed_host, **kw
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    httpd.stats = stats
    httpd.beacons = beacons
    httpd.quiet = quiet
    return httpd


# ===========================================================================
# Heartbeat -- periodic session status
# ===========================================================================

class Heartbeat:
    """Prints a compact status line periodically when there has been activity."""

    def __init__(self, stats, beacons, interval=60):
        self._stats = stats
        self._beacons = beacons
        self._interval = interval
        self._stop = threading.Event()
        self._last_beacon_count = 0

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop.wait(self._interval):
            s = self._stats.summary()
            bc = s["beacons"]
            if (s["dns"] > 0 or s["http"] > 0
                    or bc > self._last_beacon_count):
                probe = self._beacons.active_probe or "none"
                say(style(
                    f"[STAT] {s['uptime']} | "
                    f"dns:{s['dns']} http:{s['http']} beacons:{bc} "
                    f"tls:{s['tls_ok']}/{s['tls_ok'] + s['tls_fail']} "
                    f"clients:{s['clients']} "
                    f"probe:{probe}",
                    2,
                ))
                self._last_beacon_count = bc

    def stop(self):
        self._stop.set()


# ===========================================================================
# CLI
# ===========================================================================

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="host.py",
        description="DNS spoofer + HTTPS server so the PS5 User's Guide "
                    "can open this repo over the LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 host.py\n"
               "  python3 host.py --http-port 8080   # desktop testing too\n"
               "  python3 host.py --verbose\n",
    )

    net = p.add_argument_group("network")
    net.add_argument("--ip", type=validate_ip, default=None,
                     help="IP to hand out for the spoofed domain (default: auto).")
    net.add_argument("--target", default=DEFAULT_TARGET,
                     help=f"Domain to spoof (default: {DEFAULT_TARGET}).")
    net.add_argument("--dns-port", type=int, default=53,
                     help="DNS UDP port (default: 53).")
    net.add_argument("--https-port", type=int, default=443,
                     help="HTTPS TCP port (default: 443).")
    net.add_argument("--http-port", type=int, default=None,
                     help="Also serve plain HTTP on this port, e.g. 8080 for "
                          "testing in a desktop browser.")

    tls = p.add_argument_group("tls")
    tls.add_argument("--cert", default=None,
                     help="Pinned certificate PEM (default: generate a fresh "
                          "self-signed one for --target).")
    tls.add_argument("--key", default=None,
                     help="Pinned private key PEM, used with --cert.")

    toggle = p.add_argument_group("toggles")
    toggle.add_argument("--strict-host", action="store_true",
                        help="Only answer requests whose Host header is --target.")
    toggle.add_argument("--no-dns", action="store_true",
                        help="Disable the DNS server.")
    toggle.add_argument("--no-https", action="store_true",
                        help="Disable HTTPS.")
    toggle.add_argument("--no-watch", action="store_true",
                        help="Disable file-change watcher.")
    toggle.add_argument("--no-heartbeat", action="store_true",
                        help="Disable periodic status heartbeat.")
    toggle.add_argument("--verbose", action="store_true",
                        help="Log every DNS, TLS and HTTP event.")
    toggle.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color.")

    misc = p.add_argument_group("misc")
    misc.add_argument("--extract", nargs="?", const="remote-loader",
                      default=None,
                      help="Extract embedded bundle (tools/, payloads/, etc.) "
                           "to a directory and exit.")
    misc.add_argument("--beacon-log", default=BEACON_LOG,
                      help=f"Beacon log file path (default: host-beacons.log).")

    return p.parse_args(argv)


# ===========================================================================
# Main
# ===========================================================================

def print_banner(ip, args):
    """Print the startup banner."""
    w = 52
    def row(t):
        return "   |" + t.center(w) + "|"

    say("")
    say(style("   +" + "-" * w + "+", 36))
    lines = [
        f"{HOST_NAME} v{VERSION}",
        "PS5 User's Guide host",
        "serving " + (
            os.path.basename(REPO_ROOT)
            if not EMBEDDED_ZIP_B64 else "embedded bundle"
        ),
    ]
    if BUILD_TIME != "dev":
        lines.append(f"built {BUILD_TIME}")
    for line in lines:
        say(style(row(line), 36))
    say(style("   +" + "-" * w + "+", 36))
    say("")


def print_session_summary(stats, beacons):
    """Print end-of-session summary on shutdown."""
    s = stats.summary()
    bar = style("=" * 60, 36)
    say("")
    say(bar)
    say(style("  Session Summary", 1, 36))
    say(bar)
    say(f"  Uptime:       {s['uptime']}")
    say(f"  DNS queries:  {s['dns']} "
        f"({s['dns_spoofed']} spoofed, {s['dns_blocked']} blocked)")
    say(f"  HTTP reqs:    {s['http']}")
    say(f"  TLS:          {s['tls_ok']} ok, {s['tls_fail']} failed")
    say(f"  Beacons:      {s['beacons']}")
    clients = ", ".join(s["client_ips"]) if s["client_ips"] else "none"
    say(f"  Clients:      {clients}")

    probe = beacons.active_probe
    if probe:
        say(f"  Last probe:   {probe}")
        events = beacons.for_probe(probe)
        if events:
            names = [e["event"] for e in events[-20:]]
            say(f"  Probe events: {' -> '.join(names)}")

    say(bar)
    say("")


def main(argv=None):
    global COLOR
    args = parse_args(argv)
    if args.no_color:
        COLOR = False
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass

    # -- Extract mode (then exit) --
    if args.extract:
        z = get_embedded_zip()
        if not z:
            bad("No embedded bundle found in this host script "
                "(running from source).")
            return 1
        out_dir = os.path.abspath(args.extract)
        z.extractall(out_dir)
        good(f"Extracted {len(z.namelist())} files to {out_dir}")
        return 0

    if args.no_dns and args.no_https and args.http_port is None:
        bad("Every server is disabled, nothing to do.")
        return 1

    ip = args.ip or detect_local_ip()
    stats = Stats()
    beacons = BeaconStore(log_path=args.beacon_log)

    print_banner(ip, args)

    good(f"Spoofing {style(args.target, 1)} -> {style(ip, 1, 33)}")
    note("everything else gets NXDOMAIN (blocks PSN and update prompts)")
    good(f"Serving "
         f"{REPO_ROOT if not EMBEDDED_ZIP_B64 else 'embedded in-memory bundle'}")
    if args.verbose:
        good("Verbose mode: per-request logging on.")

    servers = []

    # -- DNS --
    if not args.no_dns:
        try:
            dns = DNSServer(
                ("0.0.0.0", args.dns_port), args.target, ip,
                stats, args.verbose,
            )
        except OSError as exc:
            bad(f"Could not bind DNS port {args.dns_port}: {exc}")
            hint = bind_hint("DNS", args.dns_port, exc)
            if hint:
                note(hint)
            return 1
        threading.Thread(target=dns.serve_forever, daemon=True).start()
        good(f"DNS on UDP {args.dns_port}")
        servers.append(dns)

    # -- HTTPS --
    if not args.no_https:
        try:
            httpsd = build_server(
                "0.0.0.0", args.https_port,
                args.target if args.strict_host else None,
                stats, beacons, not args.verbose,
            )
        except OSError as exc:
            bad(f"Could not bind HTTPS port {args.https_port}: {exc}")
            hint = bind_hint("HTTPS", args.https_port, exc)
            if hint:
                note(hint)
            return 1

        if not setup_tls(httpsd, args, stats):
            return 1

        threading.Thread(target=httpsd.serve_forever, daemon=True).start()
        good(f"HTTPS on TCP {args.https_port} (self-signed)")
        servers.append(httpsd)

    # -- HTTP (optional, desktop testing) --
    if args.http_port is not None:
        try:
            httpd = build_server(
                "0.0.0.0", args.http_port, None,
                stats, beacons, not args.verbose,
            )
        except OSError as exc:
            bad(f"Could not bind HTTP port {args.http_port}: {exc}")
            hint = bind_hint("HTTP", args.http_port, exc)
            if hint:
                note(hint)
        else:
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            good(f"HTTP on TCP {args.http_port} (plain, for desktop testing)")
            note(f"open http://localhost:{args.http_port}/ in a desktop browser")
            servers.append(httpd)

    if not servers:
        bad("No server started.")
        return 1

    # -- File watcher --
    watcher = None
    if not args.no_watch and not EMBEDDED_ZIP_B64:
        watcher = FileWatcher(REPO_ROOT)
        watcher.start()
        if args.verbose:
            good("File watcher active (HTML/JS changes will be logged)")

    # -- Heartbeat --
    heartbeat = None
    if not args.no_heartbeat:
        heartbeat = Heartbeat(stats, beacons)
        heartbeat.start()

    say("")
    good(f"Set the PS5 DNS to {style(ip, 1, 33)}")
    note("Settings -> Network -> Settings -> Set Up Internet Connection")
    note("-> Set Up Manually -> DNS Settings -> Primary DNS")
    say("")
    good("Waiting for the PS5. Open Settings -> User's Guide when ready.")
    say("")

    # -- Main loop --
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        say("")
        bad("Shutting down.")

        print_session_summary(stats, beacons)

        if watcher:
            watcher.stop()
        if heartbeat:
            heartbeat.stop()
        beacons.close()
        for s in servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
