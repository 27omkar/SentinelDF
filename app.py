from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash
import detector
from detector import start_watcher, stop_watcher, get_events, WATCH_FOLDERS
from entropy_analyzer import analyze_file
from process_analyzer_fixed import analyze_processes
from collections import deque
from datetime import datetime
import os
import time
import threading
import json
import hashlib
import sqlite3
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
import re
import urllib.error
import urllib.request
import smtplib
from email.message import EmailMessage
from pathlib import Path

app = Flask(__name__)
# Configure these environment variables before starting SentinelDF.
# Never hard-code credentials or share the secret key.
app.secret_key = os.environ.get("SENTINELDF_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("Set SENTINELDF_SECRET_KEY before starting SentinelDF.")
LOGIN_USERNAME = os.environ.get("SENTINELDF_USERNAME", "").strip()
LOGIN_PASSWORD = os.environ.get("SENTINELDF_PASSWORD", "")
RECOVERY_CODE = os.environ.get("SENTINELDF_RECOVERY_CODE", "")
USER_DB_PATH = Path(__file__).resolve().parent / "sentineldf_users.db"


def db_connection():
    conn = sqlite3.connect(str(USER_DB_PATH), timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_user_db():
    """Create local account storage and migrate the configured bootstrap account once."""
    with db_connection() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        # Preserve the username/password configured for the existing login, if supplied.
        # This is only a one-time bootstrap; subsequent credentials live in SQLite.
        if LOGIN_USERNAME and LOGIN_PASSWORD:
            exists = conn.execute("SELECT id FROM users WHERE username = ?", (LOGIN_USERNAME,)).fetchone()
            if not exists:
                conn.execute("INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                             (LOGIN_USERNAME, generate_password_hash(LOGIN_PASSWORD), datetime.now().isoformat(timespec="seconds")))


initialize_user_db()


EVENT_WINDOW_SECONDS = 5
MIN_EVENTS_IN_WINDOW = 20
MIN_HIGH_ENTROPY_FILES = 3
ALERT_COOLDOWN_SECONDS = 30
MAX_DOWNLOAD_FILES = 100
MAX_HASH_SIZE = 100 * 1024 * 1024  # Skip hashing files larger than 100 MiB.
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls/"
website_events = deque(maxlen=100)
website_lock = threading.Lock()
website_cache = {}
# VirusTotal's free tier is rate-limited. Only one explicit user-triggered lookup
# is made at a time; the minimum interval also helps avoid accidental bursts.
VT_MIN_REQUEST_INTERVAL_SECONDS = 16
vt_cache = {}
vt_cache_lock = threading.Lock()
vt_last_request_time = 0.0

# In-memory arrival tracking: does not move, delete, or alter files.
download_tracking_lock = threading.Lock()
download_baseline_ready = False
download_seen_files = {}
NEW_DOWNLOAD_WINDOW_SECONDS = 15 * 60

monitoring = False
alerts = deque(maxlen=100)
alert_lock = threading.Lock()
last_alert_time = 0
process_lock = threading.Lock()
previous_processes = set()
process_changes = deque(maxlen=100)

# Email notifications are sent only for HIGH/MEDIUM findings, once per unique
# finding during this server run. Credentials are read from Windows environment
# variables; never place Gmail passwords in this source file.
email_alert_lock = threading.Lock()
emailed_alert_fingerprints = set()


def send_security_alert_email(alert):
    """Send one qualifying security alert; return True only if SMTP succeeds."""
    sender = os.environ.get("SENTINELDF_EMAIL_FROM", "").strip()
    recipient = os.environ.get("SENTINELDF_EMAIL_TO", "").strip()
    app_password = os.environ.get("SENTINELDF_EMAIL_APP_PASSWORD", "").replace(" ", "").strip()
    if not sender or not recipient or not app_password:
        app.logger.warning("Security alert email not sent: Gmail environment settings are incomplete.")
        return False

    severity = str(alert.get("severity", "UNKNOWN")).upper()
    if severity not in {"HIGH", "MEDIUM"}:
        return False

    # Stable fingerprint avoids duplicate emails when the dashboard refreshes.
    identity = "|".join(str(alert.get(key, "")) for key in
                        ("severity", "title", "message", "source", "file", "url", "process", "pid"))
    fingerprint = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()
    with email_alert_lock:
        if fingerprint in emailed_alert_fingerprints:
            return False
        # Reserve before sending so concurrent dashboard refreshes cannot duplicate it.
        emailed_alert_fingerprints.add(fingerprint)

    device = os.environ.get("COMPUTERNAME", "This PC")
    subject = f"[SentinelDF] [{severity}] {alert.get('title', 'Security alert')}"
    body = "\n".join([
        "SentinelDF detected a security finding.",
        "",
        f"Device: {device}",
        f"Severity: {severity}",
        f"Detection: {alert.get('title', 'Security alert')}",
        f"Time: {alert.get('timestamp', datetime.now().isoformat(timespec='seconds'))}",
        f"Source: {alert.get('source', 'SentinelDF')}",
        f"Details: {alert.get('message', 'No additional details available.')}",
        f"Status: {alert.get('status', 'Needs investigation')}",
        "",
        "This is an automated heuristic/reputation alert, not definitive proof of compromise.",
    ])
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(sender, app_password)
            smtp.send_message(message)
        app.logger.info("Sent SentinelDF %s alert email: %s", severity, alert.get("title", "Security alert"))
        return True
    except Exception:
        app.logger.exception("Could not send SentinelDF security alert email")
        # Keep the fingerprint reserved to avoid repeated failures on every refresh.
        return False


def send_test_email():
    """Send a one-off test message without creating a security finding."""
    sender = os.environ.get("SENTINELDF_EMAIL_FROM", "").strip()
    recipient = os.environ.get("SENTINELDF_EMAIL_TO", "").strip()
    app_password = os.environ.get("SENTINELDF_EMAIL_APP_PASSWORD", "").replace(" ", "").strip()
    if not sender or not recipient or not app_password:
        return False, "Gmail settings are incomplete. Check SENTINELDF_EMAIL_FROM, SENTINELDF_EMAIL_TO, and SENTINELDF_EMAIL_APP_PASSWORD."

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = "[SentinelDF] Test email notification"
    message.set_content("""This is a test email from SentinelDF.

If you received this message, Gmail SMTP notifications are configured successfully.

This was a connectivity test, not a security alert.
""")
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(sender, app_password)
            smtp.send_message(message)
        app.logger.info("Sent SentinelDF test email to configured recipient.")
        return True, "Test email sent. Check your inbox and spam folder."
    except Exception:
        app.logger.exception("Could not send SentinelDF test email")
        return False, "Gmail SMTP failed. Check the SentinelDF CMD window for the error; do not share your app password."


def notify_for_security_alerts(alert_list):
    """Email HIGH/MEDIUM alerts surfaced by the existing Alerts API."""
    for item in alert_list:
        try:
            send_security_alert_email(item)
        except Exception:
            app.logger.exception("Unexpected error while preparing alert email")


def watcher_is_alive():
    watcher = getattr(detector, "observer", None)
    return watcher is not None and watcher.is_alive()


def event_path(event):
    path = event.get("path", "")
    if path:
        return os.path.abspath(path)
    filename = event.get("file", "")
    if filename:
        return os.path.abspath(os.path.join(os.path.expanduser("~"), "Desktop", "RansomwareTest", filename))
    return ""


def get_entropy_results():
    results = []
    seen = set()
    for event in reversed(get_events()):
        path = event_path(event)
        if not path or path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            result = analyze_file(path)
            results.append({
                "file": os.path.basename(path),
                "path": path,
                "time": event.get("time"),
                **result
            })
        except Exception:
            app.logger.exception("Entropy analysis failed for %s", path)
        if len(results) >= 20:
            break
    return results


def evaluate_behavior():
    global last_alert_time
    now = time.time()
    recent = [
        event for event in get_events()
        if 0 <= now - event.get("timestamp", 0) <= EVENT_WINDOW_SECONDS
    ]
    if len(recent) < MIN_EVENTS_IN_WINDOW:
        return

    high_entropy_files = set()
    for event in recent[-10:]:
        path = event_path(event)
        if not path or not os.path.isfile(path):
            continue
        try:
            if analyze_file(path).get("high_entropy"):
                high_entropy_files.add(path)
        except Exception:
            app.logger.exception("Behavior evaluation failed for %s", path)

    if len(high_entropy_files) < MIN_HIGH_ENTROPY_FILES:
        return
    if now - last_alert_time < ALERT_COOLDOWN_SECONDS:
        return

    alert = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "severity": "HIGH",
        "title": "Suspicious mass file activity",
        "message": (
            f"{len(recent)} file events occurred within {EVENT_WINDOW_SECONDS} seconds, "
            f"and {len(high_entropy_files)} inspected files had high entropy. "
            "This heuristic requires investigation and is not proof of ransomware."
        ),
        "events_in_window": len(recent),
        "high_entropy_files": sorted(high_entropy_files),
        "status": "Needs investigation",
        "simulated": False
    }
    with alert_lock:
        alerts.appendleft(alert)
    last_alert_time = now
    try:
        with open("ransom_alerts.log", "a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(alert) + "\n")
    except OSError:
        app.logger.exception("Could not write alert log")


def monitor_loop():
    while True:
        if monitoring:
            try:
                evaluate_behavior()
            except Exception:
                app.logger.exception("Behavior monitoring iteration failed")
        time.sleep(1)


def observe_process_changes():
    global previous_processes
    try:
        data = analyze_processes()
        processes = data.get("processes", data) if isinstance(data, dict) else data
        current = set()
        for proc in processes or []:
            if isinstance(proc, dict):
                current.add((str(proc.get("pid", "")), str(proc.get("name", ""))))
        with process_lock:
            added = current - previous_processes
            removed = previous_processes - current
            for pid, name in added:
                process_changes.append({
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "change": "started",
                    "pid": pid,
                    "name": name,
                    "action": "Observe only"
                })
            for pid, name in removed:
                process_changes.append({
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "change": "no longer listed",
                    "pid": pid,
                    "name": name,
                    "action": "Observe only"
                })
            previous_processes = current
    except Exception:
        app.logger.exception("Process-change observation failed")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_probably_pe(path):
    """Detect a Windows MZ header; this is a mismatch indicator, not malware proof."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def normalize_web_url(value):
    from urllib.parse import urlsplit, urlunsplit
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parts = urlsplit(value.strip())
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return None
        host = parts.hostname.lower()
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme.lower(), host, parts.path or "/", parts.query, ""))
    except ValueError:
        return None


def check_virustotal_url(url):
    """Check only an existing VT URL report; this does not submit the URL."""
    import base64
    from urllib.parse import urlsplit
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    normalized = normalize_web_url(url)
    if not normalized:
        return {"status": "error", "message": "Only valid HTTP(S) URLs can be checked."}, 400
    from urllib.parse import urlsplit
    host = (urlsplit(normalized).hostname or "").lower().strip("[]")
    # Local/private hostnames are not public websites. Never query VT or label them malicious.
    local_names = {"localhost", "localhost.localdomain"}
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        is_local = ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
    except ValueError:
        is_local = host in local_names or host.endswith(".localhost") or host.endswith(".local")
    if is_local:
        return {"url": normalized, "host": host, "status": "local", "reputation": "LOCAL — not checked",
                "severity": "INFO", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "message": "Local/private address; public VirusTotal reputation check skipped."}, 200
    if not api_key:
        return {"status": "not_configured", "message": "VirusTotal API key is not configured."}, 400
    with website_lock:
        if normalized in website_cache:
            return {"status": "success", "cached": True, **website_cache[normalized]}, 200
    url_id = base64.urlsafe_b64encode(normalized.encode()).decode().rstrip("=")
    req = urllib.request.Request(VIRUSTOTAL_URL_API + url_id, headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        malicious, suspicious = int(stats.get("malicious", 0) or 0), int(stats.get("suspicious", 0) or 0)
        result = {"url": normalized, "host": urlsplit(normalized).hostname or "", "status": "reported",
                  "reputation": "Malicious" if malicious else ("Suspicious" if suspicious else "No detections"),
                  "severity": "HIGH" if malicious else ("MEDIUM" if suspicious else "INFO"),
                  "malicious": malicious, "suspicious": suspicious,
                  "harmless": int(stats.get("harmless", 0) or 0), "undetected": int(stats.get("undetected", 0) or 0),
                  "link": f"https://www.virustotal.com/gui/url/{url_id}",
                  "message": "Existing VirusTotal report only; zero detections does not guarantee safety."}
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result = {"url": normalized, "host": urlsplit(normalized).hostname or "", "status": "not_found",
                      "reputation": "Unknown — no report", "severity": "UNKNOWN", "malicious": 0, "suspicious": 0,
                      "link": f"https://www.virustotal.com/gui/url/{url_id}",
                      "message": "No existing report; the URL was not submitted. Unknown does not mean safe."}
        elif exc.code in (401, 403):
            return {"status": "error", "message": "VirusTotal rejected the API key."}, 502
        elif exc.code == 429:
            return {"status": "rate_limited", "message": "VirusTotal rate limit reached; try later."}, 429
        else:
            return {"status": "error", "message": f"VirusTotal returned HTTP {exc.code}."}, 502
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return {"status": "error", "message": "Could not reach VirusTotal or parse its response."}, 502
    with website_lock:
        website_cache[normalized] = result
    return {"status": "success", **result}, 200


def human_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TB"


def inspect_downloads():
    folder = Path.home() / "Downloads"
    results = []
    api_key_configured = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
    if not folder.is_dir():
        return {
            "folder": str(folder), "files": [],
            "message": "Downloads folder not found.",
            "reputation_enabled": api_key_configured
        }

    try:
        paths = [p for p in folder.iterdir() if p.is_file()]
        paths.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        now_epoch = time.time()
        global download_baseline_ready
        with download_tracking_lock:
            if not download_baseline_ready:
                for existing_path in paths:
                    try:
                        st = existing_path.stat()
                        download_seen_files[str(existing_path.resolve())] = {
                            "first_seen": now_epoch,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                            "baseline": True
                        }
                    except OSError:
                        continue
                download_baseline_ready = True
            else:
                for current_path in paths:
                    try:
                        st = current_path.stat()
                        key = str(current_path.resolve())
                        old = download_seen_files.get(key)
                        if old is None:
                            download_seen_files[key] = {
                                "first_seen": now_epoch,
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "baseline": False
                            }
                        elif old.get("size") != st.st_size or old.get("mtime") != st.st_mtime:
                            old["size"] = st.st_size
                            old["mtime"] = st.st_mtime
                            old["last_changed"] = now_epoch
                    except OSError:
                        continue
    except OSError:
        app.logger.exception("Could not list Downloads folder")
        return {
            "folder": str(folder), "files": [],
            "message": "Downloads folder could not be read.",
            "reputation_enabled": api_key_configured
        }

    risky_extensions = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".hta", ".msi", ".com", ".jar", ".reg", ".iso", ".img", ".lnk"
    }
    double_extensions = {
        ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
        ".jpg.exe", ".jpeg.exe", ".png.exe", ".txt.exe", ".pdf.scr",
        ".doc.scr", ".jpg.scr"
    }

    for path in paths[:MAX_DOWNLOAD_FILES]:
        try:
            stat = path.stat()
            name_lower = path.name.lower()
            suffix = path.suffix.lower()
            indicators = []
            if suffix in risky_extensions:
                indicators.append("Executable or script-capable file type; verify source")
            if is_probably_pe(path) and suffix not in {".exe", ".dll", ".scr", ".com"}:
                indicators.append("Windows executable header does not match file extension")
            if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.(exe|scr|com)$", name_lower):
                indicators.append("Double extension may disguise an executable")
            if any(name_lower.endswith(ext) for ext in double_extensions):
                indicators.append("Double extension resembles a document/image")
            if path.name.startswith("."):
                indicators.append("Hidden filename")

            sha = None
            hash_status = "Hashed"
            if stat.st_size > MAX_HASH_SIZE:
                hash_status = "Skipped: larger than 100 MiB"
            else:
                try:
                    sha = sha256_file(path)
                except OSError:
                    hash_status = "Could not read file for hashing"

            with download_tracking_lock:
                tracked = download_seen_files.get(str(path.resolve()), {})
            first_seen_epoch = tracked.get("first_seen")
            newly_seen = bool(
                tracked and not tracked.get("baseline")
                and first_seen_epoch
                and (time.time() - first_seen_epoch) <= NEW_DOWNLOAD_WINDOW_SECONDS
            )
            changed_recently = bool(
                tracked.get("last_changed")
                and (time.time() - tracked["last_changed"]) <= NEW_DOWNLOAD_WINDOW_SECONDS
            )

            with vt_cache_lock:
                reputation_data = vt_cache.get(sha, {}) if sha else {}
            reputation = reputation_data.get("reputation", "Not checked")
            malicious = reputation_data.get("malicious", 0)
            suspicious = reputation_data.get("suspicious", 0)

            if reputation_data.get("status") == "reported":
                if malicious > 0:
                    assessment = f"MALICIOUS — {malicious} engine detection(s)"
                    severity = "HIGH"
                elif suspicious > 0:
                    assessment = f"SUSPICIOUS — {suspicious} engine detection(s)"
                    severity = "MEDIUM"
                else:
                    assessment = "NO DETECTIONS — report available"
                    severity = "INFO"
            elif reputation_data.get("status") == "not_found":
                assessment = "UNKNOWN — no VirusTotal report"
                severity = "UNKNOWN"
            elif reputation_data.get("status") == "error":
                assessment = "LOOKUP ERROR — retry later"
                severity = "UNKNOWN"
            elif indicators:
                assessment = "REVIEW — basic indicator only"
                severity = "LOW"
            else:
                assessment = "NOT CHECKED"
                severity = "UNKNOWN"

            results.append({
                "name": path.name,
                "path": str(path),
                "extension": suffix or "No extension",
                "size_bytes": stat.st_size,
                "size_human": human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                "sha256": sha or hash_status,
                "hash_status": hash_status,
                "indicators": indicators,
                "assessment": assessment,
                "severity": severity,
                "newly_seen": newly_seen,
                "changed_recently": changed_recently,
                "arrival_status": (
                    "NEW DOWNLOAD — review" if newly_seen
                    else ("RECENTLY CHANGED — review" if changed_recently else "Previously present")
                ),
                "first_seen": (
                    datetime.fromtimestamp(first_seen_epoch).isoformat(timespec="seconds")
                    if first_seen_epoch else None
                ),
                "reputation": reputation,
                "reputation_status": reputation_data.get("status", "not_checked"),
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": reputation_data.get("harmless", 0),
                "undetected": reputation_data.get("undetected", 0),
                "vt_link": reputation_data.get("link")
            })
        except OSError:
            app.logger.exception("Could not inspect download %s", path)

    new_files_count = sum(1 for item in results if item.get("newly_seen"))
    changed_files_count = sum(1 for item in results if item.get("changed_recently"))
    return {
        "folder": str(folder),
        "files": results,
        "new_files_count": new_files_count,
        "changed_files_count": changed_files_count,
        "new_download_window_minutes": NEW_DOWNLOAD_WINDOW_SECONDS // 60,
        "reputation_enabled": api_key_configured,
        "message": (
            "VirusTotal hash lookups are user-triggered; hashes are checked, "
            "not file contents uploaded."
        )
    }


def check_virustotal_hash(sha256):
    """Look up a SHA-256 hash in VirusTotal without uploading the file."""
    global vt_last_request_time

    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured",
            "reputation": "Not configured",
            "message": "Set the VIRUSTOTAL_API_KEY environment variable and restart SentinelDF."
        }, 400

    if not isinstance(sha256, str) or not re.fullmatch(r"[A-Fa-f0-9]{64}", sha256):
        return {"status": "error", "message": "A valid 64-character SHA-256 hash is required."}, 400

    sha256 = sha256.lower()
    with vt_cache_lock:
        cached = vt_cache.get(sha256)
        if cached and cached.get("status") in {"reported", "not_found"}:
            return {"status": "success", "cached": True, **cached}, 200

        elapsed = time.time() - vt_last_request_time
        wait_seconds = VT_MIN_REQUEST_INTERVAL_SECONDS - elapsed
        if wait_seconds > 0:
            return {
                "status": "rate_limited",
                "message": f"Please wait about {int(wait_seconds) + 1} seconds before the next VirusTotal lookup.",
                "retry_after_seconds": int(wait_seconds) + 1
            }, 429
        vt_last_request_time = time.time()

    url = VIRUSTOTAL_API_URL + sha256
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        result = {
            "status": "reported",
            "reputation": "Malicious" if malicious else ("Suspicious" if suspicious else "No detections"),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "total_engines": sum(int(value or 0) for value in stats.values()),
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
            "checked_at": datetime.now().isoformat(timespec="seconds"),
            "message": "VirusTotal hash report retrieved. Detection counts are reputation signals, not absolute proof."
        }
        with vt_cache_lock:
            vt_cache[sha256] = result
        return {"status": "success", "cached": False, **result}, 200

    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            result = {
                "status": "not_found",
                "reputation": "Unknown — no report",
                "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "message": "VirusTotal has no report for this hash. This does not mean the file is safe."
            }
            with vt_cache_lock:
                vt_cache[sha256] = result
            return {"status": "success", "cached": False, **result}, 200
        if exc.code == 429:
            return {
                "status": "rate_limited",
                "message": "VirusTotal rate limit reached. Wait before trying again.",
                "retry_after_seconds": VT_MIN_REQUEST_INTERVAL_SECONDS
            }, 429
        if exc.code in (401, 403):
            return {
                "status": "error",
                "message": "VirusTotal rejected the API key. Check that VIRUSTOTAL_API_KEY is correct and has API access."
            }, 502
        app.logger.warning("VirusTotal HTTP error %s for hash lookup", exc.code)
        return {"status": "error", "message": f"VirusTotal returned HTTP {exc.code}."}, 502
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        app.logger.warning("VirusTotal lookup failed: %s", exc)
        return {
            "status": "error",
            "message": "Could not reach VirusTotal or parse its response. Check your internet connection and try later."
        }, 502


@app.after_request
def allow_browser_extension_origin(response):
    # Allow only browser-extension origins to call the local navigation endpoint.
    origin = request.headers.get("Origin", "")
    if origin.startswith("chrome-extension://") or origin.startswith("moz-extension://"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.before_request
def require_login():
    """Protect dashboard and APIs; allow auth pages and extension event intake."""
    endpoint = request.endpoint
    allowed_endpoints = {"login", "signup", "forgot_password", "logout", "api_website_visit"}
    if endpoint in allowed_endpoints or endpoint == "static" or request.method == "OPTIONS":
        return None
    if not session.get("sentineldf_authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"status": "error", "message": "Login required."}), 401
        return redirect(url_for("login", next=request.path))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("sentineldf_authenticated"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db_connection() as conn:
            user = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["sentineldf_authenticated"] = True
            session["sentineldf_user_id"] = user["id"]
            session["sentineldf_username"] = user["username"]
            target = request.args.get("next", "")
            # Only allow relative local paths to avoid open redirects.
            if target.startswith("/") and not target.startswith("//"):
                return redirect(target)
            return redirect(url_for("index"))
        error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("sentineldf_authenticated"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(username) < 3 or len(username) > 40 or not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
            error = "Username must be 3–40 characters using letters, numbers, dot, underscore or hyphen."
        elif len(password) < 12:
            error = "Use a password with at least 12 characters."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                with db_connection() as conn:
                    conn.execute("INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                                 (username, generate_password_hash(password), datetime.now().isoformat(timespec="seconds")))
                return redirect(url_for("login", registered="1"))
            except sqlite3.IntegrityError:
                error = "That username is already registered. Choose another."
    return render_template("signup.html", error=error)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        recovery_code = request.form.get("recovery_code", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not RECOVERY_CODE:
            error = "Password recovery is not configured. Set SENTINELDF_RECOVERY_CODE in your Command Prompt and restart SentinelDF."
        elif not hmac.compare_digest(recovery_code, RECOVERY_CODE):
            error = "Invalid recovery code."
        elif len(new_password) < 12:
            error = "Use a new password with at least 12 characters."
        elif new_password != confirm:
            error = "New passwords do not match."
        else:
            with db_connection() as conn:
                user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                if user:
                    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                                 (generate_password_hash(new_password), user["id"]))
                    success = "Password reset successfully. You can now sign in with your new password."
                else:
                    error = "Account not found. Check the username or create an account first."
    return render_template("forgot_password.html", error=error, success=success)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/test-email", methods=["POST"])
def api_test_email():
    """Authenticated, explicit one-off Gmail delivery test."""
    success, message = send_test_email()
    status_code = 200 if success else 500
    return jsonify({"status": "success" if success else "error", "message": message}), status_code


@app.route("/api/status")
def api_status():
    try:
        event_count = len(get_events())
    except Exception:
        event_count = 0
    try:
        folders = [str(folder) for folder in WATCH_FOLDERS]
    except Exception:
        folders = []
    return jsonify({
        "monitoring": monitoring,
        "watcher_alive": watcher_is_alive(),
        "events": event_count,
        "alerts": len(alerts),
        "watched_folders": folders
    })


@app.route("/api/start", methods=["POST"])
def api_start():
    global monitoring
    try:
        if not watcher_is_alive():
            start_watcher()
        monitoring = True
        return jsonify({"status": "success", "monitoring": monitoring})
    except Exception as exc:
        app.logger.exception("Could not start watcher")
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global monitoring
    try:
        stop_watcher()
    except Exception:
        app.logger.exception("Could not stop watcher cleanly")
    monitoring = False
    return jsonify({"status": "success", "monitoring": monitoring})


@app.route("/api/events")
def api_events():
    return jsonify(list(get_events()))


@app.route("/api/entropy")
def api_entropy():
    return jsonify(get_entropy_results())


@app.route("/api/alerts")
def api_alerts():
    """Combine behavior alerts with download/process review indicators.
    These are heuristic review items, not malware verdicts.
    """
    combined = []
    with alert_lock:
        combined.extend(list(alerts))

    # Download findings: only files with explicit basic indicators become review alerts.
    try:
        download_data = inspect_downloads()
        for item in download_data.get("files", []):
            indicators = item.get("indicators", [])
            if indicators:
                combined.append({
                    "timestamp": item.get("modified", datetime.now().isoformat(timespec="seconds")),
                    "severity": "MEDIUM",
                    "title": "Download needs review",
                    "message": (
                        f"{item.get('name', 'A download')} has a basic indicator: "
                        f"{'; '.join(indicators)}. SHA-256: {item.get('sha256', 'Unavailable')}. "
                        "This is not proof that the file is malicious."
                    ),
                    "status": "Review file source and reputation",
                    "source": "Download Security",
                    "file": item.get("path", item.get("name", ""))
                })

            if item.get("newly_seen"):
                combined.append({
                    "timestamp": item.get("first_seen") or datetime.now().isoformat(timespec="seconds"),
                    "severity": "INFO",
                    "title": "New download observed",
                    "message": (
                        f"{item.get('name', 'A file')} appeared in Downloads while SentinelDF was running. "
                        "This is an arrival notification, not a malware verdict. Check its source and reputation."
                    ),
                    "status": "New file — review recommended",
                    "source": "Download Monitor",
                    "file": item.get("path", item.get("name", ""))
                })
            elif item.get("changed_recently"):
                combined.append({
                    "timestamp": item.get("modified", datetime.now().isoformat(timespec="seconds")),
                    "severity": "INFO",
                    "title": "Downloaded file changed",
                    "message": (
                        f"{item.get('name', 'A file')} changed while SentinelDF was running. "
                        "This is an observation only; it does not prove malicious activity."
                    ),
                    "status": "Review if unexpected",
                    "source": "Download Monitor",
                    "file": item.get("path", item.get("name", ""))
                })

            vt_status = item.get("reputation_status")
            malicious = int(item.get("malicious", 0) or 0)
            suspicious = int(item.get("suspicious", 0) or 0)
            if vt_status == "reported" and (malicious > 0 or suspicious > 0):
                severity = "HIGH" if malicious > 0 else "MEDIUM"
                combined.append({
                    "timestamp": item.get("modified", datetime.now().isoformat(timespec="seconds")),
                    "severity": severity,
                    "title": "VirusTotal reputation warning",
                    "message": (
                        f"{item.get('name', 'A file')} has {malicious} malicious and "
                        f"{suspicious} suspicious VirusTotal engine detections. "
                        "Treat this as a warning for investigation, not a perfect verdict."
                    ),
                    "status": "Investigate; do not open the file",
                    "source": "VirusTotal",
                    "file": item.get("path", item.get("name", "")),
                    "sha256": item.get("sha256", "")
                })
    except Exception:
        app.logger.exception("Could not derive download review alerts")

    # Process findings: flag paths commonly used by temporary/download execution.
    try:
        process_data = analyze_processes()
        process_list = process_data.get("processes", process_data) if isinstance(process_data, dict) else process_data
        for proc in process_list or []:
            if not isinstance(proc, dict):
                continue
            exe = str(proc.get("executable") or "")
            lower_exe = exe.lower().replace("/", "\\")
            reasons = []
            if "\\temp\\" in lower_exe or "\\appdata\\local\\temp\\" in lower_exe:
                reasons.append("executable path is under a temporary folder")
            if "\\downloads\\" in lower_exe:
                reasons.append("executable path is under Downloads")
            if reasons:
                combined.append({
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "severity": "MEDIUM",
                    "title": "Process path needs review",
                    "message": (
                        f"{proc.get('name', 'Process')} (PID {proc.get('pid', 'unknown')}): "
                        f"{'; '.join(reasons)}. A path indicator alone is not proof of malware."
                    ),
                    "status": "Observe only — investigate if unexpected",
                    "source": "Process Inventory",
                    "process": proc.get("name", ""),
                    "pid": proc.get("pid", "")
                })
    except Exception:
        app.logger.exception("Could not derive process review alerts")

    # Browser reputation findings (the browser extension only records navigations;
    # reputation is looked up only after the user clicks Check VT).
    with website_lock:
        website_snapshot = list(website_events)
    for site in website_snapshot:
        if site.get("reputation_status") == "reported" and (site.get("malicious", 0) or site.get("suspicious", 0)):
            combined.append({
                "timestamp": site.get("time", datetime.now().isoformat(timespec="seconds")),
                "severity": "HIGH" if site.get("malicious", 0) else "MEDIUM",
                "title": "Website reputation warning",
                "message": f"{site.get('host', 'Website')} has {site.get('malicious', 0)} malicious and {site.get('suspicious', 0)} suspicious VirusTotal detections. Do not rely on this alone; investigate the page.",
                "status": "Avoid interacting; investigate the URL", "source": "Website Monitor", "url": site.get("url", "")
            })

    # Email qualifying alerts surfaced in the same API used by the dashboard.
    # Fingerprinting prevents repeated messages on dashboard polling.
    notify_for_security_alerts(combined)

    # Put newest items first and limit response size.
    combined.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return jsonify(combined[:50])


@app.route("/api/processes")
def api_processes():
    try:
        data = analyze_processes()
        if isinstance(data, dict):
            if "status" not in data:
                data["status"] = "success"
            return jsonify(data)
        return jsonify({"status": "success", "processes": data or []})
    except Exception as exc:
        app.logger.exception("Process inventory failed")
        return jsonify({"status": "error", "message": str(exc), "processes": []}), 500


@app.route("/api/process-changes")
def api_process_changes():
    observe_process_changes()
    with process_lock:
        return jsonify(list(process_changes))


@app.route("/api/virustotal/check", methods=["POST"])
def api_virustotal_check():
    payload = request.get_json(silent=True) or {}
    result, status_code = check_virustotal_hash(payload.get("sha256", ""))
    return jsonify(result), status_code


@app.route("/api/processes/check-reputation", methods=["POST"])
def api_process_reputation():
    payload = request.get_json(silent=True) or {}
    raw_path = payload.get("path", "")
    if not isinstance(raw_path, str) or not raw_path:
        return jsonify({"status": "error", "message": "Executable path is required."}), 400
    path = os.path.abspath(raw_path)
    if not os.path.isfile(path):
        return jsonify({"status": "error", "message": "Executable file is not accessible."}), 404
    try:
        if os.path.getsize(path) > MAX_HASH_SIZE:
            return jsonify({"status": "error", "message": "File exceeds the 100 MiB hash limit."}), 413
        sha = sha256_file(path)
    except OSError:
        return jsonify({"status": "error", "message": "Could not read/hash file; permissions may be required."}), 403
    result, code = check_virustotal_hash(sha)
    result["sha256"] = sha
    return jsonify(result), code


@app.route("/api/websites", methods=["GET"])
def api_websites():
    with website_lock:
        return jsonify(list(website_events))


@app.route("/api/websites/visit", methods=["POST"])
def api_website_visit():
    payload = request.get_json(silent=True) or {}
    normalized = normalize_web_url(payload.get("url", ""))
    if not normalized:
        return jsonify({"status": "error", "message": "A valid HTTP(S) URL is required."}), 400
    from urllib.parse import urlsplit
    entry = {"time": datetime.now().isoformat(timespec="seconds"), "url": normalized,
             "host": urlsplit(normalized).hostname or "", "title": str(payload.get("title", ""))[:200],
             "source": str(payload.get("source", "Browser extension"))[:40], "status": "Not checked",
             "reputation_status": "not_checked", "reputation": "Not checked", "severity": "UNKNOWN",
             "message": "Navigation observed; click Check VT for an existing reputation report."}
    with website_lock:
        website_events.appendleft(entry)
    return jsonify({"status": "success", "entry": entry})


@app.route("/api/websites/check", methods=["POST"])
def api_website_check():
    payload = request.get_json(silent=True) or {}
    result, code = check_virustotal_url(payload.get("url", ""))
    if code == 200:
        with website_lock:
            for entry in website_events:
                if entry.get("url") == result.get("url"):
                    entry.update({"status": result.get("reputation", "Unknown"), "reputation_status": result.get("status", "unknown"),
                                  "reputation": result.get("reputation", "Unknown"), "severity": result.get("severity", "UNKNOWN"),
                                  "malicious": result.get("malicious", 0), "suspicious": result.get("suspicious", 0),
                                  "link": result.get("link"), "message": result.get("message", "")})
    return jsonify(result), code




def is_public_ip(value):
    """Accept only globally routable IP literals; reject hostnames and private/reserved IPs."""
    import ipaddress
    if not isinstance(value, str) or len(value) > 45:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global:
        return None
    return address


def lookup_shodan_internetdb(ip_text):
    """Query Shodan InternetDB for an explicitly supplied public IP; no port scan is performed."""
    url = "https://internetdb.shodan.io/" + ip_text
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "SentinelDF-Defensive-Lab"})
    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {
            "status": "found",
            "ip": ip_text,
            "ports": payload.get("ports", []) or [],
            "hostnames": payload.get("hostnames", []) or [],
            "tags": payload.get("tags", []) or [],
            "cpes": payload.get("cpes", []) or [],
            "vulns": payload.get("vulns", []) or [],
            "source": "Shodan InternetDB",
            "message": "Shodan's recorded InternetDB data; not a live scan. An empty CVE list does not prove safety."
        }, 200
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "not_found", "ip": ip_text, "ports": [], "hostnames": [],
                "tags": [], "cpes": [], "vulns": [], "source": "Shodan InternetDB",
                "message": "No InternetDB record found for this IP. This does not mean it is safe."
            }, 200
        return {"status": "error", "message": f"Shodan InternetDB returned HTTP {exc.code}."}, 502
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        app.logger.exception("Shodan InternetDB lookup failed")
        return {"status": "error", "message": "Could not reach Shodan InternetDB or parse its response."}, 502


def lookup_virustotal_ip(ip_text):
    """Look up an existing VirusTotal IP report; never scans the address."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "not_configured", "reputation": "Not configured",
            "message": "Set VIRUSTOTAL_API_KEY in Windows environment variables and restart SentinelDF."
        }
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip_text
    req = urllib.request.Request(url, headers={"x-apikey": api_key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
        attrs = payload.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        return {
            "status": "reported",
            "reputation": "Malicious reports found" if malicious else ("Suspicious reports found" if suspicious else "No detections in available report"),
            "malicious": malicious, "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "link": "https://www.virustotal.com/gui/ip-address/" + ip_text,
            "message": "Existing VirusTotal report only. Detection counts are signals, not a definitive verdict."
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"status": "not_found", "reputation": "Unknown — no report", "malicious": 0, "suspicious": 0,
                    "link": "https://www.virustotal.com/gui/ip-address/" + ip_text,
                    "message": "No existing VirusTotal report. Unknown does not mean safe."}
        if exc.code in (401, 403):
            return {"status": "error", "message": "VirusTotal rejected the API key."}
        if exc.code == 429:
            return {"status": "rate_limited", "message": "VirusTotal rate limit reached; wait before retrying."}
        return {"status": "error", "message": f"VirusTotal returned HTTP {exc.code}."}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        app.logger.exception("VirusTotal IP lookup failed")
        return {"status": "error", "message": "Could not reach VirusTotal or parse its response."}


@app.route("/api/intel/ip", methods=["POST"])
def api_ip_intelligence():
    payload = request.get_json(silent=True) or {}
    address = is_public_ip(payload.get("ip", ""))
    if address is None:
        return jsonify({
            "status": "error",
            "message": "Enter a valid globally routable public IP address. Private, loopback, reserved, and hostname inputs are not accepted."
        }), 400
    ip_text = str(address)
    shodan_result, shodan_code = lookup_shodan_internetdb(ip_text)
    if shodan_code != 200:
        return jsonify({"status": "error", "shodan": shodan_result, "message": shodan_result.get("message", "Shodan lookup failed.")}), shodan_code
    vt_result = lookup_virustotal_ip(ip_text)
    return jsonify({
        "status": "success",
        "ip": ip_text,
        "shodan": shodan_result,
        "reputation": vt_result
    }), 200


@app.route("/api/downloads")
def api_downloads():
    return jsonify(inspect_downloads())


if __name__ == "__main__":
    threading.Thread(target=monitor_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)
