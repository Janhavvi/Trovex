import json
import hmac
import os
import subprocess
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PORT = int(os.environ.get("PORT", "8082"))
LAB_BASE_URL = os.environ["LAB_BASE_URL"].rstrip("/")
LAB_AUTHORIZATION_REF = os.environ["LAB_AUTHORIZATION_REF"]
API_CALLBACK_URL = os.environ["API_CALLBACK_URL"].rstrip("/")
INTERNAL_SCAN_TOKEN = os.environ["INTERNAL_SCAN_TOKEN"]
ZAP_BASELINE = os.environ.get("ZAP_BASELINE", "/zap/zap-baseline.py")
active_lock = threading.Lock()
active_scans = set()
active_processes = {}
cancelled_scans = set()


def normalize_alerts(report):
    alerts = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append({
                "pluginId": str(alert.get("pluginid", "")),
                "title": alert.get("alert", "ZAP alert"),
                "severity": alert.get("riskdesc", "Informational").split(" ")[0].upper(),
                "confidence": alert.get("confidence", "Unknown"),
                "endpoint": alert.get("url", site.get("@name", LAB_BASE_URL)),
                "description": alert.get("desc", ""),
                "evidence": alert.get("evidence", ""),
                "remediation": alert.get("solution", ""),
                "cwe": str(alert.get("cweid", "")),
                "reference": alert.get("reference", ""),
            })
    return alerts


def send_callback(scan_id, status, alerts=None, error=None):
    payload = json.dumps({
        "status": status,
        "findings": alerts or [],
        "error": error,
    }).encode("utf-8")
    request = Request(
        f"{API_CALLBACK_URL}/api/internal/scans/{scan_id}/results",
        data=payload,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {INTERNAL_SCAN_TOKEN}",
        },
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        if response.status >= 300:
            raise RuntimeError(f"Trovex API callback returned HTTP {response.status}")


def get_authorized_job(scan_id):
    request = Request(
        f"{API_CALLBACK_URL}/api/internal/scans/{scan_id}",
        headers={"authorization": f"Bearer {INTERNAL_SCAN_TOKEN}"},
    )
    with urlopen(request, timeout=10) as response:
        job = json.loads(response.read())
    if job.get("status") not in {"queued", "running"} or job.get("target") != LAB_BASE_URL:
        raise ValueError("scan job is not queued for the configured private lab")


def run_baseline(scan_id):
    report_path = None
    process = None
    try:
        with tempfile.NamedTemporaryFile(dir="/zap/wrk", suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        process = subprocess.Popen(
            [ZAP_BASELINE, "-t", LAB_BASE_URL, "-m", "2", "-T", "5", "-J", os.path.basename(report_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with active_lock:
            active_processes[scan_id] = process
            should_cancel = scan_id in cancelled_scans
        if should_cancel and process.poll() is None:
            process.terminate()

        try:
            process.communicate(timeout=360)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("OWASP ZAP Baseline exceeded its six-minute execution limit") from None

        with active_lock:
            was_cancelled = scan_id in cancelled_scans
        if was_cancelled:
            raise RuntimeError("assessment cancelled by the kill switch")
        if process.returncode > 2 or not os.path.exists(report_path):
            raise RuntimeError("OWASP ZAP Baseline did not produce a report")

        with open(report_path, encoding="utf-8") as report_file:
            report = json.load(report_file)
        send_callback(scan_id, "completed", normalize_alerts(report))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, HTTPError, URLError) as error:
        try:
            send_callback(scan_id, "failed", error=str(error))
        except Exception as callback_error:
            print(f"Failed to report scan error for {scan_id}: {callback_error}", flush=True)
    finally:
        if report_path and os.path.exists(report_path):
            os.unlink(report_path)
        with active_lock:
            active_processes.pop(scan_id, None)
            cancelled_scans.discard(scan_id)
            active_scans.discard(scan_id)


def cancel_scan(scan_id):
    with active_lock:
        if scan_id not in active_scans:
            return False
        cancelled_scans.add(scan_id)
        process = active_processes.get(scan_id)
        if process and process.poll() is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        return True


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body):
        content = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        if self.path == "/healthz":
            self.respond(200, {"status": "ok", "scanner": "zap-baseline"})
            return
        self.respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path.startswith("/scans/") and self.path.endswith("/cancel"):
            provided_token = self.headers.get("authorization", "").removeprefix("Bearer ")
            if not hmac.compare_digest(provided_token, INTERNAL_SCAN_TOKEN):
                self.respond(401, {"error": "unauthorized scanner cancellation"})
                return
            try:
                scan_id = str(uuid.UUID(self.path.split("/")[2]))
            except (ValueError, IndexError):
                self.respond(400, {"error": "scanId must be a valid UUID"})
                return
            if not cancel_scan(scan_id):
                self.respond(409, {"error": "scan is not active"})
                return
            self.respond(202, {"scanId": scan_id, "status": "cancelling"})
            return

        if self.path != "/scans":
            self.respond(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("content-length", "0"))
            body = json.loads(self.rfile.read(length))
            scan_id = str(uuid.UUID(body.get("scanId", "")))
        except (ValueError, TypeError, json.JSONDecodeError):
            self.respond(400, {"error": "scanId must be a valid UUID"})
            return

        if body.get("authorizationRef") != LAB_AUTHORIZATION_REF:
            self.respond(403, {"error": "authorization reference does not match the configured lab"})
            return
        try:
            get_authorized_job(scan_id)
        except (HTTPError, URLError, ValueError, json.JSONDecodeError):
            self.respond(403, {"error": "scan job is not authorized for this lab"})
            return

        with active_lock:
            if active_scans:
                self.respond(429, {"error": "a lab baseline scan is already running"})
                return
            active_scans.add(scan_id)

        threading.Thread(target=run_baseline, args=(scan_id,), daemon=True).start()
        self.respond(202, {
            "scanId": scan_id,
            "status": "running",
            "scanner": "OWASP ZAP Baseline",
            "target": LAB_BASE_URL,
        })

    def log_message(self, format_string, *args):
        print(format_string % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()