"""Lab-only inventory API and alert receiver. No external calls or credentials."""
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

RECEIPTS = {}
LOCK = threading.Lock()


def inventory():
    ip = os.getenv("LAB_MQTT_IP", "172.28.50.13")
    return [{"identifiers": {"hostname": ["lab-mqtt-01"], "ip": [ip], "mac": ["02:42:ac:1c:32:0d"]},
             "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "category": "iot_inventory", "attributes": {"owner": "Lab", "type": "iot_device",
               "config": {"collector_note": "Collected from the inventory API"},
               "tags": ["asset-api"]}}]


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/inventory":
            self.send_json(200, inventory())
        elif self.path == "/health":
            self.send_json(200, {"status": "ok", "product": "DEEPSIGHT inventory service"})
        elif self.path == "/receipts":
            with LOCK:
                values = list(RECEIPTS.values())
            self.send_json(200, {"received": len(values), "items": values})
        else:
            self.send_json(404, {"error": "Unknown lab endpoint"})

    def do_POST(self):
        if self.path != "/webhook":
            return self.send_json(404, {"error": "Unknown lab endpoint"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > 1_000_000:
                return self.send_json(413, {"error": "Invalid body size"})
            payload = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            return self.send_json(400, {"error": "Invalid JSON"})
        key = self.headers.get("Idempotency-Key") or str(payload.get("finding_id"))
        with LOCK:
            if len(RECEIPTS) >= 1000 and key not in RECEIPTS:
                return self.send_json(503, {"error": "Lab receiver is full"})
            RECEIPTS[key] = payload
        self.send_json(200, {"accepted": True, "event_key": key})

    def log_message(self, fmt, *args):
        print("lab-feed " + fmt % args, flush=True)


def serve(host="0.0.0.0", port=8081):
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve(os.getenv("LAB_FEED_HOST", "0.0.0.0"), int(os.getenv("LAB_FEED_PORT", "8081")))
