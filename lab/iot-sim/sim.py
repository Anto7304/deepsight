"""Throwaway IoT device emulator for the DEEPSIGHT lab. Standard library only.

This is NOT real firmware and runs nothing on behalf of a client: it only presents the *network personality* of
small embedded devices (banners, a fake login prompt, a default-credential web page) so a scanner has something
realistic to find. No command is ever executed and no credential is ever accepted.

ROLE=telnet   : 23/tcp   legacy Telnet service with a login prompt
ROLE=camera   : 80/tcp   camera web admin ("default password still set" page) + 554/tcp RTSP responder
ROLE=gateway  : 22/tcp   SSH banner of an old Dropbear (banner only, no SSH implementation) + 8080/tcp status page

Ports can be overridden for tests: SIM_PORT_<NAME>=<port>.
"""
import os
import socketserver
import sys
import threading

IAC_NEGOTIATION = b"\xff\xfd\x18\xff\xfd\x1f"  # Telnet: DO TERMINAL-TYPE, DO NAWS (what real telnetd sends first)
TELNET_BANNER = b"\r\nBusyBox 1.19.4 telnetd (embedded camera shell)\r\n\r\nlogin: "
SSH_BANNER = b"SSH-2.0-dropbear_2011.54\r\n"

CAMERA_PAGE = b"""<!doctype html><html><head><title>IPC Web Admin</title></head><body style="font-family:sans-serif">
<h2>IP Camera - Web Admin</h2><p>Model DS-2CD2043 (lab emulation) - firmware 5.5.101</p>
<form><label>User <input value="admin"></label> <label>Password <input type="password" value="12345"></label>
<button type="button">Login</button></form>
<p style="color:#b00"><b>Warning:</b> the factory default credentials are still active.</p></body></html>"""

GATEWAY_PAGE = b"""<!doctype html><html><head><title>TG-200 Sensor Gateway</title></head><body style="font-family:sans-serif">
<h2>TG-200 Sensor Gateway (lab emulation)</h2><p>Sensors online: 12 - MQTT broker: 172.28.50.13:1883</p></body></html>"""


def _port(name, default):
    return int(os.getenv(f"SIM_PORT_{name}", default))


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(30)
        try:
            s.sendall(IAC_NEGOTIATION + TELNET_BANNER)
            for _ in range(3):  # a few attempts, always rejected
                if not _readline(s):
                    return
                s.sendall(b"Password: ")
                if not _readline(s):
                    return
                s.sendall(b"\r\nLogin incorrect\r\n\r\nlogin: ")
        except OSError:
            pass


def _readline(s, limit=256):
    buf = b""
    while len(buf) < limit:
        ch = s.recv(1)
        if not ch:
            return None
        if ch in (b"\n",):
            return buf
        buf += ch
    return buf


def _http_reply(page):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.settimeout(10)
            try:
                s.recv(4096)  # request is ignored; every path gets the same page
                head = (b"HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\nContent-Type: text/html\r\n"
                        b"Content-Length: " + str(len(page)).encode() + b"\r\nConnection: close\r\n\r\n")
                s.sendall(head + page)
            except OSError:
                pass
    return H


class RtspHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(10)
        try:
            data = s.recv(2048).decode("latin-1", "ignore")
            cseq = next((ln.split(":", 1)[1].strip() for ln in data.splitlines() if ln.lower().startswith("cseq")), "1")
            s.sendall(f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\nWWW-Authenticate: Basic realm=\"IPC\"\r\n\r\n".encode())
        except OSError:
            pass


class SshBannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(SSH_BANNER)  # then hang up: banner-only emulation
        except OSError:
            pass


ROLES = {
    "telnet": [("TELNET", 23, TelnetHandler)],
    "camera": [("HTTP", 80, _http_reply(CAMERA_PAGE)), ("RTSP", 554, RtspHandler)],
    "gateway": [("SSH", 22, SshBannerHandler), ("HTTP", 8080, _http_reply(GATEWAY_PAGE))],
}


def start(role, host="0.0.0.0"):
    """Start the servers of a role in background threads; returns the list of server objects."""
    servers = []
    for name, default, handler in ROLES[role]:
        srv = _Server((host, _port(name, default)), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


if __name__ == "__main__":
    role = os.getenv("ROLE", "")
    if role not in ROLES:
        sys.exit(f"ROLE must be one of {sorted(ROLES)}")
    servers = start(role)
    print(f"iot-sim role={role} listening on {[s.server_address[1] for s in servers]}", flush=True)
    threading.Event().wait()
