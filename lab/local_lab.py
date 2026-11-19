"""Linux loopback IoT lab plus a private-interface HTTP fixture. No real firmware."""
import argparse
import importlib.util
import os
from pathlib import Path
import socketserver
import threading

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class MqttStub(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            packet = self.request.recv(512)
            if packet and packet[0] == 0x10:
                self.request.sendall(b"\x20\x02\x00\x00")
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--feed-host", required=True)
    ap.add_argument("--feed-port", type=int, default=8081)
    args = ap.parse_args()
    sim = module("local_iot_sim", HERE / "iot-sim/sim.py")
    feed = module("local_inventory_api", HERE / "feed/server.py")
    servers = []
    try:
        for role, ip in [("camera", "127.0.0.2"), ("telnet", "127.0.0.3"), ("gateway", "127.0.0.4")]:
            servers.extend(sim.start(role, ip))
        mqtt = sim._Server(("127.0.0.5", 1883), MqttStub)
        servers.append(mqtt)
        threading.Thread(target=mqtt.serve_forever, daemon=True).start()
        os.environ["LAB_MQTT_IP"] = "127.0.0.5"
        threading.Thread(target=feed.serve, args=(args.feed_host, args.feed_port), daemon=True).start()
        print("Live loopback lab ready; MQTT is a protocol stub. Docker uses real Mosquitto.", flush=True)
        threading.Event().wait()
    finally:
        for server in servers:
            server.server_close()


if __name__ == "__main__":
    main()
