"""IoT lab checks that need no database: the device emulator, the TCP connector extensions and the lab files."""
import json
import os
import socket
import sys
import tempfile

os.environ.setdefault("ASIVM_DATA_DIR", tempfile.mkdtemp())
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "lab", "iot-sim"))

import pytest
import yaml

import sim
from app import normalize
from app.connectors import REGISTRY, _parse_banner


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def start(monkeypatch):
    started = []

    def _start(role):
        ports = {}
        for name, _default, _h in sim.ROLES[role]:
            ports[name] = _free_port()
            monkeypatch.setenv(f"SIM_PORT_{name}", str(ports[name]))
        started.extend(sim.start(role, "127.0.0.1"))
        return ports
    yield _start
    for srv in started:
        srv.shutdown()
        srv.server_close()


def _grab(port, send=b"", n=2048):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        if send:
            s.sendall(send)
        return s.recv(n)


def test_telnet_banner_parses_and_login_is_rejected(start):
    port = start("telnet")["TELNET"]
    banner = _grab(port).decode("latin-1")
    assert _parse_banner(23, banner.strip()) == ("BusyBox", "1.19.4")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.recv(2048)
        s.sendall(b"root\n")
        assert b"Password" in s.recv(64)
        s.sendall(b"root\n")
        assert b"Login incorrect" in s.recv(128)


def test_gateway_ssh_banner_matches_old_dropbear_rule(start):
    port = start("gateway")["SSH"]
    prod, ver = _parse_banner(22, _grab(port).decode().strip())
    assert (prod, ver) == ("dropbear", "2011.54")
    from app.engines import intel
    rule = next(v for v in intel.SEED_VULNS if v["cve_id"] == "CVE-2012-0920")["affected"][0]
    assert intel._match(rule, prod, None, ver)
    assert not intel._match(rule, "Dropbear sshd", "ssh", "2019.78")  # newer Dropbear must not match


def test_camera_web_admin_and_rtsp(start):
    ports = start("camera")
    page = _grab(ports["HTTP"], b"GET / HTTP/1.0\r\n\r\n").decode()
    assert "factory default credentials" in page and "Boa/0.94.14rc21" in page
    assert _grab(ports["RTSP"], b"OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 7\r\n\r\n").startswith(b"RTSP/1.0 401")


def test_tcp_discovery_finds_lab_services_with_static_name(start):
    ports = start("camera")
    closed = _free_port()
    cfg = {"authorized": True, "targets": ["127.0.0.1"], "ports": [ports["HTTP"], ports["RTSP"], closed], "timeout": 1.0,
           "hostnames": {"127.0.0.1": "lab-camera-01"}, "asset_type": "iot_device"}
    obs = REGISTRY["tcp_discovery"].collect(cfg, {})
    assert len(obs) == 1
    o = obs[0]
    assert o["identifiers"]["hostname"] == ["lab-camera-01"]
    assert o["attributes"]["type"] == "iot_device"
    assert {s["port"] for s in o["attributes"]["services"]} == {ports["HTTP"], ports["RTSP"]}


def test_default_scan_ports_include_iot_ports():
    ports = REGISTRY["tcp_discovery"].config_template["ports"]
    assert {23, 554, 1883, 9100} <= set(ports)


def test_lab_files_are_consistent_and_isolated():
    # Resolve the lab's explicit Compose default before inspecting the default fixture.
    # Launchers may choose another private prefix for a separate lab deployment.
    compose_text = open(os.path.join(ROOT, "docker-compose.lab.yml")).read()
    comp = yaml.safe_load(compose_text.replace("${ASIVM_LAB_PREFIX:-172.28.50}", "172.28.50"))
    assert comp["networks"]["iotlab"]["internal"] is True
    lab = {n: d for n, d in comp["services"].items() if n.startswith("lab-")}
    assert len(lab) == 4
    assert not any("ports" in d for d in comp["services"].values()), "lab must not publish host ports"
    ips = {d["hostname"]: d["networks"]["iotlab"]["ipv4_address"] for d in lab.values()}
    assert len(set(ips.values())) == 4 and all(i.startswith("172.28.50.") for i in ips.values())
    assert "iotlab" in comp["services"]["app"]["networks"]
    assert "allow_anonymous true" in open(os.path.join(ROOT, "lab", "mosquitto.conf")).read()
    inv = json.load(open(os.path.join(ROOT, "lab", "lab_inventory.json")))
    assert {o["identifiers"]["hostname"][0]: o["identifiers"]["ip"][0] for o in inv} == ips
    for o in inv:
        n = normalize.validate_observation(o)
        assert not [f for f in n["flags"] if f.startswith(("invalid", "missing_ident"))], n["flags"]
        assert "mac" in n["identifiers"]  # strong identifier -> confirmed identity, no pending decisions
    sys.path.insert(0, os.path.join(ROOT, "lab"))
    import scan_lab
    assert scan_lab.TARGETS == {ip: h for h, ip in ips.items()}
