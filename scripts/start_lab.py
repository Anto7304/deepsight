#!/usr/bin/env python3
"""Start DEEPSIGHT with an isolated scanning lab; inventory remains empty.

Default: Docker Compose project deepsight-lab on http://localhost:8001.
--local: Linux/Python loopback emulators (install requirements.txt first).
Import files and scan configuration are printed for the normal Integrations screens.
--stop: stop this lab deployment only, retaining its data. --fresh: start a new deployment.
"""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = ["-f", "docker-compose.yml", "-f", "docker-compose.lab.yml"]


def _private_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(data, output)


def _prefix_network(prefix):
    try:
        if len(prefix.split(".")) != 3:
            raise ValueError("expected three octets")
        network = ipaddress.ip_network(prefix + ".0/24", strict=True)
        if network.version != 4 or not network.is_private:
            raise ValueError("not a private IPv4 range")
        return network
    except ValueError as error:
        raise SystemExit("The lab prefix must be three octets of a private IPv4 /24, for example 172.28.51.") from error


def docker_network_inventory():
    result = subprocess.run(["docker", "network", "ls", "--quiet"], check=True, capture_output=True, text=True)
    identifiers = result.stdout.split()
    if not identifiers:
        return []
    result = subprocess.run(["docker", "network", "inspect", *identifiers], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def choose_docker_lab(name, folder, requested=None, networks=None):
    """Preserve a deployment's addresses; a new project gets an unused private /24."""
    record = folder / "docker-lab.json"
    networks = docker_network_inventory() if networks is None else networks
    own_name = name + "_iotlab"
    own = next((network for network in networks if network.get("Name") == own_name), None)
    saved = json.loads(record.read_text()) if record.is_file() else {}
    prefix = saved.get("prefix")
    if prefix and requested and requested != prefix:
        raise SystemExit("This deployment already has a saved lab prefix. Use its saved value, or use --fresh for a new deployment.")
    if not prefix and own:
        subnets = [config.get("Subnet") for config in (own.get("IPAM") or {}).get("Config") or [] if config.get("Subnet")]
        ipv4 = next((ipaddress.ip_network(subnet) for subnet in subnets if ":" not in subnet), None)
        if not ipv4 or ipv4.prefixlen != 24:
            raise SystemExit("The existing lab network is not an IPv4 /24; use a fresh lab project.")
        prefix = str(ipv4.network_address).rsplit(".", 1)[0]
    if prefix and own:
        expected = _prefix_network(prefix)
        actual = [ipaddress.ip_network(config["Subnet"]) for config in (own.get("IPAM") or {}).get("Config") or [] if config.get("Subnet")]
        if expected not in actual:
            raise SystemExit("The saved lab prefix differs from its Docker network. Use a fresh project instead of changing existing addresses.")
    if prefix and requested and requested != prefix:
        raise SystemExit("The requested lab prefix differs from the existing deployment network. Use --fresh to change it.")
    prefix = prefix or requested
    occupied = []
    for network in networks:
        if network.get("Name") == own_name:
            continue
        for config in (network.get("IPAM") or {}).get("Config") or []:
            if config.get("Subnet"):
                subnet = ipaddress.ip_network(config["Subnet"])
                if subnet.version == 4:
                    occupied.append(subnet)
    candidates = [prefix] if prefix else [f"172.28.{octet}" for octet in range(51, 251)]
    for candidate in candidates:
        subnet = _prefix_network(candidate)
        if not any(subnet.overlaps(other) for other in occupied):
            _private_json(record, {"project": name, "prefix": candidate, "subnet": str(subnet)})
            return candidate
    raise SystemExit("No non-overlapping lab subnet is available. Set ASIVM_LAB_PREFIX to a free private /24 prefix.")


def local_preflight(address, app_port, feed_port):
    listeners = [("127.0.0.1", app_port), (address, feed_port),
                 ("127.0.0.2", 80), ("127.0.0.2", 554), ("127.0.0.3", 23),
                 ("127.0.0.4", 22), ("127.0.0.4", 8080), ("127.0.0.5", 1883)]
    for host, port in listeners:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind((host, port))
        except OSError as error:
            raise SystemExit(f"The local lab cannot bind {host}:{port}: {error}. Stop the conflicting listener or use Docker.") from error


def api(url, path, token=None, body=None):
    req = urllib.request.Request(url.rstrip("/") + "/api" + path,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 method="POST" if body is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.load(response)


def private_interface():
    # UDP connect chooses a local route; it sends no packets.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.0.2.1", 9))
        address = sock.getsockname()[0]
    parsed = ipaddress.ip_address(address)
    if not parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        raise SystemExit("Local mode needs a private interface for HTTP fixtures. Use Docker or --feed-host <your private interface IP>.")
    return address


def stop_local(state):
    if not state.exists():
        print("No local lab processes were recorded.")
        return
    record = json.loads(state.read_text())
    if record.get("pids") and not record.get("processes"):
        raise SystemExit("This old local process record lacks process identity. Stop those lab processes manually; no process was terminated.")
    for process in record.get("processes", []):
        pid = process["pid"]
        try:
            stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
            if stat[19] != process["started"] or command.strip() != process["command"]:
                continue
            if Path(f"/proc/{pid}/cwd").resolve() != ROOT:
                continue
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, FileNotFoundError):
            pass
    state.unlink(missing_ok=True)
    print("Stopped the local lab. Data was retained.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--fresh", action="store_true")
    ap.add_argument("--name", default="deepsight-lab")
    ap.add_argument("--port", type=int, default=int(os.getenv("ASIVM_PORT", "8001")))
    ap.add_argument("--feed-host", help="Private local interface for HTTP fixtures (local mode only)")
    args = ap.parse_args()
    if not 1 <= args.port <= (64535 if args.local else 65535):
        raise SystemExit("Choose an application port from 1 to 64535 for local mode, or 1 to 65535 for Docker.")
    if not args.name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in args.name):
        raise SystemExit("Deployment name must use lowercase letters, digits, hyphen or underscore.")
    if args.stop and args.fresh:
        raise SystemExit("--stop and --fresh cannot be combined.")
    name = args.name + ("-" + secrets.token_hex(3) if args.fresh else "")
    folder = ROOT / "data" / name
    state = folder / "processes.json"
    compose = ["docker", "compose", "-p", name, *COMPOSE_FILES]
    if args.stop:
        if args.local:
            stop_local(state)
        else:
            stop_env = dict(os.environ)
            record = folder / "docker-lab.json"
            if record.is_file():
                stop_env["ASIVM_LAB_PREFIX"] = json.loads(record.read_text())["prefix"]
            subprocess.run([*compose, "down"], cwd=ROOT, env=stop_env, check=True)
        return
    env = dict(os.environ)
    env.update(ASIVM_KEV_AUTO_SYNC="false",
               ASIVM_WORKER="true", ASIVM_SCHEDULER="true", ASIVM_PORT=str(args.port), ASIVM_SECRET_KEY="")
    env.setdefault("ASIVM_ADMIN_USER", "admin")
    env["ASIVM_ADMIN_PASSWORD"] = env.get("ASIVM_ADMIN_PASSWORD") or getpass.getpass("Choose the administrator password (at least 12 characters): ")
    if len(env["ASIVM_ADMIN_PASSWORD"]) < 12:
        raise SystemExit("Use a password of at least 12 characters.")
    url = f"http://localhost:{args.port}"
    if args.local:
        if sys.platform != "linux":
            raise SystemExit("--local is supported on Linux. Use Docker on this platform.")
        try:
            import fastapi  # noqa: F401
            import sklearn  # noqa: F401
            import sqlalchemy  # noqa: F401
        except ImportError:
            raise SystemExit("Install requirements.txt into your Python environment before running --local.") from None
        folder.mkdir(parents=True, exist_ok=True)
        if state.exists():
            raise SystemExit(f"Local lab {name} has recorded processes. Use --stop --local first, or --fresh with a free --port.")
        address = args.feed_host or private_interface()
        parsed = ipaddress.ip_address(address)
        if not parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            raise SystemExit("--feed-host must be your own private non-loopback interface address.")
        feed_port = args.port + 1000
        local_preflight(address, args.port, feed_port)
        env.update(ASIVM_DATA_DIR=str(folder), ASIVM_DATABASE_URL=f"sqlite:///{folder}/asivm.db",
                   ASIVM_LOCAL_LAB="true", ASIVM_LAB_FEED_URL=f"http://{address}:{feed_port}",
                   ASIVM_TCP_ALLOWED_CIDRS="127.0.0.0/8")
        processes, running_processes = [], []
        for command, logfile in [
            ([sys.executable, str(ROOT / "lab/local_lab.py"), "--feed-host", address, "--feed-port", str(feed_port)], "lab.log"),
            ([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.port)], "app.log"),
        ]:
            with (folder / logfile).open("ab") as log:
                process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                running_processes.append(process)
                started = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                processes.append({"pid": process.pid, "started": started, "command": " ".join(command)})
        _private_json(state, {"processes": processes, "url": url, "name": name})
    else:
        env["ASIVM_LAB_PREFIX"] = choose_docker_lab(name, folder, env.get("ASIVM_LAB_PREFIX"))
        subprocess.run([*compose, "up", "--build", "-d"], cwd=ROOT, env=env, check=True)
    for _ in range(150):
        if args.local and any(process.poll() is not None for process in running_processes):
            stop_local(state)
            raise SystemExit("A local lab process exited during startup. Read data/<deployment-name>/app.log and lab.log before retrying.")
        try:
            if api(url, "/health").get("status") == "ok":
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(2)
    else:
        if args.local:
            stop_local(state)
        raise SystemExit("Application did not become healthy. Inspect data/<deployment-name>/app.log or docker compose -p <deployment-name> logs app.")
    try:
        token = api(url, "/auth/login", body={"username": env["ASIVM_ADMIN_USER"], "password": env["ASIVM_ADMIN_PASSWORD"]})["token"]
        overview = api(url, "/overview", token)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"Sign-in failed (HTTP {error.code}). Existing deployments keep their original password; use --fresh for a new database.") from None
    imports = folder / "imports"
    prefix = env.get("ASIVM_LAB_PREFIX", "172.28.50")
    feed_url = env.get("ASIVM_LAB_FEED_URL", f"http://{prefix}.20:8081")
    command = [sys.executable, str(ROOT / "scripts/prepare_imports.py"), "--output", str(imports), "--prefix", prefix, "--feed-url", feed_url]
    if args.local:
        command.append("--local")
    subprocess.run(command, cwd=ROOT, check=True)
    print(f"DEEPSIGHT: {url} · user {env['ASIVM_ADMIN_USER']} · deployment {name}", flush=True)
    print(f"Inventory: {overview['metrics']['assets_total']} assets. Open Integrations to configure discovery and import files.", flush=True)
    print(f"Import files: {imports.resolve()}", flush=True)
    print("TCP configuration for Network discovery:", flush=True)
    print((imports / "scan-config.json").read_text(), flush=True)
    print(f"HTTP collector: {feed_url}/inventory · alert receiver: {feed_url}/webhook", flush=True)
    print(f"Stop: python3 scripts/start_lab.py {'--local ' if args.local else ''}--name {name} --stop", flush=True)


if __name__ == "__main__":
    main()
