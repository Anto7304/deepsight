"""Launching a lab must preserve deployment addresses and avoid unrelated listeners."""
import json
import socket

import pytest

from scripts import start_lab as launcher


def network(name, subnet):
    return {"Name": name, "IPAM": {"Config": [{"Subnet": subnet}]}}


def test_new_project_skips_occupied_ranges_and_saves_addresses(tmp_path):
    networks = [network("original_iotlab", "172.28.50.0/24"), network("other", "172.28.51.0/24")]
    assert launcher.choose_docker_lab("new-lab", tmp_path, networks=networks) == "172.28.52"
    saved = json.loads((tmp_path / "docker-lab.json").read_text())
    assert saved["project"] == "new-lab"
    assert saved["subnet"] == "172.28.52.0/24"
    assert (tmp_path / "docker-lab.json").stat().st_mode & 0o777 == 0o600


def test_restart_preserves_saved_subnet(tmp_path):
    launcher.choose_docker_lab("same-lab", tmp_path, networks=[])
    networks = [network("same-lab_iotlab", "172.28.51.0/24"), network("other", "172.28.52.0/24")]
    assert launcher.choose_docker_lab("same-lab", tmp_path, networks=networks) == "172.28.51"


def test_host_network_without_ipam_does_not_block_selection(tmp_path):
    networks = [{"Name": "host", "IPAM": {"Config": None}}, {"Name": "none", "IPAM": None}]
    assert launcher.choose_docker_lab("lab", tmp_path, networks=networks) == "172.28.51"


def test_existing_project_network_is_recovered_without_metadata(tmp_path):
    networks = [network("existing_iotlab", "172.28.63.0/24")]
    assert launcher.choose_docker_lab("existing", tmp_path, networks=networks) == "172.28.63"


def test_requested_overlapping_subnet_is_refused(tmp_path):
    with pytest.raises(SystemExit, match="non-overlapping"):
        launcher.choose_docker_lab("new", tmp_path, requested="172.28.51",
                                   networks=[network("original", "172.28.0.0/16")])
    assert not (tmp_path / "docker-lab.json").exists()


def test_cannot_change_a_saved_deployment_prefix(tmp_path):
    launcher.choose_docker_lab("same", tmp_path, networks=[])
    with pytest.raises(SystemExit, match="saved"):
        launcher.choose_docker_lab("same", tmp_path, requested="172.28.62", networks=[])


def test_saved_prefix_must_match_existing_network(tmp_path):
    launcher.choose_docker_lab("same", tmp_path, networks=[])
    with pytest.raises(SystemExit, match="differs"):
        launcher.choose_docker_lab("same", tmp_path,
                                   networks=[network("same_iotlab", "172.28.62.0/24")])


def test_local_preflight_detects_a_real_conflicting_listener():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        with pytest.raises(SystemExit, match=f"127.0.0.1:{port}"):
            launcher.local_preflight("127.0.0.1", port, port + 1)


def test_legacy_process_record_never_terminates_unverified_pid(tmp_path, monkeypatch):
    record = tmp_path / "processes.json"
    record.write_text(json.dumps({"pids": [1234]}))
    monkeypatch.setattr(launcher.os, "kill", lambda *_: pytest.fail("Unverified process was signalled"))
    with pytest.raises(SystemExit, match="lacks process identity"):
        launcher.stop_local(record)
    assert record.exists()


def test_generated_scan_targets_follow_selected_prefix(tmp_path):
    from scripts.scenario_files import build
    # Only configuration generation needs no running application.
    import os
    os.environ.setdefault("ASIVM_SECRET_KEY", "tests-unused-secret")
    build(tmp_path / "files", prefix="172.28.64")
    config = json.loads((tmp_path / "files/scan-config.json").read_text())
    assert config["targets"] == [f"172.28.64.{i}" for i in range(10, 14)]
    assert config["authorized"] is True
