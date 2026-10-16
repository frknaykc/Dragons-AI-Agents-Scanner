"""Host-independent tests for the sanitizer used by hosted network observations."""

import importlib
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
trace_events = importlib.import_module("scripts.verify_network").trace_events


def test_process_attributed_inet_attempts_preserve_event_class_not_payload() -> None:
    text = (
        '101 1720000000.100000 connect(3, {sa_family=AF_UNIX, sun_path="/tmp/x"}, 12) = 0\n'
        "102 1720000000.110000 connect(3, {sa_family=AF_INET, sin_port=htons(80), "
        'sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED\n'
        '103 1720000000.120000 sendto(3, "secret", 6, 0, {sa_family=AF_INET6, '
        'sin6_addr=inet_pton(AF_INET6, "::1")}, 28) = 6\n'
    )
    events = trace_events(text)
    assert events == [
        {
            "pid": "102",
            "type": "tcp_or_udp_connect",
            "relative_ms": "10",
            "destination_class": "loopback",
        },
        {
            "pid": "103",
            "type": "datagram_send",
            "relative_ms": "20",
            "destination_class": "loopback",
        },
    ]
    assert "secret" not in str(events)


def test_non_network_and_socket_creation_are_not_outbound() -> None:
    assert (
        trace_events(
            "42 1720000000.000000 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3\n"
            "42 1720000000.100000 connect(3, {sa_family=AF_UNIX}, 10) = 0\n"
        )
        == []
    )


def test_unattributed_inet_operation_rejects_invalid_monitor() -> None:
    with pytest.raises(ValueError, match="attribution"):
        trace_events("connect(3, {sa_family=AF_INET}, 16) = 0\n")


def test_observation_workflow_only_dispatches_trusted_code_and_uploads_metadata() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load(
        (root / ".github/workflows/network-observation.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["network-observation"]
    assert [item["runner"] for item in job["strategy"]["matrix"]["include"]] == [
        "ubuntu-24.04",
        "macos-15",
        "macos-15-intel",
        "windows-2022",
    ]
    checkout = job["steps"][0]
    assert checkout["with"]["persist-credentials"] == "false"
    upload = job["steps"][-1]
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "network-validation.json"
