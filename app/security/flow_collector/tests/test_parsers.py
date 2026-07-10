import ipaddress
import struct

import pytest

from app.parsers import FlowParseError, parse_netflow_v5, parse_sflow_v5


def ethernet_ipv4_tcp(src="10.2.1.10", dst="10.0.0.30", sport=50000, dport=443):
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    ip = (
        b"\x45\x00"
        + struct.pack("!H", 40)
        + b"\x00\x00\x00\x00\x40\x06\x00\x00"
        + ipaddress.IPv4Address(src).packed
        + ipaddress.IPv4Address(dst).packed
    )
    tcp = struct.pack("!HH", sport, dport) + b"\x00" * 16
    return eth + ip + tcp


def sflow_fixture():
    header = ethernet_ipv4_tcp()
    raw = struct.pack("!IIII", 1, len(header), 0, len(header)) + header
    raw += b"\x00" * ((4 - len(raw) % 4) % 4)
    record = struct.pack("!II", 1, len(raw)) + raw
    sample_body = struct.pack("!IIIIIIII", 1, 0, 1000, 1000, 0, 2, 1, 1) + record
    sample = struct.pack("!II", 1, len(sample_body)) + sample_body
    return (
        struct.pack("!II", 5, 1)
        + ipaddress.IPv4Address("192.0.2.10").packed
        + struct.pack("!IIII", 0, 1, 100, 1)
        + sample
    )


def netflow_fixture():
    header = struct.pack("!HHIIIIBBH", 5, 1, 100, 1_700_000_000, 0, 1, 0, 0, 1)
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        int(ipaddress.IPv4Address("10.2.1.10")),
        int(ipaddress.IPv4Address("10.0.0.30")),
        0,
        2,
        1,
        10,
        5000,
        0,
        100,
        50000,
        443,
        0,
        0x12,
        6,
        0,
        0,
        0,
        24,
        24,
        0,
    )
    return header + record


def test_parses_sflow_v5_raw_ipv4_sample():
    records = parse_sflow_v5(sflow_fixture(), "switch-a")
    assert len(records) == 1
    assert records[0].src_ip == "10.2.1.10"
    assert records[0].dst_port == 443
    assert records[0].sampling_rate == 1000


def test_parses_netflow_v5():
    records = parse_netflow_v5(netflow_fixture(), "switch-b")
    assert len(records) == 1
    assert records[0].bytes == 5000
    assert records[0].protocol == 6


@pytest.mark.parametrize("data", [b"", b"\x00" * 20])
def test_rejects_truncated_datagrams(data):
    with pytest.raises(FlowParseError):
        parse_sflow_v5(data)
    with pytest.raises(FlowParseError):
        parse_netflow_v5(data)


def test_rejects_unknown_versions():
    with pytest.raises(FlowParseError, match="unsupported sFlow version"):
        parse_sflow_v5(struct.pack("!I", 4) + b"\x00" * 40)
    with pytest.raises(FlowParseError, match="unsupported NetFlow version"):
        parse_netflow_v5(struct.pack("!H", 9) + b"\x00" * 30)
