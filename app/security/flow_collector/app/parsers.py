from __future__ import annotations

import ipaddress
import struct

from .models import FlowRecord


class FlowParseError(ValueError):
    pass


def _u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise FlowParseError("truncated uint32")
    return struct.unpack_from("!I", data, offset)[0], offset + 4


def _ipv4(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def _parse_ethernet_ipv4(header: bytes) -> dict | None:
    if len(header) < 14:
        return None
    offset = 14
    eth_type = struct.unpack_from("!H", header, 12)[0]
    if eth_type == 0x8100 and len(header) >= 18:
        eth_type = struct.unpack_from("!H", header, 16)[0]
        offset = 18
    if eth_type != 0x0800 or len(header) < offset + 20:
        return None
    version_ihl = header[offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(header) < offset + ihl:
        return None
    protocol = header[offset + 9]
    src_ip = str(ipaddress.IPv4Address(header[offset + 12 : offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(header[offset + 16 : offset + 20]))
    transport = offset + ihl
    src_port = dst_port = 0
    if protocol in (6, 17) and len(header) >= transport + 4:
        src_port, dst_port = struct.unpack_from("!HH", header, transport)
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
    }


def parse_sflow_v5(data: bytes, exporter: str = "unknown") -> list[FlowRecord]:
    if len(data) < 28:
        raise FlowParseError("sFlow datagram too short")
    offset = 0
    version, offset = _u32(data, offset)
    if version != 5:
        raise FlowParseError(f"unsupported sFlow version {version}")
    address_type, offset = _u32(data, offset)
    if address_type == 1:
        if offset + 4 > len(data):
            raise FlowParseError("truncated agent address")
        agent = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
    elif address_type == 2:
        if offset + 16 > len(data):
            raise FlowParseError("truncated IPv6 agent address")
        agent = str(ipaddress.IPv6Address(data[offset : offset + 16]))
        offset += 16
    else:
        raise FlowParseError("unsupported agent address type")
    _, offset = _u32(data, offset)  # sub-agent
    _, offset = _u32(data, offset)  # sequence
    _, offset = _u32(data, offset)  # uptime
    sample_count, offset = _u32(data, offset)
    records: list[FlowRecord] = []
    for _ in range(sample_count):
        sample_type, offset = _u32(data, offset)
        sample_length, offset = _u32(data, offset)
        sample_end = offset + sample_length
        if sample_end > len(data):
            raise FlowParseError("truncated sFlow sample")
        sample_format = sample_type & 0xFFF
        if sample_format == 1:
            records.extend(_parse_flow_sample(data[offset:sample_end], exporter or agent))
        offset = sample_end
    return records


def _parse_flow_sample(sample: bytes, exporter: str) -> list[FlowRecord]:
    offset = 0
    _, offset = _u32(sample, offset)  # sequence
    _, offset = _u32(sample, offset)  # source id
    sampling_rate, offset = _u32(sample, offset)
    _, offset = _u32(sample, offset)  # sample pool
    _, offset = _u32(sample, offset)  # drops
    input_if, offset = _u32(sample, offset)
    output_if, offset = _u32(sample, offset)
    record_count, offset = _u32(sample, offset)
    result: list[FlowRecord] = []
    for _ in range(record_count):
        record_type, offset = _u32(sample, offset)
        record_length, offset = _u32(sample, offset)
        end = offset + record_length
        if end > len(sample):
            raise FlowParseError("truncated sFlow record")
        if (record_type & 0xFFF) == 1:
            parsed = _parse_raw_packet_record(sample[offset:end])
            if parsed:
                result.append(
                    FlowRecord(
                        source="sflow",
                        exporter=exporter,
                        input_if=input_if,
                        output_if=output_if,
                        sampling_rate=max(sampling_rate, 1),
                        packets=max(sampling_rate, 1),
                        bytes=parsed.pop("frame_length") * max(sampling_rate, 1),
                        **parsed,
                    )
                )
        offset = end
    return result


def _parse_raw_packet_record(record: bytes) -> dict | None:
    if len(record) < 16:
        raise FlowParseError("truncated raw packet record")
    header_protocol, frame_length, _, header_length = struct.unpack_from("!IIII", record)
    if header_protocol != 1 or 16 + header_length > len(record):
        return None
    parsed = _parse_ethernet_ipv4(record[16 : 16 + header_length])
    if parsed:
        parsed["frame_length"] = frame_length
    return parsed


NETFLOW_V5_HEADER = struct.Struct("!HHIIIIBBH")
NETFLOW_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")


def parse_netflow_v5(data: bytes, exporter: str = "unknown") -> list[FlowRecord]:
    if len(data) < NETFLOW_V5_HEADER.size:
        raise FlowParseError("NetFlow datagram too short")
    (
        version,
        count,
        _,
        unix_secs,
        _,
        _,
        _,
        _,
        sampling_interval,
    ) = NETFLOW_V5_HEADER.unpack_from(data)
    if version != 5:
        raise FlowParseError(f"unsupported NetFlow version {version}")
    expected = NETFLOW_V5_HEADER.size + count * NETFLOW_V5_RECORD.size
    if expected > len(data):
        raise FlowParseError("truncated NetFlow records")
    sampling_rate = sampling_interval & 0x3FFF or 1
    result = []
    offset = NETFLOW_V5_HEADER.size
    for _ in range(count):
        fields = NETFLOW_V5_RECORD.unpack_from(data, offset)
        offset += NETFLOW_V5_RECORD.size
        result.append(
            FlowRecord(
                source="netflow",
                exporter=exporter,
                src_ip=_ipv4(fields[0]),
                dst_ip=_ipv4(fields[1]),
                input_if=fields[3],
                output_if=fields[4],
                packets=fields[5] * sampling_rate,
                bytes=fields[6] * sampling_rate,
                src_port=fields[9],
                dst_port=fields[10],
                protocol=fields[13],
                sampling_rate=sampling_rate,
                timestamp=str(unix_secs),
            )
        )
    return result
