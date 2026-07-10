#!/usr/bin/env python3
#
# Generate synthetic SMT/Homa negative test captures.
#
# These pcaps exercise the defensive paths in print-smt.c.  They are not
# intended to be valid SMT exchanges; each packet is built to reach one parser
# boundary or malformed-field branch in a controlled way.

import calendar
import ipaddress
import struct
from datetime import datetime, timezone
from pathlib import Path


OUTDIR = Path(__file__).resolve().parent

CLIENT = "192.168.12.2"
SERVER = "192.168.12.1"
CLIENT_MAC = bytes.fromhex("020000000002")
SERVER_MAC = bytes.fromhex("020000000001")

IPPROTO_HOMA = 146

SMT_COMMON_HEADER_LEN = 28
SMT_DATA_HEADER_LEN = 52
SMT_GRANT_HEADER_LEN = 33
SMT_RESEND_HEADER_LEN = 37
SMT_CUTOFFS_HEADER_LEN = 62
SMT_ACK_HEADER_LEN = 80

SMT_DATA = 0x10
SMT_GRANT = 0x11
SMT_RESEND = 0x12
SMT_CUTOFFS = 0x15
SMT_ACK = 0x18


TYPE_NAMES = {
    SMT_DATA: "DATA",
    SMT_GRANT: "GRANT",
    SMT_RESEND: "RESEND",
    SMT_CUTOFFS: "CUTOFFS",
    SMT_ACK: "ACK",
}


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header(src, dst, payload_len, tos=0xE0, ident=0, ttl=64):
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        tos,
        total_len,
        ident,
        0x4000,
        ttl,
        IPPROTO_HOMA,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def smt_common(sport, dport, packet_type, sender_id, sequence=0, doff=5):
    payload = bytearray(SMT_COMMON_HEADER_LEN)
    struct.pack_into("!H", payload, 0, sport)
    struct.pack_into("!H", payload, 2, dport)
    struct.pack_into("!I", payload, 4, sequence)
    payload[11] = packet_type
    payload[12] = (doff & 0x0F) << 4
    struct.pack_into("!Q", payload, 20, sender_id)
    return bytes(payload)


def smt_data(sender_id, sequence=0, message_len=16, incoming=16, tls=b""):
    payload = bytearray(smt_common(32768, 2000, SMT_DATA, sender_id, sequence, 14))
    payload.extend(b"\x00" * (SMT_DATA_HEADER_LEN - len(payload)))
    struct.pack_into("!I", payload, 28, message_len)
    struct.pack_into("!I", payload, 32, incoming)
    struct.pack_into("!Q", payload, 36, 0)
    struct.pack_into("!H", payload, 44, 2000)
    struct.pack_into("!H", payload, 46, 0)
    payload[48] = 0
    payload[49:52] = b"\x00\x00\x00"
    payload.extend(tls)
    return bytes(payload)


def smt_grant(sender_id):
    payload = bytearray(smt_common(2000, 32768, SMT_GRANT, sender_id))
    payload.extend(b"\x00" * (SMT_GRANT_HEADER_LEN - len(payload)))
    struct.pack_into("!I", payload, 28, 4096)
    payload[32] = 3
    return bytes(payload)


def smt_resend(sender_id):
    payload = bytearray(smt_common(2000, 32769, SMT_RESEND, sender_id))
    payload.extend(b"\x00" * (SMT_RESEND_HEADER_LEN - len(payload)))
    struct.pack_into("!I", payload, 28, 8192)
    struct.pack_into("!I", payload, 32, 1024)
    payload[36] = 4
    return bytes(payload)


def smt_cutoffs(sender_id):
    cutoffs = [2147483647, 0, 0, 0, 1000000, 15000, 2800, 200]
    payload = bytearray(smt_common(2000, 32770, SMT_CUTOFFS, sender_id))
    payload.extend(b"\x00" * (SMT_CUTOFFS_HEADER_LEN - len(payload)))
    for index, value in enumerate(cutoffs):
        struct.pack_into("!I", payload, 28 + index * 4, value)
    struct.pack_into("!H", payload, 60, 2)
    return bytes(payload)


def smt_ack(sender_id, num_acks=2):
    payload = bytearray(smt_common(32771, 2000, SMT_ACK, sender_id))
    payload.extend(b"\x00" * (SMT_ACK_HEADER_LEN - len(payload)))
    struct.pack_into("!H", payload, 28, num_acks)
    for index in range(5):
        struct.pack_into("!Q", payload, 30 + index * 10, 1000 + index)
        struct.pack_into("!H", payload, 38 + index * 10, 2000)
    return bytes(payload)


def ethernet_frame(payload, src, dst, tos=0xE0, ident=0):
    eth = (CLIENT_MAC if dst == CLIENT else SERVER_MAC)
    eth += (CLIENT_MAC if src == CLIENT else SERVER_MAC)
    eth += b"\x08\x00"
    return eth + ipv4_header(src, dst, len(payload), tos, ident) + payload


def pcap_record(ts_sec, ts_usec, captured_frame, original_frame_len):
    return struct.pack("<IIII", ts_sec, ts_usec, len(captured_frame), original_frame_len) + captured_frame


def write_pcap(filename, records):
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    data = header + b"".join(records)
    (OUTDIR / filename).write_bytes(data)


def ts_base(hour, minute):
    return calendar.timegm(datetime(2026, 6, 11, hour, minute, 0, tzinfo=timezone.utc).timetuple())


def make_record(packet, packet_index, base_sec):
    frame = ethernet_frame(
        packet["payload"],
        packet["src"],
        packet["dst"],
        packet.get("tos", 0xE0),
        0,
    )
    captured_smt_len = packet.get("captured_smt_len", len(packet["payload"]))
    captured_len = 14 + 20 + captured_smt_len
    captured_frame = frame[:captured_len]
    return pcap_record(base_sec + packet_index, packet_index + 1, captured_frame, len(frame))


def smt_summary(packet, verbose=False):
    packet_type = packet["type"]
    if packet.get("common_invalid"):
        return "SMT [length 27 < 28] (invalid)"
    if packet.get("common_truncated"):
        return "SMT [|smt]"

    type_name = TYPE_NAMES.get(packet_type, f"type 0x{packet_type:02x}")
    text = f"SMT {packet['sport']} > {packet['dport']}, {type_name}, id {packet['sender_id']}"
    if verbose:
        text += f", doff {packet['doff']}"

    if packet.get("invalid_len") is not None:
        text += f" [length {packet['payload_len']} < {packet['invalid_len']}] (invalid)"
    elif packet.get("truncated"):
        if packet.get("data_fields"):
            text += f", offset {packet['sequence']}, msglen {packet['message_len']}"
            if verbose:
                text += f", incoming {packet['incoming']}, cutoff {packet['cutoff']}"
        text += " [|smt]"
    elif packet_type == SMT_ACK and packet.get("invalid_ack_count"):
        text += f", {packet['num_acks']} acks"
        if verbose:
            acks = ", ".join(f"id {1000 + i} port 2000" for i in range(5))
            text += f" [{acks}]"
        text += ", invalid count"

    return text


def write_expected(filename, packets, verbose=False):
    lines = []
    for index, packet in enumerate(packets, start=1):
        ts = datetime.fromtimestamp(packet["ts"], timezone.utc)
        timestamp = ts.strftime("%Y-%m-%d %H:%M:%S") + f".{packet['usec']:06d}"
        src = packet["src"]
        dst = packet["dst"]
        if verbose:
            ip_len = 20 + packet["payload_len"]
            lines.append(
                f"{index:5d}  {timestamp} IP (tos 0x{packet['tos']:x}, ttl 64, id 0, "
                f"offset 0, flags [DF], proto Homa (146), length {ip_len})"
            )
            lines.append(f"    {src} > {dst}: {smt_summary(packet, verbose=True)}")
        else:
            lines.append(f"{index:5d}  {timestamp} IP {src} > {dst}: {smt_summary(packet)}")
    (OUTDIR / filename).write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")


def packet_meta(payload, src, dst, **extra):
    packet_type = payload[11] if len(payload) > 11 else 0
    return {
        "payload": payload,
        "payload_len": len(payload),
        "src": src,
        "dst": dst,
        "tos": extra.pop("tos", 0xE0),
        "type": packet_type,
        "sport": int.from_bytes(payload[0:2], "big") if len(payload) >= 2 else 0,
        "dport": int.from_bytes(payload[2:4], "big") if len(payload) >= 4 else 0,
        "sequence": int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else 0,
        "doff": payload[12] >> 4 if len(payload) > 12 else 0,
        "sender_id": int.from_bytes(payload[20:28], "big") if len(payload) >= 28 else 0,
        **extra,
    }


def main():
    tls_probe = b"\x17\x03\x03\x00\x20" + (0).to_bytes(5, "big")
    truncated = [
        packet_meta(
            smt_common(32768, 2000, SMT_DATA, 99, doff=14),
            CLIENT,
            SERVER,
            tos=0xC0,
            captured_smt_len=27,
            truncated=True,
            common_truncated=True,
        ),
        packet_meta(
            smt_data(100, sequence=0, message_len=16, incoming=16),
            CLIENT,
            SERVER,
            tos=0xC0,
            captured_smt_len=51,
            truncated=True,
        ),
        packet_meta(
            smt_grant(101),
            SERVER,
            CLIENT,
            captured_smt_len=32,
            truncated=True,
        ),
        packet_meta(
            smt_resend(102),
            SERVER,
            CLIENT,
            captured_smt_len=36,
            truncated=True,
        ),
        packet_meta(
            smt_cutoffs(103),
            SERVER,
            CLIENT,
            captured_smt_len=61,
            truncated=True,
        ),
        packet_meta(
            smt_ack(104),
            CLIENT,
            SERVER,
            captured_smt_len=29,
            truncated=True,
        ),
        packet_meta(
            smt_data(105, sequence=8, message_len=16, incoming=16, tls=tls_probe),
            CLIENT,
            SERVER,
            tos=0xC0,
            captured_smt_len=54,
            truncated=True,
            data_fields=True,
            message_len=16,
            incoming=16,
            cutoff=0,
        ),
    ]

    malformed_common = bytearray(27)
    malformed_common[11] = SMT_DATA
    malformed_common[12] = 14 << 4

    malformed = [
        packet_meta(
            bytes(malformed_common),
            CLIENT,
            SERVER,
            tos=0xC0,
            common_invalid=True,
        ),
        packet_meta(
            smt_data(201)[:51],
            CLIENT,
            SERVER,
            tos=0xC0,
            invalid_len=SMT_DATA_HEADER_LEN,
        ),
        packet_meta(
            smt_grant(202)[:32],
            SERVER,
            CLIENT,
            invalid_len=SMT_GRANT_HEADER_LEN,
        ),
        packet_meta(
            smt_resend(203)[:36],
            SERVER,
            CLIENT,
            invalid_len=SMT_RESEND_HEADER_LEN,
        ),
        packet_meta(
            smt_cutoffs(204)[:61],
            SERVER,
            CLIENT,
            invalid_len=SMT_CUTOFFS_HEADER_LEN,
        ),
        packet_meta(
            smt_ack(205)[:79],
            CLIENT,
            SERVER,
            invalid_len=SMT_ACK_HEADER_LEN,
        ),
        packet_meta(
            smt_ack(206, num_acks=6),
            CLIENT,
            SERVER,
            invalid_ack_count=True,
            num_acks=6,
        ),
        packet_meta(
            smt_common(2000, 32772, 0x99, 207),
            SERVER,
            CLIENT,
        ),
    ]

    for base, packets, pcap_name, out_name, out_v_name in (
        (ts_base(5, 10), truncated, "smt-truncated.pcap", "smt-truncated.out", "smt-truncated-v.out"),
        (ts_base(5, 20), malformed, "smt-malformed.pcap", "smt-malformed.out", "smt-malformed-v.out"),
    ):
        records = []
        for index, packet in enumerate(packets):
            packet["ts"] = base + index
            packet["usec"] = index + 1
            records.append(make_record(packet, index, base))
        write_pcap(pcap_name, records)
        write_expected(out_name, packets, verbose=False)
        write_expected(out_v_name, packets, verbose=True)


if __name__ == "__main__":
    main()
