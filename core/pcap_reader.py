"""
core/pcap_reader.py
Pure Python PCAP parser — no third-party libraries required.
Supports pcap (classic) and pcapng formats.
Extracts: IPs, ports, DNS queries, HTTP headers, TCP/UDP flows.
"""

import struct
import socket
import io
from typing import List, Iterator


# ── PCAP magic numbers ────────────────────────────────────────────────────────
PCAP_MAGIC_LE      = 0xa1b2c3d4   # little-endian classic pcap
PCAP_MAGIC_BE      = 0xd4c3b2a1   # big-endian classic pcap
PCAP_MAGIC_NS_LE   = 0xa1b23c4d   # nanosecond timestamps LE
PCAP_MAGIC_NS_BE   = 0x4d3cb2a1   # nanosecond timestamps BE
PCAPNG_MAGIC       = 0x0a0d0d0a   # pcapng section block

# EtherType constants
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# IP protocol numbers
PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1

# Well-known ports
PORT_DNS  = 53
PORT_HTTP = 80


def _unpack(fmt, data, offset=0):
    size = struct.calcsize(fmt)
    return struct.unpack_from(fmt, data, offset), offset + size


class PCAPReader:
    """
    Reads a PCAP or PCAPNG file and yields log line strings
    that NetSentinel's analyzer can process.
    """

    def __init__(self, path: str):
        self.path = path
        self._lines: List[str] = []

    def to_log_lines(self) -> List[str]:
        with open(self.path, "rb") as f:
            raw = f.read()

        magic = struct.unpack_from("<I", raw, 0)[0]

        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
            lines = list(self._parse_pcap(raw))
        elif magic == PCAPNG_MAGIC:
            lines = list(self._parse_pcapng(raw))
        else:
            raise ValueError(
                f"Not a valid PCAP/PCAPNG file (magic=0x{magic:08x}). "
                "Convert with: tshark -r file.pcap -w out.pcap"
            )
        return lines

    # ── Classic PCAP ──────────────────────────────────────────────────────────

    def _parse_pcap(self, raw: bytes) -> Iterator[str]:
        magic = struct.unpack_from("<I", raw, 0)[0]
        endian = "<" if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE) else ">"

        # Global header: magic, version_major, version_minor, thiszone,
        #                sigfigs, snaplen, network
        hdr_fmt = f"{endian}IHHiIII"
        hdr_size = struct.calcsize(hdr_fmt)
        hdr = struct.unpack_from(hdr_fmt, raw, 0)
        link_type = hdr[6]

        offset = hdr_size
        pkt_num = 0

        while offset + 16 <= len(raw):
            pkt_num += 1
            # Packet record header
            rec_fmt = f"{endian}IIII"
            rec = struct.unpack_from(rec_fmt, raw, offset)
            ts_sec, ts_usec, incl_len, orig_len = rec
            offset += 16

            if offset + incl_len > len(raw):
                break

            pkt_data = raw[offset: offset + incl_len]
            offset += incl_len

            timestamp = f"{ts_sec}.{ts_usec:06d}"
            yield from self._parse_packet(pkt_data, link_type, timestamp, pkt_num)

    # ── PCAPNG ───────────────────────────────────────────────────────────────

    def _parse_pcapng(self, raw: bytes) -> Iterator[str]:
        offset = 0
        link_type = 1  # default Ethernet
        pkt_num = 0

        while offset + 8 <= len(raw):
            block_type = struct.unpack_from("<I", raw, offset)[0]
            block_len  = struct.unpack_from("<I", raw, offset + 4)[0]

            if block_len < 12 or offset + block_len > len(raw):
                break

            block_data = raw[offset: offset + block_len]

            # Section Header Block (0x0A0D0D0A)
            if block_type == 0x0A0D0D0A:
                pass

            # Interface Description Block (0x00000001)
            elif block_type == 0x00000001:
                link_type = struct.unpack_from("<H", block_data, 8)[0]

            # Enhanced Packet Block (0x00000006)
            elif block_type == 0x00000006:
                pkt_num += 1
                ts_high   = struct.unpack_from("<I", block_data, 12)[0]
                ts_low    = struct.unpack_from("<I", block_data, 16)[0]
                cap_len   = struct.unpack_from("<I", block_data, 20)[0]
                timestamp = f"{(ts_high << 32 | ts_low) // 1_000_000}"
                pkt_start = 28
                pkt_data  = block_data[pkt_start: pkt_start + cap_len]
                yield from self._parse_packet(pkt_data, link_type, timestamp, pkt_num)

            # Simple Packet Block (0x00000003)
            elif block_type == 0x00000003:
                pkt_num += 1
                cap_len  = struct.unpack_from("<I", block_data, 8)[0]
                pkt_data = block_data[12: 12 + cap_len]
                yield from self._parse_packet(pkt_data, link_type, str(pkt_num), pkt_num)

            offset += block_len

    # ── Packet dissection ─────────────────────────────────────────────────────

    def _parse_packet(self, data: bytes, link_type: int, timestamp: str, pkt_num: int) -> Iterator[str]:
        try:
            if link_type == 1:    # Ethernet
                yield from self._parse_ethernet(data, timestamp)
            elif link_type == 101:  # Raw IP
                yield from self._parse_ip(data, timestamp)
            elif link_type == 113:  # Linux cooked capture
                yield from self._parse_ip(data[16:], timestamp)
        except Exception:
            pass  # Never crash on a malformed packet

    def _parse_ethernet(self, data: bytes, ts: str) -> Iterator[str]:
        if len(data) < 14:
            return
        ethertype = struct.unpack_from("!H", data, 12)[0]
        payload = data[14:]

        # Strip VLAN tag
        if ethertype == ETHERTYPE_VLAN and len(data) >= 18:
            ethertype = struct.unpack_from("!H", data, 16)[0]
            payload = data[18:]

        if ethertype == ETHERTYPE_IPV4:
            yield from self._parse_ip(payload, ts)
        elif ethertype == ETHERTYPE_IPV6:
            yield from self._parse_ipv6(payload, ts)

    def _parse_ip(self, data: bytes, ts: str) -> Iterator[str]:
        if len(data) < 20:
            return
        version = (data[0] >> 4)
        if version != 4:
            return

        ihl      = (data[0] & 0x0F) * 4
        protocol = data[9]
        src_ip   = socket.inet_ntoa(data[12:16])
        dst_ip   = socket.inet_ntoa(data[16:20])
        payload  = data[ihl:]

        if protocol == PROTO_TCP:
            yield from self._parse_tcp(payload, src_ip, dst_ip, ts)
        elif protocol == PROTO_UDP:
            yield from self._parse_udp(payload, src_ip, dst_ip, ts)
        elif protocol == PROTO_ICMP:
            yield f"{ts} PROTO=ICMP SRC={src_ip} DST={dst_ip}"

    def _parse_ipv6(self, data: bytes, ts: str) -> Iterator[str]:
        if len(data) < 40:
            return
        next_header = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        payload = data[40:]

        if next_header == PROTO_TCP:
            yield from self._parse_tcp(payload, src_ip, dst_ip, ts)
        elif next_header == PROTO_UDP:
            yield from self._parse_udp(payload, src_ip, dst_ip, ts)

    def _parse_tcp(self, data: bytes, src: str, dst: str, ts: str) -> Iterator[str]:
        if len(data) < 20:
            return
        sport    = struct.unpack_from("!H", data, 0)[0]
        dport    = struct.unpack_from("!H", data, 2)[0]
        data_off = ((data[12] >> 4) * 4)
        flags    = data[13]
        payload  = data[data_off:]

        flag_str = _tcp_flags(flags)
        base_line = f"{ts} PROTO=TCP SRC={src} DST={dst} SPT={sport} DPT={dport} FLAGS={flag_str}"
        yield base_line

        # Try to parse HTTP if on port 80 or high ports with HTTP signature
        if payload and (dport == PORT_HTTP or sport == PORT_HTTP or
                        payload[:4] in (b"GET ", b"POST", b"HTTP", b"HEAD", b"PUT ", b"DELE")):
            yield from self._parse_http(payload, src, dst, ts)

    def _parse_udp(self, data: bytes, src: str, dst: str, ts: str) -> Iterator[str]:
        if len(data) < 8:
            return
        sport   = struct.unpack_from("!H", data, 0)[0]
        dport   = struct.unpack_from("!H", data, 2)[0]
        payload = data[8:]

        yield f"{ts} PROTO=UDP SRC={src} DST={dst} SPT={sport} DPT={dport}"

        # Parse DNS
        if dport == PORT_DNS or sport == PORT_DNS:
            yield from self._parse_dns(payload, src, dst, ts)

    # ── Protocol parsers ──────────────────────────────────────────────────────

    def _parse_http(self, data: bytes, src: str, dst: str, ts: str) -> Iterator[str]:
        try:
            text = data.decode("utf-8", errors="replace")
            lines = text.split("\r\n")
            if not lines:
                return

            request_line = lines[0]
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.strip()] = v.strip()
                elif line == "":
                    break

            host = headers.get("Host", dst)
            ua   = headers.get("User-Agent", "")
            ref  = headers.get("Referer", "")

            log = f"{ts} {request_line} Host: {host}"
            if ua:
                log += f" User-Agent: {ua}"
            if ref:
                log += f" Referer: {ref}"
            yield log

            # Emit extra header lines for analysis
            for k, v in headers.items():
                if k.lower() in ("x-forwarded-for", "authorization", "cookie",
                                  "x-custom-header", "x-real-ip"):
                    yield f"{ts} HTTP-HEADER {k}: {v} SRC={src}"

        except Exception:
            pass

    def _parse_dns(self, data: bytes, src: str, dst: str, ts: str) -> Iterator[str]:
        try:
            if len(data) < 12:
                return

            flags   = struct.unpack_from("!H", data, 2)[0]
            qdcount = struct.unpack_from("!H", data, 4)[0]
            is_response = (flags >> 15) & 1

            offset = 12
            for _ in range(qdcount):
                name, offset = _parse_dns_name(data, offset)
                if offset + 4 > len(data):
                    break
                qtype  = struct.unpack_from("!H", data, offset)[0]
                offset += 4

                type_str = _dns_type(qtype)
                direction = "response for" if is_response else "query for"
                yield f"{ts} DNS {direction} {name} type={type_str} SRC={src} DST={dst}"

        except Exception:
            pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tcp_flags(flags: int) -> str:
    names = [(0x01, "F"), (0x02, "S"), (0x04, "R"),
             (0x08, "P"), (0x10, "A"), (0x20, "U")]
    return "".join(c for bit, c in names if flags & bit) or "."


def _dns_type(qtype: int) -> str:
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
            255: "ANY", 10: "NULL"}.get(qtype, str(qtype))


def _parse_dns_name(data: bytes, offset: int):
    """Parse a DNS name with pointer compression support."""
    labels = []
    visited = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Pointer compression
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            if ptr in visited:
                break
            visited.add(ptr)
            name_part, _ = _parse_dns_name(data, ptr)
            labels.append(name_part)
            break
        else:
            offset += 1
            label = data[offset: offset + length]
            labels.append(label.decode("utf-8", errors="replace"))
            offset += length
    return ".".join(labels), offset


def is_pcap(path: str) -> bool:
    """Return True if the file looks like a PCAP or PCAPNG."""
    try:
        with open(path, "rb") as f:
            magic_bytes = f.read(4)
        if len(magic_bytes) < 4:
            return False
        magic = struct.unpack("<I", magic_bytes)[0]
        return magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE,
                         PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE,
                         PCAPNG_MAGIC)
    except Exception:
        return False
