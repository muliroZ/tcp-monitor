"""Construção de pcaps sintéticos para os testes (dpkt)."""

from __future__ import annotations

import socket
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import dpkt

from tcpmon.io.pcap_reader import Packet
from tcpmon.symbols import ACK, FIN, PSH, RST, SYN

FLAGS = {
    "SYN": SYN,
    "SYNACK": SYN | ACK,
    "ACK": ACK,
    "PSHACK": PSH | ACK,
    "FIN": FIN | ACK,
    "RST": RST,
    "RSTACK": RST | ACK,
    "NULL": 0,
    "XMAS": FIN | PSH | 0x20,
}


@dataclass
class P:
    """Descrição compacta de um pacote sintético."""

    ts: float
    src: tuple[str, int]
    dst: tuple[str, int]
    flags: int
    payload: bytes = b""


def tcp_frame(src: tuple[str, int], dst: tuple[str, int], flags: int, payload: bytes = b"") -> bytes:
    tcp = dpkt.tcp.TCP(sport=src[1], dport=dst[1], flags=flags, seq=1000, ack=0, data=payload)
    if ":" in src[0]:
        ip = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, src[0]),
            dst=socket.inet_pton(socket.AF_INET6, dst[0]),
            nxt=dpkt.ip.IP_PROTO_TCP,
            p=dpkt.ip.IP_PROTO_TCP,
            hlim=64,
            data=tcp,
        )
        ip.plen = len(bytes(tcp))
        tipo = dpkt.ethernet.ETH_TYPE_IP6
    else:
        ip = dpkt.ip.IP(
            src=socket.inet_aton(src[0]),
            dst=socket.inet_aton(dst[0]),
            p=dpkt.ip.IP_PROTO_TCP,
            ttl=64,
            data=tcp,
        )
        ip.len = len(bytes(ip))
        tipo = dpkt.ethernet.ETH_TYPE_IP
    eth = dpkt.ethernet.Ethernet(
        src=b"\x02\x00\x00\x00\x00\x01", dst=b"\x02\x00\x00\x00\x00\x02", type=tipo, data=ip
    )
    return bytes(eth)


def write_pcap(path: Path, pacotes: Iterable[P | tuple[float, bytes]], linktype: int = 1) -> Path:
    with path.open("wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=linktype)
        for p in pacotes:
            if isinstance(p, P):
                w.writepkt(tcp_frame(p.src, p.dst, p.flags, p.payload), ts=p.ts)
            else:
                ts, buf = p
                w.writepkt(buf, ts=ts)
    return path


def write_pcapng(path: Path, pacotes: Iterable[P]) -> Path:
    with path.open("wb") as fh:
        w = dpkt.pcapng.Writer(fh)
        for p in pacotes:
            w.writepkt(tcp_frame(p.src, p.dst, p.flags, p.payload), ts=p.ts)
    return path


def pkt(ts: float, src: tuple[str, int], dst: tuple[str, int], flags: int) -> Packet:
    """Pacote normalizado direto (sem passar por pcap)."""
    return Packet(ts, src[0], src[1], dst[0], dst[1], flags, 0)


CLI = ("10.0.0.1", 40000)
SRV = ("10.0.0.2", 80)


def handshake_completo(t0: float = 0.0, cli=CLI, srv=SRV) -> list[P]:
    return [
        P(t0 + 0.000, cli, srv, FLAGS["SYN"]),
        P(t0 + 0.010, srv, cli, FLAGS["SYNACK"]),
        P(t0 + 0.020, cli, srv, FLAGS["ACK"]),
        P(t0 + 0.030, cli, srv, FLAGS["PSHACK"], b"GET / HTTP/1.0\r\n\r\n"),
        P(t0 + 0.040, srv, cli, FLAGS["PSHACK"], b"HTTP/1.0 200 OK\r\n\r\n"),
        P(t0 + 0.050, srv, cli, FLAGS["FIN"]),
        P(t0 + 0.060, cli, srv, FLAGS["FIN"]),
        P(t0 + 0.070, srv, cli, FLAGS["ACK"]),
    ]
