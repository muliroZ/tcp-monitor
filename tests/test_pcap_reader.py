import logging
import socket

import dpkt
import pytest
from pcaputil import CLI, FLAGS, SRV, P, handshake_completo, tcp_frame, write_pcap, write_pcapng

from tcpmon.io.pcap_reader import PcapError, ReadCounters, read_packets


def test_le_pcap_ethernet(tmp_path):
    arq = write_pcap(tmp_path / "a.pcap", handshake_completo(t0=100.0))
    cont = ReadCounters()
    pkts = list(read_packets(arq, cont))
    assert len(pkts) == 8
    assert pkts[0].src == CLI and pkts[0].dst == SRV and pkts[0].flags == FLAGS["SYN"]
    assert pkts[0].ts == pytest.approx(100.0)
    assert pkts[3].payload_len > 0
    assert cont.lidos == 8 and cont.tcp_aceitos == 8 and cont.inversoes_ordem == 0


def test_le_pcapng(tmp_path):
    arq = write_pcapng(tmp_path / "a.pcapng", handshake_completo(t0=5.0))
    pkts = list(read_packets(arq))
    assert len(pkts) == 8
    assert pkts[1].flags == FLAGS["SYNACK"]
    assert pkts[0].ts == pytest.approx(5.0)


def test_le_ipv6(tmp_path):
    a, b = ("2001:db8::1", 1234), ("2001:db8::2", 80)
    arq = write_pcap(tmp_path / "v6.pcap", [P(0.0, a, b, FLAGS["SYN"]), P(0.1, b, a, FLAGS["SYNACK"])])
    pkts = list(read_packets(arq))
    assert [p.src for p in pkts] == [a, b]


def test_le_linux_sll(tmp_path):
    frame = tcp_frame(CLI, SRV, FLAGS["SYN"])
    ip = dpkt.ethernet.Ethernet(frame).data
    sll = dpkt.sll.SLL(type=0, hrd=1, hlen=6, hdr=b"\x02\x00\x00\x00\x00\x01\x00\x00", ethtype=0x0800, data=ip)
    arq = write_pcap(tmp_path / "sll.pcap", [(1.0, bytes(sll))], linktype=113)
    pkts = list(read_packets(arq))
    assert len(pkts) == 1 and pkts[0].src == CLI


def test_enlace_nao_suportado(tmp_path):
    arq = write_pcap(tmp_path / "raw.pcap", [(1.0, b"\x45" + b"\x00" * 39)], linktype=101)
    with pytest.raises(PcapError, match="tipo de enlace"):
        list(read_packets(arq))


def test_formato_desconhecido(tmp_path):
    arq = tmp_path / "lixo.pcap"
    arq.write_bytes(b"isto nao e pcap" * 4)
    with pytest.raises(PcapError):
        list(read_packets(arq))


def test_descarta_nao_tcp_e_malformados(tmp_path):
    udp = dpkt.ethernet.Ethernet(
        src=b"\x02" * 6,
        dst=b"\x04" * 6,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=dpkt.ip.IP(
            src=socket.inet_aton("10.0.0.1"),
            dst=socket.inet_aton("10.0.0.2"),
            p=dpkt.ip.IP_PROTO_UDP,
            data=dpkt.udp.UDP(sport=1, dport=2),
        ),
    )
    arp = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=b"\x00" * 28)
    syn = tcp_frame(CLI, SRV, FLAGS["SYN"])
    truncado = syn[: 14 + 20 + 8]  # TCP cortado no meio do cabeçalho
    so_eth = syn[:10]
    frag = dpkt.ethernet.Ethernet(syn)
    frag.data.mf = 1
    arq = write_pcap(
        tmp_path / "misto.pcap",
        [
            (0.0, bytes(udp)),
            (0.1, bytes(arp)),
            (0.2, truncado),
            (0.3, so_eth),
            (0.4, bytes(frag)),
            (0.5, syn),
        ],
    )
    cont = ReadCounters()
    pkts = list(read_packets(arq, cont))
    assert len(pkts) == 1 and pkts[0].ts == pytest.approx(0.5)
    d = cont.as_dict()
    assert d["pacotes_lidos"] == 6
    assert d["descartados_total"] == 5
    assert d["descartados_por_tipo"]["nao_tcp"] == 1
    assert d["descartados_por_tipo"]["nao_ip"] == 1
    assert d["descartados_por_tipo"]["fragmento_ip"] == 1


def test_inversoes_de_ordem_contadas_sem_reordenar(tmp_path, caplog):
    seq = handshake_completo()
    seq[1].ts, seq[2].ts = seq[2].ts, seq[1].ts  # inverte dois pacotes
    seq.append(P(0.001, CLI, SRV, FLAGS["ACK"]))  # volta no tempo
    arq = write_pcap(tmp_path / "fora.pcap", seq)
    cont = ReadCounters()
    with caplog.at_level(logging.WARNING):
        pkts = list(read_packets(arq, cont))
    assert [p.ts for p in pkts] == [p.ts for p in seq]  # ordem do arquivo preservada
    assert cont.inversoes_ordem == 2
    assert "inversões de ordem" in caplog.text
