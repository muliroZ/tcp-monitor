"""Leitura de pcap/pcapng com dpkt e normalização em pacotes TCP.

Regras do guia:

- aceita pcap e pcapng com enlace Ethernet (DLT_EN10MB) e Linux cooked (DLT_LINUX_SLL);
  qualquer outro tipo interrompe com erro claro;
- processa apenas TCP sobre IPv4 e IPv6; o resto é contado e descartado;
- processa na ordem do arquivo; se houver inversões de timestamp, avisa a quantidade e
  não reordena;
- pacotes truncados ou malformados são contados e descartados, sem derrubar a execução.

O tempo do sistema é sempre o timestamp do pcap. Este módulo não conhece os monitores.
"""

from __future__ import annotations

import hashlib
import logging
import socket
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import dpkt

log = logging.getLogger(__name__)

DLT_EN10MB = 1
DLT_LINUX_SLL = 113
ENLACES_SUPORTADOS = {DLT_EN10MB: "DLT_EN10MB", DLT_LINUX_SLL: "DLT_LINUX_SLL"}

_MAGICS_PCAP = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"


class PcapError(RuntimeError):
    """Arquivo de captura ilegível ou com tipo de enlace não suportado."""


class Packet(NamedTuple):
    """Pacote TCP normalizado."""

    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    flags: int
    payload_len: int

    @property
    def src(self) -> tuple[str, int]:
        return (self.src_ip, self.src_port)

    @property
    def dst(self) -> tuple[str, int]:
        return (self.dst_ip, self.dst_port)


@dataclass
class ReadCounters:
    """Contadores da leitura (vão para counters.json)."""

    lidos: int = 0
    tcp_aceitos: int = 0
    descartados: Counter = field(default_factory=Counter)
    inversoes_ordem: int = 0
    primeiro_ts: float | None = None  # primeiro quadro do arquivo (qualquer protocolo)
    max_ts: float | None = None  # maior timestamp visto (qualquer protocolo)

    def as_dict(self) -> dict:
        return {
            "pacotes_lidos": self.lidos,
            "pacotes_tcp_aceitos": self.tcp_aceitos,
            "descartados_por_tipo": dict(sorted(self.descartados.items())),
            "descartados_total": int(sum(self.descartados.values())),
            "inversoes_ordem": self.inversoes_ordem,
            "primeiro_ts": self.primeiro_ts,
            "max_ts": self.max_ts,
        }


def sha256_arquivo(path: str | Path, bloco: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(bloco):
            h.update(chunk)
    return h.hexdigest()


def _abrir_reader(fh):
    magic = fh.read(4)
    fh.seek(0)
    if magic in _MAGICS_PCAP:
        return dpkt.pcap.Reader(fh)
    if magic == _MAGIC_PCAPNG:
        return dpkt.pcapng.Reader(fh)
    raise PcapError("formato de captura desconhecido (esperado pcap ou pcapng)")


def _decodificar(buf: bytes, enlace: int, cont: ReadCounters):
    """Extrai (ip_src, ip_dst, tcp) de um quadro; devolve None e conta o motivo do descarte."""
    try:
        if enlace == DLT_EN10MB:
            l2 = dpkt.ethernet.Ethernet(buf)
        else:
            l2 = dpkt.sll.SLL(buf)
    except (dpkt.UnpackError, dpkt.NeedData, ValueError, IndexError):
        cont.descartados["enlace_malformado"] += 1
        return None

    ip = l2.data
    if isinstance(ip, dpkt.ip.IP):
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            cont.descartados["nao_tcp"] += 1
            return None
        # Fragmentos IPv4 (MF ligado ou deslocamento > 0) não são remontados.
        if ip.mf or ip.offset:
            cont.descartados["fragmento_ip"] += 1
            return None
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            cont.descartados["tcp_truncado_ou_malformado"] += 1
            return None
        try:
            src = socket.inet_ntop(socket.AF_INET, ip.src)
            dst = socket.inet_ntop(socket.AF_INET, ip.dst)
        except (ValueError, OSError):
            cont.descartados["ip_malformado"] += 1
            return None
        return src, dst, tcp

    if isinstance(ip, dpkt.ip6.IP6):
        tcp = ip.data
        if not isinstance(tcp, dpkt.tcp.TCP):
            # Cabeçalho de fragmento IPv6 ou próximo cabeçalho não-TCP.
            if dpkt.ip.IP_PROTO_FRAGMENT in getattr(ip, "extension_hdrs", {}):
                cont.descartados["fragmento_ip"] += 1
            elif getattr(ip, "p", None) == dpkt.ip.IP_PROTO_TCP:
                cont.descartados["tcp_truncado_ou_malformado"] += 1
            else:
                cont.descartados["nao_tcp"] += 1
            return None
        try:
            src = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
        except (ValueError, OSError):
            cont.descartados["ip_malformado"] += 1
            return None
        return src, dst, tcp

    if isinstance(ip, (bytes, bytearray)):
        # dpkt deixa bytes crus quando não reconhece o tipo ou quando o IP está truncado.
        tipo = getattr(l2, "type", None) if enlace == DLT_EN10MB else getattr(l2, "ethtype", None)
        if tipo in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
            cont.descartados["ip_truncado_ou_malformado"] += 1
        else:
            cont.descartados["nao_ip"] += 1
        return None

    cont.descartados["nao_ip"] += 1
    return None


def read_packets(path: str | Path, counters: ReadCounters | None = None) -> Iterator[Packet]:
    """Itera os pacotes TCP do arquivo, na ordem em que aparecem.

    ``counters`` é preenchido durante a iteração. Ao final, se houver inversões de
    ordem de timestamp, um aviso é emitido (os pacotes não são reordenados).
    """
    cont = counters if counters is not None else ReadCounters()
    path = Path(path)
    if not path.is_file():
        raise PcapError(f"arquivo de captura não encontrado: {path}")

    with path.open("rb") as fh:
        try:
            reader = _abrir_reader(fh)
        except (ValueError, dpkt.UnpackError, dpkt.NeedData) as exc:
            raise PcapError(f"{path}: cabeçalho de captura inválido ({exc})") from exc

        enlace = reader.datalink()
        if enlace not in ENLACES_SUPORTADOS:
            raise PcapError(
                f"{path}: tipo de enlace {enlace} não suportado; aceitos: "
                + ", ".join(f"{n} ({v})" for v, n in ENLACES_SUPORTADOS.items())
            )

        ts_anterior: float | None = None
        iterador = iter(reader)
        while True:
            try:
                ts, buf = next(iterador)
            except StopIteration:
                break
            except (dpkt.UnpackError, dpkt.NeedData, ValueError) as exc:
                # Registro do arquivo corrompido/truncado no fim: para de ler sem derrubar.
                cont.descartados["registro_corrompido"] += 1
                log.warning("%s: leitura interrompida em registro corrompido (%s)", path, exc)
                break

            cont.lidos += 1
            ts = float(ts)
            if ts_anterior is not None and ts < ts_anterior:
                cont.inversoes_ordem += 1
            ts_anterior = ts
            if cont.primeiro_ts is None:
                cont.primeiro_ts = ts
            if cont.max_ts is None or ts > cont.max_ts:
                cont.max_ts = ts

            dec = _decodificar(buf, enlace, cont)
            if dec is None:
                continue
            src, dst, tcp = dec
            cont.tcp_aceitos += 1
            yield Packet(ts, src, int(tcp.sport), dst, int(tcp.dport), int(tcp.flags), len(tcp.data))

    if cont.inversoes_ordem:
        log.warning(
            "%s: %d inversões de ordem de timestamp; pacotes processados na ordem do arquivo, sem reordenar",
            path,
            cont.inversoes_ordem,
        )
