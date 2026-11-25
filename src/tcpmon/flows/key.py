"""Chave de fluxo bidirecional e detecção de direção.

A chave ordena os dois pares (IP, porta) e usa ``(par_menor, par_maior)``: os dois
sentidos da conexão caem no mesmo fluxo. A ordem é a numérica dos endereços (IPv4 antes
de IPv6) e, em empate, a da porta.

Cliente: quem enviou o primeiro pacote do fluxo. Se esse pacote é SYN, é quem enviou o
primeiro SYN; se não é, o remetente é tratado como cliente e o fluxo é marcado
``sem_handshake`` (a marcação é feita pela tabela de fluxos).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import NamedTuple

from tcpmon.symbols import Direcao

Endpoint = tuple[str, int]


@lru_cache(maxsize=1 << 18)
def _ordem_ip(ip: str) -> tuple[int, int]:
    end = ipaddress.ip_address(ip)
    return (end.version, int(end))


def _ordem(ep: Endpoint) -> tuple[int, int, int]:
    v, n = _ordem_ip(ep[0])
    return (v, n, ep[1])


def format_endpoint(ep: Endpoint) -> str:
    ip, porta = ep
    return f"[{ip}]:{porta}" if ":" in ip else f"{ip}:{porta}"


def endpoint_ip(texto: str) -> str:
    """IP de um texto 'ip:porta', '[ipv6]:porta' ou só 'ip'."""
    texto = texto.strip()
    if texto.startswith("["):
        return texto[1 : texto.index("]")]
    if texto.count(":") == 1:
        return texto.split(":", 1)[0]
    return texto


class FlowKey(NamedTuple):
    menor: Endpoint
    maior: Endpoint

    def __str__(self) -> str:
        return f"{format_endpoint(self.menor)}-{format_endpoint(self.maior)}"


def flow_key(src: Endpoint, dst: Endpoint) -> FlowKey:
    if _ordem(src) <= _ordem(dst):
        return FlowKey(src, dst)
    return FlowKey(dst, src)


def direction(cliente: Endpoint, src: Endpoint) -> Direcao:
    """Direção de um pacote cujo remetente é ``src`` num fluxo cujo cliente é ``cliente``."""
    return Direcao.C if src == cliente else Direcao.S
