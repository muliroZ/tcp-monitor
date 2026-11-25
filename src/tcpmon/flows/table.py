"""Tabela de fluxos: instâncias, direção, período de carência.

Esta é a parte da base compartilhada que transforma pacotes normalizados em
(instância de fluxo, símbolo). É o mesmo código nas três configurações.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tcpmon.flows.key import Endpoint, FlowKey, direction, flow_key, format_endpoint
from tcpmon.io.pcap_reader import Packet
from tcpmon.symbols import Classe, Symbol, symbol


@dataclass(eq=False, slots=True)
class FlowInstance:
    key: FlowKey
    instancia: int
    cliente: Endpoint
    servidor: Endpoint
    inicio: float
    ultimo: float
    pacotes: int = 0
    estado: str = "INICIAL"
    midstream: bool = False
    sem_handshake: bool = False
    truncado: bool = False
    t_syn: float | None = None  # primeiro C.SYN (zera o relógio da camada 2)
    t_fim_pendente: float | None = None
    motivo_fim_pendente: str | None = None
    fim: float | None = None
    motivo_fim: str | None = None
    motivo_alerta: str | None = None
    vivo: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.key}#{self.instancia}"

    def descricao(self) -> str:
        marcas = [m for m in ("midstream", "sem_handshake", "truncado") if getattr(self, m)]
        txt = (
            f"fluxo {self.id}  cliente={format_endpoint(self.cliente)}"
            f"  servidor={format_endpoint(self.servidor)}"
        )
        return txt + (f"  [{', '.join(marcas)}]" if marcas else "")


class FlowTable:
    """Mapeia pacotes para instâncias de fluxo vivas.

    Uma chave tem no máximo uma instância viva. A numeração de instâncias de uma chave
    continua depois de a instância ser removida (reuso de porta).
    """

    def __init__(self, carencia_s: float) -> None:
        self.carencia_s = carencia_s
        self.t0: float | None = None
        self.vivos: dict[FlowKey, FlowInstance] = {}
        self._proxima_instancia: dict[FlowKey, int] = {}
        self.pico_vivos = 0

    def observar_tempo(self, t: float) -> None:
        if self.t0 is None:
            self.t0 = t

    def em_carencia(self, t: float) -> bool:
        return self.t0 is not None and (t - self.t0) < self.carencia_s

    def buscar(self, pkt: Packet) -> tuple[FlowKey, FlowInstance | None]:
        key = flow_key(pkt.src, pkt.dst)
        return key, self.vivos.get(key)

    def criar(self, key: FlowKey, pkt: Packet) -> FlowInstance:
        """Cria uma instância nova cujo cliente é o remetente de ``pkt``."""
        n = self._proxima_instancia.get(key, 0)
        self._proxima_instancia[key] = n + 1
        fluxo = FlowInstance(
            key=key,
            instancia=n,
            cliente=pkt.src,
            servidor=pkt.dst,
            inicio=pkt.ts,
            ultimo=pkt.ts,
        )
        primeira_classe = symbol(direction(fluxo.cliente, pkt.src), pkt.flags).classe
        if primeira_classe is not Classe.SYN:
            fluxo.sem_handshake = True
            if self.em_carencia(pkt.ts):
                fluxo.midstream = True
        self.vivos[key] = fluxo
        if len(self.vivos) > self.pico_vivos:
            self.pico_vivos = len(self.vivos)
        return fluxo

    def remover(self, fluxo: FlowInstance, t: float, motivo: str) -> None:
        if self.vivos.get(fluxo.key) is fluxo:
            del self.vivos[fluxo.key]
        fluxo.vivo = False
        fluxo.fim = t
        fluxo.motivo_fim = motivo

    def simbolo(self, fluxo: FlowInstance, pkt: Packet) -> Symbol:
        return symbol(direction(fluxo.cliente, pkt.src), pkt.flags)
