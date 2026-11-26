"""Camada 2 — autômato temporizado.

A camada 2 é a camada 1 mais um relógio por instância de fluxo e um prazo de handshake.
Nesta versão detecta uma única propriedade temporal: handshake que não se completa em τ_hs.

- Relógio x: zerado no primeiro ``C.SYN`` da instância; retransmissões do SYN não o zeram.
- Handshake pendente: estado ``SYN_VISTO`` ou ``SYNACK_VISTO``.
- Invariante: enquanto pendente, x ≤ τ_hs.
- Transição temporizada: quando x atinge τ_hs com o handshake pendente, o fluxo vai para ⊥
  com motivo ``HANDSHAKE_EXPIRADO``.
- Guarda: ``C.ACK``/``C.FIN`` em ``SYNACK_VISTO`` só concluem o handshake se x ≤ τ_hs.

Modo offline: um prazo por fluxo pendente numa fila de prioridade (a do motor, ``heapq``),
disparado pelos timestamps do pcap antes de cada pacote; prazos de fluxos que já saíram do
handshake pendente são descartados de forma preguiçosa. No fim da captura, os fluxos ainda
pendentes ficam ``truncado`` e não geram alerta.

Alerta: ``t_evidencia`` = timestamp do primeiro ``C.SYN``; ``t_alerta`` = ``t_evidencia`` + τ_hs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tcpmon.monitors.base import Monitor
from tcpmon.monitors.dfa import C_ACK, C_FIN, PENDENTES, Estado, Motivo

if TYPE_CHECKING:
    from tcpmon.engine import Engine
    from tcpmon.flows.table import FlowInstance

PRAZO = "prazo"


class TimedMonitor(Monitor):
    camada = 2

    def __init__(self, engine: "Engine", tau_hs_s: float) -> None:
        super().__init__(engine)
        if tau_hs_s <= 0:
            raise ValueError("tau_hs_s precisa ser positivo")
        self.tau = tau_hs_s

    def relogio(self, fluxo: "FlowInstance", t: float) -> float:
        return t - fluxo.t_syn

    def ao_entrar_pendente(self, fluxo: "FlowInstance", t: float) -> None:
        from tcpmon.engine import PRIO_PRAZO

        self.engine.agendar(t + self.tau, PRIO_PRAZO, PRAZO, fluxo, self)

    def permite(self, fluxo: "FlowInstance", simbolo, t: float) -> bool:
        if fluxo.estado is Estado.SYNACK_VISTO and simbolo in (C_ACK, C_FIN):
            return self.relogio(fluxo, t) <= self.tau
        return True

    def disparar(self, tipo: str, fluxo: "FlowInstance", t: float) -> None:
        if not fluxo.vivo or fluxo.estado not in PENDENTES:
            self.engine.cont["prazos_descartados"] += 1  # descarte preguiçoso
            return
        self.engine.cont["prazos_disparados"] += 1
        prazo = fluxo.t_syn + self.tau
        self.engine.rejeitar(
            fluxo,
            self.camada,
            Motivo.HANDSHAKE_EXPIRADO,
            t_evidencia=fluxo.t_syn,
            t_alerta=prazo,
            detalhe={"estado_anterior": str(fluxo.estado), "tau_hs_s": self.tau},
        )

    def finalizar(self, t_ultimo: float) -> None:
        # Todos os prazos ≤ último timestamp já dispararam; os pendentes restantes têm prazo
        # depois do fim da captura: não se sabe como terminariam.
        for f in self.engine.tabela.vivos.values():
            if f.estado in PENDENTES:
                f.truncado = True
                self.engine.cont["fluxos_truncados"] += 1
