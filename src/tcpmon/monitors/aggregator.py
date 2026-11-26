"""Camada 3 — agregador (contadores sobre o conjunto de fluxos).

O agregador observa os fluxos das camadas 1 e 2 e decide uma vez por janela
``[t0 + i·W, t0 + (i+1)·W)``. Só existe na configuração completa (C3), porque depende da
expiração da camada 2 para que fluxos de ataque saiam da contagem após τ_hs. Na calibração
ele roda em modo de coleta (retratos sem decisão).

Detector de handshakes pendentes: para cada servidor s da lista ``agregador.servidores``
(D36, definida antes das execuções), N_s = número de instâncias com handshake pendente. No
instante final de cada janela tira-se um retrato de N_s de todo servidor da lista (inclusive
N_s = 0); se N_s > k_s, alerta ``AGG_HANDSHAKE_PENDENTE``. k é por servidor (D36). Decidir por
retrato (e não "em qualquer instante da janela") torna o resultado comparável à fórmula
analítica. Servidores fora da lista não geram alerta do agregador.

Detector de varredura horizontal: para cada par (IP de origem, porta de destino), o número
de IPs de destino distintos em fluxos iniciados na janela; acima de k_scan, alerta
``AGG_VARREDURA_HORIZONTAL``.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING

from tcpmon.monitors.base import Monitor
from tcpmon.monitors.dfa import Motivo

if TYPE_CHECKING:
    from tcpmon.engine import Engine
    from tcpmon.flows.table import FlowInstance


class Aggregator(Monitor):
    camada = 3

    def __init__(
        self,
        engine: "Engine",
        servidores: tuple[str, ...] | None,
        k: int | dict[str, int] | None,
        k_scan: int | None,
        decidir: bool,
    ) -> None:
        super().__init__(engine)
        if not servidores:
            raise ValueError("o agregador precisa de agregador.servidores (D36): liste os IPs monitorados")
        self.servidores: tuple[str, ...] = tuple(servidores)
        if isinstance(k, dict):
            self.k: dict[str, int | None] = {s: k.get(s) for s in self.servidores}
        else:
            self.k = {s: k for s in self.servidores}
        self.k_scan = k_scan
        self.decidir = decidir
        if decidir:
            faltando = [s for s, v in self.k.items() if v is None]
            if faltando or k_scan is None:
                raise ValueError(
                    f"o agregador precisa de k por servidor e de k_scan para decidir (faltam: {faltando or 'k_scan'});"
                    " rode tcpmon calibrate"
                )
        self._monitorado = set(self.servidores)
        self.pendentes: Counter[str] = Counter()
        self._varredura: defaultdict[tuple[str, int], set[str]] = defaultdict(set)

    # Contagem de handshakes pendentes por servidor monitorado (granularidade: IP do servidor).
    def ao_entrar_pendente(self, fluxo: "FlowInstance", t: float) -> None:
        ip = fluxo.servidor[0]
        if ip in self._monitorado:
            self.pendentes[ip] += 1

    def ao_sair_pendente(self, fluxo: "FlowInstance", t: float) -> None:
        ip = fluxo.servidor[0]
        if ip in self._monitorado:
            self.pendentes[ip] -= 1

    # Varredura: destinos distintos por (origem, porta de destino) entre os fluxos iniciados.
    def ao_criar_fluxo(self, fluxo: "FlowInstance", t: float) -> None:
        self._varredura[(fluxo.cliente[0], fluxo.servidor[1])].add(fluxo.servidor[0])

    def ao_fim_janela(self, janela: int, t_inicio: float, t_fim: float) -> None:
        eng = self.engine
        saida = eng.saida
        for servidor in self.servidores:
            n = self.pendentes[servidor]
            saida.retrato(janela, t_fim, servidor, n)
            k = self.k[servidor]
            if self.decidir and n > k:
                eng.alertar(
                    self.camada,
                    Motivo.AGG_HANDSHAKE_PENDENTE,
                    "",
                    "",
                    servidor,
                    t_inicio,
                    t_fim,
                    {"N_s": n, "k": k},
                    janela=janela,
                )
        for (origem, porta), destinos in self._varredura.items():
            c = len(destinos)
            saida.varredura(janela, origem, porta, c)
            if self.decidir and c > self.k_scan:
                eng.alertar(
                    self.camada,
                    Motivo.AGG_VARREDURA_HORIZONTAL,
                    "",
                    origem,
                    "",
                    t_inicio,
                    t_fim,
                    {"porta_destino": porta, "destinos_distintos": c, "k_scan": self.k_scan},
                    janela=janela,
                )
        self._varredura = defaultdict(set)
