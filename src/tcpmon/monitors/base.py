"""Interface comum dos monitores das camadas 2 e 3.

A camada 1 (AFD) é a função de transição aplicada pela base a cada símbolo e está sempre
presente, porque as configurações são cumulativas (C1 ⊂ C2 ⊂ C3). As camadas 2 e 3 são
acopladas à base como monitores que recebem estes ganchos. Nenhum monitor lê pcap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tcpmon.engine import Engine
    from tcpmon.flows.table import FlowInstance


class Monitor:
    camada: int = 0

    def __init__(self, engine: "Engine") -> None:
        self.engine = engine

    def ao_criar_fluxo(self, fluxo: "FlowInstance", t: float) -> None:
        """Nova instância de fluxo entregue aos monitores (não chamada para midstream)."""

    def ao_entrar_pendente(self, fluxo: "FlowInstance", t: float) -> None:
        """O fluxo entrou em handshake pendente (primeiro C.SYN; relógio zerado)."""

    def ao_sair_pendente(self, fluxo: "FlowInstance", t: float) -> None:
        """O fluxo saiu do handshake pendente por qualquer motivo."""

    def permite(self, fluxo: "FlowInstance", simbolo, t: float) -> bool:
        """Guarda temporal da transição; True quando o monitor não restringe."""
        return True

    def disparar(self, tipo: str, fluxo: "FlowInstance", t: float) -> None:
        """Evento temporizado agendado por este monitor chegou ao seu instante."""

    def ao_fim_janela(self, janela: int, t_inicio: float, t_fim: float) -> None:
        """Instante final da janela ``janela`` (retrato)."""

    def finalizar(self, t_ultimo: float) -> None:
        """Fim da captura."""
