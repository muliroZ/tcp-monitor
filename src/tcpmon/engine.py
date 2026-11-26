"""Base compartilhada: tabela de fluxos, ciclo de vida, AFD e eventos temporizados.

Este é o mesmo código nas três configurações (regra 2 do guia). O que muda entre C1, C2 e
C3 é só o conjunto de monitores acoplados no final (``tcpmon.monitors``):

- C1: apenas a função de transição do AFD (camada 1), aplicada aqui a cada símbolo;
- C2: + ``TimedMonitor`` (camada 2), que agenda e dispara o prazo de handshake;
- C3: + ``Aggregator`` (camada 3), que tira retratos ao fim de cada janela.

O tempo é sempre o timestamp do pcap. Antes de processar um pacote com timestamp t, todos
os eventos com instante ≤ t são disparados em ordem; num empate de instantes a ordem é:
fim de janela, prazo de handshake, inatividade (ver DECISIONS.md).
"""

from __future__ import annotations

import heapq
import itertools
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Protocol

from tcpmon.alerts import Alerta
from tcpmon.config import Config
from tcpmon.flows.key import FlowKey, direction, format_endpoint
from tcpmon.flows.table import FlowInstance, FlowTable
from tcpmon.io.pcap_reader import Packet
from tcpmon.monitors.base import Monitor
from tcpmon.monitors.dfa import PENDENTES, Estado, Motivo, delta
from tcpmon.symbols import Classe, Symbol, classify

PRIO_JANELA, PRIO_PRAZO, PRIO_OCIOSO = 0, 1, 2
_OCIOSO = "ocioso"


@dataclass(frozen=True)
class ParametrosEngine:
    janela_s: float
    tau_hs_s: float
    carencia_s: float
    msl_s: float
    ocioso_estabelecido_s: float
    camadas: tuple[int, ...]
    k: int | dict[str, int] | None = None  # D36: um k por servidor (ou um valor para todos)
    k_scan: int | None = None
    coletar_retratos: bool = False  # retratos e contagens de varredura sem decidir (calibração)
    servidores: tuple[str, ...] | None = None  # D36: servidores monitorados pelo agregador

    @classmethod
    def de_config(
        cls,
        cfg: Config,
        *,
        tau_hs_s: float | None = None,
        camadas: tuple[int, ...] | None = None,
        k: int | dict[str, int] | None = None,
        k_scan: int | None = None,
        coletar_retratos: bool = False,
        servidores: tuple[str, ...] | None = None,
    ) -> "ParametrosEngine":
        return cls(
            janela_s=cfg.janela_s,
            tau_hs_s=cfg.tau_hs_s if tau_hs_s is None else tau_hs_s,
            carencia_s=cfg.carencia_s,
            msl_s=cfg.msl_s,
            ocioso_estabelecido_s=cfg.ocioso_estabelecido_s,
            camadas=tuple(cfg.camadas if camadas is None else camadas),
            k=cfg.agregador.k if k is None else k,
            k_scan=cfg.agregador.k_scan if k_scan is None else k_scan,
            coletar_retratos=coletar_retratos,
            servidores=cfg.agregador.servidores if servidores is None else tuple(servidores),
        )


class Saida(Protocol):
    def fluxo(self, f: FlowInstance) -> None: ...
    def retrato(self, janela: int, t_fim: float, servidor: str, n: int) -> None: ...
    def varredura(self, janela: int, origem: str, porta: int, destinos: int) -> None: ...


class SaidaMemoria:
    """Saída em memória (testes e análises pequenas)."""

    def __init__(self) -> None:
        self.fluxos: list[FlowInstance] = []
        self.retratos: list[tuple[int, float, str, int]] = []
        self.varreduras: list[tuple[int, str, int, int]] = []

    def fluxo(self, f: FlowInstance) -> None:
        self.fluxos.append(f)

    def retrato(self, janela: int, t_fim: float, servidor: str, n: int) -> None:
        self.retratos.append((janela, t_fim, servidor, n))

    def varredura(self, janela: int, origem: str, porta: int, destinos: int) -> None:
        self.varreduras.append((janela, origem, porta, destinos))


class Engine:
    def __init__(self, p: ParametrosEngine, saida: Saida | None = None) -> None:
        self.p = p
        self.saida: Saida = saida if saida is not None else SaidaMemoria()
        self.tabela = FlowTable(p.carencia_s)
        self.lapides: set[FlowKey] = set()
        self.cont: Counter = Counter()
        self.alertas: list[Alerta] = []
        self.t0: float | None = None
        self.t_max: float | None = None
        self.janela_atual = 0  # índice da janela aberta
        self.finalizado = False
        self._heap: list[tuple[Any, ...]] = []
        self._seq = itertools.count()

        self.monitores: list[Monitor] = []
        self.temporizado = None
        self.agregador = None
        if 2 in p.camadas:
            from tcpmon.monitors.timed import TimedMonitor

            self.temporizado = TimedMonitor(self, p.tau_hs_s)
            self.monitores.append(self.temporizado)
        if 3 in p.camadas or p.coletar_retratos:
            from tcpmon.monitors.aggregator import Aggregator

            self.agregador = Aggregator(
                self, servidores=p.servidores, k=p.k, k_scan=p.k_scan, decidir=3 in p.camadas
            )
            self.monitores.append(self.agregador)

    # ------------------------------------------------------------------ tempo e eventos

    def iniciar(self, t0: float) -> None:
        if self.t0 is None:
            self.t0 = t0
            self.t_max = t0
            self.tabela.observar_tempo(t0)

    def janela_de(self, t: float) -> int:
        return math.floor((t - self.t0) / self.p.janela_s)

    def agendar(self, t: float, prioridade: int, tipo: str, fluxo: FlowInstance, dono: Monitor | None) -> None:
        heapq.heappush(self._heap, (t, prioridade, next(self._seq), tipo, fluxo, dono))

    def _avancar(self, t: float) -> None:
        """Dispara, em ordem, fins de janela e eventos com instante ≤ t."""
        w, t0 = self.p.janela_s, self.t0
        heap = self._heap
        while True:
            fim_janela = t0 + (self.janela_atual + 1) * w
            prox = heap[0][0] if heap else math.inf
            if fim_janela <= prox:
                if fim_janela > t:
                    return
                i = self.janela_atual
                for m in self.monitores:
                    m.ao_fim_janela(i, t0 + i * w, fim_janela)
                self.janela_atual = i + 1
            else:
                if prox > t:
                    return
                t_ev, _, _, tipo, fluxo, dono = heapq.heappop(heap)
                if tipo == _OCIOSO:
                    self._verificar_ocioso(fluxo, t_ev)
                else:
                    dono.disparar(tipo, fluxo, t_ev)

    # ------------------------------------------------------------------ ciclo de vida

    def _timeout(self, f: FlowInstance) -> float:
        if not f.midstream and f.estado in (Estado.FIN_AMBOS, Estado.FECHADO):
            return 2.0 * self.p.msl_s
        return self.p.ocioso_estabelecido_s

    def _agendar_ocioso(self, f: FlowInstance) -> None:
        devido = f.ultimo + self._timeout(f)
        if f.ocioso_em is None or devido < f.ocioso_em:
            f.ocioso_em = devido
            self.agendar(devido, PRIO_OCIOSO, _OCIOSO, f, None)

    def _verificar_ocioso(self, f: FlowInstance, t: float) -> None:
        if not f.vivo:
            return
        f.ocioso_em = None
        if f.ultimo + self._timeout(f) > t:
            self._agendar_ocioso(f)
            return
        self.cont["fluxos_removidos_inatividade"] += 1
        self._remover(f, t, "inatividade", lapide=True)

    def _novo_fluxo(self, key: FlowKey, pkt: Packet) -> FlowInstance:
        f = self.tabela.criar(key, pkt)
        self.lapides.discard(key)
        self.cont["instancias_criadas"] += 1
        if f.midstream:
            self.cont["instancias_midstream"] += 1
        else:
            if f.instancia > 0:
                self.cont["instancias_reuso_chave"] += 1
            for m in self.monitores:
                m.ao_criar_fluxo(f, pkt.ts)
        self._agendar_ocioso(f)
        return f

    def _entrar_pendente(self, f: FlowInstance, t: float) -> None:
        f.t_syn = t
        for m in self.monitores:
            m.ao_entrar_pendente(f, t)

    def _sair_pendente(self, f: FlowInstance, t: float, motivo: str) -> None:
        f.t_fim_pendente = t
        f.motivo_fim_pendente = motivo
        for m in self.monitores:
            m.ao_sair_pendente(f, t)

    def _remover(self, f: FlowInstance, t: float, motivo: str, lapide: bool) -> None:
        if f.estado in PENDENTES:
            self._sair_pendente(f, t, motivo)
        self.tabela.remover(f, t, motivo)
        if lapide:
            self.lapides.add(f.key)
        self.saida.fluxo(f)

    def alertar(
        self,
        camada: int,
        motivo: Motivo | str,
        fluxo: str,
        cliente: str,
        servidor: str,
        t_evidencia: float,
        t_alerta: float,
        detalhe: dict,
        janela: int | None = None,
    ) -> Alerta:
        a = Alerta(
            camada=camada,
            motivo=str(motivo),
            fluxo=fluxo,
            cliente=cliente,
            servidor=servidor,
            t_evidencia=t_evidencia,
            t_alerta=t_alerta,
            janela=self.janela_de(t_evidencia) if janela is None else janela,
            detalhe=detalhe,
        )
        self.alertas.append(a)
        self.cont[f"alertas_camada{camada}_{motivo}"] += 1
        return a

    def rejeitar(
        self,
        f: FlowInstance,
        camada: int,
        motivo: Motivo,
        t_evidencia: float,
        t_alerta: float,
        detalhe: dict,
    ) -> None:
        """Entrada em ⊥: alerta único e remoção imediata do fluxo (vira lápide)."""
        if f.estado in PENDENTES:
            self._sair_pendente(f, t_alerta, str(motivo))
        f.estado = Estado.REJEICAO
        f.motivo_alerta = str(motivo)
        self.alertar(
            camada,
            motivo,
            f.id,
            format_endpoint(f.cliente),
            format_endpoint(f.servidor),
            t_evidencia,
            t_alerta,
            detalhe,
        )
        self._remover(f, t_alerta, "rejeicao", lapide=True)

    # ------------------------------------------------------------------ pacotes

    def processar(self, pkt: Packet) -> None:
        t = pkt.ts
        if self.t0 is None:
            self.iniciar(t)
        if t > self.t_max:
            self.t_max = t
        self._avancar(t)

        classe = classify(pkt.flags)
        key, f = self.tabela.buscar(pkt)
        if f is None:
            if key in self.lapides and classe is not Classe.SYN:
                self.cont["pacotes_lapide"] += 1
                return
            f = self._novo_fluxo(key, pkt)
        elif f.midstream and classe is Classe.SYN:
            # SYN numa chave midstream: a conexão antiga não é acompanhada; abre-se uma
            # instância nova (DECISIONS.md).
            self._remover(f, t, "syn_em_midstream", lapide=False)
            f = self._novo_fluxo(key, pkt)

        if f.midstream:
            f.pacotes += 1
            f.ultimo = t
            self.cont["pacotes_midstream"] += 1
            return

        simbolo = Symbol(direction(f.cliente, pkt.src), classe)
        passo = delta(f.estado, simbolo)
        if passo.nova_instancia:
            self._remover(f, t, "reuso_de_porta", lapide=False)
            f = self._novo_fluxo(key, pkt)
            simbolo = Symbol(direction(f.cliente, pkt.src), classe)
            passo = delta(f.estado, simbolo)

        f.pacotes += 1
        f.ultimo = t
        self.cont["pacotes_monitorados"] += 1

        anterior = f.estado
        if anterior in PENDENTES:
            for m in self.monitores:
                if not m.permite(f, simbolo, t):
                    # Guarda violada: só ocorre se um prazo não tiver sido disparado a tempo.
                    self.cont["guarda_temporal_violada"] += 1
                    m.disparar("guarda", f, t)
                    if not f.vivo:
                        self.cont["pacotes_lapide"] += 1
                        return

        if passo.proximo is Estado.REJEICAO:
            if passo.motivo is None:
                return  # ⊥ é absorvente (não ocorre: fluxos em ⊥ são removidos na entrada)
            self.rejeitar(
                f,
                1,
                passo.motivo,
                t,
                t,
                {"simbolo": str(simbolo), "estado_anterior": str(anterior)},
            )
            return

        f.estado = passo.proximo
        if anterior is Estado.INICIAL and passo.proximo is Estado.SYN_VISTO:
            self._entrar_pendente(f, t)
        elif anterior in PENDENTES and passo.proximo not in PENDENTES:
            self._sair_pendente(f, t, str(passo.proximo))
        if passo.proximo is not anterior:
            self._agendar_ocioso(f)

    def finalizar(self, t_ultimo: float | None = None) -> None:
        """Fim da captura: dispara eventos ≤ último timestamp e fecha o relatório."""
        if self.finalizado:
            return
        self.finalizado = True
        if self.t0 is None:
            return
        t_fim = self.t_max if t_ultimo is None else max(t_ultimo, self.t_max)
        self.t_max = t_fim
        self._avancar(t_fim)
        for m in self.monitores:
            m.finalizar(t_fim)
        for f in list(self.tabela.vivos.values()):
            f.motivo_fim = "fim_da_captura"
            self.saida.fluxo(f)

    @property
    def janelas_completas(self) -> int:
        return self.janela_atual

    def rodar(self, pacotes, t0: float | None = None, t_ultimo: float | None = None) -> "Engine":
        if t0 is not None:
            self.iniciar(t0)
        for pkt in pacotes:
            self.processar(pkt)
        self.finalizar(t_ultimo)
        return self
