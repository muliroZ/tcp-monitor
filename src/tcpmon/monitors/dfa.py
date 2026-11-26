"""Camada 1 — AFD observador da conexão TCP.

O AFD modela a conexão como vista pela rede, não a máquina de estados de cada ponta da
RFC 9293: os estados são uma projeção observável dos estados da RFC. É um *monitor*
(runtime verification): consome o traço símbolo a símbolo e entra no estado de rejeição ⊥
no instante em que não existe transição; o alerta é emitido uma única vez, na entrada em ⊥.

Regra geral: um símbolo da classe INVALIDO leva a ⊥ com motivo FLAGS_INVALIDAS a partir de
qualquer estado. "Outro" é qualquer símbolo não listado para o estado.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple

from tcpmon.symbols import Classe, Direcao, Symbol


class Estado(StrEnum):
    INICIAL = "INICIAL"
    SYN_VISTO = "SYN_VISTO"
    SYNACK_VISTO = "SYNACK_VISTO"
    ESTABELECIDO = "ESTABELECIDO"
    FIN_C = "FIN_C"
    FIN_S = "FIN_S"
    FIN_AMBOS = "FIN_AMBOS"
    FECHADO = "FECHADO"
    REJEICAO = "⊥"


class Motivo(StrEnum):
    SEM_HANDSHAKE = "SEM_HANDSHAKE"
    SYNACK_SEM_SYN = "SYNACK_SEM_SYN"
    FLAGS_INVALIDAS = "FLAGS_INVALIDAS"
    ABERTURA_SIMULTANEA = "ABERTURA_SIMULTANEA"
    TRANSICAO_INESPERADA = "TRANSICAO_INESPERADA"
    HANDSHAKE_EXPIRADO = "HANDSHAKE_EXPIRADO"
    AGG_HANDSHAKE_PENDENTE = "AGG_HANDSHAKE_PENDENTE"
    AGG_VARREDURA_HORIZONTAL = "AGG_VARREDURA_HORIZONTAL"


CAMADA_DO_MOTIVO = {
    Motivo.SEM_HANDSHAKE: 1,
    Motivo.SYNACK_SEM_SYN: 1,
    Motivo.FLAGS_INVALIDAS: 1,
    Motivo.ABERTURA_SIMULTANEA: 1,
    Motivo.TRANSICAO_INESPERADA: 1,
    Motivo.HANDSHAKE_EXPIRADO: 2,
    Motivo.AGG_HANDSHAKE_PENDENTE: 3,
    Motivo.AGG_VARREDURA_HORIZONTAL: 3,
}

# Handshake pendente (camadas 2 e 3): o fluxo está em SYN_VISTO ou SYNACK_VISTO.
PENDENTES = frozenset({Estado.SYN_VISTO, Estado.SYNACK_VISTO})


class Passo(NamedTuple):
    """Resultado de δ(estado, símbolo)."""

    proximo: Estado
    motivo: Motivo | None = None  # preenchido só na entrada em ⊥
    nova_instancia: bool = False  # reuso de porta: o símbolo abre uma nova instância


def _s(d: str, c: str) -> Symbol:
    return Symbol(Direcao(d), Classe(c))


C_SYN, C_SYNACK, C_ACK, C_FIN, C_RST = (_s("C", c) for c in ("SYN", "SYNACK", "ACK", "FIN", "RST"))
S_SYN, S_SYNACK, S_ACK, S_FIN, S_RST = (_s("S", c) for c in ("SYN", "SYNACK", "ACK", "FIN", "RST"))

_NOVA = Passo(Estado.INICIAL, None, True)


def _ir(e: Estado) -> Passo:
    return Passo(e)


def _rej(m: Motivo) -> Passo:
    return Passo(Estado.REJEICAO, m)


E = Estado
M = Motivo

# Tabela de transições do guia (uma linha da tabela = uma ou mais entradas aqui).
TRANSICOES: dict[Estado, dict[Symbol, Passo]] = {
    E.INICIAL: {
        C_SYN: _ir(E.SYN_VISTO),
        C_SYNACK: _rej(M.SYNACK_SEM_SYN),
    },
    E.SYN_VISTO: {
        C_SYN: _ir(E.SYN_VISTO),  # retransmissão do SYN
        S_SYNACK: _ir(E.SYNACK_VISTO),
        S_RST: _ir(E.FECHADO),  # porta fechada
        C_RST: _ir(E.FECHADO),  # cliente desistiu
        S_SYN: _rej(M.ABERTURA_SIMULTANEA),
    },
    E.SYNACK_VISTO: {
        C_ACK: _ir(E.ESTABELECIDO),  # handshake completo, com ou sem dados
        C_FIN: _ir(E.FIN_C),  # o FIN também confirma o SYN-ACK
        S_SYNACK: _ir(E.SYNACK_VISTO),  # retransmissão
        C_SYN: _ir(E.SYNACK_VISTO),  # retransmissão
        C_RST: _ir(E.FECHADO),  # inclui a varredura SYN
        S_RST: _ir(E.FECHADO),
    },
    E.ESTABELECIDO: {
        C_ACK: _ir(E.ESTABELECIDO),
        S_ACK: _ir(E.ESTABELECIDO),
        S_SYNACK: _ir(E.ESTABELECIDO),  # retransmissão tardia do SYN-ACK
        C_FIN: _ir(E.FIN_C),
        S_FIN: _ir(E.FIN_S),
        C_RST: _ir(E.FECHADO),
        S_RST: _ir(E.FECHADO),
    },
    E.FIN_C: {
        C_ACK: _ir(E.FIN_C),
        S_ACK: _ir(E.FIN_C),
        C_FIN: _ir(E.FIN_C),
        S_FIN: _ir(E.FIN_AMBOS),
        C_RST: _ir(E.FECHADO),
        S_RST: _ir(E.FECHADO),
    },
    E.FIN_S: {
        C_ACK: _ir(E.FIN_S),
        S_ACK: _ir(E.FIN_S),
        S_FIN: _ir(E.FIN_S),
        C_FIN: _ir(E.FIN_AMBOS),
        C_RST: _ir(E.FECHADO),
        S_RST: _ir(E.FECHADO),
    },
    E.FIN_AMBOS: {
        C_ACK: _ir(E.FIN_AMBOS),
        S_ACK: _ir(E.FIN_AMBOS),
        C_FIN: _ir(E.FIN_AMBOS),
        S_FIN: _ir(E.FIN_AMBOS),
        C_RST: _ir(E.FECHADO),
        S_RST: _ir(E.FECHADO),
        C_SYN: _NOVA,  # reuso de porta
    },
    E.FECHADO: {
        C_ACK: _ir(E.FECHADO),
        S_ACK: _ir(E.FECHADO),
        C_FIN: _ir(E.FECHADO),
        S_FIN: _ir(E.FECHADO),
        C_RST: _ir(E.FECHADO),
        S_RST: _ir(E.FECHADO),
        C_SYN: _NOVA,  # reuso de porta
    },
}

# "Outro" de cada estado.
OUTRO: dict[Estado, Passo] = {
    E.INICIAL: _rej(M.SEM_HANDSHAKE),
    E.SYN_VISTO: _rej(M.TRANSICAO_INESPERADA),
    E.SYNACK_VISTO: _rej(M.TRANSICAO_INESPERADA),
    E.ESTABELECIDO: _rej(M.TRANSICAO_INESPERADA),
    E.FIN_C: _rej(M.TRANSICAO_INESPERADA),
    E.FIN_S: _rej(M.TRANSICAO_INESPERADA),
    E.FIN_AMBOS: _rej(M.TRANSICAO_INESPERADA),
    E.FECHADO: _rej(M.TRANSICAO_INESPERADA),
}

_ABSORVE = Passo(E.REJEICAO)
_INVALIDO = _rej(M.FLAGS_INVALIDAS)


def delta(estado: Estado, simbolo: Symbol) -> Passo:
    """Função de transição δ do AFD observador."""
    if estado is E.REJEICAO:
        return _ABSORVE  # absorvente; nenhum novo alerta
    if simbolo.classe is Classe.INVALIDO:
        return _INVALIDO
    return TRANSICOES[estado].get(simbolo, OUTRO[estado])
