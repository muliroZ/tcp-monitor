"""Camada 1: um teste por linha da tabela de transições do guia."""

import itertools

import pytest

from tcpmon.monitors.dfa import Estado, Motivo, Passo, delta
from tcpmon.symbols import Classe, Direcao, Symbol, parse_symbol

E, M = Estado, Motivo
VALIDOS = [Symbol(d, c) for d, c in itertools.product(Direcao, Classe) if c is not Classe.INVALIDO]
TODOS = [Symbol(d, c) for d, c in itertools.product(Direcao, Classe)]


def s(*textos):
    return [parse_symbol(t) for t in textos]


# (estado, símbolos da linha, próximo estado, motivo, nova instância)
LINHAS = [
    ("INICIAL", s("C.SYN"), E.SYN_VISTO, None, False),
    ("INICIAL", s("C.SYNACK"), E.REJEICAO, M.SYNACK_SEM_SYN, False),
    ("SYN_VISTO", s("C.SYN"), E.SYN_VISTO, None, False),
    ("SYN_VISTO", s("S.SYNACK"), E.SYNACK_VISTO, None, False),
    ("SYN_VISTO", s("S.RST", "C.RST"), E.FECHADO, None, False),
    ("SYN_VISTO", s("S.SYN"), E.REJEICAO, M.ABERTURA_SIMULTANEA, False),
    ("SYNACK_VISTO", s("C.ACK"), E.ESTABELECIDO, None, False),
    ("SYNACK_VISTO", s("C.FIN"), E.FIN_C, None, False),
    ("SYNACK_VISTO", s("S.SYNACK", "C.SYN"), E.SYNACK_VISTO, None, False),
    ("SYNACK_VISTO", s("C.RST", "S.RST"), E.FECHADO, None, False),
    ("ESTABELECIDO", s("C.ACK", "S.ACK"), E.ESTABELECIDO, None, False),
    ("ESTABELECIDO", s("S.SYNACK"), E.ESTABELECIDO, None, False),
    ("ESTABELECIDO", s("C.FIN"), E.FIN_C, None, False),
    ("ESTABELECIDO", s("S.FIN"), E.FIN_S, None, False),
    ("ESTABELECIDO", s("C.RST", "S.RST"), E.FECHADO, None, False),
    ("FIN_C", s("C.ACK", "S.ACK", "C.FIN"), E.FIN_C, None, False),
    ("FIN_C", s("S.FIN"), E.FIN_AMBOS, None, False),
    ("FIN_C", s("C.RST", "S.RST"), E.FECHADO, None, False),
    ("FIN_S", s("C.ACK", "S.ACK", "S.FIN"), E.FIN_S, None, False),
    ("FIN_S", s("C.FIN"), E.FIN_AMBOS, None, False),
    ("FIN_S", s("C.RST", "S.RST"), E.FECHADO, None, False),
    ("FIN_AMBOS", s("C.ACK", "S.ACK", "C.FIN", "S.FIN"), E.FIN_AMBOS, None, False),
    ("FIN_AMBOS", s("C.RST", "S.RST"), E.FECHADO, None, False),
    ("FIN_AMBOS", s("C.SYN"), E.INICIAL, None, True),
    ("FECHADO", s("C.ACK", "S.ACK", "C.FIN", "S.FIN", "C.RST", "S.RST"), E.FECHADO, None, False),
    ("FECHADO", s("C.SYN"), E.INICIAL, None, True),
]

# Linhas "outro" de cada estado: todos os símbolos válidos não listados acima.
OUTRO = {
    "INICIAL": M.SEM_HANDSHAKE,
    "SYN_VISTO": M.TRANSICAO_INESPERADA,
    "SYNACK_VISTO": M.TRANSICAO_INESPERADA,
    "ESTABELECIDO": M.TRANSICAO_INESPERADA,
    "FIN_C": M.TRANSICAO_INESPERADA,
    "FIN_S": M.TRANSICAO_INESPERADA,
    "FIN_AMBOS": M.TRANSICAO_INESPERADA,
    "FECHADO": M.TRANSICAO_INESPERADA,
}


def _id(linha):
    estado, simbolos, prox, motivo, nova = linha
    return f"{estado}-{'|'.join(map(str, simbolos))}"


@pytest.mark.parametrize("linha", LINHAS, ids=_id)
def test_linha_da_tabela(linha):
    estado, simbolos, prox, motivo, nova = linha
    for simb in simbolos:
        assert delta(E(estado), simb) == Passo(prox, motivo, nova), f"{estado} + {simb}"


@pytest.mark.parametrize("estado", list(OUTRO))
def test_linha_outro(estado):
    listados = {simb for (e, simbs, *_) in LINHAS if e == estado for simb in simbs}
    outros = [simb for simb in VALIDOS if simb not in listados]
    assert outros, "todo estado tem ao menos um símbolo 'outro'"
    for simb in outros:
        assert delta(E(estado), simb) == Passo(E.REJEICAO, OUTRO[estado]), f"{estado} + {simb}"


@pytest.mark.parametrize("estado", list(OUTRO))
@pytest.mark.parametrize("direcao", list(Direcao))
def test_regra_geral_invalido(estado, direcao):
    assert delta(E(estado), Symbol(direcao, Classe.INVALIDO)) == Passo(E.REJEICAO, M.FLAGS_INVALIDAS)


@pytest.mark.parametrize("simb", TODOS, ids=str)
def test_rejeicao_absorvente_sem_novo_alerta(simb):
    passo = delta(E.REJEICAO, simb)
    assert passo.proximo is E.REJEICAO and passo.motivo is None and not passo.nova_instancia


def test_tabela_e_total():
    """δ está definida para todo par (estado, símbolo)."""
    for estado, simb in itertools.product(E, TODOS):
        assert isinstance(delta(estado, simb), Passo)


def test_aceita_handshake_e_rejeita_ack_antes_do_syn():
    """Critério do Bloco 1: aceita SYN·SYN-ACK·ACK e rejeita ACK·SYN."""
    e = E.INICIAL
    for t in ("C.SYN", "S.SYNACK", "C.ACK"):
        e = delta(e, parse_symbol(t)).proximo
    assert e is E.ESTABELECIDO
    assert delta(E.INICIAL, parse_symbol("C.ACK")) == Passo(E.REJEICAO, M.SEM_HANDSHAKE)
