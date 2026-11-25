"""Teste exaustivo das 64 combinações de SYN, ACK, FIN, RST, PSH e URG,
repetido com ECE e CWR ligados para confirmar que são ignorados."""

import itertools

import pytest

from tcpmon.symbols import (
    ACK,
    CWR,
    ECE,
    FIN,
    PSH,
    RST,
    SYN,
    URG,
    Classe,
    Direcao,
    Symbol,
    classify,
    parse_symbol,
    symbol,
)

BITS = {"SYN": SYN, "ACK": ACK, "FIN": FIN, "RST": RST, "PSH": PSH, "URG": URG}


def esperado(syn, ack, fin, rst, psh, urg):
    """Especificação da tabela do guia, escrita de forma independente da implementação."""
    if syn and not ack and not fin and not rst and not psh and not urg:
        return Classe.SYN
    if syn and ack and not fin and not rst and not psh and not urg:
        return Classe.SYNACK
    if ack and not syn and not fin and not rst:
        return Classe.ACK
    if fin and ack and not syn and not rst:
        return Classe.FIN
    if rst and not syn and not fin:
        return Classe.RST
    return Classe.INVALIDO


COMBINACOES = list(itertools.product([0, 1], repeat=6))


def _flags(combo):
    syn, ack, fin, rst, psh, urg = combo
    return (SYN * syn) | (ACK * ack) | (FIN * fin) | (RST * rst) | (PSH * psh) | (URG * urg)


def test_sao_64_combinacoes():
    assert len({_flags(c) for c in COMBINACOES}) == 64


@pytest.mark.parametrize("combo", COMBINACOES, ids=lambda c: "".join(n for n, b in zip(BITS, c) if b) or "NULL")
@pytest.mark.parametrize("ecn", [0, ECE, CWR, ECE | CWR], ids=["sem_ecn", "ece", "cwr", "ece_cwr"])
def test_classificacao_exaustiva(combo, ecn):
    assert classify(_flags(combo) | ecn) is esperado(*combo)


@pytest.mark.parametrize(
    "flags,classe",
    [
        (0, Classe.INVALIDO),  # NULL
        (FIN | PSH | URG, Classe.INVALIDO),  # Xmas
        (SYN | FIN, Classe.INVALIDO),
        (SYN | RST, Classe.INVALIDO),
        (FIN, Classe.INVALIDO),  # FIN sem ACK
        (SYN | ECE | CWR, Classe.SYN),  # SYN com negociação ECN
        (SYN | ACK | ECE, Classe.SYNACK),
        (PSH | ACK, Classe.ACK),
        (FIN | PSH | ACK, Classe.FIN),
        (RST | ACK, Classe.RST),
        (SYN | PSH, Classe.INVALIDO),
    ],
)
def test_exemplos_do_guia(flags, classe):
    assert classify(flags) is classe


def test_simbolo_texto():
    s = symbol(Direcao.C, SYN)
    assert s == Symbol(Direcao.C, Classe.SYN)
    assert str(s) == "C.SYN"
    assert str(symbol(Direcao.S, SYN | ACK)) == "S.SYNACK"
    assert parse_symbol("C.INVALIDO") == Symbol(Direcao.C, Classe.INVALIDO)
