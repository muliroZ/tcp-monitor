"""Alfabeto dos monitores: direção do pacote + classe das flags.

Antes de classificar, as flags ECE (0x40) e CWR (0x80) são ignoradas, porque aparecem
legitimamente em SYN e SYN-ACK durante a negociação de ECN.

| Classe   | Condição sobre as flags (após ignorar ECE e CWR)               |
| SYN      | Exatamente SYN                                                 |
| SYNACK   | Exatamente SYN e ACK                                           |
| ACK      | ACK ligado; SYN, FIN e RST desligados; PSH e URG livres        |
| FIN      | FIN e ACK ligados; SYN e RST desligados; PSH e URG livres      |
| RST      | RST ligado; SYN e FIN desligados; demais livres                |
| INVALIDO | Qualquer outra combinação                                      |
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

_MASCARA_SEM_ECN = 0xFF & ~(ECE | CWR)


class Classe(StrEnum):
    SYN = "SYN"
    SYNACK = "SYNACK"
    ACK = "ACK"
    FIN = "FIN"
    RST = "RST"
    INVALIDO = "INVALIDO"


class Direcao(StrEnum):
    C = "C"  # cliente -> servidor
    S = "S"  # servidor -> cliente


class Symbol(NamedTuple):
    direcao: Direcao
    classe: Classe

    def __str__(self) -> str:
        return f"{self.direcao.value}.{self.classe.value}"


def _classificar(flags: int) -> Classe:
    f = flags & _MASCARA_SEM_ECN
    if f == SYN:
        return Classe.SYN
    if f == SYN | ACK:
        return Classe.SYNACK
    if f & RST and not f & (SYN | FIN):
        return Classe.RST
    if f & ACK and not f & (SYN | FIN | RST):
        return Classe.ACK
    if f & FIN and f & ACK and not f & (SYN | RST):
        return Classe.FIN
    return Classe.INVALIDO


# Tabela pré-calculada para os 256 valores do byte de flags.
_TABELA: tuple[Classe, ...] = tuple(_classificar(f) for f in range(256))


def classify(flags: int) -> Classe:
    """Classe das flags TCP (byte de flags; bits acima de 0xFF são ignorados)."""
    return _TABELA[flags & 0xFF]


def symbol(direcao: Direcao, flags: int) -> Symbol:
    return Symbol(direcao, _TABELA[flags & 0xFF])


def parse_symbol(texto: str) -> Symbol:
    """Converte 'C.SYN' em Symbol (usado em testes e depuração)."""
    d, c = texto.split(".", 1)
    return Symbol(Direcao(d), Classe(c))
