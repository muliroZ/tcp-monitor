"""Inclusão entre configurações cumulativas (D33).

- **C1 ⊆ C2, por traço rejeitado.** A hierarquia trata de traços rejeitados: ⊥ é absorvente,
  então rejeitar um prefixo é rejeitar o traço. Para toda instância rejeitada pela C1 deve
  existir, na C2, uma instância rejeitada com a mesma chave e o mesmo instante do primeiro
  pacote, com ``t_alerta`` menor ou igual ao da C1. O motivo pode diferir. As instâncias são
  associadas por (chave, instante do primeiro pacote), nunca pelo número da instância.
- **C2 ⊆ C3, por alerta idêntico**, porque o agregador não remove fluxos.
- **Divergência por janela** (relatório à parte): alertas da C1 cuja janela não tem alerta da
  C2 com chave que case. Existe porque a C2 data o alerta pelo primeiro SYN e a C1 pelo pacote
  anômalo.

Violações são reportadas como estão, nunca filtradas.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from tcpmon.alerts import Alerta


@dataclass(frozen=True)
class Rejeitada:
    chave: str  # chave bidirecional do fluxo, sem o número da instância
    inicio: float  # instante do primeiro pacote da instância
    t_alerta: float  # instante da entrada em ⊥ (= remoção)
    motivo: str
    fluxo: str  # chave#instância, só para o relatório


def rejeitadas_de_fluxos(fluxos: Iterable) -> list[Rejeitada]:
    """Instâncias rejeitadas a partir de objetos ``FlowInstance`` (motor em memória)."""
    out = []
    for f in fluxos:
        if f.motivo_alerta:
            out.append(Rejeitada(str(f.key), f.inicio, f.fim, f.motivo_alerta, f.id))
    return out


def rejeitadas_de_csv(caminho: str | Path) -> list[Rejeitada]:
    """Instâncias rejeitadas a partir de ``flows.csv`` de uma execução."""
    df = pd.read_csv(
        caminho,
        usecols=["fluxo", "chave", "inicio", "removido_em", "motivo_alerta"],
        dtype={"fluxo": str, "chave": str, "motivo_alerta": str},
        keep_default_na=False,
    )
    df = df[df["motivo_alerta"] != ""]
    return [
        Rejeitada(r.chave, float(r.inicio), float(r.removido_em), r.motivo_alerta, r.fluxo)
        for r in df.itertuples(index=False)
    ]


@dataclass(frozen=True)
class ViolacaoTraco:
    menor: Rejeitada
    maior: Rejeitada | None  # instância correspondente com t_alerta maior, ou None se ausente


def inclusao_por_traco(menor: list[Rejeitada], maior: list[Rejeitada]) -> list[ViolacaoTraco]:
    """Instâncias rejeitadas em ``menor`` sem rejeição correspondente e tão cedo em ``maior``."""
    idx = {(r.chave, r.inicio): r for r in maior}
    out = []
    for r in menor:
        m = idx.get((r.chave, r.inicio))
        if m is None or m.t_alerta > r.t_alerta:
            out.append(ViolacaoTraco(r, m))
    return out


def alertas_ausentes(menor: list[Alerta], maior: list[Alerta]) -> list[Alerta]:
    """Alertas de ``menor`` sem correspondente idêntico em ``maior`` (multiconjunto).

    Critério de inclusão C2 ⊆ C3.
    """
    disponiveis = Counter(a.identidade() for a in maior)
    faltando = []
    for a in menor:
        ident = a.identidade()
        if disponiveis[ident] > 0:
            disponiveis[ident] -= 1
        else:
            faltando.append(a)
    return faltando


def _chave_alerta(a: Alerta) -> tuple:
    if a.fluxo:
        return ("fluxo", a.fluxo.split("#", 1)[0])
    return ("agregador", a.cliente, a.servidor)


def divergencia_por_janela(menor: list[Alerta], maior: list[Alerta]) -> list[Alerta]:
    """Alertas de ``menor`` cuja janela não tem alerta de ``maior`` com a mesma chave.

    A chave é a chave bidirecional do fluxo (sem o número da instância); para alertas do
    agregador, o par (cliente, servidor).
    """
    por_janela: dict[int, set] = defaultdict(set)
    for a in maior:
        por_janela[a.janela].add(_chave_alerta(a))
    return [a for a in menor if _chave_alerta(a) not in por_janela.get(a.janela, ())]
