"""Janelas de avaliação e seus rótulos.

Janelas ``[t0 + i·W, t0 + (i+1)·W)``, i = 0 … n−1 (n = janelas completas da execução).

- Uma janela é **positiva para a classe c** se intersecta algum episódio da classe c.
- **Zona de transição:** janelas que intersectam ``[t_fim, t_fim + τ_hs]`` de um episódio e não
  são positivas para ele não são nem positivas nem benignas (D42). Os alertas delas são
  reportados à parte.
- **Zona de tolerância (D38):** janelas que intersectam ``[t_inicio − tol, t_inicio)`` ou
  ``(t_fim, t_fim + tol]`` de um episódio e não são positivas nem de transição. Também não são
  positivas nem benignas; os alertas delas são reportados à parte. ``tol = 0`` não cria zona.
- **Fora da conta (D64, D66):** episódios cujas classes estão em
  ``avaliacao.classes_fora_da_conta`` não geram janelas positivas. As janelas que eles
  intersectam não são positivas nem benignas, e os alertas delas são reportados à parte.
  Transição e tolerância valem para eles como para os demais.
- Uma janela é **benigna** se não intersecta nenhum episódio nem zona de transição, de
  tolerância ou fora da conta.
- Uma janela positiva é **detectada** se tem ao menos um alerta cuja chave casa com a chave de
  um episódio da classe que a intersecta (mesmo IP de origem ou mesmo servidor alvo).
- Uma janela benigna é **falso alarme** se tem qualquer alerta.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from tcpmon.alerts import Alerta
from tcpmon.flows.key import endpoint_ip
from tcpmon.io.labels import Episodio


def intervalo_janelas(t_ini: float, t_fim: float, t0: float, w: float, n: int) -> range:
    """Índices das janelas que intersectam o intervalo fechado [t_ini, t_fim]."""
    i0 = max(0, math.floor((t_ini - t0) / w))
    i1 = min(n - 1, math.floor((t_fim - t0) / w))
    return range(i0, i1 + 1) if i1 >= i0 else range(0)


def janelas_antes(t_inicio: float, tol: float, t0: float, w: float, n: int) -> range:
    """Índices das janelas que intersectam o intervalo semiaberto [t_inicio − tol, t_inicio)."""
    if tol <= 0:
        return range(0)
    i0 = max(0, math.floor((t_inicio - tol - t0) / w))
    i1 = min(n - 1, math.ceil((t_inicio - t0) / w) - 1)
    return range(i0, i1 + 1) if i1 >= i0 else range(0)


def janelas_depois(t_fim: float, tol: float, t0: float, w: float, n: int) -> range:
    """Índices das janelas que intersectam o intervalo semiaberto (t_fim, t_fim + tol]."""
    if tol <= 0:
        return range(0)
    i0 = max(0, math.floor((t_fim - t0) / w))
    i1 = min(n - 1, math.floor((t_fim + tol - t0) / w))
    return range(i0, i1 + 1) if i1 >= i0 else range(0)


@dataclass
class Rotulagem:
    n: int
    t0: float
    w: float
    tau: float
    episodios: list[Episodio]
    tolerancia_s: float = 0.0
    episodios_fora_da_conta: list[Episodio] = field(default_factory=list)
    positivas: dict[str, np.ndarray] = field(default_factory=dict)  # classe -> bool[n]
    transicao: np.ndarray | None = None
    tolerancia: np.ndarray | None = None  # D38
    fora_da_conta: np.ndarray | None = None  # D64
    benigna: np.ndarray | None = None
    janelas_do_episodio: dict[str, range] = field(default_factory=dict)
    # (classe, janela) -> chaves dos episódios da classe que intersectam a janela
    chaves: dict[tuple[str, int], set[tuple[str, str]]] = field(default_factory=dict)

    @property
    def classes(self) -> list[str]:
        return sorted(self.positivas)


def rotular(
    episodios: list[Episodio],
    t0: float,
    w: float,
    n: int,
    tau: float,
    tolerancia: float = 0.0,
    fora_da_conta: frozenset[str] | set[str] = frozenset(),
) -> Rotulagem:
    contados = [e for e in episodios if e.classe not in fora_da_conta]
    r = Rotulagem(
        n=n,
        t0=t0,
        w=w,
        tau=tau,
        episodios=contados,
        tolerancia_s=tolerancia,
        episodios_fora_da_conta=[e for e in episodios if e.classe in fora_da_conta],
    )
    qualquer_positiva = np.zeros(n, dtype=bool)
    transicao = np.zeros(n, dtype=bool)
    tolerancia_z = np.zeros(n, dtype=bool)
    fora = np.zeros(n, dtype=bool)
    chaves: dict[tuple[str, int], set] = defaultdict(set)
    for e in episodios:
        jan = intervalo_janelas(e.t_inicio, e.t_fim, t0, w, n)
        if e.classe in fora_da_conta:
            for i in jan:
                fora[i] = True
        else:
            pos = r.positivas.setdefault(e.classe, np.zeros(n, dtype=bool))
            r.janelas_do_episodio[e.episodio] = jan
            for i in jan:
                pos[i] = True
                qualquer_positiva[i] = True
                chaves[(e.classe, i)].add((e.chave_tipo, e.chave_valor))
        for i in intervalo_janelas(e.t_fim, e.t_fim + tau, t0, w, n):
            if i not in jan:
                transicao[i] = True
        for i in (*janelas_antes(e.t_inicio, tolerancia, t0, w, n), *janelas_depois(e.t_fim, tolerancia, t0, w, n)):
            tolerancia_z[i] = True
    r.chaves = dict(chaves)
    # Precedência: positiva > fora da conta > transição > tolerância.
    r.fora_da_conta = fora & ~qualquer_positiva
    r.transicao = transicao & ~qualquer_positiva & ~r.fora_da_conta
    r.tolerancia = tolerancia_z & ~qualquer_positiva & ~r.fora_da_conta & ~r.transicao
    r.benigna = ~qualquer_positiva & ~fora & ~transicao & ~tolerancia_z
    return r


def tolerancia_da_execucao(run: dict) -> float:
    """D38: ``avaliacao.tolerancia_rotulo_s`` gravada na configuração de uma execução (run.json)."""
    try:
        return float(run["config"]["avaliacao"]["tolerancia_rotulo_s"])
    except (KeyError, TypeError):
        raise ValueError(
            f"execução {run.get('run_id', '?')} não registra avaliacao.tolerancia_rotulo_s na configuração; "
            "informe a tolerância explicitamente (tcpmon eval --tolerancia)"
        ) from None


def fora_da_conta_da_execucao(run: dict) -> frozenset[str]:
    """D64: ``avaliacao.classes_fora_da_conta`` da configuração de uma execução (vazia se ausente)."""
    av = (run.get("config") or {}).get("avaliacao") or {}
    return frozenset(av.get("classes_fora_da_conta") or ())


def casa(alerta: Alerta, chave_tipo: str, chave_valor: str) -> bool:
    if chave_tipo == "origem":
        return bool(alerta.cliente) and endpoint_ip(alerta.cliente) == chave_valor
    if chave_tipo == "servidor":
        return bool(alerta.servidor) and endpoint_ip(alerta.servidor) == chave_valor
    return False


def alertas_por_janela(alertas: list[Alerta]) -> dict[int, list[Alerta]]:
    out: dict[int, list[Alerta]] = defaultdict(list)
    for a in alertas:
        out[a.janela].append(a)
    return out


def detectadas(r: Rotulagem, por_janela: dict[int, list[Alerta]], classe: str) -> np.ndarray:
    """bool[n]: janelas positivas da classe com alerta cuja chave casa."""
    pos = r.positivas[classe]
    out = np.zeros(r.n, dtype=bool)
    for i in np.flatnonzero(pos):
        ch = r.chaves[(classe, int(i))]
        out[i] = any(casa(a, t, v) for a in por_janela.get(int(i), ()) for (t, v) in ch)
    return out


def com_alerta(r: Rotulagem, por_janela: dict[int, list[Alerta]]) -> np.ndarray:
    out = np.zeros(r.n, dtype=bool)
    for i in por_janela:
        if 0 <= i < r.n:
            out[i] = True
    return out


def latencia_episodio(r: Rotulagem, e: Episodio, por_janela: dict[int, list[Alerta]]) -> float | None:
    """t_alerta do primeiro alerta que casa com o episódio menos t_inicio do episódio.

    Casa: mesma chave e janela (de t_evidencia) entre as janelas positivas do episódio.
    """
    melhor = None
    for i in r.janelas_do_episodio[e.episodio]:
        for a in por_janela.get(i, ()):
            if casa(a, e.chave_tipo, e.chave_valor) and (melhor is None or a.t_alerta < melhor):
                melhor = a.t_alerta
    return None if melhor is None else melhor - e.t_inicio
