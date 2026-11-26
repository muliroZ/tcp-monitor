"""Modelo analítico M/G/∞ do número de handshakes pendentes.

Conexões legítimas chegam a um servidor por um processo de Poisson de taxa λ_L e ficam
pendentes por um tempo T qualquer; SYNs de ataque chegam com taxa λ_A e ficam pendentes
exatamente τ_hs. O número de pendentes é uma fila M/G/∞, cuja distribuição estacionária é
Poisson com média λ·E[S], independentemente da distribuição de S:

    N_L ~ Poisson(a),  a = λ_L · E[T]
    N_A ~ Poisson(b),  b = λ_A · τ_hs
    P_FA(k) = P(N_L > k)       = poisson.sf(k, a)
    P_D(k)  = P(N_L + N_A > k) = poisson.sf(k, a + b)

``scipy.stats.poisson.sf(k, mu)`` devolve exatamente P(N > k).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import numpy as np
from scipy.stats import poisson


def p_fa(k: int | np.ndarray, a: float) -> float | np.ndarray:
    return poisson.sf(k, a)


def p_d(k: int | np.ndarray, a: float, b: float) -> float | np.ndarray:
    return poisson.sf(k, a + b)


def b_ataque(lambda_a: float, tau_hs: float) -> float:
    return lambda_a * tau_hs


def k_empirico(valores: Iterable[int], alfa: float) -> int:
    """Menor inteiro k tal que a fração de valores > k seja ≤ α."""
    v = np.sort(np.asarray(list(valores), dtype=np.int64))
    if v.size == 0:
        raise ValueError("sem observações para calibrar k")
    n = v.size
    for k in range(int(v[-1]) + 1):
        acima = n - np.searchsorted(v, k, side="right")
        if acima / n <= alfa:
            return k
    return int(v[-1])  # inalcançável: com k = máximo nenhum valor é > k


def k_analitico(alfa: float, medias: Sequence[float], pesos: Sequence[float] | None = None, k_max: int = 100000) -> int:
    """Menor k com P_FA(k) ≤ α.

    Com vários servidores, P_FA(k) é a média de ``poisson.sf(k, a_s)`` ponderada pela
    quantidade de retratos de cada servidor (a mesma população usada pelo k empírico).
    """
    a = np.asarray(medias, dtype=float)
    w = np.ones_like(a) if pesos is None else np.asarray(pesos, dtype=float)
    if a.size == 0 or w.sum() <= 0:
        raise ValueError("sem servidores para calcular k analítico")
    w = w / w.sum()
    for k in range(k_max + 1):
        if float(np.sum(w * poisson.sf(k, a))) <= alfa:
            return k
    raise ValueError("k analítico acima de k_max")


def simular_mginf(
    taxa: float,
    amostrar_servico,
    duracao: float,
    instantes: np.ndarray,
    rng: np.random.Generator,
) -> np.ndarray:
    """Simula uma fila M/G/∞ e devolve o número no sistema em cada instante de ``instantes``.

    ``amostrar_servico(rng, n)`` devolve n tempos de serviço. Usado para conferir que a média
    do número no sistema converge para λ·E[S].
    """
    n = rng.poisson(taxa * duracao)
    chegadas = np.sort(rng.uniform(0.0, duracao, size=n))
    saidas = chegadas + amostrar_servico(rng, n)
    chegou = np.searchsorted(chegadas, instantes, side="right")
    saiu = np.searchsorted(np.sort(saidas), instantes, side="right")
    return chegou - saiu
