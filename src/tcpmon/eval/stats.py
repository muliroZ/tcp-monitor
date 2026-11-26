"""Estatística da avaliação: Wilson, McNemar, Holm e diferença pareada de proporções."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy.stats import norm
from statsmodels.stats.contingency_tables import mcnemar as _mcnemar
from statsmodels.stats.multitest import multipletests

LIMIAR_EXATO = 25  # McNemar exato quando há menos de 25 discordâncias (guia)


def wilson(sucessos: int, n: int, confianca: float = 0.95) -> tuple[float, float]:
    """Intervalo de Wilson para uma proporção. Com n = 0 devolve (nan, nan)."""
    if n <= 0:
        return (math.nan, math.nan)
    z = norm.ppf(0.5 + confianca / 2.0)
    p = sucessos / n
    den = 1.0 + z * z / n
    centro = (p + z * z / (2 * n)) / den
    meia = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centro - meia), min(1.0, centro + meia))


@dataclass(frozen=True)
class ResultadoMcNemar:
    b: int  # detectado só pela configuração A
    c: int  # detectado só pela configuração B
    metodo: str
    estatistica: float
    p_valor: float


def mcnemar(b: int, c: int) -> ResultadoMcNemar:
    """Teste de McNemar sobre as discordâncias b e c.

    Exato (binomial) quando b + c < 25; senão qui-quadrado com correção de continuidade.
    """
    tabela = np.array([[0, b], [c, 0]])
    if b + c < LIMIAR_EXATO:
        r = _mcnemar(tabela, exact=True)
        return ResultadoMcNemar(b, c, "exato", float(r.statistic), float(r.pvalue))
    r = _mcnemar(tabela, exact=False, correction=True)
    return ResultadoMcNemar(b, c, "qui2_corrigido", float(r.statistic), float(r.pvalue))


def holm(p_valores: list[float]) -> list[float]:
    """Valores-p corrigidos por Holm (sobre o conjunto de todos os testes)."""
    if not p_valores:
        return []
    return [float(x) for x in multipletests(p_valores, method="holm")[1]]


def diferenca_pareada(a: int, b: int, c: int, d: int, confianca: float = 0.95) -> tuple[float, float, float]:
    """Diferença P(B) − P(A) entre proporções pareadas com IC de Newcombe (método 10).

    Tabela pareada: a = ambos detectam, b = só A, c = só B, d = nenhum.
    Usa intervalos de Wilson para cada proporção e a correlação φ com a correção de
    Newcombe (1998, "Improved confidence intervals for the difference between binomial
    proportions based on paired data").
    """
    n = a + b + c + d
    if n == 0:
        return (math.nan, math.nan, math.nan)
    p_a = (a + b) / n
    p_b = (a + c) / n
    l_a, u_a = wilson(a + b, n, confianca)
    l_b, u_b = wilson(a + c, n, confianca)
    theta = p_b - p_a

    den = (a + b) * (c + d) * (a + c) * (b + d)
    if den == 0:
        phi = 0.0
    else:
        ad_bc = a * d - b * c
        if ad_bc > n / 2:
            phi = (ad_bc - n / 2) / math.sqrt(den)
        elif ad_bc >= 0:
            phi = 0.0
        else:
            phi = ad_bc / math.sqrt(den)

    delta = math.sqrt(max(0.0, (p_b - l_b) ** 2 - 2 * phi * (p_b - l_b) * (u_a - p_a) + (u_a - p_a) ** 2))
    eps = math.sqrt(max(0.0, (u_b - p_b) ** 2 - 2 * phi * (u_b - p_b) * (p_a - l_a) + (p_a - l_a) ** 2))
    return (theta, max(-1.0, theta - delta), min(1.0, theta + eps))


def diferenca_independente(x1: int, n1: int, x2: int, n2: int, confianca: float = 0.95) -> tuple[float, float, float]:
    """p1 − p2 com IC de Newcombe para amostras independentes (soma dos quadrados de Wilson).

    Usado só para conferir a implementação pareada (φ = 0 reduz ao caso independente).
    """
    p1, p2 = x1 / n1, x2 / n2
    l1, u1 = wilson(x1, n1, confianca)
    l2, u2 = wilson(x2, n2, confianca)
    th = p1 - p2
    return (th, th - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2), th + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2))
