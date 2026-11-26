"""Wilson, McNemar, Holm e diferença pareada conferidos contra valores conhecidos."""

import math

import pytest

from tcpmon.eval.stats import diferenca_independente, diferenca_pareada, holm, mcnemar, wilson


@pytest.mark.parametrize(
    "x,n,lo,hi",
    [(0, 10, 0.0, 0.2775), (5, 10, 0.2366, 0.7634), (10, 10, 0.7225, 1.0), (81, 263, 0.2553, 0.3662)],
)
def test_wilson(x, n, lo, hi):
    a, b = wilson(x, n)
    assert a == pytest.approx(lo, abs=1e-4) and b == pytest.approx(hi, abs=1e-4)


def test_wilson_sem_observacoes():
    assert all(math.isnan(v) for v in wilson(0, 0))


def test_mcnemar_exato():
    r = mcnemar(1, 6)  # 2·P(X ≤ 1 | Bin(7, 1/2)) = 2·8/128
    assert r.metodo == "exato" and r.p_valor == pytest.approx(0.125)
    assert mcnemar(0, 0).p_valor == pytest.approx(1.0)
    

def test_limiar_do_exato():
    assert mcnemar(12, 11).metodo == "exato"
    assert mcnemar(13, 12).metodo == "qui2_corrigido"


def test_mcnemar_qui2_corrigido():
    r = mcnemar(10, 30)  # (|10−30|−1)²/40 = 9,025
    assert r.estatistica == pytest.approx(9.025) and r.p_valor == pytest.approx(0.002663, rel=1e-3)


def test_holm():
    assert holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert holm([0.5]) == [0.5] and holm([]) == []


def test_diferenca_independente_newcombe():
    # Newcombe (1998), diferenças independentes: 56/70 − 48/80 = 0,2000, IC 0,0524 a 0,3339.
    th, lo, hi = diferenca_independente(56, 70, 48, 80)
    assert th == pytest.approx(0.2) and lo == pytest.approx(0.0524, abs=1e-4) and hi == pytest.approx(0.3339, abs=1e-4)


def test_diferenca_pareada_referencia():
    # Tabela pareada 20/12/2/16 (Armitage e Berry), N = 50: diferença 0,2 e IC 0,056156 a 0,329207
    # (StatsDirect, método de Newcombe baseado em Wilson). Aqui A = linha, B = coluna.
    th, lo, hi = diferenca_pareada(20, 2, 12, 16)
    assert th == pytest.approx(0.2) and lo == pytest.approx(0.056156, abs=1e-6) and hi == pytest.approx(0.329207, abs=1e-6)
    th2, lo2, hi2 = diferenca_pareada(20, 12, 2, 16)
    assert (th2, lo2, hi2) == pytest.approx((-0.2, -hi, -lo))


def test_diferenca_pareada_bordas():
    th, lo, hi = diferenca_pareada(0, 0, 10, 0)  # B detecta tudo, A nada
    assert th == 1.0 and hi == 1.0 and 0 < lo < 1
    th, lo, hi = diferenca_pareada(10, 0, 0, 0)
    assert th == 0.0 and lo <= 0 <= hi
