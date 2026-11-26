"""Camada 3: contagem dos retratos, decisões e escolha de k sobre dados sintéticos."""

import json

import numpy as np
import pytest
from conftest import FIXTURES, REPO
from engineutil import rodar
from pcaputil import FLAGS, pkt
from test_integracao_temporal import rodar_pcap

from tcpmon.analytic.model import k_analitico, k_empirico, p_d, p_fa, simular_mginf
from tcpmon.config import load_config
from tcpmon.eval.inclusao import alertas_ausentes

SYN, SA, A, R = FLAGS["SYN"], FLAGS["SYNACK"], FLAGS["ACK"], FLAGS["RST"]
SRV = ("10.0.0.2", 80)
SRV2 = ("10.0.0.3", 80)


def cli(i):
    return (f"10.1.0.{i}", 1000 + i)


def test_retratos_contam_pendentes_no_fim_de_cada_janela():
    pacotes = [
        pkt(0.0, ("10.9.9.9", 1), ("10.9.9.8", 1), SYN),  # t0 e um servidor sem relevância
        pkt(0.2, cli(1), SRV, SYN),
        pkt(0.4, cli(2), SRV, SYN),
        pkt(1.5, SRV, cli(1), SA),
        pkt(1.6, cli(1), SRV, A),  # cli(1) sai do pendente na janela 1
        pkt(2.3, cli(3), SRV2, SYN),
        pkt(2.5, SRV, cli(2), R),  # cli(2) sai do pendente na janela 2
        pkt(3.9, cli(4), SRV, SYN),
    ]
    e = rodar(pacotes, camadas=(1, 2), coletar_retratos=True, t_ultimo=4.0)
    r = {(j, s): n for j, _, s, n in e.saida.retratos}
    assert r[(0, "10.0.0.2")] == 2
    assert r[(1, "10.0.0.2")] == 1
    assert r[(2, "10.0.0.2")] == 0 and r[(2, "10.0.0.3")] == 1
    assert r[(3, "10.0.0.2")] == 1 and r[(3, "10.0.0.3")] == 1
    # SRV2 só entra nos retratos depois do primeiro SYN.
    assert (1, "10.0.0.3") not in r
    # Retrato no instante final da janela: t_fim = t0 + (i+1)·W.
    assert {t for j, t, s, n in e.saida.retratos if j == 2} == {3.0}
    assert e.alertas == [] or all(a.camada != 3 for a in e.alertas)  # modo coleta não decide


def test_expiracao_tira_o_fluxo_da_contagem():
    pacotes = [pkt(0.0, cli(1), SRV, SYN), pkt(100.0, ("10.9.9.9", 1), ("10.9.9.8", 1), SYN)]
    e = rodar(pacotes, camadas=(1, 2), coletar_retratos=True, tau_hs_s=10.0)
    n = {j: n for j, _, s, n in e.saida.retratos if s == "10.0.0.2"}
    assert n[8] == 1 and n[9] == 1  # janela 9 termina em 10.0: retrato antes do prazo (D23)
    assert n[10] == 0


def test_decisao_n_maior_que_k():
    pacotes = [pkt(0.1 * i, cli(i), SRV, SYN) for i in range(1, 6)] + [pkt(1.5, ("10.9.9.9", 1), SRV2, SYN)]
    e = rodar(pacotes, camadas=(1, 2, 3), k=4, k_scan=100, t0=0.0)
    agg = [a for a in e.alertas if a.motivo == "AGG_HANDSHAKE_PENDENTE"]
    assert len(agg) == 1  # janela 0: N=5 > 4; janela 1 incompleta (sem retrato)
    a = agg[0]
    assert a.camada == 3 and a.janela == 0 and a.servidor == "10.0.0.2" and a.fluxo == "" and a.cliente == ""
    assert a.t_evidencia == 0.0 and a.t_alerta == 1.0
    assert a.detalhe == {"N_s": 5, "k": 4}
    e2 = rodar(pacotes, camadas=(1, 2, 3), k=5, k_scan=100, t0=0.0)
    assert not [a for a in e2.alertas if a.motivo == "AGG_HANDSHAKE_PENDENTE"]


def test_varredura_horizontal():
    origem = ("10.5.5.5", 40000)
    pacotes = [pkt(0.1 * i, (origem[0], 40000 + i), (f"10.0.1.{i}", 80), SYN) for i in range(1, 7)]
    pacotes += [pkt(0.75, (origem[0], 50000), ("10.0.1.1", 22), SYN)]  # outra porta: outra contagem
    pacotes += [pkt(1.2, (origem[0], 40100), ("10.0.1.9", 80), SYN), pkt(2.0, ("10.9.9.9", 1), SRV, SYN)]
    e = rodar(pacotes, camadas=(1, 2, 3), k=1000, k_scan=5, t0=0.0)
    v = {(j, o, p): c for j, o, p, c in e.saida.varreduras}
    assert v[(0, "10.5.5.5", 80)] == 6 and v[(0, "10.5.5.5", 22)] == 1 and v[(1, "10.5.5.5", 80)] == 1
    agg = [a for a in e.alertas if a.motivo == "AGG_VARREDURA_HORIZONTAL"]
    assert len(agg) == 1
    assert agg[0].cliente == "10.5.5.5" and agg[0].janela == 0
    assert agg[0].detalhe == {"porta_destino": 80, "destinos_distintos": 6, "k_scan": 5}


def test_agregador_exige_k_para_decidir():
    with pytest.raises(ValueError):
        rodar([pkt(0.0, cli(1), SRV, SYN)], camadas=(1, 2, 3))


@pytest.mark.parametrize(
    "valores,alfa,k",
    [
        ([0] * 99 + [5], 0.01, 0),
        ([0] * 98 + [1, 5], 0.01, 1),
        ([0] * 98 + [3, 5], 0.01, 3),
        (list(range(10)), 0.0, 9),
        (list(range(10)), 0.1, 8),
        ([7] * 10, 0.01, 7),
    ],
)
def test_k_empirico(valores, alfa, k):
    assert k_empirico(valores, alfa) == k
    assert np.mean(np.asarray(valores) > k) <= alfa
    if k > 0:
        assert np.mean(np.asarray(valores) > k - 1) > alfa  # menor k possível


def test_k_analitico_valores_conhecidos():
    # Poisson(0,25): P(N>0)=0,2212; P(N>1)=0,0265; P(N>2)=0,00216.
    assert k_analitico(0.01, [0.25]) == 2
    assert p_fa(2, 0.25) == pytest.approx(0.0021614, rel=1e-4)
    assert k_analitico(0.05, [0.25]) == 1
    assert p_d(0, 0.0, 1.0) == pytest.approx(1 - np.exp(-1.0))
    # Mistura de servidores ponderada pelos retratos.
    assert k_analitico(0.01, [0.25, 0.25], [1, 1]) == 2


def test_mginf_media_converge_para_lambda_es():
    """Fila M/G/∞ com chegadas Poisson: média do número no sistema → λ·E[S] (qualquer S)."""
    rng = np.random.default_rng(42)
    lam, dur = 5.0, 20000.0
    instantes = np.linspace(100.0, dur - 100.0, 20000)
    for amostrar, es in (
        (lambda r, n: r.exponential(0.05, n), 0.05),
        (lambda r, n: r.lognormal(np.log(0.04), 0.5, n), 0.04 * np.exp(0.125)),
        (lambda r, n: np.full(n, 2.0), 2.0),
    ):
        n = simular_mginf(lam, amostrar, dur, instantes, rng)
        assert n.mean() == pytest.approx(lam * es, rel=0.05)


@pytest.mark.parametrize("pcap", sorted(FIXTURES.glob("fixture_*_s42.pcap")), ids=lambda p: p.stem)
def test_inclusao_c2_em_c3(pcap):
    c2 = rodar_pcap(pcap, (1, 2))
    cfg = load_config(REPO / "configs" / "default.yaml").com(carencia_s=0.0)
    from tcpmon.engine import Engine, ParametrosEngine, SaidaMemoria
    from tcpmon.io.pcap_reader import ReadCounters, read_packets

    for k, k_scan in ((0, 1), (3, 3)):
        e = Engine(ParametrosEngine.de_config(cfg, tau_hs_s=63.0, camadas=(1, 2, 3), k=k, k_scan=k_scan), SaidaMemoria())
        cont = ReadCounters()
        for p in read_packets(pcap, cont):
            if e.t0 is None:
                e.iniciar(cont.primeiro_ts)
            e.processar(p)
        e.finalizar(cont.max_ts)
        assert alertas_ausentes(c2.alertas, e.alertas) == []
        assert alertas_ausentes([a for a in e.alertas if a.camada < 3], c2.alertas) == []


def test_calibrate_grava_k(tmp_path):
    from tcpmon.cli import main

    pcap = FIXTURES / "fixture_temporal_s42.pcap"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"base: {REPO / 'configs' / 'experiments' / 'lab.yaml'}\nsaida: {tmp_path / 'res'}\n")
    assert main(["calibrate", "--config", str(cfg), "--pcap", str(pcap)]) == 0
    (arq,) = (tmp_path / "res").glob("*-calib/calibration.json")
    cal = json.loads(arq.read_text())
    assert isinstance(cal["k"], int) and isinstance(cal["k_scan"], int)
    assert cal["retratos"]["fracao_acima_de_k"] <= cal["alfa"]
    assert cal["tau_hs_s"] == 63.0
    assert "10.77.0.10" in cal["por_servidor"]
    # O run com --calibracao usa esses k.
    assert main(["run", "--config", str(cfg), "--pcap", str(pcap), "--calibracao", str(arq)]) == 0
    runs = [p for p in (tmp_path / "res").iterdir() if not p.name.endswith("-calib")]
    run = json.loads((runs[0] / "run.json").read_text())
    assert run["k"] == cal["k"] and run["k_scan"] == cal["k_scan"] and run["configuracao"] == "C3"
    assert (runs[0] / "snapshots.csv").is_file()
