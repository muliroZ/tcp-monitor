"""Rotulagem e pontuação de janelas; avaliação ponta a ponta numa fixture."""

import json

import numpy as np
import pandas as pd
from conftest import FIXTURES, REPO

from tcpmon.alerts import Alerta
from tcpmon.cli import main
from tcpmon.eval.windows import alertas_por_janela, com_alerta, detectadas, latencia_episodio, rotular
from tcpmon.io.labels import Episodio


def alerta(janela, cliente="", servidor="", t_alerta=None, motivo="X"):
    return Alerta(1, motivo, "", cliente, servidor, float(janela), float(janela if t_alerta is None else t_alerta), janela)


EPS = [
    Episodio("e1", "xmas", 10.5, 13.2, "origem", "10.0.0.66"),
    Episodio("e2", "synflood", 30.0, 30.0, "servidor", "10.0.0.10"),  # pontual
]


def test_positivas_transicao_benignas():
    r = rotular(EPS, t0=0.0, w=1.0, n=100, tau=5.0)
    assert list(np.flatnonzero(r.positivas["xmas"])) == [10, 11, 12, 13]
    assert list(np.flatnonzero(r.positivas["synflood"])) == [30]
    # Transição: janelas que intersectam [t_fim, t_fim + τ] e não são positivas.
    assert list(np.flatnonzero(r.transicao)) == [14, 15, 16, 17, 18, 31, 32, 33, 34, 35]
    assert not r.benigna[10] and not r.benigna[14] and r.benigna[19] and r.benigna[9]
    assert r.benigna.sum() == 100 - 4 - 1 - 10


def test_deteccao_exige_chave_e_janela():
    r = rotular(EPS, t0=0.0, w=1.0, n=100, tau=5.0)
    alertas = [
        alerta(10, cliente="10.0.0.66:4000"),  # casa
        alerta(11, cliente="10.0.0.99:4000"),  # outra origem: benigno durante o episódio
        alerta(12, servidor="10.0.0.66:80"),  # IP certo no campo errado
        alerta(30, servidor="10.0.0.10"),  # agregador: IP sem porta
        alerta(50, cliente="1.2.3.4:1"),  # falso alarme
        alerta(15, cliente="10.0.0.66:1"),  # transição: não é detecção nem falso alarme
    ]
    pj = alertas_por_janela(alertas)
    assert list(np.flatnonzero(detectadas(r, pj, "xmas"))) == [10]
    assert list(np.flatnonzero(detectadas(r, pj, "synflood"))) == [30]
    fa = com_alerta(r, pj) & r.benigna
    assert list(np.flatnonzero(fa)) == [50]


def test_latencia():
    r = rotular(EPS, t0=0.0, w=1.0, n=100, tau=5.0)
    pj = alertas_por_janela([alerta(11, cliente="10.0.0.66:1", t_alerta=11.7), alerta(12, cliente="10.0.0.66:2", t_alerta=11.9)])
    assert latencia_episodio(r, EPS[0], pj) == 11.7 - 10.5
    assert latencia_episodio(r, EPS[1], pj) is None


def test_eval_ponta_a_ponta(tmp_path):
    pcap = FIXTURES / "fixture_temporal_s42.pcap"
    rot = FIXTURES / "fixture_temporal_s42_labels.csv"
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"base: {REPO / 'configs' / 'experiments' / 'lab.yaml'}\nsaida: {tmp_path / 'res'}\n")
    cal = tmp_path / "cal.json"
    cal.write_text(json.dumps({"k": {"10.77.0.10": 3}, "k_scan": 1, "servidores": ["10.77.0.10"]}))  # valores arbitrários: o teste não depende deles
    pastas = []
    for camadas in ("1", "1,2", "1,2,3"):
        assert main(["run", "--config", str(cfg), "--pcap", str(pcap), "--camadas", camadas, "--calibracao", str(cal)]) == 0
    pastas = sorted(p for p in (tmp_path / "res").iterdir())
    saida = tmp_path / "eval"
    args = ["eval", "--rotulos", str(rot), "--saida", str(saida), "--quieto"]
    for p in pastas:
        args += ["--run", str(p)]
    assert main(args) == 0
    for arq in ("metricas.csv", "episodios.csv", "mcnemar.csv", "falsos_alarmes.csv", "transicao.csv", "desempenho.csv", "inclusao.json", "resumo.md", "pfa_por_servidor.csv"):
        assert (saida / arq).is_file()
    m = pd.read_csv(saida / "metricas.csv")
    assert set(m["config"]) == {"C1", "C2", "C3"}
    assert set(m["classe"]) == {"handshake_incompleto", "synflood_alta"}
    # Comportamento determinístico: C1 não tem nenhum alerta temporal que case.
    assert (m.loc[m["config"] == "C1", "TP"] == 0).all()
    t = pd.read_csv(saida / "mcnemar.csv")
    assert len(t) == 6 and (t["p_holm"] >= t["p_valor"]).all()
    pf = pd.read_csv(saida / "pfa_por_servidor.csv")
    assert set(pf["servidor"]) == {"10.77.0.10"} and set(pf["config"]) == {"C1", "C2", "C3"}
    inc = json.loads((saida / "inclusao.json").read_text())
    assert inc["C1_em_C2"]["violacoes"] == 0 and inc["C2_em_C3"]["violacoes"] == 0
