"""Validação analítica: testes de ajuste em dados sintéticos e geração ponta a ponta."""

import json

import numpy as np
import pytest
from conftest import FIXTURES, REPO

from tcpmon.analytic.validacao import ajustar_t, ks_exponencial, qui_quadrado_poisson
from tcpmon.cli import main


def test_qui_quadrado_aceita_poisson_e_rejeita_rajadas():
    rng = np.random.default_rng(42)
    ok = qui_quadrado_poisson(rng.poisson(2.0, 5000), 2.0)
    assert ok["p_valor"] > 0.001 and ok["gl"] >= 1
    rajadas = np.where(rng.random(5000) < 0.5, 0, rng.poisson(4.0, 5000))  # média 2, sobredisperso
    assert qui_quadrado_poisson(rajadas, 2.0)["p_valor"] < 1e-6


def test_qui_quadrado_agrupa_classes_pequenas():
    r = qui_quadrado_poisson(np.zeros(100, dtype=int), 0.01)
    assert r["p_valor"] is None and r["classes"] < 3


def test_ks_exponencial():
    rng = np.random.default_rng(42)
    assert ks_exponencial(rng.exponential(0.2, 3000))["p_valor"] > 0.001
    assert ks_exponencial(rng.uniform(0.19, 0.21, 3000))["p_valor"] < 1e-6


def test_ajuste_t_com_censura_recupera_lognormal():
    rng = np.random.default_rng(42)
    tau = 1.0
    t = rng.lognormal(np.log(0.3), 0.8, 4000)
    cens = t > tau
    t = np.where(cens, tau, t)
    r = ajustar_t(t, cens, tau)
    ln = r["distribuicoes"]["lognormal"]
    s, _, escala = ln["parametros"]
    assert s == pytest.approx(0.8, rel=0.05) and escala == pytest.approx(0.3, rel=0.05)
    assert r["P_T_maior_tau_empirica"] == pytest.approx(cens.mean())
    assert ln["P_T_maior_tau"] == pytest.approx(cens.mean(), abs=0.02)
    assert ln["AIC"] < r["distribuicoes"]["exponencial"]["AIC"]


def test_analytic_ponta_a_ponta(tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(f"base: {REPO / 'configs' / 'experiments' / 'lab.yaml'}\nsaida: {tmp_path / 'res'}\n")
    cal_pcap = FIXTURES / "fixture_estrutural_s42.pcap"
    teste = FIXTURES / "fixture_temporal_s42.pcap"
    assert main(["calibrate", "--config", str(cfg), "--pcap", str(cal_pcap)]) == 0
    (cal,) = (tmp_path / "res").glob("*-calib/calibration.json")
    cfg2 = tmp_path / "cfg2.yaml"
    cfg2.write_text(cfg.read_text() + f"entrada:\n  pcap: {teste}\n  rotulos: {FIXTURES / 'fixture_temporal_s42_labels.csv'}\n")
    assert main(["run", "--config", str(cfg2), "--calibracao", str(cal)]) == 0
    (c3,) = [p for p in (tmp_path / "res").iterdir() if not p.name.endswith("-calib")]
    assert main(["analytic", "--calibracao", str(cal.parent), "--teste", str(c3)]) == 0
    res = json.loads((c3 / "analytic.json").read_text())
    assert res["syn_flood"] and res["syn_flood"][0]["lambda_A"] == 5.0
    assert res["syn_flood"][0]["b"] == pytest.approx(5.0 * 63.0)
    srv = res["por_servidor"]["10.77.0.10"]
    assert srv["a"] == pytest.approx(srv["lambda_L"] * srv["E_T"])
    assert res["servidores"] == ["10.77.0.10"] and res["k_empirico"]["10.77.0.10"] == srv["k"]
    assert "10.77.0.10" in res["pfa_por_servidor"]
    assert srv["T_por_motivo_fim_pendente"]  # D35, diagnóstico 1
    # D53: P_D teórica também com a taxa realizada do episódio (b̂ = λ̂_A · τ_hs).
    from tcpmon.analytic.model import p_d

    ep = res["pd_no_k_escolhido"][0]
    lam_hat = res["syn_flood"][0]["lambda_A_estimado"]
    assert ep["lambda_A_estimado"] == pytest.approx(lam_hat)
    assert ep["P_D_teorica_lambda_estimado"] == pytest.approx(p_d(ep["k"], srv["a"], lam_hat * 63.0))
    for fig in ("roc_5.png", "pd_vs_taxa.png", "retratos_benignos.png", "tempo_handshake.png", "tempo_handshake_por_motivo.png"):
        assert (c3 / "figures" / fig).is_file(), fig
    assert (c3 / "curvas_roc.csv").is_file()
