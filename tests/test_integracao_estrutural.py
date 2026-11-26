"""Integração: cenários estruturais do laboratório geram os alertas esperados na camada 1.

Só comportamentos determinísticos são verificados (regra 1): cada pacote de ataque é um
fluxo próprio e precisa gerar exatamente um alerta do motivo da sua classe. Nenhum valor de
P_D ou P_FA é fixado aqui.
"""

from collections import Counter

import pytest
from conftest import FIXTURES, REPO

from tcpmon.alerts import read_alerts
from tcpmon.config import load_config
from tcpmon.io.labels import read_labels
from tcpmon.pipeline import executar

PCAP = FIXTURES / "fixture_estrutural_s42.pcap"
ROTULOS = FIXTURES / "fixture_estrutural_s42_labels.csv"
MOTIVO_DA_CLASSE = {"ack_sem_syn": "SEM_HANDSHAKE", "xmas": "FLAGS_INVALIDAS", "null": "FLAGS_INVALIDAS"}


def _cfg(tmp_path):
    base = load_config(REPO / "configs" / "default.yaml")
    return base.com(carencia_s=0.0, saida=str(tmp_path), entrada={"pcap": str(PCAP), "rotulos": str(ROTULOS), "metadado": None})


@pytest.fixture(scope="module")
def execucao_c1(tmp_path_factory):
    pasta = executar(_cfg(tmp_path_factory.mktemp("c1")), camadas=(1,))
    return pasta, read_alerts(pasta / "alerts.csv")


def test_cada_pacote_de_ataque_gera_um_alerta_da_classe(execucao_c1):
    _, alertas = execucao_c1
    for ep in read_labels(ROTULOS):
        n = ep.parametros["n_capturados"]
        assert n > 0
        do_ep = [
            a
            for a in alertas
            if a.cliente.startswith(ep.chave_valor + ":") and ep.t_inicio <= a.t_evidencia <= ep.t_fim
        ]
        assert Counter(a.motivo for a in do_ep) == Counter({MOTIVO_DA_CLASSE[ep.classe]: n}), ep.classe
        assert all(a.camada == 1 for a in do_ep)


def test_tau_vem_do_metadado_do_laboratorio(execucao_c1):
    import json

    pasta, _ = execucao_c1
    run = json.loads((pasta / "run.json").read_text())
    assert run["tau_hs_s"] == 63.0
    assert "tcp_synack_retries=5" in run["tau_hs_origem"]
    assert run["configuracao"] == "C1"
    for arq in ("alerts.csv", "flows.csv", "counters.json", "run.json"):
        assert (pasta / arq).is_file()
