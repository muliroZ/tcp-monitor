"""Integração: cenário temporal do laboratório (handshake incompleto e SYN Flood curto).

Comportamentos determinísticos verificados (regra 1: nada de P_D/P_FA fixado):
- C1 não emite HANDSHAKE_EXPIRADO;
- em C2, cada SYN de ataque cujo prazo cabe na captura gera exatamente um alerta
  HANDSHAKE_EXPIRADO com t_evidencia = timestamp do SYN e t_alerta = t_evidencia + τ_hs;
- todo alerta de C1 aparece igual em C2.
"""

import ipaddress

import pytest
from conftest import FIXTURES

from tcpmon.config import load_config
from tcpmon.engine import Engine, ParametrosEngine, SaidaMemoria
from tcpmon.eval.inclusao import alertas_ausentes
from tcpmon.io.labels import read_labels
from tcpmon.io.pcap_reader import ReadCounters, read_packets
from conftest import REPO

FIXTURES_TODAS = sorted(FIXTURES.glob("fixture_*_s42.pcap"))
TAU = 63.0


def rodar_pcap(pcap, camadas):
    cfg = load_config(REPO / "configs" / "default.yaml").com(carencia_s=0.0)
    e = Engine(ParametrosEngine.de_config(cfg, tau_hs_s=TAU, camadas=camadas), SaidaMemoria())
    cont = ReadCounters()
    for p in read_packets(pcap, cont):
        if e.t0 is None:
            e.iniciar(cont.primeiro_ts)
        e.processar(p)
    e.finalizar(cont.max_ts)
    return e


@pytest.fixture(scope="module")
def temporal():
    pcap = FIXTURES / "fixture_temporal_s42.pcap"
    return rodar_pcap(pcap, (1,)), rodar_pcap(pcap, (1, 2)), read_labels(FIXTURES / "fixture_temporal_s42_labels.csv")


def test_c1_nao_detecta_handshake_pendente(temporal):
    c1, _, _ = temporal
    assert not [a for a in c1.alertas if a.motivo == "HANDSHAKE_EXPIRADO"]


def test_c2_expira_cada_syn_de_ataque(temporal):
    _, c2, rotulos = temporal
    expirados = {a.fluxo: a for a in c2.alertas if a.motivo == "HANDSHAKE_EXPIRADO"}
    syns_ataque = []
    for f in c2.saida.fluxos:
        ip = ipaddress.ip_address(f.cliente[0])
        if f.t_syn is not None and (ip in ipaddress.ip_network("10.99.0.0/16") or f.cliente[0] == "10.77.0.30"):
            syns_ataque.append(f)
    n_esperado = sum(e.parametros["n_capturados"] for e in rotulos)
    assert len(syns_ataque) == n_esperado
    for f in syns_ataque:
        assert f.t_syn + TAU <= c2.t_max  # todos os prazos cabem na captura desta fixture
        a = expirados[f.id]
        assert a.camada == 2 and a.t_evidencia == f.t_syn and a.t_alerta == f.t_syn + TAU
    # O handshake incompleto pontual: t_evidencia é exatamente o t_inicio do episódio.
    for ep in (e for e in rotulos if e.classe == "handshake_incompleto"):
        assert ep.chave_tipo == "origem"  # D34
        assert any(a.t_evidencia == ep.t_inicio and a.cliente.startswith(ep.chave_valor + ":") for a in expirados.values())


@pytest.mark.parametrize("pcap", FIXTURES_TODAS, ids=lambda p: p.stem)
def test_inclusao_c1_em_c2(pcap):
    c1, c2 = rodar_pcap(pcap, (1,)), rodar_pcap(pcap, (1, 2))
    assert alertas_ausentes(c1.alertas, c2.alertas) == []
