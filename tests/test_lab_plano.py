"""Plano do laboratório: determinismo e estrutura (sem Docker)."""

import importlib.util
import ipaddress

import pytest
from conftest import REPO

from tcpmon.io.labels import Episodio, read_labels, validar, write_labels


def _gen():
    spec = importlib.util.spec_from_file_location("lab_generate", REPO / "lab" / "generate.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _gen()
CENARIOS = [
    "benigno",
    "calibracao",
    "ack_sem_syn",
    "xmas",
    "null",
    "handshake_incompleto",
    "synflood_baixa",
    "synflood_alta",
    "varredura_horizontal",
    "teste",
    "fixture_estrutural",
    "fixture_temporal",
    "fixture_varredura",
]


@pytest.mark.parametrize("nome", CENARIOS)
def test_plano_deterministico(nome):
    cen = gen.carregar_cenario(nome)
    a = gen.construir_plano(cen, 42)
    b = gen.construir_plano(gen.carregar_cenario(nome), 42)
    assert gen.hash_plano(a) == gen.hash_plano(b)


def test_sementes_diferentes_planos_diferentes():
    cen = gen.carregar_cenario("synflood_alta")
    assert gen.hash_plano(gen.construir_plano(cen, 42)) != gen.hash_plano(gen.construir_plano(cen, 43))


def test_teste_inclui_todas_as_classes():
    plano = gen.construir_plano(gen.carregar_cenario("teste"), 42)
    classes = {e["classe"] for e in plano["episodios"]}
    assert classes == {
        "ack_sem_syn",
        "xmas",
        "null",
        "handshake_incompleto",
        "synflood_baixa",
        "synflood_alta",
        "varredura_horizontal",
    }
    # Episódios em sequência, sem sobreposição, e dentro da duração da captura.
    eps = plano["episodios"]
    for a, b in zip(eps, eps[1:]):
        assert a["fim_s"] <= b["inicio_s"]
    assert eps[-1]["fim_s"] < plano["duracao_s"]
    # Tráfego benigno durante toda a captura.
    inst = plano["benigno"]["instantes_s"]
    assert inst[0] < eps[0]["inicio_s"] and inst[-1] > eps[-1]["fim_s"]


def test_synflood_origens_forjadas_e_taxas_da_grade():
    cen = gen.carregar_cenario("synflood_baixa")
    plano = gen.construir_plano(cen, 42)
    rede = ipaddress.ip_network(cen["faixa_forjada"])
    assert [e["parametros"]["lambda_A"] for e in plano["episodios"]] == [0.02, 0.05, 0.1, 0.5]
    for e in plano["episodios"]:
        assert e["chave_tipo"] == "servidor" and e["chave_valor"] == cen["servidor"]["ip"]
        for _, src, sport, dst, dport, flags in e["pacotes"]:
            assert ipaddress.ip_address(src) in rede
            assert dst == cen["servidor"]["ip"] and flags == gen.SYN


def test_handshake_incompleto_episodios_pontuais_isolados():
    cen = gen.carregar_cenario("handshake_incompleto")
    plano = gen.construir_plano(cen, 42)
    eps = plano["episodios"]
    assert len(eps) == cen["blocos"][0]["n_syn"] == 60  # D34
    for e in eps:
        assert e["pontual"] and e["inicio_s"] == e["fim_s"] and len(e["pacotes"]) == 1
        assert e["pacotes"][0][1] == cen["atacante"]["ip"]
        assert e["chave_tipo"] == "origem" and e["chave_valor"] == cen["atacante"]["ip"]  # D34
    lo, hi = cen["portas_origem"]["handshake_incompleto"]
    assert all(lo <= e["pacotes"][0][2] <= hi for e in eps)


@pytest.mark.parametrize("nome", ["ack_sem_syn", "xmas", "null", "varredura_horizontal"])
def test_portas_de_origem_distintas(nome):
    plano = gen.construir_plano(gen.carregar_cenario(nome), 42)
    sports = [p[2] for e in plano["episodios"] for p in e["pacotes"]]
    assert len(sports) == len(set(sports))


def test_varredura_percorre_alvos():
    cen = gen.carregar_cenario("varredura_horizontal")
    plano = gen.construir_plano(cen, 42)
    destinos = {p[3] for p in plano["episodios"][0]["pacotes"]}
    assert len(destinos) == cen["alvos"]["n"]


def test_rotulos_ida_e_volta(tmp_path):
    eps = [
        Episodio("e001", "xmas", 10.5, 20.25, "origem", "10.77.0.30", {"taxa_pps": 10.0}),
        Episodio("e002", "synflood_alta", 30.0, 330.0, "servidor", "10.77.0.10", {"lambda_A": 100.0}),
    ]
    arq = tmp_path / "labels.csv"
    write_labels(arq, eps)
    lidos = read_labels(arq)
    assert lidos == eps
    assert lidos[1].parametros == {"lambda_A": 100.0}
    assert validar(lidos) == []
    assert validar([Episodio("x", "c", 2.0, 1.0, "outro", "v")]) != []
