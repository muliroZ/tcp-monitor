import itertools

from pcaputil import CLI, FLAGS, SRV, pkt

from tcpmon.flows.key import FlowKey, direction, endpoint_ip, flow_key, format_endpoint
from tcpmon.flows.table import FlowTable
from tcpmon.symbols import Classe, Direcao

ENDPOINTS = [
    ("10.0.0.1", 40000),
    ("10.0.0.2", 80),
    ("10.0.0.10", 80),
    ("192.168.1.1", 1),
    ("10.0.0.1", 80),
    ("::1", 443),
    ("2001:db8::1", 22),
]


def test_chave_simetrica():
    for a, b in itertools.permutations(ENDPOINTS, 2):
        assert flow_key(a, b) == flow_key(b, a)


def test_chave_ordena_numericamente():
    # "10.0.0.10" < "10.0.0.9" como texto, mas não como endereço.
    k = flow_key(("10.0.0.10", 1), ("10.0.0.9", 1))
    assert k == FlowKey(("10.0.0.9", 1), ("10.0.0.10", 1))
    # Mesmo IP: desempata pela porta.
    k = flow_key(("10.0.0.1", 80), ("10.0.0.1", 40000))
    assert k.menor == ("10.0.0.1", 80)
    # IPv4 antes de IPv6.
    k = flow_key(("::1", 1), ("255.255.255.255", 1))
    assert k.menor[0] == "255.255.255.255"


def test_chaves_distintas_para_portas_distintas():
    assert flow_key(CLI, SRV) != flow_key(("10.0.0.1", 40001), SRV)


def test_direcao():
    assert direction(CLI, CLI) is Direcao.C
    assert direction(CLI, SRV) is Direcao.S


def test_formatacao_endpoint():
    assert format_endpoint(("10.0.0.1", 80)) == "10.0.0.1:80"
    assert format_endpoint(("2001:db8::1", 80)) == "[2001:db8::1]:80"
    assert endpoint_ip("10.0.0.1:80") == "10.0.0.1"
    assert endpoint_ip("[2001:db8::1]:80") == "2001:db8::1"
    assert endpoint_ip("10.0.0.1") == "10.0.0.1"
    assert endpoint_ip("2001:db8::1") == "2001:db8::1"


def test_tabela_cliente_e_quem_envia_o_primeiro_syn():
    t = FlowTable(carencia_s=0.0)
    p1 = pkt(0.0, CLI, SRV, FLAGS["SYN"])
    t.observar_tempo(p1.ts)
    key, f = t.buscar(p1)
    assert f is None
    f = t.criar(key, p1)
    assert f.cliente == CLI and f.servidor == SRV
    assert not f.sem_handshake and not f.midstream
    p2 = pkt(0.01, SRV, CLI, FLAGS["SYNACK"])
    key2, f2 = t.buscar(p2)
    assert key2 == key and f2 is f
    assert str(t.simbolo(f, p1)) == "C.SYN"
    assert str(t.simbolo(f, p2)) == "S.SYNACK"


def test_tabela_primeiro_pacote_nao_syn_marca_sem_handshake():
    t = FlowTable(carencia_s=0.0)
    p = pkt(5.0, SRV, CLI, FLAGS["ACK"])
    t.observar_tempo(p.ts)
    f = t.criar(t.buscar(p)[0], p)
    # O remetente do primeiro pacote é tratado como cliente.
    assert f.cliente == SRV
    assert f.sem_handshake and not f.midstream
    assert t.simbolo(f, p).classe is Classe.ACK


def test_tabela_carencia_marca_midstream():
    t = FlowTable(carencia_s=120.0)
    t.observar_tempo(0.0)
    dentro = pkt(119.9, CLI, SRV, FLAGS["ACK"])
    f = t.criar(t.buscar(dentro)[0], dentro)
    assert f.midstream and f.sem_handshake
    fora = pkt(120.0, ("10.0.0.3", 1), SRV, FLAGS["ACK"])
    g = t.criar(t.buscar(fora)[0], fora)
    assert g.sem_handshake and not g.midstream
    syn = pkt(1.0, ("10.0.0.4", 1), SRV, FLAGS["SYN"])
    h = t.criar(t.buscar(syn)[0], syn)
    assert not h.midstream and not h.sem_handshake
