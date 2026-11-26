"""Ciclo de vida dos fluxos no motor (base compartilhada) com a camada 1."""

from engineutil import fluxos_por_id, motivos, rodar
from pcaputil import CLI, FLAGS, SRV, pkt

from tcpmon.monitors.dfa import Estado

SYN, SA, A, F, R = FLAGS["SYN"], FLAGS["SYNACK"], FLAGS["ACK"], FLAGS["FIN"], FLAGS["RST"]


def conexao(t0, cli=CLI, srv=SRV):
    """Handshake, dados e encerramento completo (termina em FIN_AMBOS)."""
    return [
        pkt(t0 + 0.0, cli, srv, SYN),
        pkt(t0 + 0.1, srv, cli, SA),
        pkt(t0 + 0.2, cli, srv, A),
        pkt(t0 + 0.3, cli, srv, FLAGS["PSHACK"]),
        pkt(t0 + 0.4, srv, cli, F),
        pkt(t0 + 0.5, cli, srv, F),
        pkt(t0 + 0.6, srv, cli, A),
    ]


def test_conexao_normal_sem_alerta():
    e = rodar(conexao(0.0))
    assert e.alertas == []
    (f,) = e.saida.fluxos
    assert f.estado is Estado.FIN_AMBOS and f.pacotes == 7 and f.motivo_fim == "fim_da_captura"
    assert f.t_syn == 0.0 and f.t_fim_pendente == 0.2 and f.motivo_fim_pendente == "ESTABELECIDO"


def test_alerta_uma_unica_vez_e_t_evidencia_do_pacote():
    pacotes = [pkt(10.0, CLI, SRV, A), pkt(10.5, CLI, SRV, A), pkt(11.0, SRV, CLI, R)]
    e = rodar(pacotes, t0=0.0)
    assert motivos(e) == ["SEM_HANDSHAKE"]
    a = e.alertas[0]
    assert a.camada == 1 and a.t_evidencia == 10.0 and a.t_alerta == 10.0 and a.janela == 10
    assert a.cliente == "10.0.0.1:40000" and a.servidor == "10.0.0.2:80"
    assert a.detalhe == {"simbolo": "C.ACK", "estado_anterior": "INICIAL"}
    # O fluxo em ⊥ sai logo após o alerta e vira lápide: os pacotes seguintes são ignorados.
    assert e.cont["pacotes_lapide"] == 2
    (f,) = e.saida.fluxos
    assert f.estado is Estado.REJEICAO and f.motivo_fim == "rejeicao" and f.fim == 10.0


def test_carencia_marca_midstream_e_ignora():
    pacotes = [pkt(0.0, ("10.0.0.9", 1), SRV, SYN), pkt(5.0, CLI, SRV, A), pkt(6.0, SRV, CLI, A)]
    e = rodar(pacotes, carencia_s=120.0)
    assert e.alertas == []
    mid = [f for f in e.saida.fluxos if f.midstream]
    assert len(mid) == 1 and mid[0].pacotes == 2 and mid[0].sem_handshake
    assert e.cont["pacotes_midstream"] == 2


def test_apos_carencia_fluxo_sem_syn_entra_nos_monitores():
    pacotes = [pkt(0.0, ("10.0.0.9", 1), SRV, SYN), pkt(130.0, CLI, SRV, A)]
    e = rodar(pacotes, carencia_s=120.0)
    assert motivos(e) == ["SEM_HANDSHAKE"]


def test_syn_em_chave_midstream_abre_nova_instancia():
    pacotes = [pkt(0.0, CLI, SRV, A), pkt(1.0, CLI, SRV, SYN), pkt(1.1, SRV, CLI, SA), pkt(1.2, CLI, SRV, A)]
    e = rodar(pacotes, carencia_s=120.0)
    assert e.alertas == []
    insts = sorted(e.saida.fluxos, key=lambda f: f.instancia)
    assert [f.instancia for f in insts] == [0, 1]
    assert insts[0].midstream and insts[0].motivo_fim == "syn_em_midstream"
    assert insts[1].estado is Estado.ESTABELECIDO


def test_reuso_de_porta_em_fin_ambos_e_fechado():
    pacotes = conexao(0.0) + conexao(10.0)
    pacotes += [pkt(20.0, CLI, SRV, SYN), pkt(20.1, SRV, CLI, R), pkt(21.0, CLI, SRV, SYN)]
    e = rodar(pacotes)
    assert e.alertas == []
    insts = sorted(e.saida.fluxos, key=lambda f: f.instancia)
    assert [f.instancia for f in insts] == [0, 1, 2, 3]
    assert [f.motivo_fim for f in insts] == ["reuso_de_porta"] * 3 + ["fim_da_captura"]
    assert insts[2].estado is Estado.FECHADO
    assert insts[3].estado is Estado.SYN_VISTO
    assert e.cont["instancias_reuso_chave"] == 3


def test_reuso_de_porta_apos_remocao_por_lapide():
    # ⊥ remove o fluxo; um SYN do cliente na mesma chave abre nova instância.
    pacotes = [pkt(1.0, CLI, SRV, A), pkt(2.0, CLI, SRV, SYN), pkt(2.1, SRV, CLI, SA), pkt(2.2, CLI, SRV, A)]
    e = rodar(pacotes)
    assert motivos(e) == ["SEM_HANDSHAKE"]
    insts = sorted(e.saida.fluxos, key=lambda f: f.instancia)
    assert insts[1].instancia == 1 and insts[1].estado is Estado.ESTABELECIDO


def test_remocao_por_inatividade_fin_ambos_2msl():
    pacotes = conexao(0.0) + [pkt(0.6 + 119.0, CLI, SRV, A), pkt(0.6 + 119.0 + 121.0, CLI, SRV, A)]
    e = rodar(pacotes)
    # Ainda vivo aos 119 s de silêncio; removido após 120 s; o pacote seguinte cai na lápide.
    (f,) = e.saida.fluxos
    assert f.motivo_fim == "inatividade"
    assert f.fim == 0.6 + 119.0 + 120.0
    assert e.cont["pacotes_lapide"] == 1 and e.alertas == []


def test_retomada_de_conexao_ociosa_nao_vira_ack_sem_syn():
    """Lápides: ESTABELECIDO ocioso por mais de 3600 s sai da memória; a retomada é ignorada."""
    pacotes = [pkt(0.0, CLI, SRV, SYN), pkt(0.1, SRV, CLI, SA), pkt(0.2, CLI, SRV, A)]
    pacotes += [pkt(3599.0, CLI, SRV, A), pkt(3599.0 + 3601.0, CLI, SRV, A), pkt(7201.0, SRV, CLI, A)]
    e = rodar(pacotes)
    assert e.alertas == []
    (f,) = e.saida.fluxos
    assert f.motivo_fim == "inatividade" and f.fim == 3599.0 + 3600.0
    assert e.cont["pacotes_lapide"] == 2


def test_lapide_nao_bloqueia_syn():
    pacotes = [pkt(1.0, CLI, SRV, FLAGS["XMAS"]), pkt(2.0, CLI, SRV, FLAGS["NULL"]), pkt(3.0, CLI, SRV, SYN)]
    e = rodar(pacotes)
    assert motivos(e) == ["FLAGS_INVALIDAS"]
    assert e.cont["pacotes_lapide"] == 1
    assert any(f.estado is Estado.SYN_VISTO for f in e.saida.fluxos)


def test_synack_sem_syn_e_abertura_simultanea_e_transicao_inesperada():
    outro = ("10.0.0.3", 5555)
    pacotes = [
        pkt(1.0, SRV, CLI, SA),  # SYN-ACK sem SYN: o remetente vira "cliente" e o símbolo é C.SYNACK
        pkt(2.0, outro, SRV, SYN),
        pkt(2.1, SRV, outro, SYN),  # abertura simultânea
        pkt(3.0, ("10.0.0.4", 1), SRV, SYN),
        pkt(3.1, ("10.0.0.4", 1), SRV, F),  # FIN antes do SYN-ACK
    ]
    e = rodar(pacotes)
    assert motivos(e) == ["SYNACK_SEM_SYN", "ABERTURA_SIMULTANEA", "TRANSICAO_INESPERADA"]


def test_camada1_nao_tem_prazo_nem_truncado():
    e = rodar([pkt(0.0, CLI, SRV, SYN), pkt(0.1, SRV, CLI, SA), pkt(500.0, ("10.0.0.5", 1), SRV, SYN)])
    assert e.alertas == []
    assert all(not f.truncado for f in e.saida.fluxos)
    assert e.temporizado is None and e.agregador is None


def test_janelas_completas_e_t0():
    e = rodar([pkt(10.0, CLI, SRV, SYN), pkt(12.5, SRV, CLI, SA)], t0=9.5)
    assert e.t0 == 9.5 and e.janelas_completas == 3  # [9.5,10.5), [10.5,11.5), [11.5,12.5)
