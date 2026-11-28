"""Camada 2: temporização com timestamps sintéticos."""

from engineutil import motivos, rodar
from pcaputil import CLI, FLAGS, SRV, pkt

from tcpmon.monitors.dfa import C_ACK, C_FIN, Estado

SYN, SA, A, R = FLAGS["SYN"], FLAGS["SYNACK"], FLAGS["ACK"], FLAGS["RST"]
TAU = 63.0
OUTRO = ("10.0.0.9", 999)


def relogio_externo(t):
    """Pacote de outro fluxo, só para o tempo avançar até t."""
    return pkt(t, OUTRO, ("10.0.0.8", 80), A)


def pendente(t0=0.0):
    return [pkt(t0, CLI, SRV, SYN), pkt(t0 + 0.1, SRV, CLI, SA)]


def so_expirados(e):
    return [a for a in e.alertas if a.motivo == "HANDSHAKE_EXPIRADO"]


def test_expira_exatamente_em_tau():
    e = rodar(pendente(10.0) + [relogio_externo(10.0 + TAU)], camadas=(1, 2), t0=0.0)
    (a,) = so_expirados(e)
    assert a.camada == 2
    assert a.t_evidencia == 10.0 and a.t_alerta == 10.0 + TAU and a.janela == 10
    assert a.detalhe == {"estado_anterior": "SYNACK_VISTO", "tau_hs_s": TAU}
    f = next(f for f in e.saida.fluxos if f.cliente == CLI)
    assert f.estado is Estado.REJEICAO and f.fim == 10.0 + TAU
    assert f.t_fim_pendente == 10.0 + TAU and f.motivo_fim_pendente == "HANDSHAKE_EXPIRADO"
    assert not f.truncado


def test_nao_expira_antes_de_tau():
    e = rodar(pendente(0.0) + [relogio_externo(TAU - 1e-6)], camadas=(1, 2))
    assert so_expirados(e) == []
    f = next(f for f in e.saida.fluxos if f.cliente == CLI)
    assert f.truncado and f.estado is Estado.SYNACK_VISTO


def test_ack_no_instante_do_prazo_chega_tarde():
    """Prazos ≤ t disparam antes do pacote t: o ACK em x = τ encontra o fluxo já expirado."""
    e = rodar(pendente(0.0) + [pkt(TAU, CLI, SRV, A)], camadas=(1, 2))
    assert motivos(e) == ["HANDSHAKE_EXPIRADO"]
    assert e.cont["pacotes_lapide"] == 1


def test_ack_antes_do_prazo_completa():
    e = rodar(pendente(0.0) + [pkt(TAU - 0.001, CLI, SRV, A), relogio_externo(200.0)], camadas=(1, 2))
    assert so_expirados(e) == []
    assert e.cont["prazos_descartados"] == 1  # descarte preguiçoso do prazo inválido


def test_retransmissao_do_syn_nao_zera_o_relogio():
    pacotes = [pkt(0.0, CLI, SRV, SYN), pkt(1.0, CLI, SRV, SYN), pkt(3.0, CLI, SRV, SYN), pkt(7.0, CLI, SRV, SYN)]
    e = rodar(pacotes + [relogio_externo(100.0)], camadas=(1, 2))
    (a,) = so_expirados(e)
    assert a.t_evidencia == 0.0 and a.t_alerta == TAU
    assert a.detalhe["estado_anterior"] == "SYN_VISTO"


def test_retransmissoes_do_synack_tambem_nao_zeram():
    pacotes = pendente(0.0) + [pkt(t, SRV, CLI, SA) for t in (1.1, 3.1, 7.1, 15.1, 31.1)]
    e = rodar(pacotes + [relogio_externo(TAU)], camadas=(1, 2))
    (a,) = so_expirados(e)
    assert a.t_alerta == TAU


def test_prazo_depois_do_fim_da_captura_vira_truncado():
    e = rodar(pendente(0.0) + [relogio_externo(50.0)], camadas=(1, 2))
    assert so_expirados(e) == []
    f = next(f for f in e.saida.fluxos if f.cliente == CLI)
    assert f.truncado and f.motivo_fim == "fim_da_captura"
    assert e.cont["fluxos_truncados"] == 1


def test_prazo_igual_ao_ultimo_timestamp_dispara():
    e = rodar(pendente(0.0), camadas=(1, 2), t_ultimo=TAU)
    assert motivos(e) == ["HANDSHAKE_EXPIRADO"]


def test_rst_cancela_o_prazo():
    e = rodar(pendente(0.0) + [pkt(0.2, SRV, CLI, R), relogio_externo(100.0)], camadas=(1, 2))
    assert so_expirados(e) == []
    assert e.cont["prazos_descartados"] == 1


def test_syn_apos_expiracao_abre_nova_instancia():
    pacotes = pendente(0.0) + [pkt(TAU + 1.0, CLI, SRV, SYN), pkt(TAU + 1.1, SRV, CLI, SA), pkt(TAU + 1.2, CLI, SRV, A)]
    e = rodar(pacotes, camadas=(1, 2))
    assert motivos(e) == ["HANDSHAKE_EXPIRADO"]
    insts = sorted((f for f in e.saida.fluxos if f.cliente == CLI), key=lambda f: f.instancia)
    assert [f.instancia for f in insts] == [0, 1] and insts[1].estado is Estado.ESTABELECIDO


def test_guarda_da_conclusao():
    e = rodar(pendente(0.0), camadas=(1, 2))
    mon = e.temporizado
    f = next(f for f in e.saida.fluxos if f.cliente == CLI)
    assert mon.permite(f, C_ACK, TAU) and mon.permite(f, C_FIN, TAU)
    assert not mon.permite(f, C_ACK, TAU + 1e-9) and not mon.permite(f, C_FIN, TAU + 1)


def test_tau_configuravel():
    e = rodar(pendente(0.0) + [relogio_externo(7.0)], camadas=(1, 2), tau_hs_s=7.0)
    (a,) = so_expirados(e)
    assert a.t_alerta == 7.0


def test_c1_nao_expira():
    e = rodar(pendente(0.0) + [relogio_externo(500.0)], camadas=(1,))
    assert so_expirados(e) == []
    f = next(f for f in e.saida.fluxos if f.cliente == CLI)
    assert f.estado is Estado.SYNACK_VISTO and not f.truncado


def test_inclusao_por_traco_no_caso_da_d26():
    """Pacote inválido depois da expiração: o alerta idêntico some na C2, mas o traço continua
    rejeitado (mais cedo). A divergência por janela registra o efeito (D33)."""
    from tcpmon.eval.inclusao import (
        alertas_ausentes,
        divergencia_por_janela,
        inclusao_por_traco,
        rejeitadas_de_fluxos,
    )

    pacotes = pendente(0.0) + [pkt(100.0, CLI, SRV, FLAGS["XMAS"])]
    c1 = rodar(pacotes, camadas=(1,))
    c2 = rodar(pacotes, camadas=(1, 2))
    assert motivos(c1) == ["FLAGS_INVALIDAS"] and motivos(c2) == ["HANDSHAKE_EXPIRADO"]
    assert len(alertas_ausentes(c1.alertas, c2.alertas)) == 1  # inclusão por alerta idêntico falha
    r1, r2 = rejeitadas_de_fluxos(c1.saida.fluxos), rejeitadas_de_fluxos(c2.saida.fluxos)
    assert r1[0].t_alerta == 100.0 and r2[0].t_alerta == TAU
    assert inclusao_por_traco(r1, r2) == []  # a inclusão por traço vale
    assert len(divergencia_por_janela(c1.alertas, c2.alertas)) == 1


def test_inclusao_por_traco_detecta_violacao():
    from tcpmon.eval.inclusao import Rejeitada, inclusao_por_traco

    a = Rejeitada("k", 0.0, 5.0, "X", "k#0")
    assert len(inclusao_por_traco([a], [])) == 1
    assert len(inclusao_por_traco([a], [Rejeitada("k", 0.0, 6.0, "Y", "k#1")])) == 1
    assert inclusao_por_traco([a], [Rejeitada("k", 0.0, 5.0, "Y", "k#1")]) == []


def test_inclusao_por_traco_com_mesmo_inicio():
    """D71: resposta do servidor gravada antes do SYN, com o mesmo timestamp (visto no
    CIC-IDS2017). As duas configurações rejeitam a primeira instância na hora; o SYN abre outra
    no mesmo instante, que só a C2 rejeita (mais tarde). A inclusão por traço vale."""
    from tcpmon.eval.inclusao import inclusao_por_traco, rejeitadas_de_fluxos

    pacotes = [pkt(5.0, SRV, CLI, R), pkt(5.0, CLI, SRV, SYN), relogio_externo(5.0 + TAU)]
    c1 = rodar(pacotes, camadas=(1,))
    c2 = rodar(pacotes, camadas=(1, 2))
    r1, r2 = rejeitadas_de_fluxos(c1.saida.fluxos), rejeitadas_de_fluxos(c2.saida.fluxos)
    chave = [r for r in r2 if r.motivo == "HANDSHAKE_EXPIRADO"]
    assert len(chave) == 1 and chave[0].inicio == 5.0 and chave[0].t_alerta == 5.0 + TAU
    assert {(r.inicio, r.t_alerta) for r in r1 if r.chave == chave[0].chave} == {(5.0, 5.0)}
    assert inclusao_por_traco(r1, r2) == []
    # Com a ordem invertida das instâncias da C2, o resultado não muda.
    assert inclusao_por_traco(r1, list(reversed(r2))) == []
