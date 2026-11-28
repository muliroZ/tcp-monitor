"""Conversão da agenda de ataques em labels.csv (D38). Dados fictícios (faixa 192.0.2.0/24)."""

from datetime import datetime, timezone

import pytest

from tcpmon.cli import main
from tcpmon.io.agenda import AgendaError, converter, fuso
from tcpmon.io.labels import read_labels

CAB = "episodio,classe,data,inicio,fim,fuso,chave_tipo,chave_valor,ataque_oficial\n"


def utc(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def escrever(tmp_path, linhas: str, cab: str = CAB):
    p = tmp_path / "agenda.csv"
    p.write_text(cab + linhas, encoding="utf-8")
    return p


def test_deslocamento_fixo_e_iana(tmp_path):
    p = escrever(
        tmp_path,
        "a1,xmas,2017-07-05,09:47,10:10,-03:00,origem,192.0.2.1,Ataque A\n"
        "a2,xmas,2017-07-05,09:47:30,10:10:05,America/Moncton,origem,192.0.2.1,Ataque A\n"
        "a3,synflood,2017-01-10,09:00,09:05,America/Moncton,servidor,192.0.2.10,Ataque B\n"
        "a4,synflood,2017-07-05,12:00,12:01,UTC,servidor,192.0.2.10,\n",
    )
    eps, problemas = converter(p)
    assert problemas == []
    a1, a2, a3, a4 = eps
    assert (a1.t_inicio, a1.t_fim) == (utc(2017, 7, 5, 12, 47), utc(2017, 7, 5, 13, 10))
    # Moncton em julho está em ADT (UTC−3); em janeiro, em AST (UTC−4).
    assert (a2.t_inicio, a2.t_fim) == (utc(2017, 7, 5, 12, 47, 30), utc(2017, 7, 5, 13, 10, 5))
    assert a3.t_inicio == utc(2017, 1, 10, 13, 0)
    assert a4.t_inicio == utc(2017, 7, 5, 12, 0)
    assert a1.parametros["ataque_oficial"] == "Ataque A" and a1.parametros["inicio_local"] == "09:47"
    assert a1.parametros["fuso"] == "-03:00" and a1.parametros["linha_agenda"] == 2
    assert "ataque_oficial" not in a4.parametros  # coluna extra vazia não entra


def test_conversao_literal_reporta_sem_corrigir(tmp_path):
    p = escrever(
        tmp_path,
        "b1,xmas,2017-07-05,23:50,00:10,-03:00,origem,192.0.2.1,\n"  # cruza a meia-noite
        "b1,xmas,2017-07-05,10:00,10:05,-03:00,destino,192.0.2.1,\n"
        "b3,,2017-07-05,10:00,10:05,-03:00,origem,nao-e-ip,\n",
    )
    eps, problemas = converter(p)
    assert len(eps) == 3  # nada descartado
    assert eps[0].t_fim < eps[0].t_inicio  # nada ajustado
    texto = "\n".join(problemas)
    assert "b1: t_fim < t_inicio" in texto
    assert "episódio duplicado: b1" in texto
    assert "chave_tipo desconhecido 'destino'" in texto
    assert "b3: classe vazia" in texto and "não é um endereço IP" in texto


def test_erros_de_formato(tmp_path):
    with pytest.raises(AgendaError, match="colunas ausentes"):
        converter(escrever(tmp_path, "", cab="episodio,classe\n"))
    with pytest.raises(AgendaError, match="fuso desconhecido"):
        converter(escrever(tmp_path, "c1,x,2017-07-05,10:00,10:05,Lugar/Nenhum,origem,192.0.2.1,\n"))
    with pytest.raises(AgendaError, match="linha 2: 'inicio'"):
        converter(escrever(tmp_path, "c1,x,2017-07-05,10h00,10:05,-03:00,origem,192.0.2.1,\n"))
    with pytest.raises(AgendaError, match="'data'"):
        converter(escrever(tmp_path, "c1,x,05/07/2017,10:00,10:05,-03:00,origem,192.0.2.1,\n"))


@pytest.mark.parametrize(
    "texto,horas", [("-03:00", -3), ("UTC-03:00", -3), ("-3", -3), ("+05:30", 5.5), ("GMT+1", 1), ("UTC", 0)]
)
def test_fuso_deslocamento(texto, horas):
    assert fuso(texto).utcoffset(None).total_seconds() == horas * 3600


def test_cli_agenda(tmp_path, capsys):
    p = escrever(
        tmp_path,
        "d1,xmas,2017-07-05,09:47,10:10,-03:00,origem,192.0.2.1,Ataque A\n"
        "d2,xmas,2017-07-05,11:00,10:00,-03:00,origem,192.0.2.1,\n",
    )
    saida = tmp_path / "labels.csv"
    assert main(["agenda", "--entrada", str(p), "--saida", str(saida)]) == 0
    err = capsys.readouterr().err
    assert "problema (não corrigido): d2: t_fim < t_inicio" in err
    eps = read_labels(saida)
    assert [e.episodio for e in eps] == ["d1", "d2"]
    assert eps[0].t_inicio == utc(2017, 7, 5, 12, 47) and eps[0].parametros["ataque_oficial"] == "Ataque A"


def test_filtro_por_dia_e_modo_estrito(tmp_path, capsys):
    p = escrever(
        tmp_path,
        "e1,xmas,2017-07-05,09:47,10:10,-03:00,origem,192.0.2.1,\n"
        "e2,xmas,2017-07-07,09:47,10:10,-03:00,origem,192.0.2.1,\n"
        "e3,xmas,2017-07-07,11:00,10:00,-03:00,origem,192.0.2.1,\n",
    )
    eps, _ = converter(p, dias=["2017-07-07"])
    assert [e.episodio for e in eps] == ["e2", "e3"]
    saida = tmp_path / "labels.csv"
    assert main(["agenda", "--entrada", str(p), "--saida", str(saida), "--dias", "2017-07-05"]) == 0
    assert [e.episodio for e in read_labels(saida)] == ["e1"]
    # Com --estrito, problemas (aqui, fim antes do início) encerram com código 2; o arquivo é gravado.
    assert main(["agenda", "--entrada", str(p), "--saida", str(saida), "--dias", "2017-07-07", "--estrito"]) == 2
    assert "e3: t_fim < t_inicio" in capsys.readouterr().err
    assert main(["agenda", "--entrada", str(p), "--saida", str(saida), "--dias", "2017-07-01", "--estrito"]) == 2
