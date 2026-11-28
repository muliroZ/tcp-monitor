"""D76: recorte de rajada (rótulos à parte; o limiar vem da calibração)."""

import pandas as pd
import pytest

from tcpmon.cli import main
from tcpmon.eval.recorte import limiar_da_calibracao, rajada, recortar
from tcpmon.io.labels import Episodio, read_labels, write_labels

SRV = "192.0.2.10"


def flows(pasta, tempos, srv=SRV):
    pasta.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(
        {"servidor": [f"{srv}:80"] * len(tempos), "t_primeiro_syn": tempos, "midstream": [0] * len(tempos)}
    ).to_csv(pasta / "flows.csv", index=False)
    return pasta


@pytest.fixture
def pastas(tmp_path):
    cal = flows(tmp_path / "cal", [0, 10, 70, 75, 130])  # no máximo 2 por 60 s
    # Episódio de 1000 a 1600: 1 no 1º intervalo, rajada de 3 intervalos (5 por intervalo), depois 1.
    t = [1000.0] + [1060 + 60 * i + j for i in range(3) for j in range(5)] + [1000 + 60 * i for i in range(4, 10)]
    teste = flows(tmp_path / "teste", t + [5000.0])  # fora do episódio: ignorado
    return cal, teste


def test_limiar_e_fim(pastas):
    cal, teste = pastas
    assert limiar_da_calibracao(cal, SRV, 60.0) == 2
    ep = Episodio("e1", "synflood", 1000.0, 1600.0, "servidor", SRV)
    assert rajada(teste, ep, 2, 60.0) == (1060.0, 1240.0)
    assert rajada(teste, ep, 5, 60.0) is None  # nenhum intervalo passa do limiar


def test_recortar_grava_rotulos_a_parte(pastas, tmp_path):
    cal, teste = pastas
    oficial = tmp_path / "labels.csv"
    write_labels(oficial, [
        Episodio("e1", "synflood", 1000.0, 1600.0, "servidor", SRV, {"x": 1}),
        Episodio("e2", "xmas", 2000.0, 2100.0, "origem", "192.0.2.1"),
    ])
    saida = tmp_path / "recorte.csv"
    resumo = recortar(oficial, cal, teste, "synflood", 60.0, saida)
    assert resumo[0]["limiar_calibracao"] == 2 and (resumo[0]["inicio_rajada"], resumo[0]["fim_rajada"]) == (1060.0, 1240.0)
    eps = {e.episodio: e for e in read_labels(saida)}
    assert (eps["e1"].t_inicio, eps["e1"].t_fim) == (1060.0, 1240.0) and eps["e1"].parametros["fim_oficial"] == 1600.0
    antes, depois = eps["e1_antes"], eps["e1_depois"]
    assert (antes.classe, antes.t_inicio, antes.t_fim) == ("synflood_fora_da_rajada", 1000.0, 1060.0)
    assert (depois.classe, depois.t_inicio, depois.t_fim) == ("synflood_fora_da_rajada", 1240.0, 1600.0)
    assert eps["e2"].t_fim == 2100.0
    assert read_labels(oficial)[0].t_fim == 1600.0  # o oficial não muda
    assert main(["recorte", "--rotulos", str(oficial), "--calibracao", str(cal), "--teste", str(teste),
                 "--classe", "synflood", "--bin", "60", "--saida", str(tmp_path / "r2.csv")]) == 0
