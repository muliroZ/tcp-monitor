"""Recorte de rajada: o trecho de um episódio em que o ataque aparece na captura (D76).

O resultado principal usa sempre o episódio oficial. Este módulo produz, **à parte**, um
segundo conjunto de rótulos para uma análise complementar:

- o episódio (classe escolhida, chave ``servidor``) vai do seu início até o fim da rajada;
- o resto do episódio oficial vira um episódio da classe ``<classe>_apos_rajada``, que a
  avaliação deixa fora da conta (não é positivo nem benigno);
- os demais episódios ficam como estão.

**Fim da rajada:** contam-se, em intervalos de ``bin_s`` segundos a partir do início do
episódio, as instâncias novas (iniciadas por SYN) para o servidor alvo no teste. O limiar é
o maior número de instâncias novas para esse servidor num intervalo de mesmo tamanho na
calibração (só tráfego benigno; nada do teste entra no limiar). A rajada é a sequência de
intervalos acima do limiar que começa no primeiro intervalo do episódio; o fim é o fim do
último intervalo dela (limitado ao fim do episódio).
"""

from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

from tcpmon.flows.key import endpoint_ip
from tcpmon.io.labels import Episodio, read_labels, write_labels

SUFIXO_RESTO = "_apos_rajada"


def _iniciados(pasta: Path, servidor: str) -> np.ndarray:
    df = pd.read_csv(pasta / "flows.csv", usecols=["servidor", "t_primeiro_syn", "midstream"])
    df = df[df["t_primeiro_syn"].notna() & (df["midstream"] == 0)]
    df = df[df["servidor"].map(endpoint_ip) == servidor]
    return np.sort(df["t_primeiro_syn"].to_numpy(dtype=float))


def limiar_da_calibracao(pasta_cal: Path, servidor: str, bin_s: float) -> int:
    """Maior número de instâncias novas para o servidor em ``bin_s`` segundos na calibração."""
    t = _iniciados(pasta_cal, servidor)
    if t.size == 0:
        return 0
    idx = np.floor((t - t[0]) / bin_s).astype(int)
    return int(np.bincount(idx).max())


def fim_da_rajada(pasta_teste: Path, ep: Episodio, limiar: int, bin_s: float) -> float | None:
    """Fim da rajada do episódio, ou None se o primeiro intervalo não passa do limiar."""
    t = _iniciados(pasta_teste, ep.chave_valor)
    t = t[(t >= ep.t_inicio) & (t <= ep.t_fim)]
    n_bins = max(1, math.ceil((ep.t_fim - ep.t_inicio) / bin_s))
    cont = np.bincount(np.floor((t - ep.t_inicio) / bin_s).astype(int), minlength=n_bins)[:n_bins]
    acima = cont > limiar
    if not acima[0]:
        return None
    ultimo = int(np.argmin(acima)) - 1 if not acima.all() else n_bins - 1
    return min(ep.t_fim, ep.t_inicio + (ultimo + 1) * bin_s)


def recortar(
    rotulos: Path, pasta_cal: Path, pasta_teste: Path, classe: str, bin_s: float, saida: Path
) -> list[dict]:
    """Grava os rótulos com o recorte e devolve um resumo por episódio recortado."""
    eps = read_labels(rotulos)
    novos, resumo = [], []
    for e in eps:
        if e.classe != classe or e.chave_tipo != "servidor":
            novos.append(e)
            continue
        limiar = limiar_da_calibracao(pasta_cal, e.chave_valor, bin_s)
        fim = fim_da_rajada(pasta_teste, e, limiar, bin_s)
        resumo.append(
            {"episodio": e.episodio, "servidor": e.chave_valor, "bin_s": bin_s, "limiar_calibracao": limiar,
             "t_inicio": e.t_inicio, "fim_oficial": e.t_fim, "fim_rajada": fim}
        )
        if fim is None or fim >= e.t_fim:
            novos.append(e)
            continue
        params = {**e.parametros, "recorte": "rajada (D76)", "fim_oficial": e.t_fim}
        novos.append(replace(e, t_fim=fim, parametros=params))
        novos.append(
            Episodio(f"{e.episodio}_resto", classe + SUFIXO_RESTO, fim, e.t_fim, e.chave_tipo, e.chave_valor,
                     {"recorte": "resto do episódio oficial depois da rajada (D76)", "episodio_oficial": e.episodio})
        )
    write_labels(saida, novos)
    return resumo
