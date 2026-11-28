"""Recorte de rajada: o trecho de um episódio em que o ataque aparece na captura (D76).

O resultado principal usa sempre o episódio oficial. Este módulo produz, **à parte**, um
segundo conjunto de rótulos para uma análise complementar:

- o episódio (classe escolhida, chave ``servidor``) passa a cobrir só a rajada;
- as partes do episódio oficial antes e depois da rajada viram episódios da classe
  ``<classe>_fora_da_rajada``, que a avaliação deixa fora da conta (não são positivos nem
  benignos);
- os demais episódios ficam como estão.

**Rajada:** contam-se, em intervalos de ``bin_s`` segundos a partir do início do
episódio, as instâncias novas (iniciadas por SYN) para o servidor alvo no teste. O limiar é
o maior número de instâncias novas para esse servidor num intervalo de mesmo tamanho na
calibração (só tráfego benigno; nada do teste entra no limiar). A rajada é a primeira
sequência contínua de intervalos acima do limiar dentro do episódio; ela vai do início do
primeiro intervalo ao fim do último (limitado ao fim do episódio).
"""

from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd

from tcpmon.flows.key import endpoint_ip
from tcpmon.io.labels import Episodio, read_labels, write_labels

SUFIXO_RESTO = "_fora_da_rajada"


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


def rajada(pasta_teste: Path, ep: Episodio, limiar: int, bin_s: float) -> tuple[float, float] | None:
    """(início, fim) da rajada do episódio, ou None se nenhum intervalo passa do limiar."""
    t = _iniciados(pasta_teste, ep.chave_valor)
    t = t[(t >= ep.t_inicio) & (t <= ep.t_fim)]
    n_bins = max(1, math.ceil((ep.t_fim - ep.t_inicio) / bin_s))
    cont = np.bincount(np.floor((t - ep.t_inicio) / bin_s).astype(int), minlength=n_bins)[:n_bins]
    acima = cont > limiar
    if not acima.any():
        return None
    primeiro = int(np.argmax(acima))
    resto = acima[primeiro:]
    ultimo = primeiro + (int(np.argmin(resto)) - 1 if not resto.all() else resto.size - 1)
    return ep.t_inicio + primeiro * bin_s, min(ep.t_fim, ep.t_inicio + (ultimo + 1) * bin_s)


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
        r = rajada(pasta_teste, e, limiar, bin_s)
        resumo.append(
            {"episodio": e.episodio, "servidor": e.chave_valor, "bin_s": bin_s, "limiar_calibracao": limiar,
             "inicio_oficial": e.t_inicio, "fim_oficial": e.t_fim,
             "inicio_rajada": r[0] if r else None, "fim_rajada": r[1] if r else None}
        )
        if r is None:
            novos.append(e)
            continue
        ini, fim = r
        params = {**e.parametros, "recorte": "rajada (D76)", "inicio_oficial": e.t_inicio, "fim_oficial": e.t_fim}
        novos.append(replace(e, t_inicio=ini, t_fim=fim, parametros=params))
        for nome, a, b in (("antes", e.t_inicio, ini), ("depois", fim, e.t_fim)):
            if b > a:
                novos.append(
                    Episodio(f"{e.episodio}_{nome}", classe + SUFIXO_RESTO, a, b, e.chave_tipo, e.chave_valor,
                             {"recorte": f"parte do episódio oficial {nome} da rajada (D76)", "episodio_oficial": e.episodio})
                )
    write_labels(saida, novos)
    return resumo
