"""Rótulos de episódios (laboratório e, futuramente, CIC-IDS2017).

Formato de ``labels.csv`` (um episódio por linha):
``episodio, classe, t_inicio, t_fim, chave_tipo, chave_valor, parametros``

- ``chave_tipo`` é ``origem`` (IP de origem do ataque) ou ``servidor`` (servidor alvo);
- ``parametros`` é um JSON com taxas, sementes e contagens do gerador.

Regra 7 do guia: rótulos não são alterados. Este módulo só lê e grava; problemas
encontrados são reportados por ``validar``, nunca corrigidos no dado.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

COLUNAS = ("episodio", "classe", "t_inicio", "t_fim", "chave_tipo", "chave_valor", "parametros")
CHAVES = ("origem", "servidor")


@dataclass(frozen=True)
class Episodio:
    episodio: str
    classe: str
    t_inicio: float
    t_fim: float
    chave_tipo: str
    chave_valor: str
    parametros: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


def write_labels(path: str | Path, episodios: list[Episodio]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUNAS)
        for e in episodios:
            w.writerow(
                [
                    e.episodio,
                    e.classe,
                    repr(float(e.t_inicio)),
                    repr(float(e.t_fim)),
                    e.chave_tipo,
                    e.chave_valor,
                    json.dumps(e.parametros, sort_keys=True, ensure_ascii=False),
                ]
            )


def read_labels(path: str | Path) -> list[Episodio]:
    path = Path(path)
    with path.open(newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        faltando = [c for c in COLUNAS if c not in (r.fieldnames or [])]
        if faltando:
            raise ValueError(f"{path}: colunas ausentes em labels.csv: {', '.join(faltando)}")
        out = []
        for linha in r:
            params = linha["parametros"].strip()
            out.append(
                Episodio(
                    episodio=linha["episodio"],
                    classe=linha["classe"],
                    t_inicio=float(linha["t_inicio"]),
                    t_fim=float(linha["t_fim"]),
                    chave_tipo=linha["chave_tipo"],
                    chave_valor=linha["chave_valor"],
                    parametros=json.loads(params) if params else {},
                )
            )
    return out


def validar(episodios: list[Episodio]) -> list[str]:
    """Problemas encontrados nos rótulos (para registro; nada é corrigido)."""
    problemas = []
    vistos = set()
    for e in episodios:
        if e.episodio in vistos:
            problemas.append(f"episódio duplicado: {e.episodio}")
        vistos.add(e.episodio)
        if e.t_fim < e.t_inicio:
            problemas.append(f"{e.episodio}: t_fim < t_inicio")
        if e.chave_tipo not in CHAVES:
            problemas.append(f"{e.episodio}: chave_tipo desconhecido {e.chave_tipo!r}")
    return problemas
