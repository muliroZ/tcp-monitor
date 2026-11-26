"""Esquema e gravação de alertas (alerts.csv)."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

COLUNAS = (
    "run_id",
    "camada",
    "motivo",
    "fluxo",
    "cliente",
    "servidor",
    "t_evidencia",
    "t_alerta",
    "janela",
    "detalhe",
)


@dataclass(frozen=True)
class Alerta:
    camada: int
    motivo: str
    fluxo: str  # chave#instância; vazio para alertas do agregador
    cliente: str  # IP:porta do cliente, ou IP de origem na varredura
    servidor: str  # IP:porta do servidor, ou IP no agregador de handshakes
    t_evidencia: float  # define a janela do alerta
    t_alerta: float  # instante em que o alerta foi emitido
    janela: int
    detalhe: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def detalhe_json(self) -> str:
        return json.dumps(self.detalhe, sort_keys=True, ensure_ascii=False)

    def identidade(self) -> tuple:
        """Tudo que identifica o alerta, exceto o run_id (usado no teste de inclusão)."""
        return (
            self.camada,
            self.motivo,
            self.fluxo,
            self.cliente,
            self.servidor,
            self.t_evidencia,
            self.t_alerta,
            self.janela,
            self.detalhe_json(),
        )


def write_alerts(path: str | Path, run_id: str, alertas: list[Alerta]) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLUNAS)
        for a in alertas:
            w.writerow(
                [
                    run_id,
                    a.camada,
                    a.motivo,
                    a.fluxo,
                    a.cliente,
                    a.servidor,
                    repr(float(a.t_evidencia)),
                    repr(float(a.t_alerta)),
                    a.janela,
                    a.detalhe_json(),
                ]
            )


def read_alerts(path: str | Path) -> list[Alerta]:
    with Path(path).open(newline="", encoding="utf-8") as fh:
        out = []
        for r in csv.DictReader(fh):
            out.append(
                Alerta(
                    camada=int(r["camada"]),
                    motivo=r["motivo"],
                    fluxo=r["fluxo"],
                    cliente=r["cliente"],
                    servidor=r["servidor"],
                    t_evidencia=float(r["t_evidencia"]),
                    t_alerta=float(r["t_alerta"]),
                    janela=int(r["janela"]),
                    detalhe=json.loads(r["detalhe"]) if r["detalhe"] else {},
                )
            )
        return out
