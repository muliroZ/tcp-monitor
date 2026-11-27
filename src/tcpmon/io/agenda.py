"""Conversão da agenda oficial de ataques em ``labels.csv`` (decisão D38).

A equipe transcreve a agenda publicada pelo dataset numa planilha CSV, uma linha por
episódio, com as colunas:

``episodio, classe, data, inicio, fim, fuso, chave_tipo, chave_valor``

- ``data`` no formato ``AAAA-MM-DD``; ``inicio`` e ``fim`` em ``HH:MM`` ou ``HH:MM:SS``, no
  horário local da agenda;
- ``fuso`` é um nome IANA (``America/Moncton``) ou um deslocamento fixo (``-03:00``,
  ``UTC-03:00``);
- ``classe``, ``chave_tipo`` e ``chave_valor`` seguem as regras do laboratório; o mapeamento
  dos ataques do dataset para as classes do monitor é decisão da equipe e vem pronto na
  planilha.

Colunas extras (por exemplo ``ataque_oficial``, ``fonte``) vão para ``parametros``, junto com
os horários locais e o fuso originais. A conversão é literal: nenhum horário é ajustado ou
arredondado e nenhum episódio é descartado (regra 7). Problemas são reportados por
:func:`tcpmon.io.labels.validar` e por esta conversão, nunca corrigidos.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from tcpmon.io.labels import Episodio, validar, write_labels

COLUNAS_AGENDA = ("episodio", "classe", "data", "inicio", "fim", "fuso", "chave_tipo", "chave_valor")
_DESLOCAMENTO = re.compile(r"^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$", re.IGNORECASE)


class AgendaError(ValueError):
    """Agenda ilegível: coluna ausente ou campo que não pode ser interpretado."""


def fuso(texto: str) -> tzinfo:
    """Fuso a partir de um nome IANA ou de um deslocamento fixo em relação ao UTC."""
    t = texto.strip()
    m = _DESLOCAMENTO.match(t)
    if m:
        sinal, hh, mm = m.group(1), int(m.group(2)), int(m.group(3) or 0)
        if hh > 23 or mm > 59:
            raise AgendaError(f"deslocamento de fuso inválido: {texto!r}")
        delta = timedelta(hours=hh, minutes=mm)
        return timezone(-delta if sinal == "-" else delta)
    if t.upper() in ("UTC", "GMT", "Z"):
        return timezone.utc
    try:
        return ZoneInfo(t)
    except (ZoneInfoNotFoundError, ValueError):
        raise AgendaError(f"fuso desconhecido: {texto!r} (use um nome IANA ou um deslocamento como -03:00)") from None


def _hora(texto: str, campo: str, linha: int) -> time:
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(texto.strip(), fmt).time()
        except ValueError:
            continue
    raise AgendaError(f"linha {linha}: '{campo}' não é HH:MM nem HH:MM:SS: {texto!r}")


def _data(texto: str, linha: int) -> date:
    try:
        return date.fromisoformat(texto.strip())
    except ValueError:
        raise AgendaError(f"linha {linha}: 'data' não é AAAA-MM-DD: {texto!r}") from None


def epoch(dia: date, hora: time, tz: tzinfo) -> float:
    """Instante local (dia, hora, fuso) em segundos desde a época Unix (UTC)."""
    return datetime.combine(dia, hora, tzinfo=tz).timestamp()


def converter(caminho: str | Path) -> tuple[list[Episodio], list[str]]:
    """Lê a agenda e devolve os episódios e os problemas encontrados."""
    caminho = Path(caminho)
    with caminho.open(newline="", encoding="utf-8") as fh:
        r = csv.DictReader(fh)
        faltando = [c for c in COLUNAS_AGENDA if c not in (r.fieldnames or [])]
        if faltando:
            raise AgendaError(f"{caminho}: colunas ausentes na agenda: {', '.join(faltando)}")
        extras = [c for c in r.fieldnames if c not in COLUNAS_AGENDA]
        episodios = []
        for n, linha in enumerate(r, start=2):  # linha 1 é o cabeçalho
            tz = fuso(linha["fuso"])
            dia = _data(linha["data"], n)
            h_ini, h_fim = _hora(linha["inicio"], "inicio", n), _hora(linha["fim"], "fim", n)
            params = {c: linha[c] for c in extras if linha.get(c) not in (None, "")}
            params.update(
                {
                    "data_local": linha["data"].strip(),
                    "inicio_local": linha["inicio"].strip(),
                    "fim_local": linha["fim"].strip(),
                    "fuso": linha["fuso"].strip(),
                    "linha_agenda": n,
                }
            )
            episodios.append(
                Episodio(
                    episodio=linha["episodio"].strip(),
                    classe=linha["classe"].strip(),
                    t_inicio=epoch(dia, h_ini, tz),
                    t_fim=epoch(dia, h_fim, tz),
                    chave_tipo=linha["chave_tipo"].strip(),
                    chave_valor=linha["chave_valor"].strip(),
                    parametros=params,
                )
            )
    problemas = validar(episodios)
    problemas += [f"{e.episodio}: classe vazia" for e in episodios if not e.classe]
    problemas += [f"{e.episodio}: chave_valor vazia" for e in episodios if not e.chave_valor]
    for e in episodios:
        if e.chave_valor:
            try:
                ipaddress.ip_address(e.chave_valor)
            except ValueError:
                problemas.append(f"{e.episodio}: chave_valor não é um endereço IP: {e.chave_valor!r}")
    return episodios, problemas


def agenda_para_rotulos(entrada: str | Path, saida: str | Path) -> list[str]:
    """Converte a agenda em ``labels.csv`` e devolve os problemas encontrados (não corrigidos)."""
    episodios, problemas = converter(entrada)
    write_labels(saida, episodios)
    return problemas
