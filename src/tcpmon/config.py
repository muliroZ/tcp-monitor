"""Carga e validação da configuração YAML.

Regra do guia: todo parâmetro numérico do experimento vem do arquivo YAML; nenhum
valor numérico do experimento fica fixo no código. Por isso este módulo não tem
valores padrão: um arquivo de experimento herda de outro pela chave ``base`` e o
resultado da fusão precisa conter todas as chaves obrigatórias.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    """Configuração ausente, incompleta ou inválida."""


CAMADAS_VALIDAS = ((1,), (1, 2), (1, 2, 3))
GRANULARIDADES = ("servidor_ip",)

_OBRIGATORIAS = (
    "semente",
    "janela_s",
    "tau_hs_s",
    "rto_inicial_s",
    "carencia_s",
    "msl_s",
    "ocioso_estabelecido_s",
    "alfa",
    "camadas",
    "agregador",
    "entrada",
    "saida",
    "avaliacao",
)


@dataclass(frozen=True)
class AgregadorCfg:
    granularidade: str
    servidores: tuple[str, ...] | None  # D36
    k: int | dict[str, int] | None  # um valor para todos ou um k por servidor (D36)
    k_scan: int | None
    calibracao: str | None


@dataclass(frozen=True)
class EntradaCfg:
    pcap: str | None
    rotulos: str | None
    metadado: str | None


@dataclass(frozen=True)
class AvaliacaoCfg:
    # D38: tolerância dos rótulos. Janelas em [t_inicio − tol, t_inicio) e (t_fim, t_fim + tol]
    # não são positivas nem benignas. 0 = rótulos exatos (laboratório).
    tolerancia_rotulo_s: float
    # Valores extras de tolerância avaliados como análise de sensibilidade (experiments/run.py).
    sensibilidade_tolerancia_s: tuple[float, ...]


@dataclass(frozen=True)
class Config:
    semente: int
    janela_s: float
    tau_hs_s: float
    rto_inicial_s: float
    carencia_s: float
    msl_s: float
    ocioso_estabelecido_s: float
    alfa: float
    camadas: tuple[int, ...]
    agregador: AgregadorCfg
    entrada: EntradaCfg
    saida: str
    avaliacao: AvaliacaoCfg
    raw: dict[str, Any]
    origem: str | None = None
    # D39: origem declarada de tau_hs_s quando ele não vem do metadado do laboratório
    # (p. ex. "documentacao_dataset"); gravada em run.json.
    tau_hs_origem: str | None = None

    def hash_curto(self) -> str:
        """Hash curto e estável da configuração (usado no run_id)."""
        return config_hash(self.raw)

    def com(self, **mudancas: Any) -> "Config":
        """Cópia da configuração com chaves de primeiro nível alteradas."""
        raw = copy.deepcopy(self.raw)
        for chave, valor in mudancas.items():
            if isinstance(valor, tuple):
                valor = list(valor)
            raw[chave] = valor
        return from_dict(raw, origem=self.origem)


def config_hash(raw: dict[str, Any]) -> str:
    canon = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:8]


def _merge(base: dict[str, Any], over: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for chave, valor in over.items():
        if isinstance(valor, dict) and isinstance(out.get(chave), dict):
            out[chave] = _merge(out[chave], valor)
        else:
            out[chave] = copy.deepcopy(valor)
    return out


def _load_raw(path: Path, _visitados: tuple[Path, ...] = ()) -> dict[str, Any]:
    path = path.resolve()
    if path in _visitados:
        raise ConfigError(f"herança circular de configuração em {path}")
    if not path.is_file():
        raise ConfigError(f"arquivo de configuração não encontrado: {path}")
    with path.open(encoding="utf-8") as fh:
        dados = yaml.safe_load(fh) or {}
    if not isinstance(dados, dict):
        raise ConfigError(f"{path}: o YAML precisa ser um mapeamento")
    base = dados.pop("base", None)
    if base is None:
        return dados
    base_path = (path.parent / base).resolve()
    return _merge(_load_raw(base_path, _visitados + (path,)), dados)


def carregar_yaml(path: str | Path) -> dict[str, Any]:
    """Carrega um YAML resolvendo a herança pela chave ``base`` (fusão recursiva)."""
    return _load_raw(Path(path))


def _num(
    raw: dict[str, Any], chave: str, minimo: float | None = 0.0, estrito: bool = False, nome: str | None = None
) -> float:
    valor = raw[chave]
    nome = nome or chave
    if isinstance(valor, bool) or not isinstance(valor, (int, float)):
        raise ConfigError(f"'{nome}' precisa ser numérico, recebido {valor!r}")
    valor = float(valor)
    if minimo is not None:
        if estrito and valor <= minimo:
            raise ConfigError(f"'{nome}' precisa ser > {minimo}, recebido {valor}")
        if not estrito and valor < minimo:
            raise ConfigError(f"'{nome}' precisa ser >= {minimo}, recebido {valor}")
    return valor


def _servidores(valor: Any) -> tuple[str, ...] | None:
    if valor is None:
        return None
    if not isinstance(valor, (list, tuple)) or not valor:
        raise ConfigError("'agregador.servidores' precisa ser uma lista não vazia de IPs ou null")
    out = []
    for ip in valor:
        try:
            out.append(str(ipaddress.ip_address(str(ip))))
        except ValueError as exc:
            raise ConfigError(f"'agregador.servidores': IP inválido {ip!r}") from exc
    if len(set(out)) != len(out):
        raise ConfigError("'agregador.servidores' tem IPs repetidos")
    return tuple(out)


def _k(valor: Any, chave: str) -> int | dict[str, int] | None:
    if isinstance(valor, dict):
        return {str(ipaddress.ip_address(str(ip))): _int_ou_none(v, f"{chave}[{ip}]") for ip, v in valor.items()}
    return _int_ou_none(valor, chave)


def _int_ou_none(valor: Any, chave: str) -> int | None:
    if valor is None:
        return None
    if isinstance(valor, bool) or not isinstance(valor, int) or valor < 0:
        raise ConfigError(f"'{chave}' precisa ser inteiro >= 0 ou null, recebido {valor!r}")
    return int(valor)


def from_dict(raw: dict[str, Any], origem: str | None = None) -> Config:
    faltando = [c for c in _OBRIGATORIAS if c not in raw]
    if faltando:
        raise ConfigError(f"chaves obrigatórias ausentes na configuração: {', '.join(faltando)}")

    semente = raw["semente"]
    if isinstance(semente, bool) or not isinstance(semente, int):
        raise ConfigError(f"'semente' precisa ser inteiro, recebido {semente!r}")

    alfa = _num(raw, "alfa", 0.0, estrito=True)
    if alfa >= 1.0:
        raise ConfigError(f"'alfa' precisa estar em (0, 1), recebido {alfa}")

    camadas = tuple(sorted(int(c) for c in raw["camadas"]))
    if camadas not in CAMADAS_VALIDAS:
        raise ConfigError(
            f"'camadas' precisa ser cumulativa ([1], [1, 2] ou [1, 2, 3]), recebido {list(raw['camadas'])}"
        )

    agg = raw["agregador"] or {}
    for chave in ("granularidade", "k", "k_scan"):
        if chave not in agg:
            raise ConfigError(f"chave obrigatória ausente: agregador.{chave}")
    if agg["granularidade"] not in GRANULARIDADES:
        raise ConfigError(
            f"agregador.granularidade não suportada: {agg['granularidade']!r} (suportadas: {GRANULARIDADES})"
        )
    agregador = AgregadorCfg(
        granularidade=str(agg["granularidade"]),
        servidores=_servidores(agg.get("servidores")),
        k=_k(agg["k"], "agregador.k"),
        k_scan=_int_ou_none(agg["k_scan"], "agregador.k_scan"),
        calibracao=agg.get("calibracao"),
    )

    ent = raw["entrada"] or {}
    entrada = EntradaCfg(
        pcap=ent.get("pcap"),
        rotulos=ent.get("rotulos"),
        metadado=ent.get("metadado"),
    )

    av = raw["avaliacao"] or {}
    if "tolerancia_rotulo_s" not in av:
        raise ConfigError("chave obrigatória ausente: avaliacao.tolerancia_rotulo_s")
    sens = av.get("sensibilidade_tolerancia_s") or []
    if not isinstance(sens, list):
        raise ConfigError(f"'avaliacao.sensibilidade_tolerancia_s' precisa ser lista, recebido {sens!r}")
    avaliacao = AvaliacaoCfg(
        tolerancia_rotulo_s=_num(av, "tolerancia_rotulo_s", 0.0, nome="avaliacao.tolerancia_rotulo_s"),
        sensibilidade_tolerancia_s=tuple(
            _num({"v": v}, "v", 0.0, nome="avaliacao.sensibilidade_tolerancia_s") for v in sens
        ),
    )
    tau_origem = raw.get("tau_hs_origem")
    if tau_origem is not None and not isinstance(tau_origem, str):
        raise ConfigError(f"'tau_hs_origem' precisa ser texto, recebido {tau_origem!r}")

    raw_norm = copy.deepcopy(raw)
    raw_norm["camadas"] = list(camadas)

    return Config(
        semente=int(semente),
        janela_s=_num(raw, "janela_s", 0.0, estrito=True),
        tau_hs_s=_num(raw, "tau_hs_s", 0.0, estrito=True),
        rto_inicial_s=_num(raw, "rto_inicial_s", 0.0, estrito=True),
        carencia_s=_num(raw, "carencia_s", 0.0),
        msl_s=_num(raw, "msl_s", 0.0, estrito=True),
        ocioso_estabelecido_s=_num(raw, "ocioso_estabelecido_s", 0.0, estrito=True),
        alfa=alfa,
        camadas=camadas,
        agregador=agregador,
        entrada=entrada,
        saida=str(raw["saida"]),
        avaliacao=avaliacao,
        raw=raw_norm,
        origem=origem,
        tau_hs_origem=tau_origem,
    )


def load_config(path: str | Path) -> Config:
    path = Path(path)
    return from_dict(_load_raw(path), origem=str(path))


def tau_hs_de_synack_retries(synack_retries: int, rto_inicial_s: float) -> float:
    """Tempo que o Linux mantém um handshake pendente.

    O servidor retransmite o SYN-ACK ``synack_retries`` vezes com backoff exponencial
    a partir do RTO inicial e desiste após o último intervalo:
    rto * (1 + 2 + ... + 2**synack_retries) = rto * (2**(synack_retries + 1) - 1).
    Com os padrões (5 retransmissões, RTO de 1 s) o resultado é 63 s.
    """
    if synack_retries < 0:
        raise ValueError("synack_retries precisa ser >= 0")
    return rto_inicial_s * (2 ** (synack_retries + 1) - 1)
