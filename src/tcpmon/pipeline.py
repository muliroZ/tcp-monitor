"""Execução de uma configuração sobre um pcap e gravação de ``results/<run_id>/``.

Arquivos gravados:

- ``alerts.csv``, ``flows.csv``, ``counters.json``, ``run.json``;
- ``snapshots.csv`` e ``varredura.csv`` quando o agregador (ou a coleta de retratos da
  calibração) está ativo.
"""

from __future__ import annotations

import csv
import json
import logging
import platform
import resource
import subprocess
import time
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

import tcpmon
from tcpmon.alerts import write_alerts
from tcpmon.config import Config, config_hash, tau_hs_de_synack_retries
from tcpmon.engine import Engine, ParametrosEngine
from tcpmon.flows.key import format_endpoint
from tcpmon.flows.table import FlowInstance
from tcpmon.io.pcap_reader import ReadCounters, read_captura, sha256_captura

log = logging.getLogger(__name__)

COLUNAS_FLUXOS = (
    "fluxo",
    "chave",
    "instancia",
    "cliente",
    "servidor",
    "inicio",
    "fim",
    "estado_final",
    "pacotes",
    "midstream",
    "sem_handshake",
    "truncado",
    "t_primeiro_syn",
    "t_fim_pendente",
    "motivo_fim_pendente",
    "removido_em",
    "motivo_fim",
    "motivo_alerta",
)
BIBLIOTECAS = ("dpkt", "numpy", "scipy", "pandas", "statsmodels", "matplotlib", "PyYAML")


def _num(x: float | None) -> str:
    return "" if x is None else repr(float(x))


class SaidaCsv:
    """Grava fluxos, retratos e contagens de varredura à medida que são produzidos."""

    def __init__(self, pasta: Path, retratos: bool) -> None:
        self.pasta = pasta
        self._arqs = []
        self._fluxos = self._abrir("flows.csv", COLUNAS_FLUXOS)
        self._retratos = self._abrir("snapshots.csv", ("janela", "t_fim", "servidor", "N_s")) if retratos else None
        self._varr = (
            self._abrir("varredura.csv", ("janela", "origem", "porta_destino", "destinos_distintos"))
            if retratos
            else None
        )

    def _abrir(self, nome: str, colunas: tuple[str, ...]):
        fh = (self.pasta / nome).open("w", newline="", encoding="utf-8")
        self._arqs.append(fh)
        w = csv.writer(fh)
        w.writerow(colunas)
        return w

    def fluxo(self, f: FlowInstance) -> None:
        self._fluxos.writerow(
            [
                f.id,
                str(f.key),
                f.instancia,
                format_endpoint(f.cliente),
                format_endpoint(f.servidor),
                _num(f.inicio),
                _num(f.ultimo),
                str(f.estado),
                f.pacotes,
                int(f.midstream),
                int(f.sem_handshake),
                int(f.truncado),
                _num(f.t_syn),
                _num(f.t_fim_pendente),
                f.motivo_fim_pendente or "",
                _num(f.fim) if f.motivo_fim != "fim_da_captura" else "",
                f.motivo_fim or "",
                f.motivo_alerta or "",
            ]
        )

    def retrato(self, janela: int, t_fim: float, servidor: str, n: int) -> None:
        self._retratos.writerow([janela, repr(t_fim), servidor, n])

    def varredura(self, janela: int, origem: str, porta: int, destinos: int) -> None:
        self._varr.writerow([janela, origem, porta, destinos])

    def fechar(self) -> None:
        for fh in self._arqs:
            fh.close()


def caminho_metadado(cfg: Config, pcap: Path) -> Path | None:
    if cfg.entrada.metadado:
        p = Path(cfg.entrada.metadado)
        return p if p.is_file() else None
    p = pcap.with_name(pcap.name.removesuffix(".pcapng").removesuffix(".pcap") + ".meta.json")
    return p if p.is_file() else None


def resolver_tau(cfg: Config, pcap: Path) -> tuple[float, str, dict | None]:
    """τ_hs: sysctl do servidor do laboratório (metadado), senão a configuração.

    Sem metadado, a origem gravada é ``tau_hs_origem`` da configuração (D39), se houver.
    """
    meta_path = caminho_metadado(cfg, pcap)
    if meta_path is not None:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        sysctls = meta.get("sysctls_servidor", {})
        if "net.ipv4.tcp_synack_retries" in sysctls:
            r = int(sysctls["net.ipv4.tcp_synack_retries"])
            tau = tau_hs_de_synack_retries(r, cfg.rto_inicial_s)
            origem = (
                f"metadado do laboratório ({meta_path.name}): net.ipv4.tcp_synack_retries={r}, "
                f"rto_inicial_s={cfg.rto_inicial_s} -> {tau:g} s"
            )
            return tau, origem, meta
    if cfg.tau_hs_origem:  # D39
        return cfg.tau_hs_s, cfg.tau_hs_origem, None
    return cfg.tau_hs_s, "configuração (tau_hs_s)", None


def carregar_calibracao(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _git() -> dict[str, Any]:
    raiz = Path(tcpmon.__file__).resolve().parents[2]
    try:
        commit = subprocess.run(
            ["git", "-C", str(raiz), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        sujo = bool(
            subprocess.run(
                ["git", "-C", str(raiz), "status", "--porcelain", "--untracked-files=no"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )
        return {"commit": commit, "alteracoes_nao_commitadas": sujo}
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "alteracoes_nao_commitadas": None}


def _versoes() -> dict[str, str | None]:
    out: dict[str, str | None] = {"python": platform.python_version(), "tcpmon": tcpmon.__version__}
    for lib in BIBLIOTECAS:
        try:
            out[lib] = metadata.version(lib)
        except metadata.PackageNotFoundError:
            out[lib] = None
    return out


def _pasta_run(base: Path, efetiva: dict, sufixo: str = "") -> tuple[str, Path]:
    run_id = f"{datetime.now():%Y%m%d-%H%M%S}-{config_hash(efetiva)}{sufixo}"
    pasta = base / run_id
    n = 1
    while pasta.exists():
        n += 1
        pasta = base / f"{run_id}-{n}"
    pasta.mkdir(parents=True)
    return pasta.name, pasta


def executar(
    cfg: Config,
    *,
    pcap: str | Path | None = None,
    camadas: tuple[int, ...] | None = None,
    calibracao: dict | None = None,
    coletar_retratos: bool = False,
    saida_base: str | Path | None = None,
    sufixo: str = "",
    extra_run: dict | None = None,
) -> Path:
    """Executa as camadas sobre o pcap e grava a pasta da execução. Devolve a pasta."""
    pcap = Path(pcap or cfg.entrada.pcap)
    camadas = tuple(cfg.camadas if camadas is None else camadas)
    tau, tau_origem, meta = resolver_tau(cfg, pcap)

    servidores = cfg.agregador.servidores
    k, k_scan, origem_k = cfg.agregador.k, cfg.agregador.k_scan, "configuração"
    if calibracao is not None:
        k, k_scan, origem_k = calibracao["k"], calibracao["k_scan"], calibracao.get("_caminho", "calibração")
        cal_srv = calibracao.get("servidores")
        if 3 in camadas and cal_srv is not None and servidores and list(cal_srv) != list(servidores):
            raise ValueError(
                f"a calibração foi feita para os servidores {cal_srv}, mas a configuração lista {list(servidores)} (D36)"
            )
    if (3 in camadas or coletar_retratos) and not servidores:
        raise ValueError("a camada 3 e a calibração exigem agregador.servidores (D36)")
    if 3 in camadas and (k is None or k_scan is None):
        raise ValueError(
            "a camada 3 precisa de k e k_scan: rode 'tcpmon calibrate' e passe --calibracao <calibration.json>"
        )

    params = ParametrosEngine.de_config(
        cfg, tau_hs_s=tau, camadas=camadas, k=k, k_scan=k_scan, coletar_retratos=coletar_retratos
    )
    pcap_hash = sha256_captura(pcap)
    pcap_sha = pcap_hash["sha256"]
    efetiva = {
        "config": cfg.raw,
        "camadas": list(camadas),
        "tau_hs_s": tau,
        "k": k,
        "k_scan": k_scan,
        "servidores": list(servidores) if servidores else None,
        "pcap_sha256": pcap_sha,
        "intervalo": [cfg.entrada.inicio, cfg.entrada.fim],
        "coletar_retratos": coletar_retratos,
    }
    run_id, pasta = _pasta_run(Path(saida_base or cfg.saida), efetiva, sufixo)
    log.info("execução %s: camadas=%s tau_hs=%gs k=%s k_scan=%s", run_id, list(camadas), tau, k, k_scan)

    saida = SaidaCsv(pasta, retratos=params.coletar_retratos or 3 in camadas)
    engine = Engine(params, saida)
    cont = ReadCounters()
    inicio = time.perf_counter()
    try:
        for pkt in read_captura(pcap, cont, cfg.entrada.inicio, cfg.entrada.fim):
            if engine.t0 is None:
                engine.iniciar(cont.primeiro_ts)
            engine.processar(pkt)
        if engine.t0 is None and cont.primeiro_ts is not None:
            engine.iniciar(cont.primeiro_ts)
        engine.finalizar(cont.max_ts)
    finally:
        saida.fechar()
    duracao = time.perf_counter() - inicio
    pico_mem_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0

    write_alerts(pasta / "alerts.csv", run_id, engine.alertas)
    contadores = {
        "leitura": cont.as_dict(),
        "motor": dict(sorted(engine.cont.items())),
        "pico_fluxos_em_memoria": engine.tabela.pico_vivos,
        "lapides_ao_final": len(engine.lapides),
        "alertas": len(engine.alertas),
    }
    (pasta / "counters.json").write_text(json.dumps(contadores, indent=2, ensure_ascii=False))

    run = {
        "run_id": run_id,
        "configuracao": "C" + str(max(camadas)),
        "camadas": list(camadas),
        "config_arquivo": cfg.origem,
        "config": cfg.raw,
        "git": _git(),
        "tau_hs_s": tau,
        "tau_hs_origem": tau_origem,
        "k": k,
        "k_scan": k_scan,
        "k_origem": origem_k if 3 in camadas else None,
        "servidores": list(servidores) if servidores else None,
        "pcap": {"caminho": str(pcap), **pcap_hash, "inicio": cfg.entrada.inicio, "fim": cfg.entrada.fim},
        "metadado_laboratorio": {
            "sysctls_servidor": meta.get("sysctls_servidor"),
            "plano_sha256": meta.get("plano_sha256"),
            "cenario": meta.get("cenario"),
            "semente": meta.get("semente"),
        }
        if meta
        else None,
        "rotulos": cfg.entrada.rotulos,
        "semente": cfg.semente,
        "janela_s": cfg.janela_s,
        "t0": engine.t0,
        "t_ultimo": engine.t_max,
        "janelas_completas": engine.janelas_completas,
        "versoes": _versoes(),
        "desempenho": {
            "tempo_execucao_s": duracao,
            "pacotes_lidos": cont.lidos,
            "pacotes_por_segundo": cont.lidos / duracao if duracao > 0 else None,
            "pico_fluxos_em_memoria": engine.tabela.pico_vivos,
            "pico_memoria_processo_mb": pico_mem_mb,
        },
    }
    if extra_run:
        run.update(extra_run)
    (pasta / "run.json").write_text(json.dumps(run, indent=2, ensure_ascii=False, default=str))
    log.info(
        "%s: %d alertas, %d pacotes em %.1fs (%.0f pps), pico de %d fluxos",
        pasta,
        len(engine.alertas),
        cont.lidos,
        duracao,
        run["desempenho"]["pacotes_por_segundo"] or 0,
        engine.tabela.pico_vivos,
    )
    return pasta
