"""Calibração de k e k_scan (fase 6 do guia).

1. Roda as camadas 1 e 2 sobre o pcap de calibração (só tráfego benigno), coletando os
   retratos (servidor, janela) de N_s dos servidores de ``agregador.servidores`` e as
   contagens de varredura.
2. k empírico **por servidor** (D36): menor inteiro tal que a fração de retratos do servidor
   s com N_s > k seja ≤ α.
3. k analítico por servidor: menor inteiro tal que P_FA(k) ≤ α, com â_s = λ̂_L,s · Ê[T]_s
   estimado na mesma calibração.
4. k_scan pelo mesmo procedimento empírico, sobre as contagens de varredura.
5. Grava ``calibration.json``. Os experimentos usam o k empírico; o analítico é reportado.

Regra 3 do guia: nada medido no teste volta para cá.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from tcpmon.analytic.model import k_analitico, k_empirico
from tcpmon.config import Config
from tcpmon.flows.key import endpoint_ip
from tcpmon.pipeline import executar

log = logging.getLogger(__name__)


def ler_fluxos(pasta: Path) -> pd.DataFrame:
    df = pd.read_csv(pasta / "flows.csv", keep_default_na=True)
    df["servidor_ip"] = df["servidor"].map(endpoint_ip)
    df["cliente_ip"] = df["cliente"].map(endpoint_ip)
    df["T"] = df["t_fim_pendente"] - df["t_primeiro_syn"]
    return df


def estimar_por_servidor(fluxos: pd.DataFrame, duracao: float) -> pd.DataFrame:
    """λ̂_L, Ê[T] e â = λ̂_L·Ê[T] por servidor, a partir dos fluxos benignos.

    - λ̂_L: instâncias com handshake iniciado (primeiro C.SYN) para o servidor ÷ duração;
    - T: do primeiro C.SYN até sair do pendente por qualquer motivo (conclusão, RST ou
      expiração); fluxos ``truncado`` ficam de fora.
    """
    if duracao <= 0:
        raise ValueError("duração da captura precisa ser positiva")
    iniciados = fluxos[fluxos["t_primeiro_syn"].notna() & (fluxos["midstream"] == 0)]
    com_t = iniciados[iniciados["T"].notna() & (iniciados["truncado"] == 0)]
    linhas = []
    for servidor, grupo in iniciados.groupby("servidor_ip", sort=True):
        t_s = com_t.loc[com_t["servidor_ip"] == servidor, "T"].to_numpy(dtype=float)
        lam = len(grupo) / duracao
        e_t = float(np.mean(t_s)) if t_s.size else float("nan")
        linhas.append(
            {
                "servidor": servidor,
                "n_fluxos_iniciados": int(len(grupo)),
                "n_T": int(t_s.size),
                "lambda_L": lam,
                "E_T": e_t,
                "a": lam * e_t if t_s.size else float("nan"),
            }
        )
    return pd.DataFrame(linhas, columns=["servidor", "n_fluxos_iniciados", "n_T", "lambda_L", "E_T", "a"])


def calcular(pasta: Path, alfa: float) -> dict:
    """Calcula k_s (por servidor), k_scan e k analítico por servidor de uma calibração."""
    run = json.loads((pasta / "run.json").read_text(encoding="utf-8"))
    servidores = list(run.get("servidores") or [])
    retratos = pd.read_csv(pasta / "snapshots.csv")
    varredura = pd.read_csv(pasta / "varredura.csv")
    if retratos.empty or not servidores:
        raise ValueError("a calibração não produziu retratos (agregador.servidores vazio ou captura sem janelas)")
    if varredura.empty:
        raise ValueError("a calibração não produziu contagens de varredura (nenhum fluxo iniciado?)")

    k_scan = k_empirico(varredura["destinos_distintos"].to_numpy(), alfa)
    duracao = float(run["t_ultimo"]) - float(run["t0"])
    est = estimar_por_servidor(ler_fluxos(pasta), duracao).set_index("servidor")

    k, k_an, por_servidor = {}, {}, {}
    for srv in servidores:
        n_s = retratos.loc[retratos["servidor"] == srv, "N_s"].to_numpy()
        k[srv] = int(k_empirico(n_s, alfa))
        if srv in est.index:
            e = est.loc[srv]
            lam, e_t, a, n_ini, n_t = float(e["lambda_L"]), e["E_T"], e["a"], int(e["n_fluxos_iniciados"]), int(e["n_T"])
        else:  # nenhum SYN para o servidor na calibração: λ̂_L = 0 e â = 0
            lam, e_t, a, n_ini, n_t = 0.0, float("nan"), 0.0, 0, 0
        k_an[srv] = None if pd.isna(a) else int(k_analitico(alfa, [float(a)]))
        por_servidor[srv] = {
            "k": k[srv],
            "k_analitico": k_an[srv],
            "n_fluxos_iniciados": n_ini,
            "n_T": n_t,
            "lambda_L": lam,
            "E_T": None if pd.isna(e_t) else float(e_t),
            "a": None if pd.isna(a) else float(a),
            "n_retratos": int(n_s.size),
            "max_N_s": int(n_s.max()),
            "media_retratos": float(n_s.mean()),
            "var_retratos": float(n_s.var(ddof=1)) if n_s.size > 1 else None,
            "fracao_acima_de_k": float(np.mean(n_s > k[srv])),
        }
    return {
        "servidores": servidores,
        "k": k,
        "k_analitico": k_an,
        "k_scan": int(k_scan),
        "k_usado_nos_experimentos": "k (empírico, por servidor)",
        "alfa": alfa,
        "janela_s": run["janela_s"],
        "tau_hs_s": run["tau_hs_s"],
        "tau_hs_origem": run["tau_hs_origem"],
        "duracao_captura_s": duracao,
        "retratos": {"n": int(len(retratos)), "max_N_s": int(retratos["N_s"].max())},
        "varredura": {
            "n": int(len(varredura)),
            "max_destinos": int(varredura["destinos_distintos"].max()),
            "fracao_acima_de_k_scan": float((varredura["destinos_distintos"] > k_scan).mean()),
        },
        "por_servidor": por_servidor,
        "run_calibracao": run["run_id"],
        "pasta_calibracao": str(pasta),
        "pcap": run["pcap"],
    }


def calibrar(cfg: Config, pcap: str | Path, saida_base: str | Path | None = None) -> Path:
    """Executa a calibração e devolve o caminho do ``calibration.json``."""
    pasta = executar(
        cfg,
        pcap=pcap,
        camadas=(1, 2),
        coletar_retratos=True,
        saida_base=saida_base,
        sufixo="-calib",
        extra_run={"papel": "calibracao"},
    )
    resultado = calcular(pasta, cfg.alfa)
    arq = pasta / "calibration.json"
    arq.write_text(json.dumps(resultado, indent=2, ensure_ascii=False))
    log.info(
        "calibração: k=%s k_scan=%d k_analítico=%s (α=%g, %d retratos)",
        resultado["k"],
        resultado["k_scan"],
        resultado["k_analitico"],
        cfg.alfa,
        resultado["retratos"]["n"],
    )
    return arq
