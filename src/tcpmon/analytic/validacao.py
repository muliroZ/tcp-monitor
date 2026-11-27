"""Validação analítica (fase 8): estima o modelo M/G/∞ nos dados e compara com o medido.

Entradas: a pasta da calibração (``tcpmon calibrate``) e a pasta de uma execução de teste
com o agregador (C3, que grava ``snapshots.csv``). Se o modelo não se ajustar, isso é
reportado como resultado; nenhum dado é descartado para melhorar o ajuste.

Saídas na pasta do teste: ``analytic.json``, ``curvas_roc.csv``, ``pd_vs_taxa.csv`` e
``figures/`` (``roc_<taxa>.png``, ``pd_vs_taxa.png``, ``retratos_benignos.png``,
``tempo_handshake.png``).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from tcpmon.analytic.model import b_ataque, k_analitico, p_d, p_fa
from tcpmon.calibracao import estimar_por_servidor, ler_fluxos
from tcpmon.eval.stats import wilson
from tcpmon.eval.windows import rotular, tolerancia_da_execucao
from tcpmon.io.labels import read_labels

log = logging.getLogger(__name__)


def _limpo(x):
    """Converte para tipos JSON (NaN -> None)."""
    if isinstance(x, dict):
        return {str(k): _limpo(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_limpo(v) for v in x]
    if isinstance(x, (np.integer,)):
        return int(x)
    if isinstance(x, (np.floating, float)):
        return None if math.isnan(float(x)) or math.isinf(float(x)) else float(x)
    return x


# ----------------------------------------------------------------------------- Poisson


def qui_quadrado_poisson(valores: np.ndarray, media: float, min_esperado: float = 5.0) -> dict:
    """Qui-quadrado dos retratos contra Poisson(média), agrupando classes com esperado < 5.

    A última classe é a cauda P(N ≥ K). O parâmetro â é estimado dos mesmos dados de
    calibração, então gl = classes − 2.
    """
    v = np.asarray(valores, dtype=int)
    n = v.size
    if n == 0 or not (media > 0):
        return {"estatistica": None, "gl": None, "p_valor": None, "classes": 0, "nota": "sem dados ou média nula"}
    kmax = int(max(v.max(), stats.poisson.ppf(0.9999, media)))
    obs = np.bincount(v, minlength=kmax + 1)[: kmax + 1].astype(float)
    obs[kmax] += np.sum(v > kmax)
    esp = n * stats.poisson.pmf(np.arange(kmax + 1), media)
    esp[kmax] = n * stats.poisson.sf(kmax - 1, media)
    # Agrupa da cauda para a cabeça e depois da cabeça para a cauda.
    o, e = list(obs), list(esp)

    def juntar(i: int, j: int) -> None:
        """Soma a classe i na classe vizinha j e remove i."""
        e[j] += e[i]
        o[j] += o[i]
        del e[i], o[i]

    while len(e) > 1 and e[-1] < min_esperado:
        juntar(len(e) - 1, len(e) - 2)
    while len(e) > 1 and e[0] < min_esperado:
        juntar(0, 1)
    i = 0
    while i < len(e) - 1:
        if e[i] < min_esperado:
            juntar(i, i + 1)
        else:
            i += 1
    classes = len(e)
    gl = classes - 2
    if gl < 1:
        return {"estatistica": None, "gl": gl, "p_valor": None, "classes": classes, "nota": "classes insuficientes após agrupamento"}
    o_a, e_a = np.array(o), np.array(e)
    est = float(np.sum((o_a - e_a) ** 2 / e_a))
    return {"estatistica": est, "gl": gl, "p_valor": float(stats.chi2.sf(est, gl)), "classes": classes}


def ks_exponencial(intervalos: np.ndarray) -> dict:
    x = np.asarray(intervalos, dtype=float)
    x = x[x >= 0]
    if x.size < 2:
        return {"estatistica": None, "p_valor": None, "n": int(x.size)}
    r = stats.kstest(x, "expon", args=(0.0, float(x.mean())))
    return {
        "estatistica": float(r.statistic),
        "p_valor": float(r.pvalue),
        "n": int(x.size),
        "nota": "parâmetro estimado dos próprios dados: valor-p aproximado (conservador)",
    }


# ----------------------------------------------------------------------------- T


def ajustar_t(t: np.ndarray, censurado: np.ndarray, tau: float) -> dict:
    """Ajusta exponencial, log-normal e Weibull a T com censura à direita (expirados em τ)."""
    t = np.asarray(t, dtype=float)
    cens = np.asarray(censurado, dtype=bool)
    pos = t > 0
    nao_pos = int(np.sum(~pos))
    t, cens = t[pos], cens[pos]
    out = {
        "n": int(t.size),
        "n_censurados": int(cens.sum()),
        "n_T_nao_positivo_excluidos": nao_pos,
        "P_T_maior_tau_empirica": float(cens.mean()) if t.size else None,
        "nota": "fluxos expirados são observações censuradas à direita em τ_hs; ajuste por máxima "
        "verossimilhança com scipy.stats.CensoredData",
        "distribuicoes": {},
    }
    if t.size < 3:
        return out
    dados = stats.CensoredData(uncensored=t[~cens], right=t[cens])
    for nome, dist in (("exponencial", stats.expon), ("lognormal", stats.lognorm), ("weibull", stats.weibull_min)):
        try:
            params = dist.fit(dados, floc=0)
            ll = float(np.sum(dist.logpdf(t[~cens], *params)) + np.sum(dist.logsf(t[cens], *params)))
            k = len(params) - 1
            out["distribuicoes"][nome] = {
                "parametros": [float(p) for p in params],
                "P_T_maior_tau": float(dist.sf(tau, *params)),
                "log_verossimilhanca": ll,
                "AIC": 2 * k - 2 * ll,
            }
        except Exception as exc:  # ajuste numérico pode falhar; registra e segue
            out["distribuicoes"][nome] = {"erro": str(exc)}
    return out


# ----------------------------------------------------------------------------- principal


def _alvo(ep) -> str:
    return ep.chave_valor


def validar_modelo(pasta_cal: Path, pasta_teste: Path, figuras: bool = True) -> Path:
    pasta_cal, pasta_teste = Path(pasta_cal), Path(pasta_teste)
    cal = json.loads((pasta_cal / "calibration.json").read_text(encoding="utf-8"))
    run_cal = json.loads((pasta_cal / "run.json").read_text(encoding="utf-8"))
    run_teste = json.loads((pasta_teste / "run.json").read_text(encoding="utf-8"))
    if not (pasta_teste / "snapshots.csv").is_file():
        raise ValueError("a pasta de teste precisa ter snapshots.csv (execução com a camada 3)")
    tau = float(run_teste["tau_hs_s"])
    if float(run_cal["tau_hs_s"]) != tau:
        log.warning("τ_hs da calibração (%s) difere do teste (%s)", run_cal["tau_hs_s"], tau)
    alfa = float(cal["alfa"])
    servidores = list(cal.get("servidores") or [])
    k_srv = cal["k"] if isinstance(cal["k"], dict) else {s: int(cal["k"]) for s in servidores}  # D36

    # --- Estimativas na calibração --------------------------------------------------------
    fluxos_cal = ler_fluxos(pasta_cal)
    duracao_cal = float(run_cal["t_ultimo"]) - float(run_cal["t0"])
    est = estimar_por_servidor(fluxos_cal, duracao_cal).set_index("servidor")
    retratos_cal = pd.read_csv(pasta_cal / "snapshots.csv")

    por_servidor = {}
    for srv in servidores:
        if srv in est.index:
            linha = est.loc[srv]
        else:  # nenhum SYN para o servidor na calibração
            linha = {"lambda_L": 0.0, "E_T": math.nan, "a": 0.0, "n_fluxos_iniciados": 0}
        r = retratos_cal.loc[retratos_cal["servidor"] == srv, "N_s"].to_numpy()
        media = float(r.mean()) if r.size else math.nan
        var = float(r.var(ddof=1)) if r.size > 1 else math.nan
        syns = np.sort(
            fluxos_cal.loc[
                (fluxos_cal["servidor_ip"] == srv) & fluxos_cal["t_primeiro_syn"].notna() & (fluxos_cal["midstream"] == 0),
                "t_primeiro_syn",
            ].to_numpy(dtype=float)
        )
        sel = (fluxos_cal["servidor_ip"] == srv) & fluxos_cal["T"].notna() & (fluxos_cal["truncado"] == 0)
        t_vals = fluxos_cal.loc[sel, "T"].to_numpy(dtype=float)
        motivos_t = fluxos_cal.loc[sel, "motivo_fim_pendente"].fillna("").to_numpy()
        cens = motivos_t == "HANDSHAKE_EXPIRADO"
        # D35 (diagnóstico 1): T separado pela forma de saída do pendente.
        t_por_motivo = {}
        for mot in sorted(set(motivos_t)):
            v = t_vals[motivos_t == mot]
            t_por_motivo[mot] = {
                "n": int(v.size),
                "media": float(v.mean()),
                "mediana": float(np.median(v)),
                "p5": float(np.percentile(v, 5)),
                "p95": float(np.percentile(v, 95)),
                "min": float(v.min()),
                "max": float(v.max()),
            }
        por_servidor[srv] = {
            "k": k_srv.get(srv),
            "k_analitico": int(k_analitico(alfa, [float(linha["a"])])) if not math.isnan(float(linha["a"])) else None,
            "lambda_L": linha["lambda_L"],
            "E_T": linha["E_T"],
            "a": linha["a"],
            "n_fluxos_iniciados": linha["n_fluxos_iniciados"],
            "lei_de_little": {"media_retratos": media, "a": linha["a"], "n_retratos": int(r.size)},
            "indice_dispersao": var / media if media and media > 0 and not math.isnan(var) else math.nan,
            "variancia_retratos": var,
            "qui_quadrado_poisson": qui_quadrado_poisson(r, float(linha["a"])) if r.size else None,
            "ks_intervalos_exponencial": ks_exponencial(np.diff(syns)),
            "ajuste_T": ajustar_t(t_vals, cens, tau),
            "T_por_motivo_fim_pendente": t_por_motivo,
            "_T": t_vals,
            "_T_motivos": motivos_t,
            "_cens": cens,
            "_retratos": r,
        }

    # --- Teste: episódios de SYN Flood ----------------------------------------------------
    episodios = read_labels(run_teste["rotulos"]) if run_teste.get("rotulos") else []
    tolerancia = tolerancia_da_execucao(run_teste)  # D38: mesmas janelas benignas da avaliação
    rot = rotular(
        episodios,
        float(run_teste["t0"]),
        float(run_teste["janela_s"]),
        int(run_teste["janelas_completas"]),
        tau,
        tolerancia,
    )
    retratos = pd.read_csv(pasta_teste / "snapshots.csv")
    retratos["benigna"] = [bool(rot.benigna[j]) if 0 <= j < rot.n else False for j in retratos["janela"]]
    fluxos_teste = ler_fluxos(pasta_teste)
    syn_floods = [e for e in episodios if "lambda_A" in e.parametros]

    k_max = int(retratos["N_s"].max()) + 1 if not retratos.empty else 1
    ks = np.arange(0, k_max + 1)
    curvas, pd_taxa, por_episodio = [], [], []
    for e in syn_floods:
        srv = _alvo(e)
        a = por_servidor.get(srv, {}).get("a", math.nan)
        lam = float(e.parametros["lambda_A"])
        b = b_ataque(lam, tau)
        faixa = ipaddress.ip_network(e.parametros.get("faixa_forjada", "10.99.0.0/16"))
        ataque = fluxos_teste[
            fluxos_teste["t_primeiro_syn"].between(e.t_inicio, e.t_fim)
            & (fluxos_teste["servidor_ip"] == srv)
            & fluxos_teste["cliente_ip"].map(lambda ip: ipaddress.ip_address(ip) in faixa)
        ]
        dur = e.t_fim - e.t_inicio
        lam_hat = len(ataque) / dur if dur > 0 else math.nan
        est_ret = retratos[
            (retratos["servidor"] == srv) & (retratos["t_fim"] >= e.t_inicio + tau) & (retratos["t_fim"] <= e.t_fim)
        ]["N_s"].to_numpy()
        ben = retratos[(retratos["servidor"] == srv) & retratos["benigna"]]["N_s"].to_numpy()
        por_episodio.append(
            {
                "episodio": e.episodio,
                "classe": e.classe,
                "servidor": srv,
                "lambda_A": lam,
                "lambda_A_estimado": lam_hat,
                "b": b,
                "b_estimado": lam_hat * tau,
                "a": a,
                "n_retratos_estacionarios": int(est_ret.size),
                "media_retratos_estacionarios": float(est_ret.mean()) if est_ret.size else None,
                "a_mais_b": a + b,
                "n_retratos_benignos_teste": int(ben.size),
            }
        )
        k_usado = int(k_srv[srv])
        for k in ks:
            nd, nb = int(np.sum(est_ret > k)), int(np.sum(ben > k))
            dl, dh = wilson(nd, est_ret.size)
            fl, fh = wilson(nb, ben.size)
            curvas.append(
                {
                    "episodio": e.episodio,
                    "servidor": srv,
                    "k_servidor": k_usado,
                    "lambda_A": lam,
                    "k": int(k),
                    "P_FA_teorica": float(p_fa(k, a)) if not math.isnan(a) else None,
                    "P_D_teorica": float(p_d(k, a, b)) if not math.isnan(a) else None,
                    "P_FA_empirica": nb / ben.size if ben.size else None,
                    "P_FA_ic_inf": fl,
                    "P_FA_ic_sup": fh,
                    "P_D_empirica": nd / est_ret.size if est_ret.size else None,
                    "P_D_ic_inf": dl,
                    "P_D_ic_sup": dh,
                    "n_benignos": int(ben.size),
                    "n_estacionarios": int(est_ret.size),
                }
            )
        k_usado = int(k_srv[srv])
        nd = int(np.sum(est_ret > k_usado))
        dl, dh = wilson(nd, est_ret.size)
        pd_taxa.append(
            {
                "episodio": e.episodio,
                "servidor": srv,
                "lambda_A": lam,
                "k": k_usado,
                "P_D_teorica": float(p_d(k_usado, a, b)) if not math.isnan(a) else None,
                # D53: a mesma curva com b̂ = λ̂_A · τ_hs (taxa realizada no episódio).
                "lambda_A_estimado": lam_hat,
                "P_D_teorica_lambda_estimado": (
                    float(p_d(k_usado, a, lam_hat * tau)) if not (math.isnan(a) or math.isnan(lam_hat)) else None
                ),
                "P_D_empirica": nd / est_ret.size if est_ret.size else None,
                "P_D_ic_inf": dl,
                "P_D_ic_sup": dh,
                "n_estacionarios": int(est_ret.size),
            }
        )

    # D36: P_FA por servidor nos retratos das janelas benignas do teste, com k_s e â_s.
    pfa_srv = {}
    for srv in servidores:
        ben = retratos[(retratos["servidor"] == srv) & retratos["benigna"]]["N_s"].to_numpy()
        k_s = int(k_srv[srv])
        a_s = float(por_servidor[srv]["a"])
        nb = int(np.sum(ben > k_s))
        lo, hi = wilson(nb, ben.size)
        pfa_srv[srv] = {
            "k": k_s,
            "n_retratos_benignos": int(ben.size),
            "P_FA_empirica": nb / ben.size if ben.size else None,
            "P_FA_ic_inf": lo,
            "P_FA_ic_sup": hi,
            "P_FA_teorica": float(p_fa(k_s, a_s)) if not math.isnan(a_s) else None,
        }

    figs = pasta_teste / "figures"
    if figuras:
        from tcpmon.analytic.figuras import gerar_figuras

        gerar_figuras(figs, por_servidor, pd.DataFrame(curvas), pd.DataFrame(pd_taxa), tau, k_srv)

    resultado = {
        "calibracao": str(pasta_cal),
        "teste": str(pasta_teste),
        "tau_hs_s": tau,
        "tolerancia_rotulo_s": tolerancia,
        "alfa": alfa,
        "servidores": servidores,
        "k_empirico": k_srv,
        "k_analitico": {s: por_servidor[s]["k_analitico"] for s in servidores},
        "pfa_por_servidor": pfa_srv,
        "por_servidor": {s: {k: v for k, v in d.items() if not k.startswith("_")} for s, d in por_servidor.items()},
        "syn_flood": por_episodio,
        "pd_no_k_escolhido": pd_taxa,
        "figuras": sorted(p.name for p in figs.glob("*.png")) if figuras else [],
    }
    pd.DataFrame(curvas).to_csv(pasta_teste / "curvas_roc.csv", index=False)
    pd.DataFrame(pd_taxa).to_csv(pasta_teste / "pd_vs_taxa.csv", index=False)
    arq = pasta_teste / "analytic.json"
    arq.write_text(json.dumps(_limpo(resultado), indent=2, ensure_ascii=False))
    return arq
