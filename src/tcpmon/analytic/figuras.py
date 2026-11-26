"""Figuras da validação analítica (matplotlib, PNG para o artigo)."""

from __future__ import annotations

import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.ticker  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy import stats  # noqa: E402

# Paleta categórica de referência (ordem fixa): teórico, empírico, ajustes.
AZUL, LARANJA, VERDE_AGUA, AMARELO, MAGENTA = "#257de0", "#f47230", "#00b894", "#f2a600", "#ee7fac"
TEXTO, TEXTO_2, GRADE = "#191919", "#666666", "#e5e5e5"


def _estilo(ax, titulo: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(titulo, color=TEXTO, fontsize=11, loc="left")
    ax.set_xlabel(xlabel, color=TEXTO_2)
    ax.set_ylabel(ylabel, color=TEXTO_2)
    ax.grid(True, color=GRADE, linewidth=0.8)
    ax.set_axisbelow(True)
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    for lado in ("left", "bottom"):
        ax.spines[lado].set_color(TEXTO_2)
    ax.tick_params(colors=TEXTO_2)


def _salvar(fig, caminho: Path) -> None:
    fig.tight_layout()
    fig.savefig(caminho, dpi=150, facecolor="white")
    plt.close(fig)


def _taxa_txt(lam: float) -> str:
    return f"{lam:g}".replace(".", "_")


def roc(pasta: Path, curvas: pd.DataFrame, k_usado: int) -> None:
    for (ep, lam), g in curvas.groupby(["episodio", "lambda_A"], sort=False):
        g = g.sort_values("k")
        fig, ax = plt.subplots(figsize=(5.2, 4.4))
        if g["P_FA_teorica"].notna().any():
            ax.plot(g["P_FA_teorica"], g["P_D_teorica"], color=AZUL, linewidth=2, label="teórica (Poisson)")
        emp = g[g["P_FA_empirica"].notna() & g["P_D_empirica"].notna()]
        if not emp.empty:
            xerr = [emp["P_FA_empirica"] - emp["P_FA_ic_inf"], emp["P_FA_ic_sup"] - emp["P_FA_empirica"]]
            yerr = [emp["P_D_empirica"] - emp["P_D_ic_inf"], emp["P_D_ic_sup"] - emp["P_D_empirica"]]
            ax.errorbar(
                emp["P_FA_empirica"],
                emp["P_D_empirica"],
                xerr=np.clip(np.array(xerr, dtype=float), 0, None),
                yerr=np.clip(np.array(yerr, dtype=float), 0, None),
                fmt="o",
                markersize=5,
                color=LARANJA,
                ecolor=LARANJA,
                elinewidth=1,
                capsize=2,
                markeredgecolor="white",
                label="empírica (IC 95%)",
            )
            sel = emp[emp["k"] == k_usado]
            for _, r in sel.iterrows():
                ax.annotate(f"k = {k_usado}", (r["P_FA_empirica"], r["P_D_empirica"]), textcoords="offset points",
                            xytext=(8, -12), color=TEXTO, fontsize=8)
        ax.set_xlim(-0.02, 1.02)
        ax.set_ylim(-0.02, 1.02)
        n_est = int(g["n_estacionarios"].iloc[0])
        n_ben = int(g["n_benignos"].iloc[0])
        _estilo(ax, f"ROC — SYN Flood λ_A = {lam:g}/s", "P_FA", "P_D")
        ax.text(0.98, 0.30, f"episódio {ep}\n{n_est} retratos estacionários\n{n_ben} retratos benignos",
                transform=ax.transAxes, ha="right", va="bottom", color=TEXTO_2, fontsize=8)
        ax.legend(frameon=False, loc="lower right")
        _salvar(fig, pasta / f"roc_{_taxa_txt(lam)}.png")


def pd_vs_taxa(pasta: Path, pdt: pd.DataFrame, k_usado: int) -> None:
    if pdt.empty:
        return
    pdt = pdt.sort_values("lambda_A")
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    ax.plot(pdt["lambda_A"], pdt["P_D_teorica"], color=AZUL, linewidth=2, marker="o", markersize=4, label="teórica")
    emp = pdt[pdt["P_D_empirica"].notna()]
    yerr = np.clip(np.array([emp["P_D_empirica"] - emp["P_D_ic_inf"], emp["P_D_ic_sup"] - emp["P_D_empirica"]], dtype=float), 0, None)
    ax.errorbar(emp["lambda_A"], emp["P_D_empirica"], yerr=yerr, fmt="o", markersize=6, color=LARANJA,
                markeredgecolor="white", capsize=2, elinewidth=1, label="empírica (IC 95%)")
    ax.set_xscale("log")
    ax.set_ylim(-0.02, 1.02)
    _estilo(ax, f"P_D em função de λ_A (k = {k_usado})", "λ_A (SYN/s, escala log) — retratos estacionários", "P_D")
    ax.legend(frameon=False, loc="lower right")
    _salvar(fig, pasta / "pd_vs_taxa.png")


def retratos_benignos(pasta: Path, por_servidor: dict) -> None:
    alvo = max(por_servidor.items(), key=lambda kv: kv[1]["_retratos"].size, default=None)
    if alvo is None or alvo[1]["_retratos"].size == 0:
        return
    srv, d = alvo
    r = d["_retratos"]
    a = d["a"]
    kmax = int(max(r.max(), stats.poisson.ppf(0.999, a) if a and not math.isnan(a) else 0)) + 1
    x = np.arange(kmax + 1)
    obs = np.bincount(r, minlength=kmax + 1)[: kmax + 1] / r.size
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    ax.bar(x, obs, width=0.7, color=LARANJA, label=f"retratos benignos (n = {r.size})")
    if a and not math.isnan(a):
        ax.plot(x, stats.poisson.pmf(x, a), color=AZUL, linestyle="none", marker="o", markersize=7,
                markeredgecolor="white", label=f"Poisson(â = {a:.3f})")
    ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(integer=True))
    _estilo(ax, "Retratos benignos de N_s (calibração)", f"N_s (handshakes pendentes) — servidor {srv}", "fração dos retratos")
    ax.legend(frameon=False)
    _salvar(fig, pasta / "retratos_benignos.png")


def tempo_handshake(pasta: Path, por_servidor: dict, tau: float) -> None:
    alvo = max(por_servidor.items(), key=lambda kv: kv[1]["_T"].size, default=None)
    if alvo is None or alvo[1]["_T"].size < 3:
        return
    srv, d = alvo
    t = d["_T"][d["_T"] > 0]
    fig, ax = plt.subplots(figsize=(8.0, 4.2))
    bins = int(min(60, max(10, np.sqrt(t.size))))
    ax.hist(t, bins=bins, density=True, color=LARANJA, alpha=0.85, label=f"T observado (n = {t.size})")
    xs = np.linspace(0, float(np.percentile(t, 99.5)) * 1.1, 400)
    cores = {"exponencial": AZUL, "lognormal": VERDE_AGUA, "weibull": MAGENTA}
    dists = {"exponencial": stats.expon, "lognormal": stats.lognorm, "weibull": stats.weibull_min}
    for nome, info in d["ajuste_T"]["distribuicoes"].items():
        if "parametros" in info:
            ax.plot(xs, dists[nome].pdf(xs, *info["parametros"]), color=cores[nome], linewidth=2,
                    label=f"{nome} (P(T>τ) = {info['P_T_maior_tau']:.2g})")
    _estilo(ax, "Tempo de handshake benigno T", f"T (s) — servidor {srv}; P(T > τ) avaliada em τ_hs = {tau:g} s", "densidade")
    ax.legend(frameon=False, fontsize=8, loc="upper left", bbox_to_anchor=(1.01, 1.0))
    _salvar(fig, pasta / "tempo_handshake.png")


def gerar_figuras(pasta: Path, por_servidor: dict, curvas: pd.DataFrame, pdt: pd.DataFrame, tau: float, k_usado: int) -> None:
    pasta.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 9, "axes.titlesize": 10})
    if not curvas.empty:
        roc(pasta, curvas, k_usado)
    pd_vs_taxa(pasta, pdt, k_usado)
    retratos_benignos(pasta, por_servidor)
    tempo_handshake(pasta, por_servidor, tau)
