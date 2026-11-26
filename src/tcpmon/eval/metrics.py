"""Métricas da avaliação e geração das tabelas de resultados (``tcpmon eval``).

Para cada configuração (C1, C2, C3) e classe de anomalia: TP, FN, FP, TN em janelas;
P_D e P_FA com intervalo de Wilson de 95%; precisão; F1; latência (mediana e p95);
desempenho. McNemar entre pares de configurações sobre as janelas positivas pareadas, com
correção de Holm sobre todos os testes e a diferença de P_D com seu intervalo.

Regra 1: nada aqui é ajustado para reproduzir valores esperados; as tabelas reportam o que
as execuções produziram.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from tcpmon.alerts import read_alerts
from tcpmon.eval.inclusao import alertas_ausentes
from tcpmon.eval.stats import diferenca_pareada, holm, mcnemar, wilson
from tcpmon.eval.windows import (
    alertas_por_janela,
    com_alerta,
    detectadas,
    latencia_episodio,
    rotular,
)
from tcpmon.io.labels import read_labels, validar
from tcpmon.io.pcap_reader import sha256_arquivo

PARES = (("C1", "C2"), ("C2", "C3"), ("C1", "C3"))


def _div(a: float, b: float) -> float:
    return a / b if b else math.nan


class Execucao:
    def __init__(self, pasta: Path) -> None:
        self.pasta = Path(pasta)
        self.run = json.loads((self.pasta / "run.json").read_text(encoding="utf-8"))
        self.config = self.run["configuracao"]
        self.alertas = read_alerts(self.pasta / "alerts.csv")
        self.por_janela = alertas_por_janela(self.alertas)


def _metricas_config(ex: Execucao, rot, classes) -> tuple[list[dict], list[dict], dict]:
    alerta_na_janela = com_alerta(rot, ex.por_janela)
    fp = int(np.sum(alerta_na_janela & rot.benigna))
    tn = int(np.sum(~alerta_na_janela & rot.benigna))
    fa_lo, fa_hi = wilson(fp, fp + tn)
    linhas, eps_linhas, det = [], [], {}
    for c in classes:
        d = detectadas(rot, ex.por_janela, c)
        det[c] = d
        pos = rot.positivas[c]
        tp = int(np.sum(d & pos))
        fn = int(np.sum(pos)) - tp
        pd_lo, pd_hi = wilson(tp, tp + fn)
        prec = _div(tp, tp + fp)
        p_d = _div(tp, tp + fn)
        f1 = _div(2 * prec * p_d, prec + p_d) if not (math.isnan(prec) or math.isnan(p_d)) else math.nan
        lats = []
        n_eps = 0
        for e in rot.episodios:
            if e.classe != c:
                continue
            n_eps += 1
            jan = rot.janelas_do_episodio[e.episodio]
            lat = latencia_episodio(rot, e, ex.por_janela)
            if lat is not None:
                lats.append(lat)
            n_pos = len(jan)
            n_det = int(np.sum(d[list(jan)])) if n_pos else 0
            lo, hi = wilson(n_det, n_pos)
            eps_linhas.append(
                {
                    "config": ex.config,
                    "episodio": e.episodio,
                    "classe": c,
                    "chave_tipo": e.chave_tipo,
                    "chave_valor": e.chave_valor,
                    "lambda_A": e.parametros.get("lambda_A"),
                    "t_inicio": e.t_inicio,
                    "t_fim": e.t_fim,
                    "janelas_positivas": n_pos,
                    "janelas_detectadas": n_det,
                    "P_D": _div(n_det, n_pos),
                    "P_D_ic_inf": lo,
                    "P_D_ic_sup": hi,
                    "latencia_s": lat,
                }
            )
        linhas.append(
            {
                "config": ex.config,
                "classe": c,
                "TP": tp,
                "FN": fn,
                "FP": fp,
                "TN": tn,
                "P_D": p_d,
                "P_D_ic_inf": pd_lo,
                "P_D_ic_sup": pd_hi,
                "P_FA": _div(fp, fp + tn),
                "P_FA_ic_inf": fa_lo,
                "P_FA_ic_sup": fa_hi,
                "precisao": prec,
                "F1": f1,
                "n_episodios": n_eps,
                "n_episodios_detectados": len(lats),
                "latencia_mediana_s": float(np.median(lats)) if lats else math.nan,
                "latencia_p95_s": float(np.percentile(lats, 95)) if lats else math.nan,
            }
        )
    return linhas, eps_linhas, det


def _alertas_por_motivo(ex: Execucao, mascara: np.ndarray, rotulo: str) -> list[dict]:
    cont: Counter = Counter()
    janelas: dict[str, set] = {}
    for i, lista in ex.por_janela.items():
        if 0 <= i < len(mascara) and mascara[i]:
            for a in lista:
                cont[a.motivo] += 1
                janelas.setdefault(a.motivo, set()).add(i)
    return [
        {"config": ex.config, "tipo_janela": rotulo, "motivo": m, "n_alertas": n, "n_janelas": len(janelas[m])}
        for m, n in sorted(cont.items())
    ]


def avaliar(runs: list[str | Path], rotulos: str | Path, saida: str | Path | None = None) -> Path:
    execs = [Execucao(Path(p)) for p in runs]
    configs = [e.config for e in execs]
    if len(set(configs)) != len(configs):
        raise ValueError(f"configurações repetidas entre as execuções: {configs}")
    ref = execs[0].run
    for e in execs[1:]:
        for chave in ("janela_s", "t0", "janelas_completas", "tau_hs_s"):
            if e.run[chave] != ref[chave]:
                raise ValueError(f"execuções incompatíveis: '{chave}' difere ({e.run[chave]} vs {ref[chave]})")
        if e.run["pcap"]["sha256"] != ref["pcap"]["sha256"]:
            raise ValueError("execuções sobre pcaps diferentes")
    execs.sort(key=lambda e: e.config)

    episodios = read_labels(rotulos)
    problemas = validar(episodios)
    rot = rotular(episodios, float(ref["t0"]), float(ref["janela_s"]), int(ref["janelas_completas"]), float(ref["tau_hs_s"]))
    classes = rot.classes

    if saida is None:
        saida = Path(execs[0].pasta).parent / f"eval-{datetime.now():%Y%m%d-%H%M%S}"
    saida = Path(saida)
    saida.mkdir(parents=True, exist_ok=True)

    metricas, eps, det, fa, trans, desemp = [], [], {}, [], [], []
    for ex in execs:
        m, e_l, d = _metricas_config(ex, rot, classes)
        metricas += m
        eps += e_l
        det[ex.config] = d
        fa += _alertas_por_motivo(ex, rot.benigna, "benigna")
        trans += _alertas_por_motivo(ex, rot.transicao, "transicao")
        fora = sum(len(v) for i, v in ex.por_janela.items() if not (0 <= i < rot.n))
        dsp = ex.run["desempenho"]
        desemp.append(
            {
                "config": ex.config,
                "run_id": ex.run["run_id"],
                "pacotes_lidos": dsp["pacotes_lidos"],
                "tempo_execucao_s": dsp["tempo_execucao_s"],
                "pacotes_por_segundo": dsp["pacotes_por_segundo"],
                "pico_fluxos_em_memoria": dsp["pico_fluxos_em_memoria"],
                "pico_memoria_processo_mb": dsp["pico_memoria_processo_mb"],
                "alertas_total": len(ex.alertas),
                "alertas_fora_das_janelas_completas": fora,
            }
        )

    # McNemar sobre as janelas positivas pareadas, para cada par de configurações presente.
    testes = []
    for ca, cb in PARES:
        if ca not in det or cb not in det:
            continue
        for c in classes:
            pos = rot.positivas[c]
            da, db = det[ca][c][pos], det[cb][c][pos]
            a = int(np.sum(da & db))
            b = int(np.sum(da & ~db))
            cc = int(np.sum(~da & db))
            d = int(np.sum(~da & ~db))
            r = mcnemar(b, cc)
            dif, lo, hi = diferenca_pareada(a, b, cc, d)
            testes.append(
                {
                    "classe": c,
                    "config_a": ca,
                    "config_b": cb,
                    "n_pares": int(np.sum(pos)),
                    "ambos": a,
                    "so_a": b,
                    "so_b": cc,
                    "nenhum": d,
                    "discordantes": b + cc,
                    "metodo": r.metodo,
                    "estatistica": r.estatistica,
                    "p_valor": r.p_valor,
                    "dif_P_D_b_menos_a": dif,
                    "dif_ic_inf": lo,
                    "dif_ic_sup": hi,
                }
            )
    for t, p in zip(testes, holm([t["p_valor"] for t in testes])):
        t["p_holm"] = p

    inclusao = {}
    por_cfg = {e.config: e for e in execs}
    for menor, maior in (("C1", "C2"), ("C2", "C3")):
        if menor in por_cfg and maior in por_cfg:
            falt = alertas_ausentes(por_cfg[menor].alertas, por_cfg[maior].alertas)
            inclusao[f"{menor}_em_{maior}"] = {
                "alertas_em_" + menor: len(por_cfg[menor].alertas),
                "ausentes_em_" + maior: len(falt),
                "exemplos_ausentes": [a.identidade() for a in falt[:20]],
            }

    pd.DataFrame(metricas).to_csv(saida / "metricas.csv", index=False)
    pd.DataFrame(eps).to_csv(saida / "episodios.csv", index=False)
    pd.DataFrame(testes).to_csv(saida / "mcnemar.csv", index=False)
    pd.DataFrame(fa, columns=["config", "tipo_janela", "motivo", "n_alertas", "n_janelas"]).to_csv(
        saida / "falsos_alarmes.csv", index=False
    )
    pd.DataFrame(trans, columns=["config", "tipo_janela", "motivo", "n_alertas", "n_janelas"]).to_csv(
        saida / "transicao.csv", index=False
    )
    pd.DataFrame(desemp).to_csv(saida / "desempenho.csv", index=False)
    (saida / "inclusao.json").write_text(json.dumps(inclusao, indent=2, ensure_ascii=False, default=str))
    meta = {
        "execucoes": {e.config: str(e.pasta) for e in execs},
        "rotulos": str(rotulos),
        "rotulos_sha256": sha256_arquivo(rotulos),
        "problemas_nos_rotulos": problemas,
        "janela_s": ref["janela_s"],
        "tau_hs_s": ref["tau_hs_s"],
        "t0": ref["t0"],
        "janelas_completas": rot.n,
        "janelas_benignas": int(rot.benigna.sum()),
        "janelas_transicao": int(rot.transicao.sum()),
        "janelas_positivas_por_classe": {c: int(rot.positivas[c].sum()) for c in classes},
    }
    (saida / "avaliacao.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    (saida / "resumo.md").write_text(_resumo(meta, metricas, testes, desemp, inclusao), encoding="utf-8")
    return saida


def _fmt(x, nd=3) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    return f"{x:.{nd}f}"


def _resumo(meta, metricas, testes, desemp, inclusao) -> str:
    linhas = [
        "# Resultados da avaliação",
        "",
        f"- Janela W = {meta['janela_s']} s; τ_hs = {meta['tau_hs_s']} s; {meta['janelas_completas']} janelas completas "
        f"({meta['janelas_benignas']} benignas, {meta['janelas_transicao']} de transição).",
        f"- Rótulos: `{meta['rotulos']}` (problemas encontrados: {len(meta['problemas_nos_rotulos'])}).",
        "",
        "## P_D por classe e configuração (IC de Wilson 95%)",
        "",
    ]
    configs = sorted({m["config"] for m in metricas})
    classes = sorted({m["classe"] for m in metricas})
    idx = {(m["config"], m["classe"]): m for m in metricas}
    linhas.append("| Classe | " + " | ".join(configs) + " |")
    linhas.append("| --- |" + " --- |" * len(configs))
    for c in classes:
        cel = []
        for cfg in configs:
            m = idx[(cfg, c)]
            cel.append(f"{_fmt(m['P_D'])} [{_fmt(m['P_D_ic_inf'])}, {_fmt(m['P_D_ic_sup'])}] ({m['TP']}/{m['TP'] + m['FN']})")
        linhas.append(f"| {c} | " + " | ".join(cel) + " |")
    linhas += ["", "## P_FA por configuração", "", "| Config | P_FA [IC 95%] | FP/(FP+TN) |", "| --- | --- | --- |"]
    for cfg in configs:
        m = idx[(cfg, classes[0])] if classes else None
        if m:
            linhas.append(
                f"| {cfg} | {_fmt(m['P_FA'], 4)} [{_fmt(m['P_FA_ic_inf'], 4)}, {_fmt(m['P_FA_ic_sup'], 4)}] | {m['FP']}/{m['FP'] + m['TN']} |"
            )
    linhas += ["", "## Precisão, F1 e latência", "", "| Config | Classe | Precisão | F1 | Latência mediana (s) | Latência p95 (s) | Episódios detectados |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for m in metricas:
        linhas.append(
            f"| {m['config']} | {m['classe']} | {_fmt(m['precisao'])} | {_fmt(m['F1'])} | {_fmt(m['latencia_mediana_s'], 2)} | "
            f"{_fmt(m['latencia_p95_s'], 2)} | {m['n_episodios_detectados']}/{m['n_episodios']} |"
        )
    if testes:
        linhas += [
            "",
            "## McNemar (janelas positivas pareadas, correção de Holm)",
            "",
            "| Classe | A × B | só A | só B | Método | p | p (Holm) | ΔP_D (B−A) [IC 95%] |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for t in testes:
            linhas.append(
                f"| {t['classe']} | {t['config_a']} × {t['config_b']} | {t['so_a']} | {t['so_b']} | {t['metodo']} | "
                f"{t['p_valor']:.3g} | {t['p_holm']:.3g} | {_fmt(t['dif_P_D_b_menos_a'])} [{_fmt(t['dif_ic_inf'])}, {_fmt(t['dif_ic_sup'])}] |"
            )
    linhas += ["", "## Desempenho", "", "| Config | Pacotes/s | Pico de fluxos | Pico de memória (MB) | Tempo (s) |", "| --- | --- | --- | --- | --- |"]
    for d in desemp:
        linhas.append(
            f"| {d['config']} | {_fmt(d['pacotes_por_segundo'], 0)} | {d['pico_fluxos_em_memoria']} | "
            f"{_fmt(d['pico_memoria_processo_mb'], 1)} | {_fmt(d['tempo_execucao_s'], 1)} |"
        )
    if inclusao:
        linhas += ["", "## Inclusão de alertas entre configurações", ""]
        for k, v in inclusao.items():
            n_aus = [x for c, x in v.items() if c.startswith("ausentes")][0]
            linhas.append(f"- {k.replace('_em_', ' ⊆ ')}: {n_aus} alertas ausentes")
    linhas.append("")
    return "\n".join(linhas)
