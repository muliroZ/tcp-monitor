#!/usr/bin/env python3
"""Diagnóstico do atraso efetivo do netem (decisão D35, passos 2 e 3).

    python lab/diagnostico_netem.py --semente 44
    python lab/diagnostico_netem.py --reanalisar results/diagnostico_netem/<pasta>

Para cada variante de ``lab/scenarios/diagnostico_netem.yaml``:

- sobe a topologia do laboratório só com tráfego benigno;
- captura **na ponte** (como no experimento) e **dentro do container cliente** ao mesmo tempo;
- o cliente registra o instante em que abre cada conexão e a porta local.

Medidas por conexão:

- ``T`` = primeiro pacote do cliente com ACK após o SYN-ACK − primeiro SYN, na ponte (o que o
  monitor mede: a saída do pendente é o primeiro ``C.ACK``, com ou sem dados);
- ``d_ack`` = esse mesmo pacote − SYN-ACK, na ponte;
- ``T_ack_puro`` / ``d_ack_puro``: idem, mas só com o ACK puro (sem carga) do handshake;
- ``primeiro_ack_com_dados``: conexões em que o primeiro pacote do cliente com ACK na ponte
  carrega dados, isto é, o segmento da requisição ultrapassou o ACK puro no netem;
- ``d_syn`` = SYN na ponte − instante registrado pela aplicação antes do ``connect`` (atraso do
  SYN, incluindo o tempo do ``connect`` até a fila de saída);
- diferenças entre os instantes do mesmo pacote nas duas capturas. A captura dentro do container
  vê o egresso **depois** do qdisc (o tap do AF_PACKET fica na transmissão do driver), então ela
  não mede o atraso do netem; serve só de controle.

Portas locais reutilizadas (mais de um SYN com números de sequência distintos na mesma porta,
ou porta repetida no log do cliente) são excluídas das medidas por conexão e contadas à parte.

Compara com a média teórica da normal truncada em 0 (o netem não aplica atraso negativo).
Nenhum parâmetro do experimento é alterado (D35). Saída em ``results/diagnostico_netem/``.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

import dpkt
import numpy as np
from scipy import integrate, optimize, stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate as gen  # noqa: E402

from tcpmon.config import carregar_yaml  # noqa: E402

SYN, ACK, RST, FIN = 0x02, 0x10, 0x04, 0x01


def _merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def ler(pcap: Path, ip_cliente: str, ip_servidor: str) -> list[tuple]:
    """(ts, sentido, porta_cliente, flags, seq, ack, carga) dos pacotes TCP cliente↔servidor.

    ``carga`` vem dos cabeçalhos IP/TCP, não do buffer capturado (snaplen curto).
    """
    out = []
    with pcap.open("rb") as fh:
        for ts, buf in dpkt.pcap.Reader(fh):
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
            except (dpkt.UnpackError, dpkt.NeedData):
                continue
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            src, dst, tcp = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.data
            carga = ip.len - ip.hl * 4 - tcp.off * 4
            if src == ip_cliente and dst == ip_servidor:
                out.append((float(ts), "C", tcp.sport, tcp.flags, tcp.seq, tcp.ack, carga))
            elif src == ip_servidor and dst == ip_cliente:
                out.append((float(ts), "S", tcp.dport, tcp.flags, tcp.seq, tcp.ack, carga))
    return out


def conexoes(pacotes: list[tuple]) -> tuple[dict[int, dict], set[int]]:
    """Por porta do cliente: instantes do primeiro SYN, do primeiro SYN-ACK, do primeiro pacote do
    cliente com ACK após ele (``ack``, com a indicação de carga) e do primeiro ACK puro.

    Devolve também as portas reutilizadas (SYNs com números de sequência distintos).
    """
    c: dict[int, dict] = {}
    isn: dict[int, set] = {}
    for ts, sentido, porta, flags, seq, _ack, carga in pacotes:
        d = c.setdefault(porta, {})
        f = flags & 0x3F
        if sentido == "C" and f == SYN:
            isn.setdefault(porta, set()).add(seq)
            d.setdefault("syn", ts)
        elif sentido == "S" and f == SYN | ACK and "synack" not in d and "syn" in d:
            d["synack"] = ts
        elif sentido == "C" and f & ACK and not f & (SYN | RST) and "synack" in d:
            if "ack" not in d:
                d["ack"], d["ack_com_dados"] = ts, carga > 0
            if carga == 0 and not f & FIN and "ack_puro" not in d:
                d["ack_puro"] = ts
    return c, {p for p, s in isn.items() if len(s) > 1}


def diferencas(primeira: list[tuple], segunda: list[tuple], sentido: str) -> list[float]:
    """Instante na ``segunda`` − instante na ``primeira`` para o mesmo pacote.

    Pacotes idênticos (mesmo sentido, porta, flags, seq, ack e carga; p. ex. ACKs duplicados)
    são pareados pela ordem de ocorrência: a n-ésima cópia com a n-ésima cópia.
    """
    ocorr: dict[tuple, list[float]] = {}
    for ts, *ch in segunda:
        if ch[0] == sentido:
            ocorr.setdefault(tuple(ch), []).append(ts)
    vistos: dict[tuple, int] = {}
    out = []
    for ts, *ch in primeira:
        if ch[0] != sentido:
            continue
        k = tuple(ch)
        i = vistos.get(k, 0)
        lista = ocorr.get(k, [])
        if i < len(lista):
            out.append(lista[i] - ts)
        vistos[k] = i + 1
    return out


def resumo(v) -> dict:
    v = np.asarray([x for x in v if x is not None and np.isfinite(x)], dtype=float) * 1000.0
    if v.size == 0:
        return {"n": 0}
    return {
        "n": int(v.size),
        "media_ms": float(v.mean()),
        "dp_ms": float(v.std(ddof=1)) if v.size > 1 else None,
        "mediana_ms": float(np.median(v)),
        "p5_ms": float(np.percentile(v, 5)),
        "p95_ms": float(np.percentile(v, 95)),
        "min_ms": float(v.min()),
        "max_ms": float(v.max()),
    }


def _atraso_netem(mu: float, sigma: float):
    """Atraso de um pacote no netem: normal(mu, sigma) com valores negativos tratados como 0.

    Para o diagnóstico só importam média e cauda; com mu = 50 e sigma = 20 a massa abaixo de 0
    é 0,6%. Usa-se a normal truncada em 0 como referência.
    """
    return stats.truncnorm((0 - mu) / sigma, np.inf, loc=mu, scale=sigma)


def media_normal_truncada(mu: float, sigma: float) -> float:
    if sigma <= 0:
        return mu
    return float(_atraso_netem(mu, sigma).mean())


def referencia_minimo_dois(mu: float, sigma: float) -> dict:
    """Média, dp e quantis do mínimo de dois atrasos independentes do netem (em ms).

    É o T esperado quando o ACK puro e o segmento de dados que o segue recebem atrasos
    independentes e o primeiro a chegar à ponte encerra o handshake.
    """
    if sigma <= 0:
        return {"media_ms": mu, "dp_ms": 0.0, "p5_ms": mu, "mediana_ms": mu, "p95_ms": mu}
    d = _atraso_netem(mu, sigma)
    sf2 = lambda x: d.sf(x) ** 2  # noqa: E731
    sup = mu + 12 * sigma
    m = integrate.quad(sf2, 0, sup)[0]
    m2 = integrate.quad(lambda x: 2 * x * sf2(x), 0, sup)[0]
    q = {f"{n}_ms": float(optimize.brentq(lambda x: 1 - sf2(x) - p, 0, sup)) for n, p in (("p5", 0.05), ("mediana", 0.5), ("p95", 0.95))}
    return {"media_ms": float(m), "dp_ms": float(np.sqrt(m2 - m * m)), **q}


def rodar_variante(nome: str, cen: dict, semente: int, base: Path, imagem: str) -> dict:
    plano = gen.construir_plano(cen, semente)
    tag = f"diag{re.sub(r'[^a-z0-9]', '', nome)[:12]}-{os.getpid()}"
    work = base / f".tmp-{tag}"
    work.mkdir(parents=True)
    (work / "plano.json").write_text(json.dumps(plano))
    lab = gen.Laboratorio(cen, tag, work, imagem)
    try:
        lab.subir(False)
        lab._run(
            "capcliente",
            ["--network", f"container:{lab.nome('cliente')}", "--cap-add", "NET_RAW", imagem,
             "tcpdump", "-i", "eth0", "-s", str(cen["captura"]["snaplen"]), "-U", "-n", "-w", "/data/cliente.pcap"],
            rede=False,
        )
        lab.iniciar_captura()
        inicio = time.time() + float(cen["espera_inicio_s"])
        lab.exec("cliente", ["python", "/lab/client.py", "--plano", "/data/plano.json", "--inicio", repr(inicio),
                             "--log", "/data/cliente_log.json"], detach=True)
        fim = inicio + plano["duracao_s"]
        while time.time() < fim:
            time.sleep(min(10.0, max(0.5, fim - time.time())))
        limite = time.time() + float(cen["espera_logs_s"])
        while time.time() < limite and not (work / "cliente_log.json").exists():
            time.sleep(0.5)
        time.sleep(1.0)
        gen.sh(["docker", "stop", "-t", "15", lab.nome("capcliente")], check=False)
        stats_ponte = lab.parar_captura()
        tc = gen.sh(["docker", "exec", lab.nome("cliente"), "tc", "-s", "qdisc", "show", "dev", "eth0"], check=False)
    finally:
        lab.corrigir_dono()
        lab.derrubar()

    for arq in ("captura.pcap", "cliente.pcap", "cliente_log.json"):
        if (work / arq).exists():
            shutil.move(work / arq, base / f"{nome}_{arq}")
    shutil.rmtree(work, ignore_errors=True)
    meta = {"captura_ponte": stats_ponte, "tc_qdisc_estatisticas": tc}
    (base / f"{nome}_captura_meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    return analisar(nome, cen, semente, base, meta)


def analisar(nome: str, cen: dict, semente: int, base: Path, meta: dict) -> dict:
    """Medidas de uma variante a partir dos arquivos já gravados em ``base``."""
    plano = gen.construir_plano(cen, semente)
    ipc, ips = cen["cliente"]["ip"], cen["servidor"]["ip"]
    ponte = ler(base / f"{nome}_captura.pcap", ipc, ips)
    dentro = ler(base / f"{nome}_cliente.pcap", ipc, ips)
    log = json.loads((base / f"{nome}_cliente_log.json").read_text())["conexoes"]
    cp, reusadas_ponte = conexoes(ponte)
    portas_log = [r["porta_local"] for r in log if r and r.get("porta_local")]
    reusadas_log = {p for p in portas_log if portas_log.count(p) > 1}
    excluir = reusadas_ponte | reusadas_log
    t_app = {r["porta_local"]: r["t_inicio"] for r in log if r and r.get("porta_local") not in (None, *excluir)}
    validas = {p: d for p, d in cp.items() if p not in excluir and "ack" in d}

    T = [d["ack"] - d["syn"] for d in validas.values()]
    d_ack = [d["ack"] - d["synack"] for d in validas.values()]
    T_puro = [d["ack_puro"] - d["syn"] for d in validas.values() if "ack_puro" in d]
    d_ack_puro = [d["ack_puro"] - d["synack"] for d in validas.values() if "ack_puro" in d]
    com_dados = sum(1 for d in validas.values() if d["ack_com_dados"])
    d_syn = [cp[p]["syn"] - t for p, t in t_app.items() if p in validas]
    # Mesmo pacote nas duas capturas. Saída do cliente: ponte − container (o container vê o
    # egresso depois do qdisc). Entrada no cliente: container − ponte.
    dif_c = diferencas(dentro, ponte, "C")
    dif_s = diferencas(ponte, dentro, "S")

    nt = cen["netem"]
    mu, sigma = float(nt["delay_ms"]), float(nt["jitter_ms"])
    np.savez(base / f"{nome}.npz", T=np.array(T), d_ack=np.array(d_ack), T_puro=np.array(T_puro),
             d_ack_puro=np.array(d_ack_puro), d_syn=np.array(d_syn))
    return {
        "variante": nome,
        "netem": nt,
        "media_teorica_atraso_ms": media_normal_truncada(mu, sigma),
        "referencia_minimo_dois_atrasos": referencia_minimo_dois(mu, sigma),
        "conexoes_planejadas": len(plano["benigno"]["instantes_s"]),
        "portas_reutilizadas_excluidas": {"ponte": len(reusadas_ponte), "log_cliente": len(reusadas_log)},
        "conexoes_com_handshake_na_ponte": len(T),
        "primeiro_ack_com_dados": {"n": com_dados, "fracao": com_dados / len(T) if T else None},
        "T_ponte": resumo(T),
        "d_ack_ponte": resumo(d_ack),
        "T_ponte_ack_puro": resumo(T_puro),
        "d_ack_puro_ponte": resumo(d_ack_puro),
        "d_syn_app_ate_ponte": resumo(d_syn),
        "ponte_menos_container_saida_cliente": resumo(dif_c),
        "container_menos_ponte_entrada_cliente": resumo(dif_s),
        **meta,
    }


def figura(base: Path, resultados: list[dict]) -> None:
    """ECDF dos atrasos por variante, com as referências teóricas da variante configurada."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cores = ["#257de0", "#f47230", "#00b894"]
    texto, texto2, grade = "#191919", "#666666", "#e5e5e5"
    fig, axs = plt.subplots(1, 3, figsize=(15, 4.6), sharey=True)
    paineis = (
        (axs[0], "d_ack", "Primeiro pacote do cliente com ACK (o que o monitor usa)"),
        (axs[1], "d_ack_puro", "Só o ACK puro do handshake"),
        (axs[2], "d_syn", "SYN (aplicação → ponte)"),
    )
    xs = np.linspace(0, 130, 500)
    ref = next((r for r in resultados if float(r["netem"]["jitter_ms"]) > 0), None)
    for ax, chave, titulo in paineis:
        if ref is not None:
            d = _atraso_netem(float(ref["netem"]["delay_ms"]), float(ref["netem"]["jitter_ms"]))
            ax.plot(xs, d.cdf(xs), color=texto2, linewidth=1.2, linestyle="--", label="teórico: um atraso N(50, 20)")
            ax.plot(xs, 1 - d.sf(xs) ** 2, color=texto, linewidth=1.2, linestyle=":", label="teórico: mínimo de dois atrasos")
        for cor, r in zip(cores, resultados):
            v = np.sort(np.load(base / f"{r['variante']}.npz")[chave] * 1000)
            if v.size:
                ax.step(v, np.arange(1, v.size + 1) / v.size, where="post", linewidth=2, color=cor,
                        label=f"{r['variante']} (n = {v.size}, média {v.mean():.1f} ms)")
        ax.set_title(titulo, loc="left", fontsize=10, color=texto)
        ax.set_xlabel("atraso até a ponte (ms)", color=texto2)
        ax.set_xlim(0, 130)
        ax.grid(True, color=grade, linewidth=0.8)
        ax.set_axisbelow(True)
        for lado in ("top", "right"):
            ax.spines[lado].set_visible(False)
        ax.tick_params(colors=texto2)
    axs[0].set_ylabel("fração acumulada das conexões", color=texto2)
    h, lab = axs[0].get_legend_handles_labels()
    fig.legend(h, lab, loc="lower center", ncol=3, frameon=False, fontsize=8.5)
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    fig.savefig(base / "diagnostico_netem.png", dpi=150, facecolor="white")
    plt.close(fig)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--semente", type=int, help="obrigatória ao capturar")
    ap.add_argument("--saida", default=str(gen.REPO / "results" / "diagnostico_netem"))
    ap.add_argument("--variantes", nargs="*", default=None)
    ap.add_argument("--reanalisar", metavar="PASTA",
                    help="refaz medidas e figura a partir das capturas já gravadas em PASTA, sem subir o laboratório")
    a = ap.parse_args(argv)
    cen = gen.carregar_cenario("diagnostico_netem")
    variantes = cen.pop("variantes")
    if a.reanalisar:
        base = Path(a.reanalisar)
        anterior = json.loads((base / "diagnostico.json").read_text())
        semente, imagem = anterior["semente"], anterior["imagem"]
        commit_captura = anterior.get("commit_git_captura", anterior.get("commit_git"))
        metas = {r["variante"]: {k: r[k] for k in ("captura_ponte", "tc_qdisc_estatisticas")} for r in anterior["variantes"]}
        resultados = []
        for r in anterior["variantes"]:
            nome = r["variante"]
            arq = base / f"{nome}_captura_meta.json"
            meta = json.loads(arq.read_text()) if arq.exists() else metas[nome]
            resultados.append(analisar(nome, _merge(cen, variantes[nome]), semente, base, meta))
    else:
        if a.semente is None:
            ap.error("--semente é obrigatória ao capturar")
        semente = a.semente
        base = Path(a.saida) / datetime.now().strftime("%Y%m%d-%H%M%S")
        base.mkdir(parents=True)
        imagem = gen.imagem_lab(cen["imagem"])
        commit_captura = gen._commit_git()
        resultados = []
        for nome, over in variantes.items():
            if a.variantes and nome not in a.variantes:
                continue
            print(f"[diag] variante {nome}", flush=True)
            resultados.append(rodar_variante(nome, _merge(cen, over), semente, base, imagem))
    figura(base, resultados)
    out = {"semente": semente, "imagem": imagem, "commit_git_captura": commit_captura,
           "commit_git_analise": gen._commit_git(), "variantes": resultados}
    (base / "diagnostico.json").write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(base / "diagnostico.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
