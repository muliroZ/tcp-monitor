#!/usr/bin/env python3
"""Reproduz os resultados do zero com um único comando.

    python experiments/run.py --todos                 # todos os experimentos de configs/experiments/
    python experiments/run.py --config configs/experiments/lab.yaml
    python experiments/run.py --todos --gerar         # regenera também os pcaps do laboratório

Para cada configuração de experimento:
1. gera os pcaps do laboratório se não existirem (ou com --gerar);
2. calibra k e k_scan no pcap de calibração (só benigno);
3. executa C1, C2 e C3 sobre o pcap de teste, cada uma num processo próprio (para que o pico
   de memória medido seja o da configuração);
4. avalia (tcpmon eval), repete a avaliação para cada valor de
   ``avaliacao.sensibilidade_tolerancia_s`` (D38) e faz a validação analítica (tcpmon analytic);
5. grava ``<saida>/experimento.json`` com as pastas produzidas.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from tcpmon.config import load_config  # noqa: E402

TCPMON = [sys.executable, "-m", "tcpmon.cli"]


def rodar(cmd: list[str]) -> str:
    print("$", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    if r.stderr:
        sys.stderr.write(r.stderr)
    if r.returncode != 0:
        raise SystemExit(f"falhou ({r.returncode}): {' '.join(cmd)}")
    linhas = [l for l in r.stdout.splitlines() if l.strip()]
    return linhas[0] if linhas else ""


def gerar_dados(cfg, exp: dict, forcar: bool) -> None:
    pcap_teste = REPO / cfg.entrada.pcap
    pcap_cal = REPO / exp["calibracao_pcap"]
    pares = (
        (pcap_cal, exp["calibracao_cenario"], exp["calibracao_semente"]),
        (pcap_teste, exp["teste_cenario"], cfg.semente),
    )
    for pcap, cenario, semente in pares:
        if pcap.exists() and not forcar:
            print(f"[dados] {pcap.relative_to(REPO)} já existe", flush=True)
            continue
        subprocess.run(
            [sys.executable, str(REPO / "lab" / "generate.py"), "--cenario", cenario, "--semente", str(semente),
             "--saida-dir", str(pcap.parent), "--nome", pcap.stem],
            cwd=REPO,
            check=True,
        )


def experimento(caminho: Path, forcar_geracao: bool) -> dict:
    cfg = load_config(caminho)
    exp = cfg.raw.get("experimento") or {}
    if "calibracao_pcap" not in exp:
        raise SystemExit(f"{caminho}: falta a seção 'experimento.calibracao_pcap'")
    gerar_dados(cfg, exp, forcar_geracao)

    cal = rodar(TCPMON + ["calibrate", "--config", str(caminho), "--pcap", exp["calibracao_pcap"]])
    execucoes = {}
    for camadas in exp.get("configuracoes", [[1], [1, 2], [1, 2, 3]]):
        rotulo = f"C{max(camadas)}"
        execucoes[rotulo] = rodar(
            TCPMON + ["run", "--config", str(caminho), "--camadas", ",".join(map(str, camadas)), "--calibracao", cal]
        )
    args_eval = TCPMON + ["eval", "--rotulos", cfg.entrada.rotulos, "--quieto"]
    for pasta in execucoes.values():
        args_eval += ["--run", pasta]
    avaliacao = rodar(args_eval)
    # D38: análise de sensibilidade da tolerância de rótulo, com as mesmas execuções.
    sensibilidade = {}
    for tol in cfg.avaliacao.sensibilidade_tolerancia_s:
        destino = Path(avaliacao) / f"tolerancia_{tol:g}s"
        sensibilidade[f"{tol:g}"] = rodar(args_eval + ["--tolerancia", repr(tol), "--saida", str(destino)])
    analitica = None
    if "C3" in execucoes:
        analitica = rodar(
            TCPMON + ["analytic", "--calibracao", str(Path(cal).parent), "--teste", execucoes["C3"]]
        )
    resumo = {
        "config": str(caminho),
        "quando": datetime.now().isoformat(timespec="seconds"),
        "calibracao": cal,
        "execucoes": execucoes,
        "avaliacao": avaliacao,
        "sensibilidade_tolerancia": sensibilidade,
        "analitica": analitica,
    }
    saida = REPO / cfg.saida
    saida.mkdir(parents=True, exist_ok=True)
    (saida / "experimento.json").write_text(json.dumps(resumo, indent=2, ensure_ascii=False))
    print(f"[ok] {caminho.name}: {avaliacao}", flush=True)
    return resumo


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Reproduz os experimentos do zero.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--todos", action="store_true", help="todas as configurações em configs/experiments/")
    g.add_argument("--config", action="append", help="uma configuração de experimento (repita para várias)")
    ap.add_argument("--gerar", action="store_true", help="regenera os pcaps do laboratório mesmo se existirem")
    a = ap.parse_args(argv)
    configs = (
        sorted((REPO / "configs" / "experiments").glob("*.yaml")) if a.todos else [Path(c).resolve() for c in a.config]
    )
    for c in configs:
        experimento(c, a.gerar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
