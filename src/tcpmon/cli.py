"""Linha de comando do tcpmon."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from tcpmon import __version__


def _cmd_symbols(args: argparse.Namespace) -> int:
    from tcpmon.flows.table import FlowTable
    from tcpmon.io.pcap_reader import ReadCounters, read_packets

    tabela = FlowTable(carencia_s=args.carencia)
    ordem: list = []
    sequencias: dict = {}
    cont = ReadCounters()
    for pkt in read_packets(args.pcap, cont):
        tabela.observar_tempo(pkt.ts)
        key, fluxo = tabela.buscar(pkt)
        if fluxo is None:
            fluxo = tabela.criar(key, pkt)
            ordem.append(fluxo)
            sequencias[id(fluxo)] = []
        fluxo.pacotes += 1
        fluxo.ultimo = pkt.ts
        sequencias[id(fluxo)].append((pkt.ts, tabela.simbolo(fluxo, pkt)))

    out = sys.stdout
    limite = args.max_fluxos if args.max_fluxos and args.max_fluxos > 0 else len(ordem)
    for fluxo in ordem[:limite]:
        out.write(fluxo.descricao() + "\n")
        for ts, simb in sequencias[id(fluxo)]:
            out.write(f"  {ts:.6f}  {simb}\n")
    if limite < len(ordem):
        out.write(f"... {len(ordem) - limite} fluxos omitidos (--max-fluxos)\n")
    c = cont.as_dict()
    out.write(
        f"# fluxos={len(ordem)} pacotes_lidos={c['pacotes_lidos']} tcp={c['pacotes_tcp_aceitos']}"
        f" descartados={c['descartados_total']} inversoes_ordem={c['inversoes_ordem']}\n"
    )
    return 0


def _camadas(texto: str | None) -> tuple[int, ...] | None:
    if not texto:
        return None
    return tuple(int(x) for x in texto.replace(" ", "").split(",") if x)


def _cmd_run(args: argparse.Namespace) -> int:
    from tcpmon.config import load_config
    from tcpmon.pipeline import carregar_calibracao, executar

    cfg = load_config(args.config)
    cal_path = args.calibracao or cfg.agregador.calibracao
    calibracao = None
    if cal_path:
        calibracao = carregar_calibracao(cal_path)
        calibracao["_caminho"] = str(cal_path)
    pasta = executar(
        cfg,
        pcap=args.pcap,
        camadas=_camadas(args.camadas),
        calibracao=calibracao,
        saida_base=args.saida,
    )
    print(pasta)
    return 0


def _cmd_calibrate(args: argparse.Namespace) -> int:
    from tcpmon.calibracao import calibrar
    from tcpmon.config import load_config

    cfg = load_config(args.config)
    print(calibrar(cfg, args.pcap, saida_base=args.saida))
    return 0


def _cmd_eval(args: argparse.Namespace) -> int:
    from tcpmon.eval.metrics import avaliar

    pasta = avaliar(args.run, args.rotulos, args.saida, tolerancia=args.tolerancia)
    print(pasta)
    if not args.quieto:
        print((pasta / "resumo.md").read_text(encoding="utf-8"))
    return 0


def _cmd_analytic(args: argparse.Namespace) -> int:
    from tcpmon.analytic.validacao import validar_modelo

    print(validar_modelo(args.calibracao, args.teste, figuras=not args.sem_figuras))
    return 0


def _cmd_agenda(args: argparse.Namespace) -> int:
    from tcpmon.io.agenda import agenda_para_rotulos

    problemas = agenda_para_rotulos(args.entrada, args.saida)
    print(args.saida)
    for p in problemas:
        print(f"problema (não corrigido): {p}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tcpmon",
        description="Monitor de conexões TCP por autômatos (AFD, autômato temporizado e agregador).",
    )
    p.add_argument("--version", action="version", version=f"tcpmon {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="mensagens de depuração")
    sub = p.add_subparsers(dest="comando", metavar="<comando>")

    s = sub.add_parser("symbols", help="imprime a sequência de símbolos de cada fluxo (depuração)")
    s.add_argument("--pcap", required=True, help="arquivo pcap ou pcapng")
    s.add_argument(
        "--carencia",
        type=float,
        default=0.0,
        help="período de carência G em segundos, só para marcar fluxos midstream (padrão: 0)",
    )
    s.add_argument("--max-fluxos", type=int, default=0, help="limita a quantidade de fluxos impressos")
    s.set_defaults(func=_cmd_symbols)

    c = sub.add_parser("calibrate", help="calcula k e k_scan sobre o pcap de calibração (só benigno)")
    c.add_argument("--config", required=True, help="arquivo YAML da configuração")
    c.add_argument("--pcap", required=True, help="pcap de calibração (apenas tráfego benigno)")
    c.add_argument("--saida", default=None, help="sobrescreve a pasta base de saída")
    c.set_defaults(func=_cmd_calibrate)

    r = sub.add_parser("run", help="executa as camadas configuradas e grava results/<run_id>/")
    r.add_argument("--config", required=True, help="arquivo YAML da configuração")
    r.add_argument("--calibracao", default=None, help="calibration.json com k e k_scan (camada 3)")
    r.add_argument("--pcap", default=None, help="sobrescreve entrada.pcap da configuração")
    r.add_argument("--camadas", default=None, help="sobrescreve 'camadas' (ex.: 1 ou 1,2 ou 1,2,3)")
    r.add_argument("--saida", default=None, help="sobrescreve a pasta base de saída")
    r.set_defaults(func=_cmd_run)

    e = sub.add_parser("eval", help="gera métricas, intervalos e testes estatísticos de execuções")
    e.add_argument("--run", action="append", required=True, help="pasta de uma execução (repita para C1, C2, C3)")
    e.add_argument("--rotulos", required=True, help="labels.csv dos episódios")
    e.add_argument("--saida", default=None, help="pasta das tabelas (padrão: <pasta da 1ª execução>/../eval-<data>)")
    e.add_argument("--quieto", action="store_true", help="não imprime o resumo")
    e.add_argument(
        "--tolerancia",
        type=float,
        default=None,
        help="tolerância de rótulo em segundos (D38); padrão: avaliacao.tolerancia_rotulo_s das execuções",
    )
    e.set_defaults(func=_cmd_eval)

    a = sub.add_parser("analytic", help="validação analítica (M/G/∞) e suas figuras")
    a.add_argument("--calibracao", required=True, help="pasta da calibração (contém calibration.json)")
    a.add_argument("--teste", required=True, help="pasta de uma execução C3 sobre o pcap de teste")
    a.add_argument("--sem-figuras", action="store_true", help="não gera as figuras")
    a.set_defaults(func=_cmd_analytic)

    g = sub.add_parser("agenda", help="converte a agenda oficial de ataques (CSV transcrito) em labels.csv (D38)")
    g.add_argument("--entrada", required=True, help="agenda transcrita (ver tcpmon/io/agenda.py)")
    g.add_argument("--saida", required=True, help="labels.csv de destino")
    g.set_defaults(func=_cmd_agenda)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
