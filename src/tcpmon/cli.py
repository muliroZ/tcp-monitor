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
