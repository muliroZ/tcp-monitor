"""Executor do plano de ataque (Scapy). Roda apenas dentro do container atacante, numa rede
Docker interna sem acesso externo. Cada pacote do plano tem deslocamento, origem, destino e
flags definidos pelo gerador com semente fixa; aqui só se envia no instante previsto."""

import argparse
import json
import time

from scapy.all import IP, TCP, conf  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plano", required=True)
    ap.add_argument("--inicio", type=float, required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    with open(a.plano) as fh:
        plano = json.load(fh)
    conf.verb = 0
    sock = conf.L3socket()
    log = []
    try:
        for ep in plano["episodios"]:
            enviados = 0
            t_primeiro = t_ultimo = None
            for off, src, sport, dst, dport, flags in ep["pacotes"]:
                espera = a.inicio + off - time.time()
                if espera > 0:
                    time.sleep(espera)
                pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=1000 + enviados, window=1024)
                sock.send(pkt)
                agora = time.time()
                if t_primeiro is None:
                    t_primeiro = agora
                t_ultimo = agora
                enviados += 1
            log.append({"episodio": ep["episodio"], "enviados": enviados, "t_primeiro": t_primeiro, "t_ultimo": t_ultimo})
    finally:
        sock.close()
        with open(a.log, "w") as fh:
            json.dump({"episodios": log}, fh)


if __name__ == "__main__":
    main()
