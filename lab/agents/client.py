"""Cliente HTTP benigno: abre uma conexão em cada instante do plano (chegadas Poisson
calculadas pelo gerador com semente fixa) e registra início e fim de cada uma."""

import argparse
import json
import socket
import threading
import time


def conexao(servidor, porta, timeout, registro, i):
    t_ini = time.time()
    erro = None
    porta_local = None
    try:
        with socket.create_connection((servidor, porta), timeout=timeout) as s:
            porta_local = s.getsockname()[1]
            s.sendall(b"GET / HTTP/1.0\r\nHost: servidor\r\n\r\n")
            while s.recv(4096):
                pass
    except OSError as exc:
        erro = type(exc).__name__
    registro[i] = {"t_inicio": t_ini, "t_fim": time.time(), "erro": erro, "porta_local": porta_local}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plano", required=True)
    ap.add_argument("--inicio", type=float, required=True, help="instante absoluto do deslocamento 0")
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    with open(a.plano) as fh:
        plano = json.load(fh)
    b = plano["benigno"]
    instantes = b["instantes_s"]
    registro = [None] * len(instantes)
    threads = []
    for i, off in enumerate(instantes):
        espera = a.inicio + off - time.time()
        if espera > 0:
            time.sleep(espera)
        th = threading.Thread(
            target=conexao, args=(b["servidor"], b["porta"], b["timeout_s"], registro, i), daemon=True
        )
        th.start()
        threads.append(th)
    for th in threads:
        th.join(timeout=b["timeout_s"] + 5)
    with open(a.log, "w") as fh:
        json.dump({"conexoes": registro}, fh)


if __name__ == "__main__":
    main()
