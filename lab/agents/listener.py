"""Alvo da varredura: escuta numa porta sem aceitar conexões (o kernel completa o handshake)."""

import argparse
import socket
import time

ap = argparse.ArgumentParser()
ap.add_argument("--porta", type=int, required=True)
ap.add_argument("--backlog", type=int, required=True)
a = ap.parse_args()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", a.porta))
s.listen(a.backlog)
while True:
    time.sleep(3600)
