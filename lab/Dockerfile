# Imagem única do laboratório: servidor, cliente benigno, atacante, alvos da varredura e captura.
FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends tcpdump iproute2 iptables hping3 procps \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy==2.8.0

COPY agents/ /lab/
WORKDIR /lab
CMD ["sleep", "infinity"]
