# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/);
versões seguem [SemVer](https://semver.org/lang/pt-BR/).

## [0.2.0] — 2026-11-25

Fase 3 do guia: laboratório.

### Adicionado
- Imagem Docker única do laboratório (`lab/Dockerfile`): servidor HTTP, cliente benigno,
  atacante Scapy, alvos da varredura e captura `tcpdump`.
- `lab/generate.py`: plano determinístico por semente, topologia em rede Docker interna,
  `netem` 50 ± 20 ms no cliente, rota da faixa forjada, bloqueio de RST no handshake
  incompleto, captura na ponte, `labels.csv` e metadado (sysctls, τ_hs e origem, hash do
  plano, estatísticas da captura).
- Cenários: benigno, calibracao, ack_sem_syn, xmas, null, handshake_incompleto,
  synflood_baixa, synflood_alta, varredura_horizontal e teste (todos em sequência).
- `tcpmon.io.labels`: leitura, gravação e validação de rótulos.
- Fixtures de integração (< 1 MB) geradas pelo laboratório em `tests/fixtures/`.
- `lab/docker-compose.yml` com a mesma topologia para inspeção manual.
- Decisões D11–D19 em `DECISIONS.md`.


## [0.1.0] — 2026-11-25

Fases 1 (ambiente) e 2 (leitura e fluxos) do guia de implementação.

### Adicionado
- Estrutura do pacote `tcpmon`, `pyproject.toml` com dependências fixadas e extras `lab` e `dev`.
- Configuração YAML (`configs/default.yaml`) com herança por `base` e validação.
- Leitor de pcap/pcapng com dpkt (`DLT_EN10MB` e `DLT_LINUX_SLL`), TCP sobre IPv4/IPv6,
  contagem de descartes por tipo e de inversões de ordem.
- Classificação de flags em símbolos (`C.SYN`, `S.SYNACK`, ...), ignorando ECE e CWR.
- Chave de fluxo bidirecional, detecção de direção e marcação `sem_handshake`/`midstream`.
- Comando `tcpmon symbols --pcap <arquivo>`.
- Testes: 64 combinações de flags (com e sem ECE/CWR), chave, direção, carência, leitor.
