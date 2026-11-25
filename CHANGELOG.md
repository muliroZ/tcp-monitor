# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/);
versões seguem [SemVer](https://semver.org/lang/pt-BR/).

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
