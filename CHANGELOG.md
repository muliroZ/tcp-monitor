# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/);
versões seguem [SemVer](https://semver.org/lang/pt-BR/).

## [0.5.0] — 2026-11-26

Fases 7 (avaliação) e 8 (validação analítica).

### Adicionado
- `tcpmon eval`: rotulagem de janelas (positivas, transição, benignas), TP/FN/FP/TN, P_D e
  P_FA com IC de Wilson, precisão, F1, latência (mediana e p95), desempenho, McNemar (exato
  ou corrigido) com Holm e ΔP_D com IC de Newcombe para dados pareados; tabelas CSV e
  `resumo.md`.
- `tcpmon analytic`: λ̂_L, Ê[T], â, lei de Little, índice de dispersão, qui-quadrado e KS,
  ajuste de T com censura, λ̂_A por episódio, curvas ROC teóricas com pontos empíricos e
  figuras.
- `experiments/run.py --todos`: reprodução completa com um comando.
- Testes estatísticos conferidos contra valores publicados (Wilson, McNemar, Holm, Newcombe).
- Decisões D42–D50 (implementação das fases 7 e 8).

### Corrigido
- Diagnóstico do `netem`: a contagem de reordenação comparava duas capturas pós-qdisc; pacotes
  idênticos passam a ser pareados pela ordem de ocorrência; sinal da diferença na entrada.
- `rejeitadas_de_csv` lê `flows.csv` como texto (avisos de tipos mistos do pandas).

### Alterado
- D34: `handshake_incompleto` com chave de associação por origem e 60 SYNs (era servidor e 20);
  a captura `teste` passa a durar ~154 min. Fixture temporal regenerada.
- D33: inclusão C1 ⊆ C2 verificada por traço rejeitado (mesma chave e instante do primeiro
  pacote, `t_alerta` da C2 ≤ C1); a comparação por alerta idêntico vira o relatório de
  divergência por janela. C2 ⊆ C3 continua por alerta idêntico.
- D36: `agregador.servidores` (lista de IPs monitorados, obrigatória com o agregador), retratos
  só desses servidores desde a primeira janela, k por servidor na calibração e no agregador,
  P_FA por servidor na avaliação (`pfa_por_servidor.csv`) e na validação analítica, ROC por
  servidor.
- D35 (diagnóstico 1): estatísticas e figura de T separadas por `motivo_fim_pendente`.
- D35 (diagnósticos 2 e 3): `lab/diagnostico_netem.py`. Captura na ponte e dentro do cliente
  ao mesmo tempo, em três variantes (configurado, sem fila filha, sem jitter), com ECDFs e as
  referências teóricas de um atraso e do mínimo de dois atrasos, e `--reanalisar` para refazer
  a análise sem Docker. O cliente do laboratório registra a porta local de cada conexão, e a
  fila filha do `netem` passa a ser explícita em `_base.yaml`.
- D53: `pd_vs_taxa.csv`, `analytic.json` e `pd_vs_taxa.png` trazem também a P_D teórica com a
  taxa realizada em cada episódio (λ̂_A).
- D52: resultado do diagnóstico. O `netem` com jitter reordena o ACK puro e o segmento de dados
  seguinte em cerca de 50% das conexões, com ou sem fila filha. Por isso T ≈ 39 ms (o mínimo
  de dois atrasos), e não 50 ms. A verificação da D13 não se sustenta. Fica pendente com a
  equipe.

## [0.4.0] — 2026-11-25

Fase 6: camada 3 (agregador) e calibração.

### Adicionado
- Agregador: retrato de handshakes pendentes por servidor no fim de cada janela
  (`AGG_HANDSHAKE_PENDENTE`) e detector de varredura horizontal (`AGG_VARREDURA_HORIZONTAL`).
- `tcpmon calibrate`: k e k_scan empíricos, k analítico, λ̂_L, Ê[T] e â por servidor
  (`calibration.json`); `tcpmon run --calibracao` aplica os valores.
- `snapshots.csv` e `varredura.csv` nas execuções com agregador.
- Núcleo do modelo analítico (`tcpmon.analytic.model`): P_FA(k), P_D(k), k empírico e
  analítico, simulação M/G/∞.
- Testes: contagem dos retratos, decisões, escolha de k em dados sintéticos, convergência
  da M/G/∞ para λ·E[S], inclusão C2 ⊆ C3 nas fixtures e calibração ponta a ponta.
- Decisões D28–D32.

## [0.3.0] — 2026-11-25

Fases 4 (camada 1 — AFD) e 5 (camada 2 — autômato temporizado).

### Adicionado
- AFD observador com estado de rejeição ⊥ e motivos de alerta; tabela de transições do guia.
- Motor compartilhado: instâncias, carência, reuso de porta, lápides, remoção por
  inatividade, fila de eventos temporizados e janelas, ganchos para as camadas 2 e 3.
- Camada 2: relógio por fluxo, prazo τ_hs em fila de prioridade, guarda, marcação `truncado`.
- `tcpmon run`: grava `alerts.csv`, `flows.csv`, `counters.json` e `run.json`; τ_hs lido do
  metadado do laboratório.
- Verificação de inclusão de alertas entre configurações (`tcpmon.eval.inclusao`).
- Configurações de experimento `configs/experiments/lab*.yaml` (W = 1, 5 e 10 s).
- Testes: uma linha da tabela por teste, ciclo de vida, temporização (expiração em τ_hs,
  retransmissão que não zera o relógio, prazo depois do fim da captura), integração com as
  fixtures do laboratório e inclusão C1 ⊆ C2.
- Decisões D20–D27.

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
