# tcp-monitor

Monitor de conexões TCP por autômatos para detecção de intrusão. Implementa e avalia três
monitores cumulativos sobre a **mesma base** de leitura de pcap e montagem de fluxos:

| Configuração | Camadas | Modelo |
| --- | --- | --- |
| C1 | 1 | Autômato finito determinístico (AFD) observador da conexão |
| C2 | 1 + 2 | AFD + autômato temporizado (prazo de handshake τ_hs) |
| C3 | 1 + 2 + 3 | AFD + autômato temporizado + agregador (contadores por servidor) |

A pergunta de pesquisa é qual o poder expressivo mínimo necessário para detectar cada
classe de anomalia (sequência, flags inválidas, temporal, volumétrica) e qual a
probabilidade de detecção alcançável por cada classe, comparando os valores empíricos com
as curvas teóricas do modelo M/G/∞.

> Os resultados esperados do documento de pesquisa são hipóteses, não metas. Nada no
> código é ajustado para reproduzi-los.

## Estado

| Fase | Conteúdo | Estado |
| --- | --- | --- |
| 1 | Ambiente | ✅ |
| 2 | Leitura e fluxos | ✅ |
| 3 | Laboratório (Docker) | ✅ |
| 4 | Camada 1 — AFD | ✅ |
| 5 | Camada 2 — Autômato temporizado | ✅ |
| 6 | Camada 3 — Agregador e calibração | ✅ |
| 7 | Avaliação | ✅ |
| 8 | Validação analítica | ✅ |
| 9 | CIC-IDS2017 | bloqueada por pendências |
| 10 | Baselines (opcional) | — |

## Instalação

Requer Python ≥ 3.11.

```bash
python -m venv .venv            # ou: uv venv .venv
.venv/bin/pip install -e ".[dev]"        # núcleo + testes
.venv/bin/pip install -e ".[lab,dev]"    # + gerador do laboratório (scapy)
```

## Uso

```bash
tcpmon --help
tcpmon symbols --pcap captura.pcap            # sequência de símbolos de cada fluxo
tcpmon run --config configs/experiments/lab.yaml --camadas 1   # executa C1 e grava results/<run_id>/
tcpmon calibrate --config configs/experiments/lab.yaml --pcap data/lab/calibracao_s43.pcap
tcpmon run --config configs/experiments/lab.yaml --calibracao results/lab/<run_id>-calib/calibration.json   # C3
tcpmon eval --run results/lab/<C1> --run results/lab/<C2> --run results/lab/<C3> --rotulos data/lab/teste_s42_labels.csv
```

`tcpmon eval` gera, na pasta `eval-<data>/`: `metricas.csv` (TP, FN, FP, TN, P_D e P_FA com IC
de Wilson 95%, precisão, F1, latência mediana e p95 por configuração e classe),
`episodios.csv`, `mcnemar.csv` (pares C1×C2, C2×C3, C1×C3 com correção de Holm e ΔP_D com IC
de Newcombe), `falsos_alarmes.csv`, `transicao.csv`, `desempenho.csv`, `inclusao.json` e
`resumo.md`.

### Validação analítica e reprodução completa

```bash
tcpmon analytic --calibracao results/lab/<run_id>-calib --teste results/lab/<C3>
python experiments/run.py --todos          # gera dados se faltarem, calibra, roda C1/C2/C3, avalia e valida
```

`tcpmon analytic` estima λ̂_L, Ê[T] e â = λ̂_L·Ê[T] na calibração, confere a lei de Little
(média dos retratos × â), o índice de dispersão, o qui-quadrado contra Poisson(â) e o KS dos
intervalos entre SYNs contra a exponencial; ajusta exponencial, log-normal e Weibull a T com
censura em τ_hs; estima λ̂_A de cada SYN Flood pela faixa forjada e compara as curvas teóricas
`P_FA(k) = poisson.sf(k, â)` e `P_D(k) = poisson.sf(k, â + b)` (b = λ_A·τ_hs) com os pontos
empíricos dos retratos estacionários. Grava `analytic.json`, `curvas_roc.csv`,
`pd_vs_taxa.csv` e `figures/` (`roc_<taxa>.png`, `pd_vs_taxa.png`, `retratos_benignos.png`,
`tempo_handshake.png`).

`tcpmon run` grava em `results/<run_id>/` (`run_id` = data, hora e hash curto da
configuração efetiva): `alerts.csv`, `flows.csv`, `counters.json` e `run.json` (configuração
completa, commit Git, τ_hs e sua origem, SHA-256 do pcap, versões das bibliotecas, semente,
pacotes por segundo, pico de fluxos e de memória). τ_hs vem do metadado do laboratório
(`<pcap>.meta.json`) quando existe; senão, de `tau_hs_s`.

Exemplo de saída:

```
fluxo 10.0.0.1:40000-10.0.0.2:80#0  cliente=10.0.0.1:40000  servidor=10.0.0.2:80
  0.000000  C.SYN
  0.010000  S.SYNACK
  0.020000  C.ACK
```

### Laboratório

Gera tráfego benigno e de ataque em containers Docker numa rede **interna** (sem acesso
externo), captura na ponte da rede e grava pcap, rótulos e metadado:

```bash
python lab/generate.py --cenario xmas --semente 42          # ou --scenario/--seed
python lab/generate.py --cenario teste --semente 42         # todos os ataques em sequência (~154 min)
python lab/generate.py --cenario calibracao --semente 43    # só benigno, 15 min
python lab/generate.py --cenario teste --semente 42 --apenas-plano   # só o plano, sem Docker
```

Saída em `data/lab/` (fora do Git): `<cenario>_s<semente>.pcap`, `..._labels.csv`,
`....meta.json` (sysctls do servidor, τ_hs e sua origem, estatísticas da captura, hash do
plano) e `....plano.json`.

| Cenário | Classe | Como é gerado | Chave |
| --- | --- | --- | --- |
| benigno / calibracao | — | Cliente HTTP, chegadas Poisson λ_L = 5/s, netem 50 ± 20 ms | — |
| ack_sem_syn | sequência | ACK sem handshake, 10 pacotes/s por 5 min | origem |
| xmas | flags inválidas | FIN+PSH+URG, 10 pacotes/s por 5 min | origem |
| null | flags inválidas | sem flags, 10 pacotes/s por 5 min | origem |
| handshake_incompleto | temporal | 60 SYNs isolados (75 s entre eles), RST bloqueado; cada SYN é um episódio | origem |
| synflood_baixa / synflood_alta | volumétrica | SYNs forjados de 10.99.0.0/16, Poisson λ_A ∈ {0,02 … 100}/s | servidor |
| varredura_horizontal | volumétrica | SYN na porta 80 de 20 hosts, 10/s por 5 min | origem |

Os parâmetros ficam em `lab/scenarios/*.yaml` (herdam de `_base.yaml`). Requisitos: Docker
com permissão para o usuário; a imagem `tcpmon-lab` é construída automaticamente.

### Camada 1 — AFD observador

O AFD modela a conexão como vista pela rede (projeção observável dos estados da RFC 9293):
`INICIAL → SYN_VISTO → SYNACK_VISTO → ESTABELECIDO → FIN_C/FIN_S → FIN_AMBOS`, mais
`FECHADO` e o estado de rejeição ⊥. Qualquer símbolo sem transição leva a ⊥ e emite um único
alerta (`SEM_HANDSHAKE`, `SYNACK_SEM_SYN`, `FLAGS_INVALIDAS`, `ABERTURA_SIMULTANEA`,
`TRANSICAO_INESPERADA`) com `t_evidencia` = timestamp do pacote. A tabela completa está em
`src/tcpmon/monitors/dfa.py`, com um teste por linha em `tests/test_dfa_transicoes.py`.

### Camada 2 — autômato temporizado

Relógio por instância de fluxo, zerado no primeiro `C.SYN` (retransmissões não o zeram).
Com o handshake pendente (`SYN_VISTO`/`SYNACK_VISTO`) vale o invariante x ≤ τ_hs; quando x
atinge τ_hs o fluxo vai para ⊥ com `HANDSHAKE_EXPIRADO` (`t_evidencia` = primeiro SYN,
`t_alerta` = `t_evidencia` + τ_hs). Os prazos ficam numa fila de prioridade disparada pelos
timestamps do pcap; fluxos ainda pendentes no fim da captura ficam `truncado`, sem alerta.
τ_hs = 63 s no padrão Linux (`tcp_synack_retries = 5`, RTO inicial 1 s: 1+2+4+8+16+32).

### Camada 3 — agregador e calibração

Ao fim de cada janela `[t0 + i·W, t0 + (i+1)·W)` o agregador tira um retrato de N_s (handshakes
pendentes por IP de servidor); se N_s > k, alerta `AGG_HANDSHAKE_PENDENTE`. Também conta, por
(IP de origem, porta de destino), os IPs de destino distintos dos fluxos iniciados na janela;
acima de k_scan, alerta `AGG_VARREDURA_HORIZONTAL`.

`tcpmon calibrate` roda as camadas 1 e 2 sobre o pcap de calibração (só benigno) e grava em
`calibration.json`: k empírico (menor k com fração de retratos N_s > k ≤ α), k_scan pelo mesmo
critério, k analítico (menor k com `poisson.sf(k, â) ≤ α`, â = λ̂_L·Ê[T]) e as estimativas por
servidor. Os experimentos usam o k empírico; o analítico é reportado para comparação.

### Alfabeto

Cada símbolo combina a direção (`C` cliente → servidor, `S` servidor → cliente) com a
classe das flags, ignorando ECE e CWR:

| Classe | Condição |
| --- | --- |
| SYN | Exatamente SYN |
| SYNACK | Exatamente SYN e ACK |
| ACK | ACK ligado; SYN, FIN e RST desligados |
| FIN | FIN e ACK ligados; SYN e RST desligados |
| RST | RST ligado; SYN e FIN desligados |
| INVALIDO | Qualquer outra combinação (NULL, Xmas, SYN+FIN, ...) |

## Configuração

Todo parâmetro numérico vem de YAML (`configs/default.yaml`). Um experimento herda da
configuração padrão e altera só o necessário:

```yaml
base: ../default.yaml
camadas: [1, 2]
janela_s: 5.0
```

## Testes

```bash
.venv/bin/pytest
```

## Estrutura

```
src/tcpmon/
├── cli.py, config.py
├── io/pcap_reader.py      # dpkt → pacotes normalizados
├── symbols.py             # flags + direção → símbolo
├── flows/key.py           # chave bidirecional e direção
├── flows/table.py         # tabela de fluxos e instâncias
├── engine.py              # base compartilhada: ciclo de vida, eventos, janelas
├── pipeline.py            # execução e gravação de results/<run_id>/
├── alerts.py              # esquema de alertas
├── io/labels.py           # rótulos de episódios
├── monitors/dfa.py        # camada 1
├── monitors/timed.py      # camada 2
├── monitors/aggregator.py # camada 3
├── calibracao.py          # escolha de k e k_scan
├── analytic/model.py      # M/G/∞, P_FA(k), P_D(k), k analítico
├── analytic/validacao.py  # estimativas, testes de aderência, curvas (tcpmon analytic)
├── analytic/figuras.py    # figuras do artigo
├── eval/inclusao.py       # inclusão de alertas entre configurações
├── eval/windows.py        # janelas, rótulos de janela, detecção, latência
├── eval/metrics.py        # métricas e tabelas (tcpmon eval)
└── eval/stats.py          # Wilson, McNemar, Holm, diferença pareada
lab/                       # laboratório Docker (generate.py, cenários, agentes)
experiments/run.py         # reproduz todos os resultados
configs/                   # default.yaml e experimentos
tests/                     # pytest
```

Decisões de implementação não cobertas pelo guia estão em [DECISIONS.md](DECISIONS.md);
histórico de versões em [CHANGELOG.md](CHANGELOG.md).

## Licença

MIT — ver [LICENSE](LICENSE).
