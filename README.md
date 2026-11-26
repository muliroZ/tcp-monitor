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
| 5 | Camada 2 — Autômato temporizado | ⏳ |
| 6 | Camada 3 — Agregador e calibração | ⏳ |
| 7 | Avaliação | ⏳ |
| 8 | Validação analítica | ⏳ |
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
```

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
python lab/generate.py --cenario teste --semente 42         # todos os ataques em sequência (~104 min)
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
| handshake_incompleto | temporal | 20 SYNs isolados (75 s entre eles), RST bloqueado | servidor |
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
└── monitors/dfa.py        # camada 1
lab/                       # laboratório Docker (generate.py, cenários, agentes)
configs/                   # default.yaml e experimentos
tests/                     # pytest
```

Decisões de implementação não cobertas pelo guia estão em [DECISIONS.md](DECISIONS.md);
histórico de versões em [CHANGELOG.md](CHANGELOG.md).

## Licença

MIT — ver [LICENSE](LICENSE).
