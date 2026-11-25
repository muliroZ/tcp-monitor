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
| 3 | Laboratório (Docker) | ⏳ |
| 4 | Camada 1 — AFD | ⏳ |
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
```

Exemplo de saída:

```
fluxo 10.0.0.1:40000-10.0.0.2:80#0  cliente=10.0.0.1:40000  servidor=10.0.0.2:80
  0.000000  C.SYN
  0.010000  S.SYNACK
  0.020000  C.ACK
```

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
└── flows/table.py         # tabela de fluxos
configs/                   # default.yaml e experimentos
tests/                     # pytest
```

Decisões de implementação não cobertas pelo guia estão em [DECISIONS.md](DECISIONS.md);
histórico de versões em [CHANGELOG.md](CHANGELOG.md).

## Licença

MIT — ver [LICENSE](LICENSE).
