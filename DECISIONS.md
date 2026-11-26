# Decisões de implementação

Registro de casos não cobertos pelo guia de implementação que afetam (ou podem afetar) o
resultado, com a escolha feita e o motivo (regra 5 do guia). Cada item deve ser levado à
equipe; itens marcados **[equipe]** já foram decididos por ela.

Formato: `D<n> — título` · data · fase · status (`aberta` = aguardando revisão da equipe,
`decidida` = confirmada pela equipe).

---

## Decisões da equipe

### D1 — Parâmetros do laboratório **[equipe]**
2026-11-25 · fase 3 · decidida

Resolve as pendências "Laboratório (bloqueiam a fase 3)" do guia:

- λ_L = 5 conexões/s (chegadas Poisson).
- Grade de λ_A ∈ {0,02; 0,05; 0,1; 0,5; 1; 10; 100} SYN/s.
- Episódio de 5 min; calibração benigna de 15 min.
- O servidor mantém as sysctls padrão do Linux, incluindo `tcp_syncookies = 1`.

### D2 — Latência emulada com `tc netem` **[equipe]**
2026-11-25 · fase 3 · decidida

Na rede Docker o RTT é ~0,05 ms, o que tornaria T ≈ 0 e â = λ_L·E[T] ≈ 0 (k empírico
degenerado em 0 e validação analítica sem conteúdo). A equipe decidiu aplicar
`netem delay 50ms 20ms distribution normal` na saída do cliente benigno.

### D3 — Agregador e abertura simultânea **[equipe]**
2026-11-25 · modelo · decidida

Granularidade do agregador por IP do servidor, α = 0,01 e abertura simultânea indo para
⊥ com motivo `ABERTURA_SIMULTANEA`, como proposto no guia.

---

## Decisões de implementação (aguardando revisão)

### D4 — Fragmentos IP não são remontados
2026-11-25 · fase 2 · aberta

Pacotes IPv4 com MF ligado ou deslocamento > 0 e pacotes IPv6 com cabeçalho de
fragmento são contados em `fragmento_ip` e descartados. Motivo: o guia não prevê
remontagem; fragmentar segmentos TCP é raro em tráfego legítimo e é técnica de evasão
(limitação a declarar no artigo).

### D5 — Checksums não são verificados
2026-11-25 · fase 2 · aberta

Checksums IP/TCP não são validados. Capturas feitas no próprio host costumam ter
checksum incorreto por *offload* da placa; descartá-los removeria tráfego legítimo.

### D6 — Ordem da chave de fluxo
2026-11-25 · fase 2 · aberta

"Par menor" usa a ordem numérica do endereço (IPv4 antes de IPv6) e, em empate, a
porta. Qualquer ordem total serve para a simetria; a numérica deixa a chave legível.

### D7 — pcapng com várias interfaces
2026-11-25 · fase 2 · aberta

O leitor do dpkt usa o tipo de enlace da primeira interface do pcapng. Arquivos com
interfaces de tipos de enlace diferentes não são suportados. As capturas do laboratório
têm uma única interface.

### D8 — Descartes do leitor por categoria
2026-11-25 · fase 2 · aberta

Categorias em `counters.json`: `nao_ip`, `nao_tcp`, `fragmento_ip`,
`ip_truncado_ou_malformado`, `tcp_truncado_ou_malformado`, `ip_malformado`,
`enlace_malformado` e `registro_corrompido` (registro do arquivo ilegível; a leitura
para nesse ponto com aviso, sem derrubar a execução).

### D9 — Configuração com herança e chaves adicionais
2026-11-25 · fase 1 · aberta

Para que nenhum número fique fixo no código, a configuração não tem valores padrão
em Python: arquivos de experimento herdam de `configs/default.yaml` pela chave `base`.
Chaves adicionadas ao esquema do guia:

- `rto_inicial_s` (1,0): RTO inicial usado para derivar τ_hs de `tcp_synack_retries`
  (τ_hs = RTO·(2^(r+1) − 1); r = 5 dá 63 s, como no guia).
- `agregador.calibracao`: caminho de um `calibration.json` (alternativa a `--calibracao`).
- `entrada.metadado`: metadado do laboratório (sysctls, τ_hs); `null` procura
  `<pcap>.meta.json` ao lado do pcap.

### D10 — Versão do Python
2026-11-25 · fase 1 · aberta

O ambiente da equipe usa Python 3.15 (o guia pede ≥ 3.11). As versões das dependências
estão fixadas no `pyproject.toml` a partir da primeira instalação que funcionou.

### D11 — Ponto de captura na ponte Docker
2026-11-25 · fase 3 · aberta

O `tcpdump` roda num container com `--network host` e captura a ponte da rede interna do
laboratório (equivalente a uma porta espelhada no switch): vê o tráfego de todos os hosts,
inclusive dos alvos da varredura. `snaplen` = 128 bytes (cabeçalhos completos). As
estatísticas do `tcpdump` (descartes do kernel) vão para o metadado.

### D12 — Isolamento e destino dos SYN-ACK forjados
2026-11-25 · fase 3 · aberta

A rede é `--internal` (sem rota padrão). O servidor recebe a rota `10.99.0.0/16 via
<atacante>`: os SYN-ACK destinados às origens forjadas aparecem na captura e chegam ao
atacante, que tem `net.ipv4.ip_forward = 0` e os descarta em silêncio (sem RST e sem ICMP).
Sem essa rota o kernel do servidor não enviaria os SYN-ACK (rede inalcançável) e a captura
não os mostraria. Os containers do Docker vêm com `ip_forward = 1`; por isso o atacante
recebe a sysctl explicitamente.

### D13 — `netem` sem reordenação
2026-11-25 · fase 3 · aberta

O `netem` com *jitter* reordena pacotes por padrão. Foi adicionada uma fila `pfifo` filha
(`limit 1000`): o atraso varia, mas a ordem é preservada. Motivo: a decisão D2 pediu
latência, não reordenação; reordenação é uma limitação discutida à parte no artigo.

### D14 — Backlog do servidor e alvos da varredura
2026-11-25 · fase 3 · aberta

O servidor HTTP (Python, HTTP/1.0) usa `listen(511)`, o padrão do nginx; as sysctls do
kernel ficam no padrão (D1). A varredura percorre 20 hosts que escutam na porta 80 sem
aceitar conexões (o kernel completa o handshake). O atacante não bloqueia RST na varredura:
o kernel dele reseta cada SYN-ACK, como numa varredura SYN real.

### D15 — Estrutura dos episódios
2026-11-25 · fase 3 · aberta

Valores em `lab/scenarios/*.yaml`:

- `ack_sem_syn`, `xmas`, `null`, `varredura_horizontal`: um episódio contínuo de 5 min com
  10 pacotes/s em intervalos fixos (em toda janela de 1 s há pacotes de ataque). Cada
  pacote usa uma porta de origem nova, de uma faixa exclusiva do tipo de ataque, para que
  cada pacote seja um fluxo próprio e nenhum caia numa lápide.
- `xmas` e `null` percorrem as portas de destino 1–1024 do servidor.
- `handshake_incompleto`: 20 SYNs espaçados de 75 s (> τ_hs), cada SYN um **episódio
  pontual** (`t_inicio = t_fim` = timestamp capturado do SYN). Motivo: com um episódio
  contínuo de 5 min, a P_D por janela mediria a taxa de SYNs, não a detecção; e com
  espaçamento menor que τ_hs o cenário viraria um SYN Flood de baixa taxa.
- `synflood_baixa` (λ_A ∈ {0,02; 0,05; 0,1; 0,5}) e `synflood_alta` (λ_A ∈ {1; 10; 100}):
  um episódio de 5 min por taxa. A divisão entre "baixa" e "alta" é só de nomenclatura.
- 60 s de aquecimento só com tráfego benigno e 120 s (≥ τ_hs + margem) após cada episódio,
  para que a zona de transição termine antes do próximo episódio.

### D16 — Tempo dos rótulos
2026-11-25 · fase 3 · aberta

Containers e captura usam o mesmo relógio (kernel do host). Episódios contínuos usam o
intervalo planejado (`inicio + deslocamento`); episódios pontuais usam o timestamp do
pacote de ataque no pcap (o plano é o *fallback*). O metadado e a coluna `parametros`
guardam enviados, capturados e primeiro/último timestamp capturado, para auditoria.

### D17 — O que "reprodutível" significa no laboratório
2026-11-25 · fase 3 · aberta

A mesma semente produz o mesmo plano (instantes das conexões benignas e todos os pacotes de
ataque), verificável pelo `plano_sha256` do metadado. O pcap não é idêntico byte a byte entre
execuções: a temporização do kernel e do `netem` varia.

### D18 — Orquestração sem `docker compose`
2026-11-25 · fase 3 · aberta

O plugin `docker compose` não está instalado no ambiente da equipe. `lab/generate.py` cria a
topologia com a CLI `docker`; `lab/docker-compose.yml` descreve a mesma topologia para
inspeção manual. O guia usa `--cenario/--semente` numa tabela e `--scenario/--seed` noutra;
os dois pares são aceitos.

### D19 — Chave de associação do handshake incompleto
2026-11-25 · fase 3 · aberta

Seguindo o guia, a chave do `handshake_incompleto` é o servidor alvo. Consequência: um alerta
de tráfego benigno para o mesmo servidor, na mesma janela, também conta como detecção.
O mesmo vale para o SYN Flood.

### D20 — Inatividade nos estados que o guia não lista
2026-11-25 · fase 4 · aberta

O guia define a remoção por inatividade para `FIN_AMBOS`/`FECHADO` (2×MSL), `ESTABELECIDO`
(3600 s) e ⊥ (imediata). Para `SYN_VISTO`, `SYNACK_VISTO`, `FIN_C`, `FIN_S` e fluxos
`midstream` foi usado o mesmo limite de `ESTABELECIDO` (`ocioso_estabelecido_s`). Motivo:
evitar memória ilimitada sem inventar parâmetro novo; conexões semi-encerradas podem durar
legitimamente. Na C1 isso significa que handshakes pendentes ficam até 3600 s em memória
(o "monitor como alvo" é medido pelo pico de fluxos).

### D21 — SYN numa chave `midstream`
2026-11-25 · fase 4 · aberta

Um SYN (de qualquer lado) que chega a uma chave marcada `midstream` encerra essa instância
(motivo `syn_em_midstream`) e abre uma nova, que entra nos monitores. Os demais pacotes de
um fluxo `midstream` são contados e ignorados.

### D22 — SYN numa chave removida (lápide)
2026-11-25 · fase 4 · aberta

O guia fala em "SYN do cliente"; numa chave removida não há fluxo vivo para definir o
cliente. Qualquer SYN abre uma nova instância e o remetente é o cliente dela (mesma regra
do primeiro pacote de um fluxo). Pacotes não-SYN numa lápide são contados
(`pacotes_lapide`) e ignorados.

### D23 — Ordem de eventos simultâneos
2026-11-25 · fases 4–6 · aberta

Antes de um pacote com timestamp t, disparam todos os eventos com instante ≤ t (como no
guia; um prazo exatamente em t expira antes do pacote). Em empate de instantes: fim de
janela, depois prazo de handshake, depois inatividade. Assim o retrato da janela i
corresponde ao estado imediatamente antes do instante final (limite à esquerda) e um pacote
no instante exato da fronteira pertence à janela seguinte.

### D24 — t0 e fim da captura
2026-11-25 · fase 4 · aberta

t0 é o timestamp do primeiro quadro do arquivo (de qualquer protocolo) e o "último
timestamp" é o maior timestamp visto. Janelas que terminam depois do último timestamp não
são fechadas (sem retrato); `run.json` registra `janelas_completas`.

### D25 — Colunas adicionais em `flows.csv`
2026-11-25 · fase 4 · aberta

Além das colunas do guia: `t_primeiro_syn`, `t_fim_pendente` e `motivo_fim_pendente`
(necessárias para estimar T na validação analítica), `removido_em`, `motivo_fim`
(`rejeicao`, `inatividade`, `reuso_de_porta`, `syn_em_midstream`, `fim_da_captura`) e
`motivo_alerta`.

### D26 — Exceção teórica à inclusão C1 ⊆ C2 (levar à equipe)
2026-11-25 · fase 5 · aberta

Seguindo o guia, um fluxo que expira na camada 2 vai para ⊥, é removido e vira lápide. Na
C1 o mesmo fluxo continua vivo (sem prazo). Se, **depois** de τ_hs, chegar a essa chave um
pacote que a C1 rejeita (por exemplo, flags inválidas), a C1 emite um alerta que a C2 não
emite (na C2 o pacote cai na lápide e é ignorado). De forma análoga, um SYN tardio abre
uma instância nova na C2 e não na C1, e a numeração de instâncias diverge. A inclusão
estrita só vale quando nenhum pacote anômalo chega a um fluxo já expirado. Nada foi
alterado para esconder o caso: `tcpmon.eval.inclusao.alertas_ausentes` lista qualquer
violação, e a avaliação a reporta. Nas fixtures do laboratório não há violação.

### D27 — Guarda temporal
2026-11-25 · fase 5 · aberta

Como os prazos ≤ t disparam antes de cada pacote, a guarda x ≤ τ_hs de `C.ACK`/`C.FIN` em
`SYNACK_VISTO` nunca falha. Ela continua implementada; se falhar, o fluxo expira com o
mesmo alerta da transição temporizada e o contador `guarda_temporal_violada` registra o
ocorrido (esperado: 0).
