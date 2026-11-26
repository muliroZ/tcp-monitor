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

### D33 — Inclusão entre camadas por traço rejeitado **[equipe]**
2026-11-25 · fase 5 · decidida · resolve D26

A propriedade formal da hierarquia trata de traços rejeitados, não de alertas idênticos:
⊥ é absorvente, então rejeitar um prefixo é rejeitar o traço. O critério de inclusão passa a
ser:

- **C1 ⊆ C2:** para toda instância rejeitada pela C1 existe, na C2, uma instância rejeitada
  com a mesma chave e o mesmo instante do primeiro pacote, com `t_alerta` menor ou igual
  ao da C1. O motivo pode ser diferente (ex.: `HANDSHAKE_EXPIRADO` na C2 e
  `FLAGS_INVALIDAS` na C1). As instâncias são associadas pela chave mais o instante do
  primeiro pacote, nunca pelo número da instância, que diverge quando um SYN tardio abre
  uma instância nova só na C2.
- **C2 ⊆ C3:** continua valendo o teste por alerta idêntico, porque o agregador não remove
  fluxos.
- O teste por traço substitui o teste por alerta idêntico no critério de pronto da fase 5.
  A listagem atual (`tcpmon.eval.inclusao.alertas_ausentes`) vira o relatório de
  **divergência por janela**: alertas da C1 cuja janela não tem alerta da C2 com chave que
  case. Esse efeito existe, porque a C2 data o alerta pelo primeiro SYN e a C1 pelo pacote
  anômalo, e é reportado à parte na avaliação.
- O artigo enuncia a inclusão sobre traços rejeitados.

### D34 — `handshake_incompleto`: chave por origem e 60 SYNs **[equipe]**
2026-11-25 · fase 3 · decidida · altera D15 e D19

- A chave de associação do `handshake_incompleto` passa a ser `origem` (IP do atacante,
  que envia do próprio endereço). Com a chave por servidor, um alerta de tráfego benigno
  para o mesmo servidor na mesma janela contava como detecção (D19).
- `n_syn` passa de 20 para 60, com o mesmo espaçamento de 75 s (> τ_hs). O cenário dura
  cerca de 75 min, e o cenário `teste` cresce na mesma medida. Motivo: com 20 episódios o
  intervalo de Wilson é largo demais (20/20 dá limite inferior ≈ 0,84).
- Os episódios continuam pontuais (D15).
- Consequência: os alertas `AGG_HANDSHAKE_PENDENTE` têm `cliente` vazio e não casam com
  chave por origem. Na C3, a detecção desse cenário vem do alerta da camada 2 herdado,
  o que é coerente com a classe (temporal, modelo mínimo AT). A associação compara só o
  IP da coluna `cliente` (que traz IP:porta).
- O SYN Flood mantém a chave por servidor: as origens são forjadas e o modelo é por
  servidor. O guia deve ter a tabela de cenários atualizada.

### D35 — Diagnóstico do T medido no laboratório **[equipe]**
2026-11-25 · fase 8 · decidida · complementa D2 e D13

O T médio medido (38,7 ms) ficou abaixo dos 50 ms configurados no `netem`. A validação
analítica não é afetada, porque â e a lei de Little usam o Ê[T] medido. Antes de reportar,
faz-se um diagnóstico do aparato:

1. Histograma de T dos fluxos benignos da calibração, separado por `motivo_fim_pendente`
   (conclusão, RST, expiração).
2. Medição direta do atraso do `netem`: capturar dentro do container cliente e na ponte ao
   mesmo tempo e comparar os instantes de cada pacote.
3. Verificar o efeito do corte de atrasos negativos da normal e da fila `pfifo` sobre a
   distribuição efetiva.

Se a causa for erro de medição no código, ele é corrigido e registrado. Se for
comportamento do `netem` ou do kernel, o artigo reporta o atraso efetivo medido, com a
causa. Em nenhum caso os parâmetros do `netem` são mudados para que T chegue a 50 ms.

### D36 — Servidores monitorados e k por servidor **[equipe]**
2026-11-25 · fase 6 · decidida · resolve D28 e substitui D31

- Nova chave `agregador.servidores`: lista de IPs monitorados pelo detector de handshakes
  pendentes, definida **antes** de qualquer execução sobre o teste e gravada em `run.json`.
  - Laboratório: o servidor HTTP.
  - CIC-IDS2017 e CIC-DDoS2019: os servidores internos da rede vítima, conforme a
    documentação de cada dataset (lista a preencher pela equipe depois da conferência na
    página da UNB; ver D37).
- Retratos só para os servidores da lista, inclusive com N_s = 0.
- **k por servidor:** k_s empírico = menor inteiro tal que a fração de retratos do
  servidor s com N_s > k seja ≤ α. O k analítico também é por servidor, com â_s. A média
  ponderada da D31 deixa de ser usada. `calibration.json` grava um k por servidor.
- Motivo: juntar servidores com taxas muito diferentes forma uma mistura de Poissons
  (dispersão > 1) e deixa o servidor mais movimentado com P_FA bem acima de α.
- A P_FA é reportada por servidor e agregada. As ROC são por servidor.
- Servidores fora da lista não geram alerta do agregador (limitação declarada).

### D37 — Escopo dos datasets reais **[equipe]**
2026-11-25 · fase 9 · decidida

- **CIC-IDS2017** para as classes estruturais e temporais (varreduras com flags inválidas,
  handshakes) e como tráfego realista para as três configurações.
- **CIC-DDoS2019**, no dia que contém SYN Flood, para a camada 3 e a validação analítica em
  tráfego real.
- Motivo: até onde a equipe sabe, o CIC-IDS2017 não tem SYN Flood (os DoS são de
  aplicação, o DDoS é LOIC HTTP e o PortScan é vertical, contra um único host).
- **A conferir na página oficial da UNB antes de implementar** (as afirmações acima vieram
  de memória): lista de ataques e horários de cada dia, IPs e sistemas operacionais das
  vítimas, IP do atacante visto na captura interna (provavelmente o endereço do NAT) e qual
  dia do CIC-DDoS2019 contém SYN Flood.
- Pendência nova: definir o conjunto de calibração do CIC-DDoS2019, que não tem, até onde
  se sabe, um dia só benigno.
- O critério de pronto da fase 9 passa a ser: o pipeline completo roda sobre um dia de cada
  dataset.

### D38 — Rótulos do CIC-IDS2017 pela agenda oficial **[equipe]**
2026-11-25 · fase 9 · decidida

- Os episódios vêm da agenda oficial de ataques publicada pela UNB (ataque, início, fim,
  atacante, vítima), convertida para `labels.csv`.
- Fuso: a agenda está no horário local de New Brunswick (ADT, UTC−3); converte-se para
  epoch UTC, a mesma base dos timestamps do pcap.
- `chave_tipo` segue a regra do laboratório: `origem` para classes de sequência, flags e
  varredura; `servidor` para classes volumétricas contra um alvo.
- **Tolerância de ±60 s:** as janelas em `[t_inicio − 60, t_inicio)` e
  `(t_fim, t_fim + 60]` não são positivas nem benignas, como a zona de transição. Seus
  alertas são reportados à parte. Sensibilidade com 0, 60 e 300 s.
- Os CSVs por fluxo (CICFlowMeter) não definem rótulos; servem só de auditoria. Problemas
  conhecidos (Engelen et al., 2021; Lanvin et al., 2022) são registrados, nunca corrigidos
  no dado (regra 7). Escolher a fonte oficial dos rótulos é regra de conversão, não
  alteração do dado.
- O CIC-DDoS2019 usa a mesma regra, com o fuso e a agenda da sua própria documentação.

### D39 — τ_hs nos datasets reais **[equipe]**
2026-11-25 · fase 9 · decidida

- τ_hs = 63 s para todos os servidores, justificado pelo sistema operacional dos alvos
  (Linux com padrões: `tcp_synack_retries = 5`, RTO inicial de 1 s), a confirmar na
  documentação (D37).
- Análise de sensibilidade com o valor padrão do Windows Server, tirado de fonte oficial
  da Microsoft.
- `run.json` grava τ_hs com origem `documentacao_dataset`.

### D40 — Calibração do CIC-IDS2017 na segunda-feira **[equipe]**
2026-11-25 · fase 9 · decidida

A calibração usa o dia só benigno (segunda-feira, 3 de julho de 2017), com G = 120 s. Os
demais dias são teste. Nada medido no teste volta para a escolha de parâmetros.

### D41 — Baselines Zeek e Suricata entram no artigo **[equipe]**
2026-11-25 · fase 10 · decidida

- Os dois rodam sobre os mesmos pcaps, e os logs são convertidos para o esquema de
  `alerts.csv`.
- Enquadramento de complementaridade, não de competição: cobertura complementar, latência,
  falsos alarmes em tráfego benigno e custo computacional.
- Versões exatas de Zeek e Suricata e a data do conjunto de regras (ET Open) ficam fixadas
  e gravadas em `run.json`.
- A conversão (`conn_state` do Zeek, como S0, REJ e SH, e as assinaturas do Suricata para as
  classes de anomalia) é registrada aqui, item por item, antes da execução.

### Pendências que continuam com a equipe

- Conferir na página da UNB os fatos listados na D37 e preencher `agregador.servidores`.
- Baixar os pcaps do CIC-IDS2017 (segunda-feira e dias de ataque) e do dia de SYN Flood do
  CIC-DDoS2019. A equipe ainda não os tem.
- Definir a calibração do CIC-DDoS2019 (D37).

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
2026-11-25 · fase 3 · decidida (D35)

O `netem` com *jitter* reordena pacotes por padrão. Foi adicionada uma fila `pfifo` filha
(`limit 1000`): o atraso varia, mas a ordem é preservada. Motivo: a decisão D2 pediu
latência, não reordenação; reordenação é uma limitação discutida à parte no artigo.

**Verificação (D52):** neste kernel a fila filha **não** impede a reordenação. O ACK puro do
handshake e o segmento de dados que o segue trocam de ordem em cerca de metade das conexões,
com ou sem a `pfifo`. A intenção da D13 não é cumprida pelo aparato. A equipe decidiu manter
os dados e reportar a reordenação como limitação (D52).

### D14 — Backlog do servidor e alvos da varredura
2026-11-25 · fase 3 · aberta

O servidor HTTP (Python, HTTP/1.0) usa `listen(511)`, o padrão do nginx; as sysctls do
kernel ficam no padrão (D1). A varredura percorre 20 hosts que escutam na porta 80 sem
aceitar conexões (o kernel completa o handshake). O atacante não bloqueia RST na varredura:
o kernel dele reseta cada SYN-ACK, como numa varredura SYN real.

### D15 — Estrutura dos episódios
2026-11-25 · fase 3 · decidida, alterada pela D34

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
2026-11-25 · fase 3 · decidida, alterada pela D34

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

### D26 — Exceção teórica à inclusão C1 ⊆ C2
2026-11-25 · fase 5 · decidida (D33)

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

### D28 — Conjunto de servidores dos retratos
2026-11-25 · fase 6 · decidida (D36)

A cada fim de janela tira-se um retrato de N_s para todo servidor (IP) que já recebeu ao
menos um SYN de abertura desde o início da captura, inclusive com N_s = 0. A janela final
incompleta não tem retrato (D24). No laboratório isso é o servidor HTTP e, depois da
varredura, os alvos dela. **Para o CIC-IDS2017 isso precisa ser revisto**: com milhares de
servidores ociosos, os retratos com N_s = 0 dominariam a calibração de k.

### D29 — Campos dos alertas do agregador
2026-11-25 · fase 6 · aberta

`janela = i`, `t_evidencia` = início da janela (t0 + i·W) e `t_alerta` = fim da janela (instante
da decisão). `AGG_HANDSHAKE_PENDENTE` tem `servidor` = IP e `cliente` vazio;
`AGG_VARREDURA_HORIZONTAL` tem `cliente` = IP de origem e `servidor` vazio, com a porta de
destino e a contagem em `detalhe`.

### D30 — "Fluxos iniciados" na varredura
2026-11-25 · fase 6 · aberta

A contagem de varredura considera toda instância de fluxo nova entregue aos monitores (não
`midstream`) cujo primeiro pacote está na janela, agrupada por (IP do cliente, porta do
servidor) e contando IPs de servidor distintos. Não se restringe a fluxos abertos com SYN.

### D31 — Estimativa de â e k analítico com vários servidores
2026-11-25 · fase 6 · substituída pela D36

λ̂_L por servidor = instâncias com primeiro `C.SYN` para o servidor ÷ (último timestamp − t0);
Ê[T] também é estimado por servidor (fluxos `truncado` fora; expirados entram com T = τ_hs).
Com mais de um servidor, o k analítico usa a P_FA média ponderada pelo número de retratos de
cada servidor — a mesma população do k empírico. No laboratório há um único servidor
benigno, e as duas formas coincidem.

### D32 — Camadas na calibração
2026-11-25 · fase 6 · aberta

`tcpmon calibrate` sempre roda as camadas 1 e 2 (como pede o guia), independentemente de
`camadas` na configuração, com o agregador em modo de coleta (retratos e contagens sem
decisão). A pasta da calibração (`results/.../<run_id>-calib/`) guarda `flows.csv`,
`snapshots.csv`, `varredura.csv` e `calibration.json`.

> D42–D50 são as decisões de implementação das fases 7 e 8, renumeradas porque os números
> D33–D41 passaram a identificar decisões da equipe.

### D42 — Janela positiva × zona de transição
2026-11-25 · fase 7 · aberta

Lido ao pé da letra, "janelas que intersectam `[t_fim, t_fim + τ_hs]`" incluiria a própria
janela que contém `t_fim` — e um episódio pontual nunca teria janela positiva. Por isso a
janela que intersecta o episódio é positiva; a zona de transição são as demais janelas que
intersectam `[t_fim, t_fim + τ_hs]`. Uma janela positiva para qualquer episódio nunca é de
transição; benignas são as que não são nem uma coisa nem outra. A zona de transição vale para
todas as classes.

### D43 — Latência
2026-11-25 · fase 7 · aberta

Latência do episódio = `t_alerta` do primeiro alerta que casa com ele (mesma chave e janela
de `t_evidencia` entre as janelas positivas do episódio) − `t_inicio`. Reporta-se mediana e
p95 por configuração e classe, mais a latência de cada episódio em `episodios.csv`. O
documento de pesquisa também cita latência em pacotes; o guia define em tempo, e é o que se
mede.

### D44 — Precisão, F1 e falso alarme
2026-11-25 · fase 7 · aberta

FP e TN são contados nas janelas benignas, com qualquer alerta de qualquer camada; por isso
P_FA é a mesma para todas as classes de uma configuração. Precisão por classe =
TP_classe / (TP_classe + FP). `falsos_alarmes.csv` detalha os motivos dos alertas em janelas
benignas e `transicao.csv` os alertas nas zonas de transição.

### D45 — McNemar e diferença de P_D
2026-11-25 · fase 7 · aberta

Pares C1×C2, C2×C3 e C1×C3, por classe, sobre as janelas positivas da classe. Exato
(binomial) com menos de 25 discordâncias; senão qui-quadrado com correção de continuidade.
Holm sobre todos os testes da avaliação. A diferença reportada é P_D(B) − P_D(A) com IC de
Newcombe para dados pareados (método 10, intervalos de Wilson e φ corrigido), conferido
contra a tabela de referência 20/12/2/16 (IC 0,056156 a 0,329207).

### D46 — Alertas fora das janelas completas
2026-11-25 · fase 7 · aberta

Alertas cuja janela é a final incompleta não entram nas métricas; a quantidade aparece em
`desempenho.csv` (`alertas_fora_das_janelas_completas`).

### D47 — Testes de aderência à Poisson
2026-11-25 · fase 8 · aberta

Qui-quadrado dos retratos benignos da calibração contra Poisson(â), com a última classe
sendo a cauda P(N ≥ K) e classes de frequência esperada < 5 agrupadas com a vizinha (da
cauda para a cabeça e depois no meio). Como â vem da mesma calibração, gl = classes − 2.
KS dos intervalos entre primeiros SYNs benignos contra a exponencial com média estimada dos
próprios dados: o valor-p é aproximado (registrado no `analytic.json`).

### D48 — População dos pontos empíricos da ROC
2026-11-25 · fase 8 · aberta

Para cada episódio de SYN Flood, P_FA empírica = fração dos retratos **do servidor alvo**
nas janelas benignas do teste com N_s > k; P_D empírica = fração dos retratos do servidor
alvo com `t_fim` entre `t_inicio + τ_hs` e `t_fim` do episódio (regime estacionário). Usar só o
servidor alvo mantém a comparação com a curva teórica, que usa o â desse servidor; os alvos
da varredura (quase sempre N_s = 0) diluiriam a P_FA.

### D49 — Ajuste de T com censura
2026-11-25 · fase 8 · aberta

Exponencial, log-normal e Weibull (locação fixa em 0) ajustadas por máxima verossimilhança
com `scipy.stats.CensoredData`: fluxos expirados entram como censurados à direita em τ_hs.
Valores T ≤ 0 (impossíveis para essas distribuições) são excluídos e contados em
`n_T_nao_positivo_excluidos`. O AIC de cada ajuste é reportado.

### D50 — Execução completa dos experimentos
2026-11-25 · fase 8 · aberta

`experiments/run.py` roda cada configuração (C1, C2, C3) num processo próprio para que o pico
de memória (`ru_maxrss`) seja o da configuração. A calibração do laboratório usa a semente 43
e o teste a 42 (sementes diferentes, como pede o guia), definidas em
`configs/experiments/lab.yaml`. A análise de sensibilidade (W = 5 e 10 s) recalibra k e
k_scan para cada janela, sobre o mesmo pcap de calibração.

### D51 — Detalhes de implementação da D36
2026-11-25 · fase 6 · aberta

- `agregador.servidores` é obrigatório sempre que o agregador roda (C3 e calibração); sem a
  lista, a execução para com erro. Os IPs são normalizados e não podem se repetir.
- `agregador.k` aceita um inteiro (o mesmo k para todos os servidores da lista) ou um
  mapeamento IP → k; o `calibration.json` grava o mapeamento. `k_scan` continua único.
- Um servidor da lista sem nenhum SYN na calibração tem λ̂_L = 0 e â = 0 (Ê[T] indefinido);
  o k empírico dele sai dos retratos (todos N_s = 0, logo k = 0).
- `tcpmon run` recusa uma calibração feita para outra lista de servidores.
- Na avaliação, `pfa_por_servidor.csv` conta como falso alarme do servidor s a janela benigna
  com alerta cujo campo `servidor` é s (qualquer camada) e, à parte, só os
  `AGG_HANDSHAKE_PENDENTE`. A P_FA agregada continua em `metricas.csv`.
- Na validação analítica, `analytic.json` traz `pfa_por_servidor` (retratos benignos do teste
  com N_s > k_s contra `poisson.sf(k_s, â_s)`) e as figuras ganham sufixo com o IP quando há
  mais de um servidor.

### D52 — Resultado do diagnóstico da D35: reordenação no `netem` **[equipe]**
2026-11-26 · fase 8 · decidida · resultado da D35; contradiz a verificação da D13

**Causa medida.** O `netem` sorteia um atraso independente N(50, 20) ms para cada pacote. O
ACK puro do handshake e o segmento da requisição HTTP, que o cliente envia logo depois,
recebem atrasos independentes; em cerca de metade das conexões o segmento de dados chega à
ponte antes do ACK puro. O handshake termina no primeiro pacote do cliente com ACK, com ou sem
dados: no monitor (primeiro `C.ACK` em `SYNACK_VISTO`) e também no kernel do servidor, que
estabelece a conexão com esse segmento. Assim, T = mínimo de dois atrasos independentes, e
não um atraso.

**Medidas** (`lab/diagnostico_netem.py --semente 44`, 120 s de tráfego benigno por variante,
captura na ponte e dentro do container cliente; kernel 7.3.4-300.fc45; resultados em
`results/diagnostico_netem/20261126-113104/`):

| Variante | Conexões | 1º ACK com dados | T (o monitor) | T pelo ACK puro | SYN app → ponte |
| --- | --- | --- | --- | --- | --- |
| configurado (50 ± 20 ms, `pfifo`) | 547 | 50,3% | 39,5 ± 15,9 ms | 49,5 ± 18,7 ms | 51,1 ± 19,4 ms |
| sem fila filha | 585 | 48,5% | 38,9 ± 16,9 ms | 48,9 ± 19,5 ms | 49,8 ± 20,5 ms |
| sem jitter (50 ms) | 583 | 0% | 50,2 ± 0,08 ms | 50,2 ± 0,08 ms | 50,5 ± 2,2 ms |

Referências teóricas (normal truncada em 0): um atraso tem média 50,35 ms; o mínimo de dois
atrasos independentes tem média 39,28 ms, dp 15,80 ms, p5 12,8 ms e p95 65,3 ms. Na variante
configurada, T medido tem p5 12,1 ms e p95 65,0 ms. Na calibração do experimento
(`calibracao_s43.pcap`), o pacote de dados chega antes do ACK puro em 50,0% das 3 819
conexões; T pelo primeiro ACK = 38,9 ms e pelo ACK puro = 48,5 ms.

**Conclusões.**

- Não é erro de medição no código: com atraso constante (sem jitter), T medido na ponte é
  50,2 ms. O ponto de captura e a leitura do pcap estão corretos.
- A fila `pfifo` filha não muda nada: a reordenação ocorre igual com e sem ela. A
  verificação da D13 (“a ordem é preservada”) é falsa neste kernel.
- O corte de atrasos negativos da normal é desprezível (0,6% da massa; média 50,35 ms).
- O T que o monitor mede é o tempo que a conexão de fato fica pendente no servidor. Ê[T] = 38,7 ms
  na calibração é o valor efetivo, e é ele que entra em â e na lei de Little.
- Pela D35, os parâmetros do `netem` não foram alterados. O artigo deve reportar o atraso
  efetivo e a causa: o `netem` com jitter reordena pacotes de uma mesma conexão.

**Controles.** A captura dentro do container vê o egresso **depois** do qdisc (diferença
ponte − container de 0,02 ms na saída), então ela não mede o atraso do `netem` e não serve
para contar reordenação. Na entrada, container − ponte fica entre 0 e 0,04 ms. Pacotes
idênticos (ACKs duplicados) são pareados pela ordem de ocorrência. Portas locais
reutilizadas são excluídas: 19 na variante configurada, 0 sem fila filha, 1 sem jitter.

**Decisão da equipe (2026-11-26):** os dados ficam como estão e a reordenação vira limitação do
artigo. As capturas `calibracao_s43` e `teste_s42` e o `netem` (50 ± 20 ms, normal, com a fila
`pfifo`) não mudam. O artigo reporta o T efetivo medido (Ê[T] = 38,7 ms na calibração), a causa
(o `netem` com jitter reordena pacotes de uma mesma conexão; o handshake termina no primeiro
segmento do cliente com ACK) e o resultado da variante sem jitter como controle.

### D53 — P_D teórica também com a taxa realizada do episódio **[equipe]**
2026-11-26 · fase 8 · decidida

O guia define b = λ_A × τ_hs com o λ_A do gerador e pede para reportar λ̂_A junto. As chegadas
de ataque são Poisson, então o número de SYNs de um episódio de 300 s varia: na captura `teste`
(semente 42), o episódio de λ_A = 0,05/s teve 9 SYNs forjados (λ̂_A = 0,03/s) em vez dos cerca
de 15 esperados. A comparação pedida pelo guia (P_D teórica com λ_A nominal) continua igual.
`pd_vs_taxa.csv` e `pd_no_k_escolhido` em `analytic.json` ganham `lambda_A_estimado` e
`P_D_teorica_lambda_estimado` = `poisson.sf(k, â + λ̂_A · τ_hs)`, e `pd_vs_taxa.png` mostra
esse valor como losango vazado. λ̂_A é estimado no episódio inteiro, pelos fluxos da faixa
forjada. Motivo: separar o erro do modelo da variação amostral do gerador.

**Decisão da equipe (2026-11-26):** mantida como está.

### D54 — Dependência entre janelas e intervalos de Wilson **[equipe]**
2026-11-26 · fase 7–8 · decidida · sem mudança no código

O guia pede intervalos de Wilson para P_D e P_FA por janela, e o Wilson supõe janelas
independentes. Não são: um SYN de ataque fica pendente τ_hs = 63 s e entra em cerca de 63
retratos seguidos com W = 1 s; um episódio de SYN Flood a 0,02/s tem uns 6 SYNs. Na prática, os
237 retratos estacionários desse episódio carregam bem menos informação do que 237 ensaios
independentes, e o IC de Wilson subestima a incerteza, principalmente nas taxas baixas e na
P_FA do agregador. O mesmo vale, em menor grau, para o McNemar sobre janelas pareadas.
Mantido como o guia pede. Opções levadas à equipe: reportar a limitação; acrescentar ICs por
bootstrap em blocos (blocos ≥ τ_hs); ou repetir os episódios de taxa baixa com várias sementes
e usar o episódio como unidade.

**Decisão da equipe (2026-11-26):** reportar como limitação do artigo. Os intervalos de Wilson e
o McNemar continuam como o guia pede, sem ICs adicionais. O artigo deve dizer que as janelas
não são independentes (cada SYN de ataque fica pendente τ_hs e aparece em retratos seguidos)
e que, por isso, os ICs por janela subestimam a incerteza, sobretudo nas taxas baixas de SYN
Flood e na P_FA do agregador.

### D55 — Efeito de W na calibração do k empírico **[equipe]**
2026-11-26 · fase 6–8 · decidida · sem mudança no código

Os retratos são tirados no fim de cada janela, então a calibração de 15 min rende 903
retratos com W = 1 s, 180 com W = 5 s e 90 com W = 10 s. Com α = 0,01, o k empírico sai 2 com
W = 1 s e 1 com W = 5 s e 10 s; o k analítico é 2 nos três casos. Com k = 1, a P_FA do
agregador no teste é 3/191 = 0,016 (W = 5 s) e 2/57 = 0,035 (W = 10 s), acima de α, mas de
acordo com a teoria para k = 1 (`poisson.sf(1, â)` = 0,0169). Com 90 ou 180 retratos, o
quantil 1 − α = 0,99 fica mal estimado: no máximo 0 ou 1 retrato acima de k. Mantido como o
guia pede (k empírico da calibração, mesmo W). Opções levadas à equipe: tirar os retratos da
calibração com W = 1 s em qualquer configuração, aumentar a calibração, ou usar o k analítico
quando houver poucos retratos.

**Decisão da equipe (2026-11-26):** mantida como está. O k empírico continua vindo da calibração
com o mesmo W da execução, e os resultados de W = 5 s e 10 s (k = 1) são reportados como estão.
