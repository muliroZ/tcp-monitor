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
