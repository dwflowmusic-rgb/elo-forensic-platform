# 08 — Catálogo de Decisões Arquiteturais (ADR Catalog)

Este documento consolida as **8 Decisões Arquiteturais Estruturantes (`ADR-001` a `ADR-008`)** que regem a plataforma **ELO**, explicitando contexto, decisão tomada, alternativas descartadas e consequências empíricas.

---

## ADR-001: Arquitetura Limpa/Hexagonal com Isolamento Estrito entre Fases Auditado via AST
- **Status**: Aceito e Imposto em Build (`Portão G1`).
- **Contexto**: Pipelines forenses monolíticos tendem a acoplar leitura de disco, parsing binário, banco de dados e geração de laudos, tornando impossível testar regras probatórias sem montar volumes reais ou impedir efeitos colaterais cruzados entre etapas do EDRM.
- **Decisão**: Dividir `src/edrm/` em 10 pacotes verticais independentes (`igrm_governance`, `phase01`..`phase08`, `continuous_analysis`), cada um com `domain/` e `application/` 100% livres de I/O e zero imports entre fases, comunicando-se unicamente via `@dataclass(frozen=True, slots=True)` em `edrm.shared_kernel.contracts` e conectados em `EloForensicContainer`.
- **Alternativas Rejeitadas**: Arquitetura em camadas horizontais compartilhadas com ORM mutável (rejeitada por permitir mutação acidental de estado entre fases e dificultar provas de imutabilidade).
- **Consequências**: Suítes unitárias rodam em milissegundos com dublês `InMemory` equivalentes por Liskov (`G8`), e qualquer tentativa futura de violar fronteiras falha instantaneamente no linter sintático `G1`.

---

## ADR-002: Proibição Absoluta de Ponto Flutuante IEEE-754 (`Zero Float Lock`)
- **Status**: Aceito e Imposto em Build (`Portão G1`).
- **Contexto**: Em aritmética binária IEEE-754 (`float`), expressões triviais como `0.1 + 0.2 != 0.3` acumulam desvios de arredondamento em quebras bancárias (`SIMBA`), coordenadas geográficas (`ERB`) e escores estatísticos, comprometendo a reprodutibilidade exata entre arquiteturas de CPU e violando o rigor exigido em perícias contábil-financeiras.
- **Decisão**: Banir o tipo `float` das camadas nucleares via inspeção AST (`ast.Name(id="float")` e literais `float`):
  - Valores monetários representados exclusivamente em centavos inteiros `int` / SQL `BIGINT` (`CentsAmount`, `parse_money_to_cents`).
  - Tamanhos de arquivo em `ByteSize(int)`.
  - Coordenadas geográficas em milionésimos de grau inteiros (`MicroDegreesCoord(int)`).
  - Compressibilidade/entropia de blocos de $64\text{ KiB}$ em *permille* inteiro ($0..1000$).
  - Estatísticas (Cochran, RRF, distância euclidiana exata e Regra do 3) calculadas exclusivamente com `decimal.Decimal` sob precisão controlada de 28 dígitos.
- **Alternativas Rejeitadas**: Uso de `round(val, 2)` sobre `float` (rejeitado por manter erro acumulado intermediário).
- **Consequências**: Determinismo bit-a-bit idêntico em qualquer plataforma POSIX/x86_64/ARM64.

---

## ADR-003: Software 1.0 Governando IA (`BlockingVerifierEngine` + Calibração ISO/IEC 27041)
- **Status**: Aceito e Imposto em Build (`Portões G2, G6, G7`).
- **Contexto**: LLMs são estocásticos e suscetíveis tanto a alucinações numéricas/factuais quanto a ataques de *Indirect Prompt Injection* embutidos em documentos apreendidos no HD investigado.
- **Decisão**:
  1. Cálculos criptográficos, somas financeiras, normalizações UTC e cruzamentos de paridade são executados **100% por código determinístico Software 1.0**.
  2. Qualquer texto candidato atravessa primeiro o `PromptInjectionShield` na entrada e, na saída, sofre **dupla passagem obrigatória** pelo `BlockingVerifierEngine`, que exige âncora `ControlNumber` + `SHA-256` existente no catálogo e confere todos os números e hashes citados contra o corpus verificado.
  3. Antes de iniciar qualquer caso, `SelfCalibrationSuite` testa o próprio verificador com 1 controle positivo e 2 controles negativos sintéticos (**ISO/IEC 27041**).
- **Alternativas Rejeitadas**: Uso de "LLM-as-a-Judge" para revisar saídas de outro LLM (rejeitado por empilhar probabilidades sem garantia determinística).
- **Consequências**: Eliminação matemática de hashes inventados, centavos distorcidos ou entidades fantasma no Parecer Técnico-Pericial.

---

## ADR-004: Abertura SQLite Estritamente Imutável (`mode=ro&immutable=1` + `PRAGMA query_only=1`)
- **Status**: Aceito e Imposto em Build (`Portões G1, G4, G11.2`).
- **Contexto**: No SQLite3 padrão, mesmo abrir um banco apenas para `SELECT` pode disparar recuperação automática de *hot journal* ou alterar contadores/locks quando há arquivos `-wal`/`-shm` adjacentes, corrompendo o hash da evidência original.
- **Decisão**: Todo conector SQLite voltado a evidências (`ReadOnlyMediaScannerAdapter`, `ImmutableStructuralHealthAdapter`, `UniversalExtractorRunnerAdapter` e `StateIpedStorageReaderAdapter`) é obrigado a construir a URI `file:<path>?mode=ro&immutable=1` via `SafeOsPath.to_sqlite_immutable_uri()`, passar `uri=True` ao `sqlite3.connect` e executar imediatamente `PRAGMA query_only = 1;`. A inspeção de transações pendentes em `-wal` e `freelist` é feita por leitura binária direta em bytes (`PureSqliteBinaryForensicCarver`), nunca forçando checkpoint no banco original.
- **Alternativas Rejeitadas**: Copiar e consolidar `-wal` sobre o próprio arquivo antes de calcular hash (rejeitado por adulterar o estado probatório recebido).
- **Consequências**: Preservação 100% garantida de `PreScanSnapshot == PostScanSnapshot` e visibilidade separada entre registros ativos B-Tree (`ACTIVE_BTREE_ROW`), frames `-wal` (`WAL_UNCOMMITTED_FRAME`) e páginas livres (`CARVED_FREELIST_OR_UNALLOCATED`).

---

## ADR-005: Interoperabilidade Clean-Room com Casos Portáteis `.iped` Estatais (16 Shards GZIP)
- **Status**: Aceito e Imposto em Build (`Portão G11.2`).
- **Contexto**: No Brasil, grande parte das mídias disponibilizadas pela Polícia Federal, Polícias Civis e GAECOs consiste em casos portáteis gerados pelo indexador IPED contendo `sleuth.db` e até 16 bancos `iped/data/storage-0..15.db`. Depender exclusivamente de JVM externa pesada impede auditorias rápidas e não detecta omissões nos parâmetros originais de processamento estatal.
- **Decisão**: Construir em Python puro (`Clean-Room`, sem copiar código GPL/Java) dois componentes complementares:
  1. `StateIpedCaseAuditor` (Fase 01): audita perfis `fastmode`/`triage`, flags `deleteIgnoredItems`, HashDB supressor e `--downloadInternetData`.
  2. `StateIpedStorageReaderAdapter` (Fase 04): consulta `sleuth.db` e faz *streaming* GZIP direto dos blobs em `storage-0..15.db` em modo `immutable=1`, mantendo `IpedCliExternalBridge` apenas como ponte opcional supervisionada quando o binário externo estiver instalado.
- **Alternativas Rejeitadas**: Exigir instalação obrigatória de Java + IPED externo para abrir casos `.iped` (rejeitado por quebrar portabilidade zero-dependência e ocultar auditoria metodológica do perfil estatal).
- **Consequências**: Auditoria instantânea de casos `.iped` em qualquer máquina com Python 3.12+ e geração automática de quesitos específicos na Fase 07.

---

## ADR-006: Escalonamento Determinístico em 5 Filas ($P_0 \rightarrow P_4$) e Checkpoints de Contêineres
- **Status**: Aceito e Imposto em Build (`Portão G11.4`).
- **Contexto**: Processar arquivos em ordem puramente alfabética faz com que bancos de mensagens (`msgstore.db`) sejam lidos antes da agenda de contatos (`wa.db`) ou antes da descompactação de contêineres `.ufdr`/`.zip`, perdendo correlações de autoria (`@lid` $\rightarrow$ número real). Além disso, quedas de energia em arquivos `.zip` gigantes exigiriam retrabalho integral sem checkpoints.
- **Decisão**: Instituir o `PriorityTierScheduler` ($P_0$: mídias atômicas/`-wal`/não alocado $\rightarrow$ $P_1$: contêineres expansíveis $\rightarrow$ $P_2$: contatos `wa.db`/contas/`.lnk` $\rightarrow$ $P_3$: chats primários $\rightarrow$ $P_4$: fusão cross-backup e timeline UTC) aliado ao `ContainerExpansionCheckpointManager` persistido em `container_expansion_checkpoints`.
- **Alternativas Rejeitadas**: Grafo dinâmico assíncrono não determinístico com threads concorrentes sem barreira (rejeitado por produzir ordens de `ControlNumber` variáveis entre execuções).
- **Consequências**: Resolução determinística 100% reprodutível de identidades `@lid` e retomada resiliente a falhas abruptas.

---

## ADR-007: Busca Híbrida RRF ($k=60$) + `CompressedRoaringBitset` + Espaço Métrico Exato
- **Status**: Aceito e Imposto em Build (`Portões G6, G11.5`).
- **Contexto**: Buscas puramente léxicas perdem variações contextuais, enquanto buscas puramente vetoriais perdem números exatos de processos, CPFs, placas ou hashes. Adicionalmente, aproximações de ponto flutuante em similaridade vetorial podem violar a desigualdade triangular em agrupamentos periciais.
- **Decisão**:
  - Combinar `SQLite FTS5 (BM25)` e `DeterministicHashEmbedder` via **Reciprocal Rank Fusion** ($\text{score}(d) = \sum \frac{1}{60 + \text{rank}_i(d)}$ em `Decimal`).
  - Implementar `ExactMetricSimilarity` usando aritmética inteira/Decimal com raiz quadrada `Decimal.sqrt()` de 28 dígitos, preservando $d(x, z) \le d(x, y) + d(y, z)$.
  - Representar subconjuntos documentais da Fase 05 com `CompressedRoaringBitset` particionado em blocos de $2^{16}$ inteiros.
- **Alternativas Rejeitadas**: Índices aproximados probabilísticos HNSW não determinísticos como fonte primária (rejeitados por variar resultados conforme ordem de inserção ou semente).
- **Consequências**: Recuperação híbrida instantânea, 100% determinística e auditável.

---

## ADR-008: Soberania Loopback `127.0.0.1`, Token Efêmero HMAC e Segurança AST NIST SSDF v1.1
- **Status**: Aceito e Imposto em Build (`Portões G1, G11.1`).
- **Contexto**: Serviços locais que fazem bind em `0.0.0.0` ou carecem de autenticação expõem autos sigilosos na rede local (LAN/Wi-Fi do escritório ou laboratório) e a ataques *CSRF / DNS Rebinding* originados do navegador; paralelamente, desserializadores como `pickle` permitem execução remota de código ao abrir artefatos maliciosos.
- **Decisão**:
  - `ForensicLoopbackHttpServer` recusa em nível construtor qualquer host diferente de `"127.0.0.1"` (`SecrecySocketViolationError`) e exige em todas as requisições o cabeçalho `X-ELO-Session-Token` (256 bits gerados por `secrets.token_urlsafe(32)`) validado por `hmac.compare_digest`.
  - Bloquear na árvore sintática (`G1`) qualquer uso de `pickle`, `marshal`, `shelve`, `eval`, `exec`, `shell=True` e `verify=False`, registrando um Mini-SBOM auditável em `execution_manifest.json`.
- **Alternativas Rejeitadas**: Autenticação opcional por variável de ambiente desativada por padrão (rejeitada pelo princípio *Secure-by-Default* do NIST SSDF PW.1.3).
- **Consequências**: Conformidade integral com NIST SP 800-218 v1.1, Resolução CNJ n. 615/2025 e Recomendação CFOAB n. 001/2024.
