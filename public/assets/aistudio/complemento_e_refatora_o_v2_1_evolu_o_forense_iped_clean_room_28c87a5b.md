# MANIFESTO DE COMPLEMENTO E REFATORAÇÃO CIRÚRGICA (DELTA v2.1) — EVOLUÇÃO FORENSE *CLEAN-ROOM* (IPED + NIST SSDF v1.1 + RECONCILIAÇÃO EDRM 2.0)

## 1. PROPÓSITO E REGRA DE OURO DA REFATORAÇÃO NÃO-DESTRUTIVA

Este documento é uma **Especificação Delta Incremental (`v2.1`)** sobre o **Manifesto Mestre Greenfield (`v2.0`)** já em implementação. Seu objetivo é evoluir e refinar a plataforma **ELO** sem descartar, reescrever à toa ou quebrar qualquer módulo, contrato ou teste já aprovado nas ondas anteriores.

### 1.1 Protocolo de Preservação do Código Existente e Compatibilidade Retroativa
1. **Inspeção Antes da Edição:** Antes de alterar qualquer linha, inspecione a árvore atual de `src/edrm/` e `tests/` para identificar exatamente em qual Onda (`1` a `5`) o projeto se encontra.
2. **Extensão Aberta-Fechada (OCP) Antes de Modificação:** Novas capacidades entram prioritariamente como **novos adaptadores, novos validadores puros, novos extratores registrados em `ExtractorRegistry`/`SignatureRegistry` e novos casos de uso coesos**, mantendo intactos os fluxos que já passam nos testes.
3. **Evolução Compatível de Contratos (`@dataclass(frozen=True, slots=True)`):** Todo novo atributo adicionado aos contratos em `edrm/shared_kernel/contracts.py` deve possuir **valor padrão imutável seguro** (`= ()`, `= None`, `= False`), garantindo que `100%` dos testes unitários e chamadas das ondas anteriores continuem compilando e passando sem quebra de assinatura.
4. **Licenciamento Soberano (100% *Clean-Room* vs. GNU GPLv3):** É terminantemente proibido copiar código Java do IPED. Aproveitamos: (a) a leitura imutável em Python puro dos bancos e arquivos de configuração deixados pelo IPED em mídias policiais entregues à defesa; (b) algoritmos universais reimplementados do zero em Python 3.12+ tipado; e (c) invocação *out-of-process* via CLI quando instalado.

### 1.2 Reconciliação Normativa Estrita (Rigor Documental e Científico)
Refatore strings normativas, cabeçalhos de relatórios e *docstrings* para refletir com exatidão documental absoluta:
* **IGRM v4.1:** Citar sempre como *"IGRM v4.1 (versão vigente oficial do EDRM)"*, **sem** atribuir a data não confirmada de *"junho de 2026"*.
* **Diretrizes de Processamento EDRM (`1.0` a `5.0`):** Tratá-las como **piso funcional verificável (*"floor, not a ceiling"*)** cuja ordem operacional deve se adaptar à dependência técnica dos dados — o que fundamenta oficialmente a refatoração da Fase 04 para o **Escalonamento em 5 Estágios de Dependência Referencial ($P_0 \rightarrow P_4$)**.
* **Fronteira Metodológica Clara:** Distinguir nos relatórios dos dossiês o que é **padrão conceitual do EDRM 2.0** (CC BY 4.0 EDRM.net, publicado em 01/09/2026, com *left lean*, bloco *Data Acquisition*, *Continuous Analysis*, *Review* como nexo e *Disposition*) do que constitui **engenharia forense e adaptação processual penal brasileira do ELO** (correlação com os $10$ passos do art. 158-B do CPP, marcação lógica sem descarte físico no *De-NISTing*, separação determinística vs. IA e auditoria de casos `.iped` / POP Senasp Vol. 5 — 2024).

---

## 2. REFATORAÇÕES E COMPLEMENTOS EXATOS POR PACOTE ARQUITETURAL

### 2.1 DELTA NO NÚCLEO COMPARTILHADO (`edrm.shared_kernel`)

1. **Novos Enums Forenses (`enums.py`):**
   * `ProcessingPriorityTier`:
     * `P0_ATOMIC_MEDIA_WAL_UNALLOCATED = 0` (mídias soltas, PDFs, espaço não alocado e arquivos auxiliares `-wal`/`-journal` para garantir que hashes e logs transacionais existam antes dos bancos);
     * `P1_EXPANDABLE_CONTAINERS_IMAGES = 1` (`E01`, `EX01`, `RAW`, `UFDR`, `UFDX`, `ZIP`, `7Z`, `RAR`, casos `.iped`);
     * `P2_CONTACTS_ACCOUNTS_SYSTEM_ARTIFACTS = 2` (SQLites gerais, `wa.db`, `ContactsV2.sqlite`, `UFED_CONTACT`, `UFED_USER_ACCOUNT`, `.lnk`, `USBStor`, `$UsnJrnl`);
     * `P3_PRIMARY_MESSAGING_CHATS = 3` (`msgstore.db`, `ChatStorage.sqlite`, `cache4.db` Telegram, Discord, Skype, `UFED_CHAT`);
     * `P4_CROSS_BACKUP_MERGE_TIMELINE = 4` (mesclagens multi-backup e reconciliação referencial final).
   * `SqliteRowAllocationState`:
     * `ACTIVE_BTREE_ROW` (linha ativa lida das páginas *B-Tree* oficiais);
     * `WAL_UNCOMMITTED_FRAME` (registro recuperado de *frame* de *Write-Ahead Log* ainda não consolidado);
     * `CARVED_FREELIST_OR_UNALLOCATED` (registro apagado/fragmento reconstruído de *freelist* ou espaço livre de página — alerta obrigatório conforme NIST IR 8354).
   * `StateIpedProfileRisk`: `FORENSIC_FULL`, `FASTMODE_OR_TRIAGE_OMISSIVE`, `BLIND_MODE`, `CUSTOM_MODIFIED`, `NOT_IPED_SOURCE`.

2. **Motor Linear de Validadores Matemáticos Brasileiros, Fiscais e Cripto (`validators_br_crypto.py` — 100% Puro, Zero I/O, Zero `float`):**
   * Implemente um varredor linear determinístico em passagem única $O(n)$ (baseado em Trie / autômato `Aho-Corasick` de prefixos/padrões sem *catastrophic backtracking*, com teto de segurança `MAX_HITS_PER_ITEM = 50_000`) acoplado a funções puras de validação algébrica estrita:
     * **Documentos Civis e Veiculares Brasileiros:** `validate_cpf` (Módulo 11, rejeitando sequências repetidas `111...`), `validate_cnpj` (Módulo 11 alfanumérico/numérico), `validate_cnh`, `validate_pis_pasep`, `validate_titulo_eleitor`, `validate_renavam` e `validate_mercosul_plate`.
     * **Financeiro e Fiscal Brasileiro (Cruzamento Automático com SIMBA):**
       * `validate_boleto_linha_digitavel` ($47$ ou $48$ dígitos com conferência exata dos dígitos verificadores Módulo 10 nos campos e Módulo 11 geral, extraindo valor em centavos inteiros `int` e fator de vencimento);
       * `validate_chave_nfe_danfe` ($44$ dígitos numéricos validando UF IBGE, AAMM, CNPJ emitente, modelo `55`/`65` e dígito verificador Módulo 11 no $44^\circ$ dígito).
     * **Financeiro Internacional e Criptoativos:** `validate_credit_card_luhn` (algoritmo de Luhn), `validate_bitcoin_address` (`Base58Check` duplo `SHA-256` e `Bech32` `bc1`), `validate_ethereum_eip55`, `validate_tron_address` e `validate_bip39_seed_checksum` (conferindo os bits finais de `SHA-256` da entropia da frase-semente).

3. **Sensor Inteiro de Compressibilidade para Criptografia Sem Cabeçalho (`compressibility_probe.py` — Zero `float`):**
   * Em vez de entropia de Shannon em ponto flutuante, meça em janelas deslizantes de $65.536\text{ bytes}$ ($64\text{ KiB}$) com sobreposição (*overlap*) de $1.024\text{ bytes}$ ($1\text{ KiB}$) a razão inteira em milésimos (`permille: int = (compressed_len * 1000) // raw_len`) usando compressor rápido determinístico (`zlib` nível `1` na biblioteca padrão Python ou `lz4.block` se presente).
   * Se `permille >= 995` em arquivo $\ge 64\text{ KiB}$ cuja assinatura de $16\text{ bytes}$ for `UNKNOWN_BINARY` (isto é, não sendo `JPEG`, `PNG`, `MP4`, `ZIP`, `RAR`, `7Z`, `GZIP` ou `PDF` comprimido), classifique como `HEADERLESS_HIGH_ENTROPY_ENCRYPTED` (capturando volumes VeraCrypt, TrueCrypt, BitLocker bruto ou contêineres AES proprietários sem *magic bytes*).
   * Na extração de strings brutas de arquivos corrompidos/desconhecidos, descarte janelas com `permille >= 995` para não poluir o índice `BM25` com lixo pseudoaleatório.

4. **Extensão Retrocompatível dos Contratos (`contracts.py`):**
   * Adicione `StateIpedAuditReport` (com default `None`) em `MediaAutoDiscoveryBlueprint` e `Phase01ToPhase02Contract`.
   * Adicione `headerless_encrypted_candidates: tuple[str, ...] = ()` em `Phase01ToPhase02Contract`.
   * Adicione `recovered_deleted_sqlite_rows_count: int = 0` e `physical_link_tracker_findings_count: int = 0` em `Phase04ToPhase05Contract`.

---

### 2.2 DELTA NA GOVERNANÇA E SEGURANÇA DE SOFTWARE (`edrm.igrm_governance` — NIST SSDF v1.1)

Incorpore práticas executáveis do **NIST SP 800-218 (SSDF v1.1 — `PO.4`, `PS.1`, `PS.3`, `PW.1`, `PW.4`, `PW.7`, `PW.8`)** para blindar o ELO exatamente onde ferramentas forenses legadas falham:
1. **Bloqueio de Desserialização Insegura (`PW.5` / `PW.7` — Resposta à falha `SEC-03` do IPED):** Proíba via auditoria AST no Portão `G1` qualquer importação ou chamada de `pickle`, `cPickle`, `marshal`, `shelve` ou `yaml.unsafe_load` em todo o código-fonte. Toda persistência usa apenas SQLite/PostgreSQL parametrizado e JSON validado.
2. **Integridade de Rede e TLS Estrito (`PW.1.3` — Resposta às falhas `SEC-01`, `SEC-02` e `SEC-04` do IPED):**
   * Proíba via AST qualquer desativação de verificação de certificado SSL (`verify=False`, `ssl._create_unverified_context`, `CERT_NONE`).
   * Qualquer servidor local (`local_api.py` ou endpoint de inferência) aceita *bind* exclusivamente em `127.0.0.1` exigindo cabeçalho de token efêmero de sessão (`X-ELO-Session-Token` gerado via `secrets.token_urlsafe(32)`), jamais expondo portas abertas em `0.0.0.0`.
3. **Guardião Pai-Filho de Subprocessos e Limpeza de `staging/` (`SubprocessSandboxSupervisor`):**
   * Qualquer ferramenta externa ou *worker* pesado roda sob supervisão com *timeout* explícito, memória monitorada e registro prévio de sua subpasta temporária dentro de `workspace/staging/`. Se o processo filho travar ou sofrer *crash* nativo, o supervisor encerra a árvore de processos, limpa imediatamente os temporários órfãos e grava o incidente em `DeadLetterStore` sem derrubar o pipeline principal.
4. **Proveniência e Manifesto de Composição (`PS.3` — Mini-SBOM no `execution_manifest.json`):** Inclua no manifesto de execução a versão exata do interpretador Python, plataforma e lista determinística `(pacote, versão, sha256_módulo)` de todos os componentes carregados.

---

### 2.3 DELTA NAS FASES 01 E 02 (`edrm.phase01_identification` & `edrm.phase02_preservation`)

1. **Novo Módulo: Auditor Automático de Casos Portáteis `.iped` Entregues pelo Estado (`StateIpedCaseAuditor`):**
   * **Gatilho de Detecção Automática na Fase 01:** Ao varrer `--source`, se encontrar marcadores estruturais de saída do IPED (`IPED-SearchApp.exe`, `iped/conf/IPEDConfig.txt`, `iped/conf/TaskInstaller.xml`, `sleuth.db` ou `iped/data/storage-0.db`), reconheça a fonte como `STATE_IPED_PORTABLE_CASE`.
   * **Inspeção Pericial Determinística (100% Somente Leitura):**
     1. *Auditoria de Perfil e Omissão Metodológica:* Faz *parse* de `IPEDConfig.txt`, `LocalConfig.txt`, `TaskInstaller.xml` e `ParserConfig.xml` verificando se o perito estatal rodou perfil reduzido (`fastmode`, `triage` ou `blind`) ou desabilitou tarefas críticas (`enableCarving`, `enableLedCarving`, `enableSQLiteUndelete` / recuperação de apagados, `enableOCR`, `processUnallocatedSpace`, `hash` sem `sha-256`).
     2. *Auditoria de Supressão de Arquivos:* Verifica `IgnoreFilesByPathTask.js`, exclusão por `HashDB` e exclusão física de subitens ignorados (`deleteIgnoredItemData`).
     3. *Auditoria de Contaminação Externa (`--downloadInternetData`):* Inspeciona logs/configurações do caso `.iped` procurando indícios de ativação do `LinkDownloader` do WhatsApp (download de mídias na internet/CDN da Meta fora da mídia apreendida, violando o isolamento do art. 158-B, II, do CPP).
     4. *Alerta de Prova Negativa em `palavras-chave.txt`:* Registra que o método `Manager.filterKeywords()` do IPED remove da lista salva os termos pesquisados que obtiveram $0$ ocorrências, impedindo presumir que um termo ausente da lista final não foi pesquisado ou vice-versa sem o auto circunstanciado.
2. **Integração da Sonda de Criptografia Sem Assinatura:**
   * Conecte `compressibility_probe.py` na Microfase 1.3 (Identificação) e na Subetapa 2.3 — Eixo 6 (`ACESSIBILIDADE_E_CIFRAGEM` da Preservação), sinalizando arquivos `HEADERLESS_HIGH_ENTROPY_ENCRYPTED`.

---

### 2.4 DELTA NA FASE 04 — PROCESSAMENTO UNIVERSAL (`edrm.phase04_processing`)

*(Se a Onda 3 já tiver sido escrita, refatore cirurgicamente os pontos abaixo mantendo os contratos; se ainda for construída, já nasça com este desenho completo).*

1. **Refatoração do Orquestrador da Subetapa 4.1 para as 5 Filas de Dependência Referencial ($P_0 \rightarrow P_4$):**
   * Substitua o consumo linear simples por uma fila multi-estágio indexada por `ProcessingPriorityTier` (`0` a `4`):
     * Dentro de cada estágio $P_k$, aplique embaralhamento determinístico $O(1)$ (*swap-and-pop* usando `random.Random(seed)` isolado) para diluir gargalos de arquivos grandes sem perder reprodutibilidade;
     * Ao esvaziar o estágio $P_k$, execute uma **Barreira de Sincronização e Commit/Refresh do Catálogo**, garantindo que, quando o estágio $P_3$ (ex.: `WhatsApp` / `Telegram` / `UFED_CHAT`) iniciar, $100\%$ dos hashes de mídias ($P_0$) e $100\%$ das agendas de contatos e `-wal` ($P_0$/$P_2$) já estejam consultáveis no repositório!
   * **Três Travas Anti-Colapso e Anti-Perda na Expansão de Contêineres:**
     1. *Semáforo `max_expanding_containers` (padrão `2` a `4`):* Limita quantos contêineres pesados são expandidos simultaneamente em `staging/`;
     2. *Trava Anti-Recursão por Hash:* Aborta expansão se `child_sha256 == parent_container_sha256`;
     3. *Retomada com Verificação de Pais Incompletos (`verify_incomplete_parent_containers`):* Na retomada de *checkpoint* após interrupção, verifica se todo contêiner pai marcado como `EXPANDING` atingiu `COMPLETED_ALL_CHILDREN = True`; caso contrário, reprocessa os filhos faltantes do pai de forma idempotente (`ON CONFLICT DO NOTHING`) para jamais perder subitens silenciosamente!

2. **Leitor Nativo em Python dos 16 Shards do IPED + Sharding Próprio `00..15`:**
   * **Leitor `StateIpedStorageReaderAdapter`:** Quando a fonte for um caso `.iped` entregue pela polícia, lê em `mode=ro&immutable=1` + `PRAGMA query_only=1` tanto `sleuth.db` (`tsk_files`) quanto os 16 bancos `iped/data/storage-0.db` a `storage-15.db` (calculando o shard pelo nibble superior `(first_hash_byte >> 4) & 0x0F`, consultando `SELECT data FROM t1 WHERE id = ?` e descomprimindo o stream `GZIP` em blocos sem depender de Java!).
   * **Sharding Local Opcional para Textos Massivos:** Ao armazenar blobs comprimidos de subitens/textos extraídos gigantes em `workspace/catalog/`, permita particionar em $16$ arquivos SQLite (`blob_shard_00.sqlite` .. `blob_shard_0f.sqlite`) pelo primeiro caractere hexadecimal do `SHA-256`, eliminando contenção de escrita concorrente.

3. **Carving `Aho-Corasick` Contínuo ($1\text{ MiB}$) e Janelamento com `Overlap`:**
   * Implemente `StreamingSignatureCarver` lendo blocos de $1\text{ MiB}$ (`1_048_576` bytes) e **preservando o ponteiro de estado (`current_state`) do autômato `Aho-Corasick` entre blocos consecutivos**, capturando assinaturas que cruzem exatamente a fronteira de $1\text{ MiB}$ sem cópia extra de memória (incluindo validador de cabeçalho SQLite lendo tamanho de página `uint16 big-endian` no offset $16$ e contagem de páginas `uint32 big-endian` no offset $28$).
   * Na indexação de textos longos (`hybrid_search_chunks`), divida em janelas com `chunk_overlap_chars` explícito (ex.: $4.096$ chars com sobreposição de $512$ chars) vinculadas ao mesmo `ControlNumber` pai, impedindo que CPFs, lacres ou citações sejam decepados na fronteira de dois *chunks*.

4. **Quatro Upgrades nos Extratores da Subetapa 4.3:**
   * **Upgrade A — Inspetor Binário Não-Destrutivo de Registros Apagados em SQLite (`SQLiteDeletedRecordsInspector`):**
     * Além das queries `SELECT` em `mode=ro&immutable=1` (que produzem `SqliteRowAllocationState.ACTIVE_BTREE_ROW`), inspecione em leitura binária pura (`rb`) o arquivo SQLite e seu irmão `-wal` (se existir): identifique páginas na *freelist* (offset $32$: primeiro trunk page; offset $36$: total de páginas livres), espaço não alocado dentro de folhas *B-Tree* (`0x0D`) e *frames* não consolidados do `-wal`, extraindo strings/células legíveis recuperáveis **sempre** carimbadas com `WAL_UNCOMMITTED_FRAME` ou `CARVED_FREELIST_OR_UNALLOCATED` (jamais misturando silenciosamente com linhas ativas!).
   * **Upgrade B — Mensageria Moderna (WhatsApp `lid`, *View-Once* e Enquetes, Zero Download Externo):**
     * No extrator WhatsApp (`msgstore.db` / `ChatStorage.sqlite`), suporte tabelas modernas `jid` / `lid_me_mapping` / `chat` para resolver identificadores `lid` (*Linked Identity*), sinalize mensagens de visualização única (*view-once*) e opções de enquete (`message_poll_option`), e **garanta que nenhuma rotina tente baixar mídias ausentes de URLs externas**.
   * **Upgrade C — Extrator de Artefatos de Autoria e Conexão Física (`.lnk`, `USBStor`, `$UsnJrnl`):**
     * Adicione `WindowsArtifactProvenanceExtractor`: decodifica binariamente arquivos de atalho Windows `.lnk` (assinatura `4C 00 00 00` + CLSID `01 14 02 00...`), lendo a seção `LinkInfo` e o bloco `DistributedLinkTracker` (`Droid` / `DroidBirth`) para extrair `machine_id`, `volume_serial_number` e o `MAC Address` da placa de rede da máquina onde o arquivo foi originalmente criado — prova pericial decisiva para demonstrar autoria real ou implante externo de arquivo! Suporte também extração de entradas CSV/binárias de `$UsnJrnl:$J` e dispositivos USB (`USBStor`).
   * **Upgrade D — Cache Global Imutável de Transcrição Acústica por `SHA-256` (`AudioTranscriptDeduplicatedCache`):**
     * Antes de acionar `Silero VAD` + `Faster-Whisper` sobre qualquer áudio/nota de voz, consulte a tabela `audio_transcript_cache(audio_sha256 PRIMARY KEY, duration_ms, model_id, segments_json)`. Se o mesmo áudio encaminhado $50$ vezes em grupos de WhatsApp já tiver sido transcrito uma vez, reaproveite instantaneamente os segmentos milimétricos associando-os ao novo `ControlNumber`!

---

### 2.5 DELTA NA ANÁLISE CONTÍNUA, REVISÃO E APRESENTAÇÃO (`continuous_analysis`, `phase05_review`, `phase07_presentation`)

1. **Filtragem Booleana Instantânea por Bitmap (`CompressedRoaringBitset` — `phase05_review`):**
   * Implemente um motor enxuto de conjuntos de bits comprimidos sobre inteiros ordenados (`doc_seq_id` $\leftrightarrow$ `ControlNumber`, usando `pyroaring` se instalado ou *chunks* inteiros `int` bit-packed nativos do Python com operações bitwise `&`, `|`, `-`), permitindo cruzar filtros complexos (`Custodiante` $\cap$ `Pós-Apreensão` $\cap$ `Chave DANFE/Boleto` $\setminus$ `Sigilo Advogado`) em milissegundos.
2. **Exatidão Algébrica na Busca Vetorial/Métrica (`continuous_analysis`):**
   * Proíba qualquer atalho que some ou subtraia **distâncias quadráticas** diretamente em podas de desigualdade triangular (evitando o bug matemático $(\sqrt{a}-\sqrt{b})^2 \neq a-b$ identificado na `PhotoDnaTree` do IPED, issue `#2777`). Use similaridade de cosseno normalizada ou distância euclidiana real exata.
3. **Novas Regras de Nulidade e Quesitos Automáticos (`phase05_review` & `phase07_presentation`):**
   * Alimente o `EvidentiaryDefectClassifier` (Fase 05) e o `StrategicInterrogatoryBuilder` (Fase 07) com 4 novos gatilhos automáticos:
     1. *Omissão Metodológica em Caso `.iped` Estatal:* Perito usou `fastmode`/`triage` desligando *carving*/`SQLiteUndelete`/OCR mas atestou ausência de vestígios $\rightarrow$ Quesito de incompletude metodológica (ISO/IEC 27041 e POP Senasp `5.01`/`5.02`);
     2. *Contaminação por Download Pós-Apreensão (`--downloadInternetData`):* Caso `.iped` baixou mídia externa da internet sem isolamento $\rightarrow$ Preliminar de quebra da cadeia de custódia (CPP, arts. 158-A e 158-B, II) e prova ilícita/não auditável;
     3. *Indistinção entre Registro SQLite Ativo e Fragmento Recuperado:* Relatório policial atribuiu autoria/conteúdo com base em célula truncada de *freelist*/*slack* sem advertência científica $\rightarrow$ Impugnação técnica fundada no **NIST IR 8354**;
     4. *Divergência de Origem Física via `.lnk` (`Droid` / `MAC Address`):* Arquivo incriminador possui `DroidBirth` / `MAC Address` pertencente a máquina diversa da apreendida com o acusado (ou estação policial!) $\rightarrow$ Alerta crítico de autoria/implante.

---

## 3. PORTÃO ADICIONAL DE AUTO-TESTE CUMULATIVO (`G11` EM `tools/run_forensic_gates.py`)

Mantenha **intactos e obrigatórios todos os portões existentes (`G0` até a onda atual / `G10`)** e acrescente o **Portão `G11` — Homologação Delta v2.1 (IPED Clean-Room, SSDF & Forense Avançado)**, exigindo `EXIT CODE 0`:

1. **`G11.1` (Segurança NIST SSDF v1.1 via AST):** Confirma `0` ocorrências de `pickle`/`marshal`/`shelve`/`unsafe_load`, `0` ocorrências de desativação SSL (`verify=False`/`CERT_NONE`) e *bind* restrito a `127.0.0.1` com token de sessão.
2. **`G11.2` (Auditoria de Caso Portátil `.iped` Estatal Sintético):** Cria em diretório temporário uma estrutura sintética fiel de caso `.iped` contendo `iped/conf/IPEDConfig.txt` (com perfil `fastmode` e `enableCarving = false`), log de `--downloadInternetData`, `sleuth.db` e shards `iped/data/storage-0.db`..`storage-15.db` com tabela `t1(id, data)` comprimida em `GZIP`. Verifica que o `StateIpedCaseAuditor` detecta o caso na Fase 01, extrai os subitens em `mode=ro&immutable=1` sem alterar `mtime_ns` e gera os quesitos correspondentes.
3. **`G11.3` (Sonda de Criptografia Sem Cabeçalho + Validadores Nacionais/Cripto):** Testa detecção de bloco pseudoaleatório de $128\text{ KiB}$ sem *magic bytes* como `HEADERLESS_HIGH_ENTROPY_ENCRYPTED` (zero `float`), além de casos válidos e inválidos (dígito adulterado em $1$ unidade) para `CPF`, `CNPJ`, `Linha Digitável de Boleto`, `Chave NFe/DANFE 44 dígitos`, `Cartão Luhn`, `Bitcoin` e `BIP-39`.
4. **`G11.4` (Orquestrador $P_0 \rightarrow P_4$ + Retomada de Pai Incompleto + Cache Áudio `SHA-256`):** Prova que `wa.db` ($P_2$) e um anexo de mídia ($P_0$) são indexados antes de `msgstore.db` ($P_3$) mesmo inseridos fora de ordem; simula interrupção no meio de um `.zip` com $5$ filhos e comprova que a retomada recupera os filhos restantes sem duplicar os já gravados; e prova que $3$ cópias do mesmo áudio acionam o transcritor apenas $1$ vez.
5. **`G11.5` (SQLite Apagados Rotulados + Parser Binário `.lnk` + Bitmap de Revisão):** Constrói banco SQLite sintético com $1$ linha ativa e $1$ registro em página livre/*WAL*, confirmando separação estrita `ACTIVE_BTREE_ROW` vs. `CARVED_FREELIST_OR_UNALLOCATED`; decodifica um binário `.lnk` sintético extraindo o `MAC Address` de `DroidBirth`; e valida interseção/diferença booleana exata no `CompressedRoaringBitset`.

---

## 4. COMANDO ENXUTO PRONTO PARA COLAR NA SESSÃO ATIVA DO GOOGLE AI STUDIO

> **Como usar:** Anexe este documento (`manifesto_complemento_refatoracao_iped_v2_1.md`) na conversa em andamento do Google AI Studio onde o primeiro manifesto já está sendo programado e envie o comando abaixo:

```text
PAUSA DE SINCRONIZAÇÃO ARQUITETURAL — APLICAÇÃO DO COMPLEMENTO E REFATORAÇÃO CIRÚRGICA DELTA v2.1

Leia integralmente o documento anexado "Complemento e Refatoração v2.1 — Evolução Forense IPED Clean-Room". Como já estamos programando o Manifesto Mestre v2.0 nesta sessão, você está PROIBIDO de apagar ou reescrever do zero o que já está funcionando. Aplique uma refatoração incremental não-destrutiva e aditiva seguindo rigorosamente Google Python Style Guide, princípios cirúrgicos de Andrej Karpathy (Software 1.0 determinístico, zero código morto, zero float em bytes/moeda/entropia) e Enterprise SOLID (OCP via registros plugáveis, LSP, ISP, DIP e isolamento absoluto entre fases):

1. DIAGNÓSTICO DO ESTADO ATUAL: Inspecione primeiro os arquivos já criados na sua Sandbox Python e identifique exatamente quais pacotes e portões (`G0`..`G10`) já existem.
2. REFATORAÇÃO RETROCOMPATÍVEL IMEDIATA (SOBRE O QUE JÁ FOI CRIADO):
   - Estenda `edrm.shared_kernel` com `ProcessingPriorityTier` ($P_0 \rightarrow P_4$), `SqliteRowAllocationState`, `validators_br_crypto.py` (varredura linear $O(n)$ + dígitos verificadores exatos de CPF, CNPJ, Boleto Bancário, DANFE 44 dígitos, Luhn e BIP-39), `compressibility_probe.py` ($64\text{ KiB}$ inteiro em permille sem `float`) e campos retrocompatíveis nos contratos (`default` imutáveis).
   - Refatore `edrm.igrm_governance` aplicando NIST SSDF v1.1 (bloqueio AST de `pickle`/`marshal`/`verify=False`, bind exclusivo `127.0.0.1` com token de sessão, mini-SBOM e supervisor de subprocessos com limpeza garantida de `staging/`).
   - Injete a reconciliação normativa estrita (IGRM v4.1 sem data de junho/2026; EDRM Processing 1.0–5.0 como piso funcional flexível).
   - Adicione nas Fases 01/02 já construídas o `StateIpedCaseAuditor` (detectando casos portáteis `.iped` estatais, perfis omissivos `fastmode`/`triage`, `filterKeywords` e `--downloadInternetData`) e o sensor de criptografia sem cabeçalho.
3. INCORPORAÇÃO DIRETA NAS DEMAIS FASES (REFAZENDO CIRURGICAMENTE SE JÁ EXISTIREM OU JÁ NASCENDO EM v2.1 NAS PRÓXIMAS ONDAS):
   - Fase 04: Orquestrador em 5 Filas de Dependência ($P_0 \rightarrow P_4$) com barreira de índice + retomada de contêineres pais incompletos + leitor imutável dos 16 shards `storage-0..15.db` (`GZIP` em streaming) + carving `Aho-Corasick` preservando estado entre blocos de $1\text{ MiB}$ + `SQLiteDeletedRecordsInspector` rotulado + WhatsApp `lid`/*view-once* (zero download externo) + extrator binário `.lnk` (`MAC Address` / `DroidBirth`) + cache de transcrição de áudio por `SHA-256`.
   - Análise Contínua, Fase 05 e Fase 07: `CompressedRoaringBitset`, busca métrica algebricamente exata e quesitos automáticos para anomalias `.iped`, `.lnk` e SQLite recuperado.
4. VALIDAÇÃO EMPÍRICA OBRIGATÓRIA: Adicione os testes aplicáveis do Portão `G11` em `tools/run_forensic_gates.py`, execute na sua Sandbox Python todos os portões já construídos mais as verificações `G11` em loop até obter `EXIT CODE 0` comprovado no console (zero regressão e `PreScanSnapshot == PostScanSnapshot`), atualize o script `materialize_*.py` com hashes `SHA-256` e prossiga a entrega!
```