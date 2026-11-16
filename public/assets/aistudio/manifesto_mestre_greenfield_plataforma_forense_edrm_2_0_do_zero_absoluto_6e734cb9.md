# MANIFESTO MESTRE E ESPECIFICAÇÃO INTEGRAL DE ENGENHARIA — PLATAFORMA UNIVERSAL DE AUDITORIA PROBATÓRIA E DESCOBERTA FORENSE (EDRM 2.0 GREENFIELD)

## 1. VISÃO DO PRODUTO DO ZERO ABSOLUTO: PARADIGMA *PLUG-AND-ANALYZE*

### 1.1 Conceito Central da Plataforma
A plataforma **ELO — Motor Universal de Auditoria Probatória e Descoberta Eletrônica** é um software forense construído do zero absoluto (*Clean-Slate / Greenfield*) para atuar como um **laboratório pericial automatizado de defesa criminal**.

Sua operação parte de um fluxo direto e universal: **o usuário conecta um ou mais HDs, SSDs, pendrives, imagens forenses ou diretórios contendo as provas brutas originais de um caso (`--source <caminho_da_midia>`) e aponta uma pasta limpa de trabalho (`--workspace <pasta_do_caso>`)**. Sem exigir nenhuma configuração manual de formatos nem conhecimento prévio do que existe dentro do disco, o sistema entra em ação combinando **sensores binários determinísticos** com **inteligência artificial governada** para:

1. **Bloquear logicamente qualquer escrita na mídia de prova conectada**, tirando uma fotografia matemática inicial de todos os metadados físicos antes de ler o primeiro byte;
2. **Autodescobrir a estrutura completa do HD desconhecido** (assinaturas binárias reais, contêineres forenses, bancos de dados de aplicativos, documentos processuais primários, quebras bancárias, registros telefônicos, áudios, vídeos, imagens de disco e arquivos criptografados ou corrompidos);
3. **Compreender o caso e os esquemas encontrados em conjunto com a IA** (identificando autos de apreensão, mandados, fichas de cadeia de custódia, laudos, custodiantes, aparelhos apreendidos e até esquemas de bancos SQLite ou planilhas inéditas encontradas no HD, sem jamais permitir que a IA altere dados ou invente informações);
4. **Executar de ponta a ponta todas as fases do ciclo oficial EDRM 2.0**, entregando diagnósticos periciais matematicamente verificáveis, matrizes de omissão de provas brutas, detecção de manipulação ou atividade pós-apreensão, pareceres técnicos prontos, quesitos estratégicos e dossiês visuais interativos *offline*.

### 1.2 Arquitetura Normativa em Três Camadas Independentes
O sistema separa com precisão cirúrgica o fluxo gerencial de descoberta eletrônica, os padrões internacionais de engenharia forense e o direito probatório penal brasileiro:

1. **Ciclo de Vida da Evidência Digital — EDRM 2.0 (Publicado em 01/09/2026 — CC BY 4.0 EDRM.net):**
   Organiza a transformação progressiva de **Volume Bruto de Dados em Relevância Jurídica** (*Volume to Relevance continuum*) em uma arquitetura viva, iterativa e bidirecional:
   * **Base Fundacional Transversal:** **Governança da Informação** (*Information Governance Reference Model* — **IGRM v4.1**, junho/2026), regendo segurança, isolamento de workspace, sigilo, auditoria e ciclo de retenção sob todas as fases.
   * **Faixa Superior Transversal:** **Análise Contínua (*Continuous Analysis*)**, integrando discernimento humano, estatística, busca híbrida e IA auditada desde o primeiro segundo de leitura do HD até a apresentação em juízo.
   * **Bloco Acoplado de Aquisição de Dados (*Data Acquisition*):**
     * **Fase 01 — Identificação (*Identification*)**
     * **Fase 02 — Preservação (*Preservation*)**
     * **Fase 03 — Coleta (*Collection*)**
     * **Fase 04 — Processamento (*Processing* — Subetapas Oficiais $1.0$ a $5.0$)**
   * **Bloco de Mérito Jurídico, Contraditório e Encerramento:**
     * **Fase 05 — Revisão (*Review* — Nexo Central de Relevância Jurídica)**
     * **Fase 06 — Produção (*Production*)**
     * **Fase 07 — Apresentação (*Presentation*)**
     * **Fase 08 — Destinação Final (*Disposition* — reconectada à base IGRM)**

2. **Normas Internacionais de Ciência Forense, Qualidade e IA:**
   * **ABNT NBR ISO/IEC 27037:** Identificação, coleta, aquisição e preservação de evidência digital (auditabilidade, repetibilidade, reprodutibilidade e justificabilidade).
   * **ISO/IEC 27041:** Garantia de adequação e validação prévia de ferramentas e métodos periciais mediante provas de controle positivo e negativo antes do exame real.
   * **ISO/IEC 27042:** Diretrizes para análise, interpretação e reprodução independente por terceiros.
   * **RFC 3227 (IETF):** Ordem de volatilidade (*Order of Volatility*) e registro de deriva de relógio frente ao UTC (*clock drift*).
   * **SWGDE Best Practices (18-Q-001 / 20-F-005 v2.0 / 18-F-003):** Validação empírica de extratores e limites de linhas do tempo móveis.
   * **NIST SP 800-88 Rev. 2 (set./2025) & IEEE 2883-2022:** Sanitização certificada de mídias (*Clear*, *Purge / Cryptographic Erase* e *Destroy*).
   * **ISO/IEC 42001:** Gestão auditável e rastreabilidade de sistemas de Inteligência Artificial.

3. **Marco Processual Penal e Regulatório Brasileiro:**
   * **Código de Processo Penal (Lei nº 13.964/2019):** Cadeia de custódia em $10$ etapas nos arts. 158-A a 158-F (**I — Reconhecimento, II — Isolamento, III — Fixação, IV — Coleta, V — Acondicionamento, VI — Transporte, VII — Recebimento, VIII — Processamento, IX — Armazenamento e X — Descarte**), regime de nulidade de provas ilícitas e derivadas (art. 157) e garantia de acesso e exame técnico independente pela defesa sobre a matéria-prima bruta (art. 159, §§ 5º e 6º).
   * **POP Senasp de Perícia Criminal — Volume 5: Informática Forense (2024):** Procedimentos operacionais `5.01` (mídias de armazenamento), `5.02` (dispositivos móveis), `5.03` (local de informática), `5.04` (local de internet/nuvem) e `5.05` (apreensão de celulares).
   * **Jurisprudência Consolidada:** **STF Tema 977** (reserva de jurisdição e acesso integral), **STJ Jurisprudência em Teses — Edição 281** (mesmidade, cadeia de custódia e auditabilidade por hash), **STJ RHC 184.003/SP** (imprestabilidade de arquivos corrompidos/cifrados inacessíveis à defesa), **IN BCB nº 636/2025** (padrão SIMBA) e **Decreto nº 12.975/2026** (porta lógica obrigatória em conexões `CGNAT`).
   * **Governança de IA e Sigilo Profissional:** **Resoluções CNJ nº 615/2025 e nº 674/2026** e **Recomendação CFOAB nº 001/2024**.

---

## 2. OS 8 PILARES DA VALIDADE PERICIAL E JURÍDICA CONVERTIDOS EM TRAVAS DE CÓDIGO

Nenhum princípio pericial fica restrito a documentação teórica. Todos os **8 pilares** são implementados como **travas físicas bloqueantes (*Harness Engineering*)** verificadas automaticamente em cada execução:

| Pilar Pericial | Requisito Jurídico-Científico | Trava Determinística Executável no Código |
| :--- | :--- | :--- |
| **1. Confiabilidade** | ISO/IEC 27041; SWGDE 18-Q-001 | Todo pipeline inicia executando `SelfCalibrationSuite`: injeta em memória $1$ controle positivo (zero falsos positivos em âncoras estruturais) e $2$ controles negativos ($1$ adulteração numérica/hash + $1$ entidade textual inventada). Se o verificador não bloquear ambos, lança `VerifierCalibrationError` e aborta antes de tocar no HD. |
| **2. Auditabilidade** | ISO/IEC 42001; CNJ 615/2025 | Toda operação gera `execution_manifest.json` (contendo o `SHA-256` do próprio código-fonte executado, versões de binários, parâmetros, horários UTC e uso de memória), livro de auditoria *append-only* (`audit_ledger.jsonl` + tabela `ai_audit_log`) e `MANIFESTO_SHA256.txt`. |
| **3. Reprodutibilidade** | ISO/IEC 27042; CPP art. 159, § 5º | Proibição estática via AST de `float` para dinheiro ou bytes (uso estrito de `int`/`BIGINT` em centavos e `Decimal`); proibição do `hash()` volátil do Python em favor de `hashlib.sha256`; sementes inteiras fixas e registradas (`seed`) em qualquer amostragem; geração automática de script passo a passo de contraprova para o perito judicial. |
| **4. Rastreabilidade (Cadeia de Custódia)** | CPP arts. 158-A a 158-F | Todo artefato recebe `ControlNumber` imutável com genealogia familiar pai-filho (`CN-00000001` $\rightarrow$ `CN-00000001.0001`) e todo dado extraído exige `SourceAnchor` (`origin_control_number`, `origin_path`, `locator`, `verbatim_excerpt`, `captured_at_utc`, `origin_sha256`). |
| **5. Integridade** | ISO/IEC 27037; CPP art. 158-B | `SourceWriteBlockerGuard` proíbe qualquer abertura de escrita, truncamento ou mudança de permissão nas mídias `--source` (`ReadOnlyViolationError`); bancos SQLite de prova abrem **exclusivamente** via URI `file:...?mode=ro&immutable=1` combinada com `PRAGMA query_only = 1;`; conferência matemática obrigatória `PreScanSnapshot == PostScanSnapshot` (`st_size` e `st_mtime_ns` idênticos em $100\%$ dos arquivos do HD conectado). |
| **6. Autenticidade** | FIPS 180-4; STF Tema 977 | Cálculo `SHA-256` em *streaming* de blocos fixos ($4\text{ MiB}$); leitura dos primeiros $16\text{ bytes}$ (*Magic Bytes*) para desmascarar extensões falsas/camufladas; contagem de revisões incrementais `%%EOF` em PDFs; confronto direto contra hashes lavrados na apreensão estatal. |
| **7. Imparcialidade** | CPP art. 159; POP Senasp 2024 | Qualificação obrigatória de cada item em `EpistemicStatus` (`VERIFIED_FACT`, `STATE_ALLEGATION`, `ANALYTICAL_INFERENCE`, `EXPLICIT_GAP`); política *Zero-Silent-Drop* (nenhum dado ou falha é omitido silenciosamente); preservação de conflitos lado a lado (`DivergenceRecord`); deduplicação e filtragem apenas lógicas (preservando a **prova negativa**). |
| **8. Fundamentação Metodológica** | Cochran (1977); Hanley & Lippman-Hand (1983) | Revisão obrigatória de $100\%$ nos achados críticos de uso judicial + Amostragem Finita Estratificada de Cochran ($95\%$ de confiança, margem de $\pm 10\%$) nos demais estratos + Teste de Elusão e Regra do 3 ($3/n$) sobre itens filtrados. |

---

## 3. COMO FUNCIONA A AUTODESCOBERTA: HD CONECTADO + SENSORES DETERMINÍSTICOS + IA GOVERNADA

Quando o usuário conecta um HD desconhecido repleto de arquivos heterogêneos, o sistema **jamais despeja gigabytes brutos na janela de um modelo de IA** (o que violaria a matemática criptográfica, estouraria memória e geraria alucinações). Em vez disso, opera uma **Engrenagem Simbiótica em Duas Camadas Separadas por Barreira Vermelha**:

```text
[HD / Mídia de Prova Conectada (--source)]  ===> Protegida por SourceWriteBlockerGuard (100% Read-Only)
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CAMADA A — SONDA FORENSE DETERMINÍSTICA (100% Código Python Compilado — ZERO IA)                │
│ 1. Fotografia física inicial (os.stat: tamanho exato, timestamps nanosegundos, inodes/atributos)│
│ 2. Censo em streaming: SHA-256 (4 MiB), Magic Bytes (16B), camuflagem de extensão e entropia    │
│ 3. Radiografia estrutural sem extração pesada:                                                  │
│    - Listagem do Central Directory de ZIP / UFDR / UFDX / TAR / 7Z / RAR                        │
│    - Extração de schemas CREATE TABLE e amostras frias de SQLite (mode=ro&immutable=1)          │
│    - Inspeção de cabeçalhos CSV/TXT/SIMBA/CDR, árvores XML e marcadores %%EOF / XMP de PDFs     │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │ (Envia apenas Metadados Estruturais, Schemas e
                                                │  Texto Extraído de Peças Processuais Ancoradas)
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ CAMADA B — INTÉRPRETE ANALÍTICO ASSISTIDO POR IA LOCAL (Análise Contínua Governada)             │
│ 1. Reconhecimento Documental: identifica quais PDFs/DOCXs do HD são Autos de Apreensão,         │
│    Mandados, FAVs, Decisões ou Laudos Periciais e extrai fichas estruturadas ancoradas          │
│ 2. Intérprete de Schemas Inéditos: ao encontrar um banco SQLite ou CSV de aplicativo/operadora  │
│    desconhecido no HD, analisa o schema das tabelas/colunas e propõe o Mapeamento de Extração   │
│ 3. Orquestrador de Prioridade: sugere o Plano de Execução das Fases 01 a 08 conforme o perfil   │
│    real de provas encontrado naquele HD específico                                              │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ BARREIRA VERMELHA — VERIFICADOR DETERMINÍSTICO BLOQUEANTE (Código Puro — Falha Zero)            │
│ Confere matematicamente cada ID, SHA-256, número, coluna SQL e citação «literal» contra a fonte │
│ real antes de persistir qualquer registro no Catálogo ou aprovar qualquer relatório!            │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Isolamento Automático do Workspace de Caso (`CaseWorkspaceLayout`)
Para qualquer caso novo, o usuário informa apenas um diretório raiz de trabalho (`--workspace`), onde o sistema cria e governa automaticamente cinco zonas estritas:
1. `workspace/vault/` — Cofre imutável das evidências coletadas e manifestos criptográficos (`chmod a-w` no POSIX / `FILE_ATTRIBUTE_READONLY` no Windows).
2. `workspace/staging/` — Caixa de areia temporária e isolada para descompactação recursiva de contêineres pesados e execução de ferramentas externas (expurgada de forma verificada na Fase 08).
3. `workspace/catalog/` — Banco de dados relacional e índice analítico de busca híbrida (`SQLite 3` portátil de fábrica ou `PostgreSQL 17 + pgvector` configurável).
4. `workspace/deliverables/` — Única pasta de saída dos relatórios oficiais das Fases 01 a 08, pareceres periciais, *load files* e dossiê HTML5 *offline*.
5. `workspace/audit/` — Livro *append-only* de eventos, fotos físicas *Antes $\times$ Depois* da mídia conectada, logs de auditoria de IA, `MANIFESTO_SHA256.txt` e pacotes anti-perda (`git bundle`).

*(Suporte multiplataforma transparente: caminhos longos acima de $260$ caracteres no Windows recebem automaticamente o prefixo estendido `\\?\` ou `\\?\UNC\` na camada de infraestrutura, mantendo o caminho lógico limpo nas entidades e relatórios).*

---

## 4. ARQUITETURA DE SOFTWARE: CLEAN ARCHITECTURE + HEXAGONAL + DDD + SOLID

### 4.1 Regra Concêntrica de Dependência e Acoplamento Mínimo
O código nasce organizado sob **Clean Architecture** e **Arquitetura Hexagonal (*Ports & Adapters*)**, auditadas estaticamente via árvore sintática (`AST`) a cada execução de testes:

* **Direção Única e Estrita de Dependências:**
  `bootstrap` $\rightarrow$ `interfaces` / `infrastructure` $\rightarrow$ `application (use_cases + ports + dto)` $\rightarrow$ `domain (entities + value_objects + pure_services)` $\rightarrow$ `shared_kernel`.
* **Pureza Total de Domínio e Aplicação:**
  Nenhum módulo dentro de `domain/` ou `application/` pode importar bibliotecas de sistema operacional, disco, banco de dados, sub-processos ou rede (`os`, `sys`, `shutil`, `glob`, `subprocess`, `sqlite3`, `psycopg`, `zipfile`, `tarfile`, `socket`, `http`, `urllib`, `requests`).
* **Isolamento Absoluto Entre Fases (Zero Acoplamento Cruzado):**
  Os pacotes das fases (`igrm_governance`, `phase01_identification` até `phase08_disposition` e `continuous_analysis`) **nunca importam uns aos outros**. Toda transição de dados entre uma fase e a seguinte ocorre $100\%$ por meio de **Contratos de Transição Imutáveis** (`@dataclass(frozen=True, slots=True)`) residentes em `edrm.shared_kernel.contracts` e conectados exclusivamente no `Composition Root` (`edrm/bootstrap/container.py`).
* **Princípios SOLID Aplicados em Todo o Código:**
  * **S (*Single Responsibility*):** Um caso de uso por microfase e um extrator por família de formato.
  * **O (*Open/Closed*):** Registro plugável (`ExtractorRegistry` e `SignatureRegistry`) permitindo adicionar novos formatos forenses descobertos em futuros HDs sem alterar os casos de uso existentes.
  * **L (*Liskov Substitution*):** Adaptadores `InMemory` (para testes instantâneos) e adaptadores físicos reais passam exatamente na mesma suíte de testes de contrato.
  * **I (*Interface Segregation*):** Portas pequenas e específicas (`typing.Protocol` com $1$ a $3$ métodos coesos).
  * **D (*Dependency Inversion*):** Toda dependência externa é injetada via abstração explícita no construtor.

### 4.2 Stack Dual-Mode (Execução Portátil Imediata $\leftrightarrow$ Escala Industrial)
Para que o sistema rode imediatamente com **Python 3.12+ puro** (tanto na Sandbox do Google AI Studio quanto em qualquer estação local recém-instalada) e ao mesmo tempo escale para HDs de múltiplos terabytes, cada porta hexagonal conta com dois adaptadores intercambiáveis por configuração:

| Porta Hexagonal | Modo Portátil Nativo (*Zero Dependências Externas*) | Modo Escala Industrial (*Plugável sob Demanda*) |
| :--- | :--- | :--- |
| **Persistência e Busca Híbrida** | `SQLite 3` nativo (`ACID` + `FTS5 BM25` + vetores exatos em memória/disco) | `PostgreSQL 17` + `pgvector (HNSW 1024d)` + `tsvector GIN` |
| **Orquestração de Filas/Retomada** | `SqliteCheckpointedQueueAdapter` (transacional, retomável após queda de energia) | `Redis` + `Dramatiq` (workers paralelos CPU / GPU) |
| **Imagens Forenses e Contêineres** | `NativeContainerProbeAdapter` (`zipfile`, `tarfile`, headers binários em streaming) | `IpedCliExternalAdapter` (`IPED 4.3.x --nogui -profile fastmode/triage`) + `The Sleuth Kit` |
| **Documentos, PDFs e OCR** | Parser binário nativo de fluxos PDF (`%%EOF`, `/Info`, `XMP`, texto) | `Apache Tika` + `QPDF` + `ExifTool 13.59+` + `Tesseract 5 (por)` |
| **Áudio e Interceptações** | `NativeWaveEnergySegmenterAdapter` (inspeção PCM/WAV determinística) | `Silero VAD` + `Faster-Whisper (large-v3)` local |
| **IA Analítica e Descoberta** | `DeterministicHeuristicDiscoveryAdapter` (opera 100% *offline* sem GPU) | `Ollama / vLLM` local (`Qwen 3` / `Gemma 4`) + `BGE-M3` embeddings |

### 4.3 Árvore Completa de Diretórios da Plataforma

```text
elo_forensic/
├── pyproject.toml
├── AGENTS.md                                           # Constituicao arquitetural concisa para agentes
├── CLAUDE.md                                           # Contem apenas: @AGENTS.md
├── materialize_elo_platform.py                         # Instalador integral automatico com verificacao SHA-256
├── tools/
│   └── run_forensic_gates.py                           # Executor autonomo em loop dos Portoes G0 a G10
├── src/
│   └── edrm/
│       ├── __init__.py
│       ├── shared_kernel/                              # NUCLEO PURO COMPARTILHADO E CONTRATOS ENTRE FASES
│       │   ├── __init__.py
│       │   ├── enums.py                                # Enums forenses, epistemicos, cadeias CPP e severidades
│       │   ├── exceptions.py                           # Excecoes tipadas (ReadOnlyViolationError, etc.)
│       │   ├── value_objects.py                        # Sha256Hash, ByteSize, CentsAmount, UtcTimestamp,
│       │   │                                           # SafeOsPath, ControlNumber, SourceAnchor
│       │   ├── time_normalizer.py                      # Conversor unico UTC (Unix 1970, Cocoa 2001, QuickTime 1904, ISO)
│       │   ├── money_parser.py                         # Parser monetario exato para centavos inteiros (BIGINT)
│       │   └── contracts.py                            # Contratos imutaveis 00->01->02->03->04->05->06->07->08
│       │                                               # + AutoDiscoveryBlueprint + IterativeDiscoveryFeedbackPort
│       │
│       ├── igrm_governance/                            # CAMADA 00: GOVERNANCA DA INFORMACAO (IGRM v4.1)
│       │   ├── domain/                                 # WorkspaceLayout, SourceWriteBlockerPolicy, SecrecyPolicy
│       │   ├── application/                            # InitializeCaseWorkspaceUseCase, CalibrateToolsUseCase
│       │   └── infrastructure/                         # FsWriteBlockerGuard, ExecutionManifestWriter, AppendOnlyLedger
│       │
│       ├── phase01_identification/                     # FASE 01: IDENTIFICACAO & AUTODESCOBERTA DO HD
│       │   ├── domain/                                 # MediaCensus, MagicSignatureClassifier, SchemaFingerprint,
│       │   │                                           # Custodian, PopSenaspMetadata, ParityMatrixEngine, CochranMath
│       │   ├── application/                            # ProbeUnknownMediaUseCase,AiAssistedStructureDiscoveryUseCase,
│       │   │                                           # ExtractPrimaryDeclarationsUseCase, ComputeParityMatrixUseCase,
│       │   │                                           # SealPhase01UseCase, ReceiveIterativeFeedbackUseCase
│       │   └── infrastructure/                         # ReadOnlyMediaScanner, StreamingSha256Hasher,
│       │                                               # ImmutableSqliteSchemaProber, ContainerHeaderProber,
│       │                                               # SqliteCatalog01Repo, Phase01MarkdownCompiler
│       │
│       ├── phase02_preservation/                       # FASE 02: PRESERVACAO (DEFENSIVA & ESTATAL NA ORIGEM)
│       │   ├── domain/                                 # StructuralHealthAudit, SpofRedundancyEvaluator,
│       │   │                                           # StateOriginPreservation6Axes, LegalHoldRecord
│       │   ├── application/                            # AuditMediaPreservationUseCase, AuditSqliteWalIntegrityUseCase,
│       │   │                                           # EvaluateStateCustody6AxesUseCase, SealPhase02UseCase
│       │   └── infrastructure/                         # OsReadonlyAttributeChecker, ImmutableSqliteIntegrityRunner,
│       │                                               # SqliteCatalog02Repo, Phase02MarkdownCompiler
│       │
│       ├── phase03_collection/                         # FASE 03: COLETA VERIFICADA & AQUISICAO DEFENSAVEL
│       │   ├── domain/                                 # AcquisitionPlan, ControlNumberGenealogy, StateCollectionAudit
│       │   ├── application/                            # PlanAcquisitionUseCase, ExecuteVerifiedVaultCopyUseCase,
│       │   │                                           # AuditStateCollectionMethodUseCase, SealPhase03UseCase
│       │   └── infrastructure/                         # FsyncColdVerifyCopier, VaultReadonlyLocker, IcpManifestWriter
│       │
│       ├── phase04_processing/                         # FASE 04: PROCESSAMENTO (MODULOS OFICIAIS EDRM 1.0 A 5.0)
│       │   ├── domain/                                 # StagingJob, DeNistAndDedupPolicy, PostSeizureDetector,
│       │   │                                           # PdfForensicModel, MobileChatRecord, SimbaFinancialEntry,
│       │   │                                           # CdrErbRecord, AudioTranscriptSegment, ProcessingException
│       │   ├── application/                            # Substep4_1_IngestUnpack, Substep4_2_LogicalFilter,
│       │   │                                           # Substep4_3_UniversalExtractors, Substep4_4_PersistAndFeedback,
│       │   │                                           # Substep4_5_OfficialFiveReports
│       │   └── infrastructure/                         # SafeContainerUnpacker, IpedCliExternalBridge,
│       │                                               # PdfBinaryAndOcrExtractor, MobileSqliteChatExtractor,
│       │                                               # DynamicUnknownSqliteExtractor, CellebriteUfdrStreamParser,
│       │                                               # SimbaOfxParser, CdrAnatelParser, AudioVadWhisperExtractor,
│       │                                               # EmailMboxEmlParser, CgnatLogParser, DeadLetterStore
│       │
│       ├── continuous_analysis/                        # FAIXA TRANSVERSAL: ANALISE CONTINUA, BUSCA RRF & IA LOCAL
│       │   ├── domain/                                 # HybridRrfFusion, UnifiedUtcTimeline, PromptInjectionShield,
│       │   │                                           # BlockingVerifierEngine, CochranElusionRuleOf3Qc
│       │   ├── application/                            # HybridSearchUseCase, BuildUnifiedTimelineUseCase,
│       │   │                                           # GovernedAiInterpretUseCase, VerifyDocumentDeterministically
│       │   └── infrastructure/                         # SqliteFtsVectorStore, PostgresPgvectorStore,
│       │                                               # LocalLlmEndpointAdapter, BlockingVerifierAdapter, AiAuditRepo
│       │
│       ├── phase05_review/                             # FASE 05: REVISAO & CONFRONTO LAUDO X PROVA BRUTA
│       │   ├── domain/                                 # PrivilegeShield, ThesisTagging, ReportVsRawContradiction,
│       │   │                                           # EvidentiaryDefectClassifier
│       │   ├── application/                            # TagReviewItemsUseCase, DetectMaterialContradictionsUseCase,
│       │   │                                           # ClassifyNullitiesUseCase, FreezeReviewSetUseCase
│       │   └── infrastructure/                         # ReviewStoreAdapter, ContradictionReportExporter
│       │
│       ├── phase06_production/                         # FASE 06: PRODUCAO PERICIAL (PARECER 7 BLOCOS & LOAD FILES)
│       │   ├── domain/                                 # SevenBlockExpertOpinion, ConcordanceEdrmLoadFile, ReproScript
│       │   ├── application/                            # CompileSevenBlockOpinionUseCase, ExportLoadFilesUseCase,
│       │   │                                           # PrepareIcpDetachedSignatureUseCase
│       │   └── infrastructure/                         # ExpertOpinionMarkdownWriter, SafeLoadFileWriter
│       │
│       ├── phase07_presentation/                       # FASE 07: APRESENTACAO (QUESITOS & DOSSIE INTERATIVO OFFLINE)
│       │   ├── domain/                                 # StrategicInterrogatoryBuilder, LegalThesisExhibit, CourtView
│       │   ├── application/                            # GenerateCustomQuesitosUseCase, BuildOfflineHtmlDossierUseCase
│       │   └── infrastructure/                         # SingleFileOfflineHtmlCompiler, MotionExhibitExporter
│       │
│       ├── phase08_disposition/                        # FASE 08: DESTINACAO FINAL, EXPURGO STAGING & NIST 800-88
│       │   ├── domain/                                 # StagingPurgeReceipt, RecoveryBundleSpec, NistSanitizationCert
│       │   ├── application/                            # PurgeStagingVerifiedUseCase, BuildRecoveryBundleUseCase,
│       │   │                                           # ExecutePostJudgmentDispositionUseCase
│       │   └── infrastructure/                         # StagingCleanerAdapter, GitBundleAdapter, Nist80088Sanitizer
│       │
│       ├── interfaces/                                 # CLI UNIFICADA PLUG-AND-ANALYZE & API LOCAL
│       │   ├── cli.py                                  # Comandos: init-case, plug-hd, run-phase, run-all, search
│       │   └── local_api.py                            # Interface HTTP estritamente em 127.0.0.1
│       │
│       └── bootstrap/                                  # COMPOSITION ROOT (INJECAO EXPLICITA DE DEPENDENCIAS)
│           └── container.py
│
└── tests/
    ├── architecture/                                   # Auditoria AST: Clean/Hexagonal, SOLID, zero float/hash()
    ├── fakes/                                          # Adaptadores InMemory completos para todas as portas
    ├── contract/                                       # Testes Liskov (InMemory == Infraestrutura Fisica Real)
    ├── unit/                                           # Testes exaustivos de todos os calculos e regras das 9 camadas
    └── e2e_synthetic/                                  # Simula um HD bruto desconhecido plugado do zero (00 -> 08)
```

---

## 5. CONTRATOS HEXAGONAIS IMUTÁVEIS E ESQUEMA CANÔNICO DO BANCO DE DADOS

### 5.1 Contratos de Transição Entre Fases (`edrm/shared_kernel/contracts.py`)
Todas as fases comunicam-se exclusivamente por objetos de valor imutáveis serializáveis em JSON canônico (`sort_keys=True`) com assinatura `SHA-256`:

1. **`CaseGovernanceContract` (`Camada 00` $\rightarrow$ Todas):** `case_id`, `run_id`, caminhos validados de `workspace` (`vault`, `staging`, `catalog`, `deliverables`, `audit`), raízes protegidas `--source`, nível de sigilo (`JUDICIAL_SECRECY_LOCAL_ONLY` vs. `PUBLIC_RECORD`) e recibo de aprovação da auto-calibração ISO 27041.
2. **`MediaAutoDiscoveryBlueprint` (Sonda Determinística $\leftrightarrow$ IA Governada na `Fase 01`):** Censo completo de extensões, assinaturas binárias de $16\text{ bytes}$, arquivos camuflados, árvore de contêineres, schemas `CREATE TABLE` de bancos SQLite inéditos encontrados no HD, cabeçalhos de planilhas/CSVs e candidatos a peças processuais primárias.
3. **`Phase01ToPhase02Contract` (`Fase 01` $\rightarrow$ `Fase 02`):** Fotografia física inicial (`PreScanSnapshot`), catálogo `SHA-256` inicial das fontes, fichas POP Senasp extraídas de peças primárias, matriz preliminar *Declarado $\times$ Entregue* e lista de bancos/contêineres que exigem auditoria profunda de preservação.
4. **`Phase02ToPhase03Contract` (`Fase 02` $\rightarrow$ `Fase 03`):** Diagnóstico de integridade estrutural (`-wal`/`-shm`, `quick_check`, `%%EOF`), mapa de risco de cópia única (`SPOF`), avaliação dos $6$ Eixos da Preservação Estatal e lista aprovada de itens para aquisição rumo ao `vault/` (ou indexação referenciada para imagens brutas multi-terabyte).
5. **`Phase03ToPhase04Contract` (`Fase 03` $\rightarrow$ `Fase 04`):** Manifesto verificado do `vault/` (`source_sha256 == vault_sha256`), árvore raiz de `ControlNumbers` (`CN-00000001`), mapeamentos dinâmicos de schemas aprovados e diretório `staging/` autorizado.
6. **`IterativeDiscoveryFeedbackPayload` (`Fase 04` / `Fase 05` $\rightarrow$ `Fase 01` via `IterativeDiscoveryFeedbackPort`):** Sempre que a descompactação profunda ou o OCR na Fase 04 revelar novos Autos de Apreensão, FAVs, Mandados, Laudos ou novos custodiantes dentro do HD, realimenta automaticamente a Fase 01 para gerar uma nova versão auditada da Matriz *Declarado $\times$ Entregue* sem qualquer acoplamento entre pacotes!
7. **`Phase04ToPhase05Contract` (`Fase 04` $\rightarrow$ `Fase 05`):** URI e hash do catálogo analítico populado, contagens dos $5$ Relatórios EDRM 5.0, alertas automáticos medidos (eventos pós-apreensão, múltiplas revisões PDF, duplicidades financeiras, saltos impossíveis de ERB, CGNAT sem porta lógica) e índice híbrido `RRF` pronto.
8. **`Phase05ToPhase06Contract` (`Fase 05` $\rightarrow$ `Fase 06`):** Conjunto congelado de revisão (`FrozenReviewSet`), matriz de contradições materiais *Relatório Policial/Laudo $\times$ Dado Bruto do HD* e classificação jurídica dos vícios probatórios.
9. **`Phase06ToPhase07Contract` (`Fase 06` $\rightarrow$ `Fase 07`):** Parecer Técnico Defensivo nos $7$ Blocos Oficiais aprovado pelo Verificador Bloqueante (`0` erros), *load files* e roteiro determinístico de reprodução independente.
10. **`Phase07ToPhase08Contract` (`Fase 07` $\rightarrow$ `Fase 08`):** Lista completa de entregáveis finais lacrados, autorização de expurgo verificado da pasta temporária `staging/` e diretrizes de retenção/sanitização.

### 5.2 Modelagem Relacional Unificada (`SQLite 3` & `PostgreSQL 17`)
* Todos os valores monetários são gravados exclusivamente em centavos inteiros (`BIGINT`, ex.: `R$ 1.540,90` $\rightarrow$ `154090`).
* Todos os carimbos de tempo preservam a string bruta original, a época de origem (`UNIX_1970_S`, `UNIX_1970_MS`, `COCOA_2001_S`, `COCOA_2001_NS`, `QUICKTIME_1904_S`, `ISO8601_OFFSET`, `LOCAL_ASSUMED`) e o instante normalizado em UTC.
* Coordenadas geográficas de antenas e GPS usam micrograus inteiros (`BIGINT`, graus $\times 1.000.000$) para evitar imprecisão de ponto flutuante.

Tabelas nucleares obrigatórias no catálogo unificado:
1. `governance_runs` (`run_id`, `case_id`, `phase_code`, `codebase_sha256`, `pre_scan_snapshot_sha256`, `post_scan_snapshot_sha256`, `zero_source_mutation_confirmed`).
2. `discovered_media_sources` (`source_id`, `mount_path`, `total_files`, `total_bytes`, `filesystem_hint`, `scanned_at_utc`).
3. `custodians` (`custodian_id`, `name`, `role`, `identifiers_json`, `epistemic_status`, `anchor_json`).
4. `declared_evidence_items` (`declared_id`, `custodian_id`, `primary_doc_type`, `seizure_utc`, `brand`, `model`, `serial_number`, `imei_chassis_json`, `imei_memory_json`, `iccid_json`, `lock_state`, `rf_isolation`, `seals_in_json`, `seals_out_json`, `working_copy_examined`, `state_sha256`, `master_hashlist_sha256`, `expected_raw_format`, `epistemic_status`, `anchor_json`).
5. `evidence_inventory_tree` (`control_number`, `parent_control_number`, `source_id`, `origin_rel_path`, `vault_rel_path`, `size_bytes`, `mtime_utc_ns`, `is_os_readonly`, `sha256_hex`, `magic_signature`, `extension_spoofed`, `is_encrypted_or_corrupted`, `pdf_eof_count`, `has_wal_shm_sibling`, `is_denist_logical`, `duplicate_of_cn`, `all_custodians_json`, `all_source_paths_json`).
6. `dynamic_schema_blueprints` (`schema_hash`, `container_cn`, `db_or_table_name`, `columns_json`, `inferred_domain`, `extraction_sql_template`, `approved_by_verifier`).
7. `custody_and_parity_findings` (`finding_id`, `declared_id`, `matched_cn`, `parity_state`, `preservation_axis`, `defect_category`, `legal_tags_json`, `is_judicial_critical`, `epistemic_status`, `anchor_json`).
8. `unified_timeline_events` (`event_id`, `origin_cn`, `event_type`, `raw_ts`, `epoch_kind`, `tz_declared`, `ts_utc`, `is_post_seizure`, `actor_origin`, `actor_target`, `content_verbatim`, `locator`, `origin_sha256`).
9. `financial_ledger_entries` (`entry_id`, `origin_cn`, `bank_code`, `branch`, `account`, `holder_tax_id`, `counterparty_tax_id`, `tx_utc`, `debit_credit`, `amount_cents`, `raw_amount_text`, `is_inter_file_duplicate`, `locator`, `origin_sha256`).
10. `telecom_cdr_erb_events` (`cdr_id`, `origin_cn`, `caller`, `callee`, `imei`, `start_utc`, `duration_sec`, `cell_cgi`, `lat_microdeg`, `lon_microdeg`, `azimuth_deg`, `impossible_speed_flag`, `locator`, `origin_sha256`).
11. `hybrid_search_chunks` (`chunk_id`, `origin_cn`, `locator`, `text_clean`, `injection_neutralized`, `vector_blob`, `origin_sha256`).
12. `ai_and_qc_audit_log` (`audit_id`, `ts_utc`, `phase_code`, `model_name`, `prompt_sha256`, `tokens_in`, `tokens_out`, `verifier_passed`, `rejected_claims_count`, `sampling_method`, `stratum_stats_json`).

---

## 6. ESPECIFICAÇÃO PASSO A PASSO DE TODAS AS FASES E MICROFASES DO PROGRAMA

### 6.0 CAMADA FUNDACIONAL 00 — GOVERNANÇA DA INFORMAÇÃO (`edrm.igrm_governance` — IGRM v4.1)
Roda automaticamente na inicialização do caso e envolve cada comando subsequente:
* **Microfase 0.1 — Criação e Blindagem do Workspace:** Inicializa a árvore limpa `vault/`, `staging/`, `catalog/`, `deliverables/` e `audit/`, impedindo sobreposição com qualquer pasta de mídia `--source`.
* **Microfase 0.2 — Bloqueador Lógico de Escrita na Fonte (`SourceWriteBlockerGuard`):** Intercepta todas as operações de sistema de arquivos do programa; qualquer tentativa de abrir descritor de arquivo em modo de escrita (`w`, `a`, `r+`, `x`), renomear, apagar ou alterar permissões dentro de `--source` dispara imediatamente `ReadOnlyViolationError`.
* **Microfase 0.3 — Auto-Calibração Prévia de Ferramentas (ISO/IEC 27041):** Roda em memória a bateria de calibração do **Verificador Determinístico Bloqueante**, exigindo aprovação simultânea no controle positivo e nos dois controles negativos (mutação numérica/hash e entidade textual fantasma).
* **Microfase 0.4 — Soberania de Dados e Sigilo Judicial:** Quando `secrecy_level == JUDICIAL_SECRECY_LOCAL_ONLY` (padrão de fábrica), bloqueia no nível de socket qualquer conexão externa fora de `127.0.0.1` / `localhost`, assegurando cumprimento físico da Recomendação CFOAB nº 001/2024 e das Resoluções CNJ nº 615/2025 e nº 674/2026.

---

### 6.1 FASE 01 — IDENTIFICAÇÃO E AUTODESCOBERTA DO HD (`edrm.phase01_identification` — CPP Art. 158-B, I)
Executa o reconhecimento completo da mídia recém-conectada em **4 Etapas e 11 Microfases**:

* **Etapa 1.A — Fotografia Inicial e Sonda Binária Passiva do HD:**
  * *Microfase 1.1 (Snapshot Físico Inicial):* Percorre `--source` em modo estritamente passivo (`os.scandir` / `os.stat`), registrando `size_bytes`, `mtime_utc_ns` e atributos de cada arquivo para formar a linha de base imutável `PreScanSnapshot`.
  * *Microfase 1.2 (Cálculo `SHA-256` em Streaming Retomável):* Calcula `SHA-256` em blocos fixos de $4\text{ MiB}$ (ou reaproveita manifesto anterior do próprio workspace em *warm-start*), mantendo *checkpoint* transacional a cada lote para suportar desconexão acidental de cabo USB sem perder o progresso.
  * *Microfase 1.3 (Classificação por Magic Bytes de $16\text{ Bytes}$ e Camuflagem):* Inspeciona os primeiros $16\text{ bytes}$ de cada arquivo para identificar sua natureza binária real (`SQLITE3`, `EWF_E01`, `AFF4`, `ZIP_CONTAINER`, `CELLEBRITE_UFDR_UFDX`, `RAR_V4_V5`, `SEVEN_ZIP`, `PDF_DOCUMENT`, `PST_OST`, `GZIP`, `LUKS`, `PGP_GPG`, `WHATSAPP_CRYPT`, áudio/vídeo/imagem ou texto), sinalizando imediatamente `extension_spoofed = True` quando a extensão nominal contradiz o cabeçalho binário (ex.: banco SQLite ou planilha renomeada para `.dll` ou `.tmp`).

* **Etapa 1.B — Radiografia Estrutural e Autodescoberta Assistida por IA:**
  * *Microfase 1.4 (Radiografia Interna Sem Descompactação Bruta):* Lê os diretórios centrais de arquivos `.zip`/`.ufdr`/`.tar`, extrai os comandos `CREATE TABLE` de todos os bancos SQLite via URI `mode=ro&immutable=1` + `PRAGMA query_only=1` (detectando também presença de irmãos `-wal`/`-shm`), lê as primeiras linhas de cabeçalho de arquivos tabulares `.csv`/`.txt` e conta marcadores `%%EOF` em PDFs.
  * *Microfase 1.5 (Descoberta Inteligente de Schemas e Peças do Caso):* O Intérprete Analítico examina os schemas e metadados levantados na Microfase 1.4 para: (a) localizar dentro do HD quais documentos são peças processuais primárias (`AUTO_APREENSAO`, `MANDADO`, `FAV`, `DECISAO_JUDICIAL`, `LAUDO_PERICIAL`, `DENUNCIA`); e (b) reconhecer tabelas de aplicativos conhecidos ou propor `DynamicSchemaBlueprint` para bancos/planilhas específicas daquele caso, gerando o Mapa Completo do HD.
  * *Microfase 1.6 (Reconciliação de Cópias e Famílias na Mídia):* Agrupa arquivos repetidos em múltiplas pastas ou mídias pela hierarquia determinística: (1) `EXACT_SHA256`, (2) `FILENAME_AND_EXACT_BYTES`, (3) `WEAK_NAME_ONLY_UNCONFIRMED` e (4) `UNRESOLVED_GAP`.

* **Etapa 1.C — Catalogação POP Senasp 2024 e Confronto *Declarado $\times$ Entregue*:**
  * *Microfase 1.7 (Extração Atômica de Custodiantes e Vestígios):* Extrai exclusivamente das peças primárias identificadas todos os custodiantes e vestígios com os parâmetros de auditoria do **POP Senasp Vol. 5 (2024)**: data/hora UTC da apreensão, marca, modelo, série, `IMEI` impresso no chassi vs. `IMEI` em memória, `ICCID`, verificação de segundo espaço/pasta segura, estado `BFU`/`AFU`, isolamento radioelétrico (Faraday / $3$ camadas de alumínio / modo avião verificado), números de lacre de coleta e de relacre, realização do exame sobre cópia vs. mídia original e hash lavrado pelo Estado (incluindo o hash da lista de hashes).
  * *Microfase 1.8 (Saneamento Zero-Silent-Drop e Conflitos Lado a Lado):* Converte qualquer campo ausente em `EXPLICIT_GAP` (jamais descartando o registro), isola contradições entre duas peças oficiais em `DivergenceRecord` e sanitiza textos contra *prompt injection* indireto.
  * *Microfase 1.9 (Motor Determinístico Declarado $\times$ Entregue):* Cruza o que o Estado declarou ter apreendido/extraído contra o que realmente veio dentro do HD conectado, classificando nos $7$ estados forenses:
    1. `MATCHED_INTACT_HASH`
    2. `MATCHED_WITHOUT_ORIGIN_HASH` (tags: `CPP_ART_158_B`, `POP_SENASP_2024_5_01`)
    3. `DIVERGENT_HASH_OR_SIZE` (tags: `CPP_ART_158_A_MESMIDADE`, `QUEBRA_CADEIA_CUSTODIA`)
    4. `DECLARED_RAW_NOT_DELIVERED` — quando há menção ou PDF parcial no HD, mas falta o contêiner bruto integral `E01`, `UFDR`/`UFDX`, `SQLite`, `SIMBA` ou `CDR` (tags: `STF_TEMA_977`, `STJ_EDICAO_281`, `CPP_ART_159_P6`)
    5. `DELIVERED_ENCRYPTED_OR_CORRUPTED` (tags: `STJ_RHC_184003_SP`, `CERCEAMENTO_DEFESA`)
    6. `DELIVERED_UNDOCUMENTED_IN_AUTOS` (tags: `CPP_ART_158_B_ORIGEM_OMISSA`)
    7. `DEFERRED_AWAITING_PRIMARY_DOC`.

* **Etapa 1.D — Verificação Bloqueante, Amostragem de Cochran e Lacre da Fase 01:**
  * *Microfase 1.10 (Auditoria 100% Críticos + Cochran):* Inclui $100\%$ dos achados críticos na conferência obrigatória e sorteia amostra finita estratificada de Cochran ($Z = 1.96, p = 0.5, e = 0.10$) nos demais estratos:
    $$n_0 = \frac{Z^2 \cdot p \cdot (1 - p)}{e^2}, \qquad n = \left\lceil \frac{n_0}{1 + \frac{n_0 - 1}{N}} \right\rceil$$
  * *Microfase 1.11 (Compilação Verificada e Handoff `01` $\rightarrow$ `02`):* Valida todos os relatórios Markdown da Fase 01 no Verificador Bloqueante (`0` falhas), confere `PreScanSnapshot == PostScanSnapshot` e emite `Phase01ToPhase02Contract`.

---

### 6.2 FASE 02 — PRESERVAÇÃO (`edrm.phase02_preservation` — CPP Art. 158-B, II, III e V)
Audita se os dados do HD conectado foram preservados corretamente pelo Estado desde a cena do fato e blinda a custódia defensiva local em **4 Subetapas**:
* **Subetapa 2.1 — Diagnóstico de Integridade Estrutural das Mídias e Bancos:**
  * Executa `PRAGMA quick_check` sobre bancos SQLite abertos em `mode=ro&immutable=1`;
  * Audita transações pendentes em arquivos `-wal`/`-shm` (medindo de forma não destrutiva se há registros no `-wal` ainda não consolidados nas páginas principais do banco);
  * Testa integridade de cabeçalhos e CRCs de pacotes compactados e sinaliza truncamentos ou setores danificados.
* **Subetapa 2.2 — Mapa de Risco de Cópia Única (`SPOF`) e Preservação Defensiva:**
  * Avalia se cada evidência crítica possui cópia preservada no `vault/` com bloqueio de escrita do sistema operacional ativo e identifica itens em Ponto Único de Falha (`SPOF`) que exigem aquisição imediata na Fase 03.
* **Subetapa 2.3 — Auditoria Pericial da Preservação Estatal nos 6 Eixos Obrigatórios:**
  * Mantendo $1$ linha atômica por vestígio ancorado (zero fusão heurística), avalia a atuação policial/pericial nos **6 Eixos de Origem**:
    1. `ISOLAMENTO_RADIOELETRICO_E_VOLATILIDADE` (uso de bolsa de Faraday, $3$ camadas de papel-alumínio, modo avião verificado, coleta de RAM em máquinas ligadas conforme RFC 3227 e bloqueador de escrita);
    2. `ESTADO_ENERGETICO_BLOQUEIO_E_RELOGIO` (`BFU` vs. `AFU`, estado ligado/desligado e registro de *clock drift* em relação ao UTC);
    3. `CADEIA_DE_LACRES_E_FAV` (numeração contínua de envelopes, relacres pós-perícia, Ficha de Acompanhamento de Vestígio individualizada e detecção de divergências alfanuméricas ou caracteres homógrafos);
    4. `CERTIFICACAO_DE_HASH_NA_ORIGEM` (existência ou omissão de `SHA-256` no ato da apreensão/coleta e no recebimento pericial, além do hash da lista de hashes exigido pelo POP Senasp `5.01`/`5.02`);
    5. `INTEGRIDADE_FISICA_E_LOGICA_DO_VESTIGIO` (corrupção de blocos, páginas SQLite danificadas, edições incrementais não explicadas);
    6. `ACESSIBILIDADE_E_CIFRAGEM` (contêineres e backups criptografados sem chave ou senha disponibilizada nos autos).
* **Subetapa 2.4 — Emissão do Termo Técnico de Preservação (*Legal Hold*) e Handoff `02` $\rightarrow$ `03`:**
  * Compila os relatórios da Fase 02 aprovados com `0` erros no Verificador Bloqueante, aplica amostragem de Cochran, reconfere `0` mutações no HD de origem e emite `Phase02ToPhase03Contract`.

---

### 6.3 FASE 03 — COLETA E AQUISIÇÃO DEFENSÁVEL (`edrm.phase03_collection` — CPP Art. 158-B, IV, VI e VII + Arts. 158-C e 158-D)
Transfere de forma forense os elementos do HD conectado para o cofre protegido do caso (`workspace/vault/`) — ou gera espelho referenciado verificado para imagens de disco gigantes — e audita o método de extração usado pela polícia:
* **Etapa 3.1 — Plano Inteligente de Aquisição:** Permite escolher entre ingestão integral do HD para `vault/` ou ingestão seletiva guiada pela Fase 02 + indexação referenciada imutável (ideal quando o HD conectado possui imagens brutas `.E01`/`.RAW` de vários terabytes e o usuário deseja economizar espaço sem perder a garantia de `SHA-256`).
* **Etapa 3.2 — Cópia Forense em Streaming com `os.fsync` e Releitura Fria:**
  * Lê a origem em blocos de $4\text{ MiB}$ calculando `sha256_source` em tempo real;
  * Grava em `workspace/vault/`, força descarga física do cache de memória do sistema operacional para o disco (`os.fsync`), fecha o descritor, reabre o arquivo recém-gravado em leitura fria e calcula `sha256_vault`;
  * **Bloqueio de Mesmidade:** Só homologa a coleta se `sha256_source == sha256_vault` e `bytes_source == bytes_vault`; qualquer diferença de $1\text{ bit}$ remove o arquivo defeituoso e lança `CollectionHashMismatchError`.
* **Etapa 3.3 — Genealogia `ControlNumber` e Trava Física Read-Only:** Atribui número de controle único (`CN-00000001`) preservando os carimbos de tempo originais em manifesto lateral e aplica permissão somente leitura (`chmod a-w` / `FILE_ATTRIBUTE_READONLY`) no cofre.
* **Etapa 3.4 — Auditoria do Método Estatal de Coleta e Manifesto ICP-Brasil:** Avalia tecnicamente quem realizou a extração estatal (perito oficial vs. agente sem justificativa — art. 158-C do CPP), o método empregado (aquisição física *bitstream*, *Full File System*, extração lógica parcial ou gravação manual de tela tratada como última opção de alto risco pelo POP Senasp `5.02`), se o exame ocorreu indevidamente direto no aparelho original e se houve trânsito por aplicativos mensageiros que destroem metadados. Emite manifesto pronto para assinatura qualificada ICP-Brasil e publica `Phase03ToPhase04Contract`.

---

### 6.4 FASE 04 — PROCESSAMENTO UNIVERSAL (`edrm.phase04_processing` — Subetapas Oficiais EDRM 1.0 a 5.0 + CPP Art. 158-B, VIII)
Processa **exclusivamente cópias em `workspace/staging/` ou leituras imutáveis**, jamais tocando no HD original nem alterando o `vault/`, executando as **5 Subetapas Oficiais das Diretrizes de Processamento do EDRM**:

* **Subetapa 4.1 (EDRM 1.0 — Ingestão de ESI, Descompactação Segura e Ponte Externa IPED CLI):**
  * Fila transacional idempotente com *checkpoint* por micro-lote (retoma exatamente de onde parou sem duplicar registros via `ON CONFLICT DO NOTHING`);
  * Desempacota recursivamente `.zip`, `.ufdr`, `.ufdx`, `.tar`, `.gz`, `.7z`, `.rar` e anexos em `workspace/staging/` mantendo rigorosamente o vínculo pai-filho (`CN-00000001.0001` $\rightarrow$ `CN-00000001.0001.0001`), com defesas ativas contra *Zip Bomb* e *Path Traversal* (`../`);
  * **Ponte Limpa via Linha de Comando com IPED 4.3.x:** Quando disponível no ambiente para imagens pesadas (`E01`, `AFF4`, `RAW`, `UFDR` massivos), invoca o binário externo `iped --nogui -d <fonte_ro> -o <workspace/staging/iped_out> -profile fastmode` (ou `triage`), importando em seguida os metadados, hashes e textos do banco resultante `sleuth.db` em `mode=ro&immutable=1` — aproveitando todo o poder do motor da Polícia Federal sem misturar código Java GPL-3.0 ao núcleo Python (e operando com *fallback* Python nativo completo caso o IPED não esteja instalado).

* **Subetapa 4.2 (EDRM 2.0 — Filtragem Inicial Não Destrutiva: *De-NISTing* e Deduplicação):**
  * **De-NISTing Seguro de Família Documental:** Compara hashes contra a lista de arquivos de sistema conhecidos (*NSRL RDS*), aplicando `is_denist_logical = True` **exclusivamente sobre itens de nível superior (*parent*)**, jamais quebrando anexos filhos de e-mails ou conversas;
  * **Deduplicação Lógica com Prova Negativa Preservada:** Marca cópias exatas (`duplicate_of_cn`) consolidando `all_custodians_json` e `all_source_paths_json` **sem excluir nenhuma linha do banco**, garantindo que a defesa possa provar tanto onde um arquivo estava quanto em quais aparelhos/custodiantes ele **não** existia.

* **Subetapa 4.3 (EDRM 3.0 — Extratores Determinísticos das 11 Categorias Forenses + Extrator Dinâmico de Schemas Inéditos):**
  1. **Documentos, Autos e PDFs:** Extrai texto nativo por página (`p. <n>`), aciona OCR (`Tesseract -l por`) somente em páginas escaneadas sem texto nativo (evitando perda silenciosa de documentos digitalizados), compara metadados `/Info` vs. `XMP` e alerta quando `pdf_eof_count > 1` (*Incremental Updates* recuperáveis) ou `/ModDate` posterior à assinatura.
  2. **Mensageiros e Bancos Móveis Conhecidos + Inéditos:** Extrai WhatsApp Android (`msgstore.db`, época Unix $1970\text{ ms}$, resolução de contatos `lid`), WhatsApp iOS (`ChatStorage.sqlite`, época Cocoa $2001 + 978.307.200\text{ s}$), Telegram, SMS, registros de chamadas e histórico web em `immutable=1`. Para **qualquer banco SQLite desconhecido** descoberto no HD na Fase 01, executa o `DynamicUnknownSqliteExtractor` sobre o `DynamicSchemaBlueprint` validado. Em todos os eventos móveis, roda automaticamente o **Detector de Atividade Pós-Apreensão**, cravando `is_post_seizure = True` sempre que `ts_utc > seizure_utc`!
  3. **Contêineres Cellebrite (`UFDR` / `UFDX` / `UFD` / `report.xml`):** Parser XML em *streaming* (`iterparse` com descarte imediato de nós da RAM), preservando versão da ferramenta forense, mensagens citadas/respondidas, itens marcados como deletados e coordenadas.
  4. **Quebras Bancárias e Fiscais (`SIMBA` BACEN / IN BCB 636/2025, `OFX`, Extratos CSV):** Valida a estrutura relacional (`CASO`, `TITULARES`, `CONTAS`, `EXTRATO`, `ORIGEM_DESTINO`), converte valores diretamente para `amount_cents: int` (`BIGINT`, zero `float`) e roda o **Detector de Duplicidade Contábil Inter-Arquivos** para impedir somas acusatórias infladas.
  5. **Registros Telefônicos `CDR` e Antenas `ERB`:** Padroniza horários locais das operadoras para UTC estrito, cruza `CGI`/`CellID` com a base georreferenciada da ANATEL (latitude/longitude em micrograus inteiros + azimute de setor) e sinaliza deslocamentos com velocidade humana fisicamente impossível entre duas antenas consecutivas.
  6. **Áudios, Mídias de Voz e Interceptações:** Segmenta fala humana via `Silero VAD` (impedindo alucinações repetitivas de transcrição em trechos de silêncio ou ruído), transcreve localmente via `Faster-Whisper` com âncora exata em milissegundos (`[00:02:14.120 -> 00:02:19.450]`) e verifica quebras abruptas de cabeçalho/fase.
  7. **Fotografias e Vídeos:** Extrai EXIF completo, serial de câmera, GPS e distingue arquivos originais de câmera de mídias recomprimidas/despojadas de metadados por mensageiros.
  8. **Caixas e Mensagens de E-mail (`PST`, `OST`, `MBOX`, `EML`):** Reconstrói a rota de servidores `Received:` em UTC, preserva `Message-ID` / `In-Reply-To` (*Email Threading*) e verifica cabeçalhos criptográficos `SPF`, `DKIM`, `ARC` e `DMARC`.
  9. **Imagens Forenses de Disco (`E01`, `AFF4`, `RAW/DD`):** Cataloga partições, espaço não alocado e arquivos recuperados por *carving*, mantendo distinção clara entre arquivo ativo e fragmento recuperado.
  10. **Logs de Internet e Nuvem (`IP` / `CGNAT`):** Audita a presença obrigatória da **porta lógica de origem** associada ao IP compartilhado e ao timestamp UTC com fuso explícito (Decreto nº 12.975/2026).
  11. **Extrator Profundo de Peças Processuais Primárias:** Extrai entidades e vestígios de novos autos, mandados, FAVs e laudos descompactados durante o processamento.

* **Subetapa 4.4 (EDRM 4.0 — Saída Normalizada e Gatilho Iterativo `04` $\rightarrow$ `01`):**
  * Grava os registros normalizados no catálogo analítico e dispara `IterativeDiscoveryFeedbackPort` sempre que o Extrator #11 descobrir novas peças primárias dentro de contêineres do HD, atualizando automaticamente o escopo e a Matriz *Declarado $\times$ Entregue* da Fase 01.

* **Subetapa 4.5 (EDRM 5.0 — Os 5 Relatórios Oficiais de Processamento e Fila de Exceções):**
  * Gera deterministicamente: (1) Relatório de Inventário de Arquivos; (2) Relatório por Custodiante/Aparelho; (3) Relatório Auditável de Filtragem (*De-NIST* e Deduplicação); (4) Relatório de Cadeia de Custódia do Processamento; e (5) Relatório Completo de Exceções (*Dead-Letter Queue*: arquivos criptografados, protegidos por senha ou corrompidos). Emite `Phase04ToPhase05Contract`.

---

### 6.5 FAIXA TRANSVERSAL — ANÁLISE CONTÍNUA, BUSCA HÍBRIDA `RRF` E IA GOVERNADA (`edrm.continuous_analysis`)
Serve todas as fases sob rigorosa separação entre matemática exata e inferência assistida:
* **Motor de Busca Híbrida `RRF` (*Reciprocal Rank Fusion*):** Funde busca léxica exata (`BM25` — implacável para CPFs, placas, lacres, hashes, telefones e valores exatos) com busca semântica vetorial (`BGE-M3` 1024d) usando $k = 60$:
  $$\text{Score}_{\text{RRF}}(d) = \frac{1}{k + r_{\text{lex}}(d)} + \frac{1}{k + r_{\text{vec}}(d)}$$
* **Linha do Tempo Unificada Multi-Fonte em UTC:** Cruza na mesma régua cronológica mensagens de celular, chamadas, antenas ERB, transferências bancárias SIMBA, criação/edição de arquivos e horários lavrados pela polícia nos autos.
* **Escudo Anti-*Prompt Injection* e Disjuntor de Orçamento:** Textos extraídos de provas recebem isolamento estrutural antes de qualquer leitura por IA local (`Ollama` / `vLLM`), sob teto estrito de tokens por chamada e zero subagentes autônomos descontrolados.
* **Verificador Determinístico Bloqueante:** Nenhuma síntese, sugestão ou parágrafo assistido por IA é aceito sem trazer `control_number`, `origin_sha256`, `locator` e `verbatim_quote`. O código confere caractere por caractere no banco se o hash e o trecho literal existem identicamente na fonte; qualquer desvio bloqueia a saída e registra a rejeição em `ai_and_qc_audit_log`.
* **Controle Estatístico Triplo de Qualidade:** Aplica **Amostragem de Cochran** ($95\%, \pm 10\%$) nos itens classificados, **Teste de Elusão** no conjunto não selecionado/filtrado e a **Regra do 3 de Hanley & Lippman-Hand** ($\text{limite superior IC } 95\% \approx 3/n$ quando zero erros são observados em $n$ itens inspecionados).

---

### 6.6 FASE 05 — REVISÃO (`edrm.phase05_review` — Nexo Central de Relevância Jurídica)
* **Etapa 5.1 — Filtro de Prerrogativas e Marcação Estratégica:** Isola comunicações protegidas por sigilo profissional advogado-cliente e organiza os achados por fato imputado, custodiante e tese defensiva.
* **Etapa 5.2 — Motor de Confronto Material (*Relatório Policial / Laudo $\times$ Prova Bruta do HD*):** Compara automaticamente trechos citados pela acusação com o banco bruto processado na Fase 04, revelando: (a) diálogos truncados com omissão das mensagens imediatamente anteriores e posteriores que mudam o sentido da conversa; (b) valores financeiros contados em duplicidade; (c) suposta presença física em ERB desmentida por azimute oposto ou registro simultâneo de Wi-Fi/GPS no próprio celular; e (d) conclusões periciais sem lastro nos arquivos examinados.
* **Etapa 5.3 — Classificador Jurídico do Vício Probatório:** Enquadra cada falha técnica segundo sua consequência processual penal concreta:
  1. `FORMAL_IRREGULARITY` (irregularidade administrativa sem dano à mesmidade);
  2. `CUSTODY_BREAK_WEIGHT_REDUCTION` (quebra documentada da cadeia de custódia nos arts. 158-A a 158-F do CPP, impondo esvaziamento/redução do peso probatório);
  3. `DEFENSE_PARITY_VIOLATION_TEMA_977` (sonegação de contêiner bruto integral ou mídia inacessível/cifrada — art. 159, § 6º, do CPP, STF Tema 977 e STJ RHC 184.003/SP);
  4. `ABSOLUTE_NULLITY_ILLICIT_EVIDENCE` (acesso sem autorização judicial válida, extrapolação de mandado ou manipulação pós-apreensão — art. 157 do CPP).
* **Etapa 5.4 — Congelamento Auditável do Conjunto de Revisão:** Lacra o conjunto selecionado sem deletar itens não selecionados e emite `Phase05ToPhase06Contract`.

---

### 6.7 FASE 06 — PRODUÇÃO (`edrm.phase06_production` — CPP Art. 159, §§ 5º e 6º)
* **Etapa 6.1 — Compilador Determinístico do Parecer Técnico Defensivo nos 7 Blocos Oficiais:**
  1. *Preâmbulo, Identificação Processual e Delimitação do Escopo*;
  2. *Inventário Criptográfico das Mídias Recebidas e Cadeia de Custódia Defensiva*;
  3. *Metodologia Científica, Calibração ISO/IEC 27041 e Ferramentas Auditáveis*;
  4. *Exame de Integralidade, Matriz Declarado $\times$ Entregue e Exceções Técnicas*;
  5. *Achados Periciais Medidos, Linhas do Tempo UTC e Confronto Material com o Laudo Estatal*;
  6. *Protocolo Exato de Reprodução Independente* (comandos determinísticos, queries SQL e hashes para que o perito do juízo repita o exame sobre a mídia acautelada pelo Estado e obtenha exatamente o mesmo resultado);
  7. *Respostas Fundamentadas aos Quesitos, Conclusão Técnica e Manifesto de Assinatura ICP-Brasil*.
* **Etapa 6.2 — Exportação de *Load Files* Forenses:** Gera arquivos de carga padronizados (`.DAT`/`.CSV` com delimitadores seguros e `EDRM XML`) mantendo numeração `ControlNumber` e vínculos familiares.
* **Etapa 6.3 — Dupla Passagem no Verificador Bloqueante (`0` Falhas) e Empacotamento ICP-Brasil:** Valida $100\%$ das cifras, hashes e citações literais antes de gravar em `workspace/deliverables/` e emite `Phase06ToPhase07Contract`.

---

### 6.8 FASE 07 — APRESENTAÇÃO (`edrm.phase07_presentation`)
* **Etapa 7.1 — Gerador Automático de Quesitos Periciais Sob Medida:** Converte cada anomalia real detectada no HD em quesitos técnicos objetivos ancorados no **POP Senasp Vol. 5 (2024)** e nos arts. 158-A a 158-F do CPP.
* **Etapa 7.2 — Quadros Probatórios Prontos para Petições, Memoriais e Sustentação Oral:** Gera anexos sintéticos estruturados para requerimentos de acesso à integralidade (Tema 977/STF), preliminares de nulidade e memoriais.
* **Etapa 7.3 — Dossiê Interativo *Offline* em Arquivo Único `HTML5`:** Compila um painel visual $100\%$ autocontido (sem nenhuma dependência de internet ou CDN externa, seguro para exibição em gabinete, audiência ou plenário) com busca instantânea, Linha do Tempo UTC filtrável, comparador visual *Lado a Lado (Relatório Acusatório $\times$ Dado Bruto Original)* e cartões de verificação `SHA-256`. Emite `Phase07ToPhase08Contract`.

---

### 6.9 FASE 08 — DESTINAÇÃO FINAL E CICLO DE RETENÇÃO (`edrm.phase08_disposition` — CPP Art. 158-B, X + NIST SP 800-88 Rev. 2)
* **Etapa 8.1 — Expurgo Verificado da Área Efêmera `workspace/staging/`:** Após confirmar por `SHA-256` que todos os catálogos, relatórios e pacotes de auditoria estão íntegros em `catalog/`, `deliverables/` e `audit/`, limpa com segurança os arquivos temporários descompactados em `staging/`, liberando espaço em disco sem jamais tocar no HD de origem nem em `vault/`.
* **Etapa 8.2 — Empacotamento Anti-Perda (`Recovery Bundle`):** Gera pacote autocontido versionado (`git bundle` + `MANIFESTO_SHA256.txt`) da estrutura do projeto e dos relatórios auditados.
* **Etapa 8.3 — Destinação Pós-Trânsito em Julgado Certificada (NIST SP 800-88 Rev. 2):** Operação protegida por dupla confirmação explícita do responsável (`require_explicit_human_authorization = True`): emite termos formais de devolução/encerramento de custódia e executa sanitização certificada (*Purge / Cryptographic Erase* compatível com SSD/NVMe moderno ou verificação de destruição, conforme **NIST SP 800-88 Rev. 2**, set./2025) sobre cópias de trabalho cujo descarte legal tenha sido determinado após o trânsito em julgado, gerando `CertificateOfDisposition.json` reconectado à base **IGRM v4.1**.

---

## 7. LOOP AUTOMÁTICO DE AUTO-TESTE E HOMOLOGAÇÃO (`tools/run_forensic_gates.py` — `G0` A `G10`)

O código gerado pela IA é proibido de encerrar qualquer etapa sem antes executar e passar com **`EXIT CODE 0`** em todos os portões cumulativos do verificador autônomo `tools/run_forensic_gates.py`:

* **`G0` — Higiene Total de Código:** Varre via AST todos os arquivos `.py` exigindo zero erros de sintaxe, zero `TODO`/`FIXME`, zero `pass` ou `...` em implementações concretas e zero `NotImplementedError` fora de classes abstratas.
* **`G1` — Auditoria Estática AST de Clean Architecture, Hexagonal, SOLID e Travas Forenses:** Prova matematicamente na árvore sintática: (a) zero imports de I/O em `domain/` e `application/`; (b) zero imports cruzados entre pacotes das fases `00` a `08`; (c) uso exclusivo de `typing.Protocol` nas portas e `@dataclass(frozen=True)` nas entidades/contratos; (d) zero uso de `float` em módulos monetários/bytes e zero uso de `hash()` volátil do Python.
* **`G2` — Calibração ISO/IEC 27041:** Confirma que o Verificador Bloqueante passa no controle positivo e bloqueia $100\%$ dos controles negativos (numérico/hash adulterado e entidade textual inventada).
* **`G3` — Validação da Camada 00 e Fase 01 (Autodescoberta do HD):** Testa `SourceWriteBlockerGuard` (`ReadOnlyViolationError`), detecção de *Magic Bytes* ($16\text{ bytes}$) e camuflagem de extensão, radiografia de SQLite imutável e `DynamicSchemaBlueprint`, *Zero-Silent-Drop*, Matriz *Declarado $\times$ Entregue* ($7$ estados) e cálculo exato de Cochran.
* **`G4` — Validação das Fases 02 e 03 (Preservação e Coleta):** Testa detecção não destrutiva de `-wal`/`-shm` e `quick_check`, classificador dos $6$ Eixos da Preservação Estatal, cópia `os.fsync` + releitura fria bloqueando corrupção simulada de $1\text{ bit}$ (`CollectionHashMismatchError`) e árvore de `ControlNumbers`.
* **`G5` — Validação da Fase 04 (Processamento EDRM 1.0–5.0):** Testa descompactação segura anti-*Zip-Bomb* em `staging/`, *De-NIST* preservando famílias pai-filho, deduplicação lógica preservando prova negativa, conversão exata WhatsApp Android ($1970$) e iOS ($2001 + 978.307.200\text{ s}$), detector automático de atividade pós-apreensão, extrator dinâmico de SQLite inédito, parser SIMBA em centavos `BIGINT`, normalizador CDR/ERB em micrograus/UTC, ponte externa IPED CLI simulada e retroalimentação `04` $\rightarrow$ `01`.
* **`G6` — Validação da Análise Contínua e Fase 05 (Revisão):** Testa busca híbrida `RRF`, linha do tempo multi-fonte UTC, escudo anti-*prompt injection*, rejeição imediata de alucinação pelo Verificador Bloqueante, cálculo de Elusão + Regra do 3 ($3/n$) e motor de contradições *Laudo $\times$ Bruto*.
* **`G7` — Validação das Fases 06, 07 e 08:** Testa compilação do Parecer Técnico nos $7$ Blocos Oficiais (`0` erros no Verificador), geração de *Load Files*, geração automática de quesitos POP Senasp 2024, painel único `HTML5` $100\%$ *offline*, expurgo seguro exclusivo de `staging/` e certificado NIST SP 800-88 Rev. 2.
* **`G8` — Substituição de Liskov (Fakes $\equiv$ Infraestrutura Real):** Roda exatamente a mesma bateria de contratos contra os adaptadores `InMemory` e contra os adaptadores físicos em sistema de arquivos real.
* **`G9` — Verificação do Instalador Autocontido:** Executa `materialize_elo_platform.py --target <temp> --verify` confirmando reconstrução limpa e conferência `SHA-256` de $100\%$ dos módulos.
* **`G10` — Simulação Ponta a Ponta *Plug-and-Analyze* de HD Bruto Desconhecido (`00` $\rightarrow$ `08`):** Cria automaticamente em diretório temporário um **"HD Forense Sintético Desconhecido"** contendo: (a) um Auto de Apreensão e um Laudo Oficial em texto/PDF com divergência de lacre e omissão de um `.ufdr` bruto; (b) um banco SQLite de WhatsApp com mensagem enviada $2\text{ horas}$ **após** o horário da apreensão; (c) um segundo banco SQLite de aplicativo inédito (descoberto dinamicamente pelo motor de schemas!); (d) um arquivo SQLite camuflado com extensão `.dll`; (e) um PDF com $2$ marcadores `%%EOF`; (f) um pacote financeiro SIMBA com lançamento duplicado; (g) registros CDR/ERB e log CGNAT sem porta lógica; e (h) um arquivo criptografado sem senha. Executa o comando único `plug-and-run-all`, valida que todas as fases `00` a `08` + o loop iterativo `04` $\rightarrow$ `01` completam com `0` falhas no Verificador Bloqueante e prova matematicamente que **nenhum bit ou timestamp do HD simulado foi alterado (`PreScanSnapshot == PostScanSnapshot`)**!

---

## 8. COMANDO MESTRE PARA O GOOGLE AI STUDIO MAX (CONSTRUÇÃO INTEGRAL EM 5 ONDAS)

Para extrair **código $100\%$ completo, profundo, sem resumos e testado ao vivo** no **Google AI Studio Max** sem esbarrar no limite físico de tokens de saída de uma única resposta, utilize **uma única janela de chat contínua**:

1. **Configuração no Painel Direito do Google AI Studio:**
   * **Model:** Selecione o modelo **Max / Pro Thinking** mais avançado disponível.
   * **Temperature:** **`0.1`**
   * **Thinking Budget:** **`Max / High`**
   * **Tools $\rightarrow$ Code Execution:** **`ON` (Ativado)** — obrigatório para a IA gravar, rodar e auto-corrigir os portões `G0` a `G10` na Sandbox Python antes de entregar cada onda.
2. **Caixa `System Instructions`:** Cole o **Bloco 8.1** abaixo.
3. **Chat Principal:** Envie em sequência as **Ondas 1 a 5** do **Bloco 8.2** (sempre na mesma conversa).

---

### 8.1 COPIAR E COLAR EM `SYSTEM INSTRUCTIONS` DO GOOGLE AI STUDIO

```text
Você é um Principal Forensic Software Architect & Staff Python Systems Engineer construindo do zero absoluto (100% Greenfield, sem qualquer código legado) a plataforma "ELO — Motor Universal Plug-and-Analyze de Auditoria Probatória e Descoberta Forense (EDRM 2.0 Completo)" em Python 3.12+.

LEIS INEGOCIÁVEIS EM TODAS AS ONDAS DESTA CONSTRUÇÃO:
1. PROJETO 100% DO ZERO E UNIVERSAL: O sistema não possui caminhos fixos nem dependências de projetos antigos. O usuário aponta qualquer mídia/HD conectado (`--source`) e qualquer pasta limpa de caso (`--workspace`), e o software descobre, audita e processa tudo do zero. Suporte transparente tanto POSIX/Linux (para execução real imediata na sua Sandbox Python do Google AI Studio) quanto Windows NTFS (caminhos longos `\\?\`, `FILE_ATTRIBUTE_READONLY` e URIs imutáveis quando `os.name == "nt"`).
2. PROIBIÇÃO TOTAL DE ESQUELETOS OU CÓDIGO INCOMPLETO: Jamais use `TODO`, `FIXME`, `pass` ou `...` em métodos concretos, `NotImplementedError` em classes concretas ou comentários como `# implementar restante`. Escreva 100% das classes, schemas SQL, algoritmos e testes de ponta a ponta.
3. CLEAN ARCHITECTURE, HEXAGONAL (PORTS & ADAPTERS) E SOLID AUDITADOS POR AST:
   - `domain/` e `application/` são 100% puros (zero imports de `os`, `sys`, `shutil`, `subprocess`, `sqlite3`, `zipfile`, `socket`, `http`, `urllib` e zero I/O).
   - Acoplamento zero entre pacotes de fases (`igrm_governance`, `phase01_identification` até `phase08_disposition` e `continuous_analysis`); toda comunicação ocorre exclusivamente pelos contratos imutáveis em `edrm.shared_kernel.contracts` injetados em `edrm.bootstrap.container`.
4. OS 8 PILARES PERICIAIS EM CÓDIGO:
   - Zero `float` para valores monetários ou bytes (`int`/`BIGINT` em centavos e `Decimal`).
   - Zero `hash()` nativo volátil do Python para IDs persistentes (use exclusivamente `hashlib.sha256`).
   - `SourceWriteBlockerGuard` impede fisicamente qualquer escrita na mídia `--source` (`ReadOnlyViolationError`) e comprova `PreScanSnapshot == PostScanSnapshot`.
   - Bancos SQLite de evidência abrem exclusivamente com `file:...?mode=ro&immutable=1` + `PRAGMA query_only = 1;`.
   - Toda saída documental ou assistida por IA passa pelo Verificador Determinístico Bloqueante (`0` erros obrigatórios).
5. LOOP OBRIGATÓRIO DE AUTO-TESTE NA SANDBOX PYTHON: Em cada Onda, grave os arquivos no sistema de arquivos da sua Sandbox via Code Execution, execute `python tools/run_forensic_gates.py` em loop corrigindo qualquer falha até obter `EXIT CODE 0` comprovado no console, e entregue todos os arquivos completos acompanhados do instalador verificável `materialize_waveX.py`.
```

---

### 8.2 COMANDOS SEQUENCIAIS DAS 5 ONDAS (ENVIAR NO CHAT DO GOOGLE AI STUDIO)

#### ONDA 1 DE 5 — Núcleo Compartilhado, Todos os Contratos (`00`–`08`), Governança IGRM v4.1 e Fase 01 Completa (Identificação & Autodescoberta do HD)
```text
Inicie a construção 100% Greenfield da Plataforma ELO executando a ONDA 1 DE 5 conforme o Manifesto Mestre abaixo:
[COLE AQUI AS SEÇÕES 1 A 7 DESTE MANIFESTO MESTRE]

Construa com 100% do código completo, grave na sua Sandbox Python e execute o loop de auto-teste até `EXIT CODE 0`:
1. Raiz do projeto: `pyproject.toml`, `AGENTS.md` e `CLAUDE.md`.
2. Pacote `edrm.shared_kernel` COMPLETO: `enums.py`, `exceptions.py`, `value_objects.py` (`Sha256Hash`, `ByteSize`, `CentsAmount`, `UtcTimestamp`, `SafeOsPath` com suporte automático a caminhos longos `\\?\`, `ControlNumber`, `SourceAnchor`), `time_normalizer.py` (Unix 1970 s/ms, Apple Cocoa 2001 + 978307200s, QuickTime 1904, ISO8601 -> UTC), `money_parser.py` (string -> centavos inteiros `int` sem `float`) e `contracts.py` contendo JÁ DEFINIDOS TODOS OS CONTRATOS IMUTÁVEIS DA CAMADA 00 ATÉ A FASE 08 + `MediaAutoDiscoveryBlueprint` + `IterativeDiscoveryFeedbackPort`.
3. Pacote `edrm.igrm_governance` COMPLETO (Camada 00 — IGRM v4.1: criação isolada do `CaseWorkspaceLayout`, `SourceWriteBlockerGuard` protegendo qualquer HD `--source`, suite de Auto-Calibração ISO/IEC 27041 com 1 controle positivo e 2 controles negativos, bloqueio de sockets externos em segredo de justiça, `ExecutionManifestWriter` e `AppendOnlyLedger`).
4. Pacote `edrm.phase01_identification` COMPLETO (todas as 4 Etapas e 11 Microfases: `PreScanSnapshot`, `SHA-256` em streaming de 4 MiB com checkpoint retomável, classificador de Magic Bytes de 16B + detecção de extensão camuflada, radiografia sem descompactação de ZIP/UFDR + schemas `CREATE TABLE` de SQLites via `immutable=1` + `%%EOF` em PDFs, `AiAssistedStructureDiscoveryUseCase` gerando `MediaAutoDiscoveryBlueprint` e `DynamicSchemaBlueprint` para bancos desconhecidos no HD, catalogação POP Senasp Vol. 5 2024 de peças primárias, política Zero-Silent-Drop + `DivergenceRecord`, Matriz Declarado x Entregue em 7 estados com tags STF Tema 977 / STJ Edição 281 / CPP, amostragem finita de Cochran 95%/10%, compilação validada pelo Verificador Bloqueante, `Phase01ToPhase02Contract` e `ReceiveIterativeFeedbackUseCase`).
5. Crie `tools/run_forensic_gates.py` implementando e rodando os Portões `G0`, `G1`, `G2` e `G3` até `EXIT CODE 0` na Sandbox Python, e entregue todos os arquivos completos + `materialize_wave1.py`.
```

#### ONDA 2 DE 5 — Fase 02 Completa (Preservação) e Fase 03 Completa (Coleta e Aquisição Verificada)
```text
ONDA 1 homologada. Mantendo todos os arquivos e contratos na Sandbox Python, execute agora a ONDA 2 DE 5 com código 100% completo e zero acoplamento entre pacotes de fases:
1. Pacote `edrm.phase02_preservation` COMPLETO (Subetapas 2.1 a 2.4 consumindo `Phase01ToPhase02Contract`: auditoria estrutural `PRAGMA quick_check` em `mode=ro&immutable=1`, detecção não destrutiva de registros pendentes em irmãos `-wal`/`-shm` e checagem de cabeçalhos/CRCs de pacotes; avaliação de risco de cópia única `SPOF` e atributos read-only do cofre; classificador atômico dos 6 Eixos da Preservação Estatal segundo CPP art. 158-B II/III/V, RFC 3227 e POP Senasp 2024 incluindo detector de divergências e caracteres homógrafos em números de lacre; `LegalHoldRecord`, relatórios validados com 0 falhas no Verificador Bloqueante, amostragem de Cochran e emissão de `Phase02ToPhase03Contract`).
2. Pacote `edrm.phase03_collection` COMPLETO (Etapas 3.1 a 3.4 consumindo `Phase02ToPhase03Contract`: planejamento de aquisição integral ou seletiva/referenciada para `workspace/vault/`; copiador forense em streaming de 4 MiB com `os.fsync` + releitura fria exigindo `sha256_source == sha256_vault` e lançando `CollectionHashMismatchError` ao menor bit divergente; geração da árvore genealógica `ControlNumber` + aplicação de permissão somente leitura no `vault/`; auditoria técnica do método estatal de coleta art. 158-C/D CPP + manifesto pronto para assinatura ICP-Brasil + emissão de `Phase03ToPhase04Contract`).
3. Atualize `edrm/bootstrap/container.py`, adicione o Portão `G4` em `tools/run_forensic_gates.py`, rode em loop `G0` a `G4` na Sandbox Python até `EXIT CODE 0` e entregue todos os arquivos completos da Onda 2 + `materialize_wave2.py`.
```

#### ONDA 3 DE 5 — Fase 04 Completa (Processamento Universal EDRM 1.0–5.0, 11 Extratores + SQLite Dinâmico e Ponte IPED CLI)
```text
ONDA 2 homologada. Execute agora a ONDA 3 DE 5 construindo com código 100% completo o pacote `edrm.phase04_processing` consumindo `Phase03ToPhase04Contract`:
1. Subetapa 4.1 (EDRM 1.0): Fila idempotente com checkpoint em disco, descompactador recursivo seguro em `workspace/staging/` (gerando `ControlNumbers` filhos com travas anti-Zip-Bomb e anti-Path-Traversal) e `IpedCliExternalBridge` (`--nogui -profile fastmode/triage` lendo `sleuth.db` em `mode=ro&immutable=1` sem violar GPL-3.0, com fallback Python nativo automático).
2. Subetapa 4.2 (EDRM 2.0): Marcação lógica não destrutiva *De-NIST* (aplicada apenas a itens *parent* para jamais quebrar famílias documentais pai-filho) e deduplicação lógica por `SHA-256` consolidando `all_custodians_json` e `all_source_paths_json` sem deletar linhas (preservando prova negativa).
3. Subetapa 4.3 (EDRM 3.0): Implemente os extratores determinísticos completos:
   - PDFs e Documentos (texto por página, hook OCR `Tesseract`, conflito `/Info` vs `XMP` e alerta `%%EOF > 1`);
   - Bancos Móveis WhatsApp Android (1970 ms + contatos `lid`) e iOS (2001 + 978307200s) em `immutable=1` + **Extrator Dinâmico `DynamicUnknownSqliteExtractor`** capaz de extrair dados de qualquer banco SQLite inédito descoberto no HD a partir de `DynamicSchemaBlueprint` validado + **Detector Automático de Atividade Pós-Apreensão** (`ts_utc > seizure_utc`);
   - Cellebrite `UFDR`/`UFDX` XML em streaming de baixa RAM (`iterparse`);
   - Quebras Financeiras `SIMBA` / `OFX` / CSV em centavos inteiros `BIGINT` (zero `float`) + detector de duplicidades contábeis inter-arquivos;
   - Telecom `CDR` e `ERBs` em UTC + cruzamento georreferenciado ANATEL (micrograus inteiros + azimute) + detector de velocidade fisicamente impossível;
   - Áudios (segmentador VAD + hook `Faster-Whisper` ancorado ao milissegundo + detector de descontinuidade);
   - E-mails (`MBOX`/`EML` cabeçalhos `Received:` UTC, `SPF`/`DKIM`/`DMARC` e threading) e Logs `CGNAT` (auditoria obrigatória de porta lógica — Decreto 12.975/2026);
   - Extrator estruturado de Peças Processuais Primárias encontradas dentro do HD.
4. Subetapas 4.4 e 4.5 (EDRM 4.0 e 5.0): Persistência relacional unificada, disparo automático em `IterativeDiscoveryFeedbackPort` atualizando a Fase 01 com novas peças primárias descobertas, geração dos 5 Relatórios Oficiais EDRM 5.0 + `DeadLetterStore` e emissão de `Phase04ToPhase05Contract`.
5. Adicione o Portão `G5` em `tools/run_forensic_gates.py`, rode em loop `G0` a `G5` na Sandbox Python até `EXIT CODE 0` e entregue todos os arquivos completos da Onda 3 + `materialize_wave3.py`.
```

#### ONDA 4 DE 5 — Análise Contínua (Busca Híbrida RRF, Linha do Tempo UTC, Verificador Bloqueante) e Fase 05 Completa (Revisão)
```text
ONDA 3 homologada. Execute agora a ONDA 4 DE 5 construindo com código 100% completo:
1. Pacote `edrm.continuous_analysis` COMPLETO:
   - Indexador de chunks ancorados e Motor de Busca Híbrida `RRF` (`k=60`, combinando `SQLite FTS5 BM25` + similaridade vetorial determinística e interface plugável `PostgreSQL + pgvector`);
   - Construtor de Linha do Tempo Unificada Multi-Fonte em UTC (fundindo chats, chamadas, ERBs, SIMBA, PDFs e autos);
   - Orquestrador `LocalLlmEndpointAdapter` (`Ollama`/`vLLM` em `127.0.0.1` com disjuntor rígido de orçamento de tokens e fallback determinístico offline);
   - Escudo `PromptInjectionShield` + motor completo `BlockingVerifierEngine` (rejeitando qualquer saída cujo ID, hash, número ou substring literal divirja do catálogo e gravando em `ai_and_qc_audit_log`);
   - Controle estatístico `CochranElusionRuleOf3Qc` (Cochran 95%/10%, Teste de Elusão sobre itens filtrados e Regra do 3 `3/n` de Hanley & Lippman-Hand).
2. Pacote `edrm.phase05_review` COMPLETO consumindo `Phase04ToPhase05Contract`:
   - Escudo de sigilo profissional advogado-cliente e marcação por tese defensiva;
   - Motor `DetectMaterialContradictionsUseCase` (*Relatório Policial/Laudo vs. Prova Bruta do HD*: captura diálogos pinçados fora de contexto recuperando as mensagens vizinhas omitidas, somas SIMBA infladas por duplicidade e contradições de localização ERB/GPS);
   - Classificador `EvidentiaryDefectClassifier` (`FORMAL_IRREGULARITY`, `CUSTODY_BREAK_WEIGHT_REDUCTION`, `DEFENSE_PARITY_VIOLATION_TEMA_977`, `ABSOLUTE_NULLITY_ILLICIT_EVIDENCE`);
   - Congelamento auditável `FreezeReviewSetUseCase` e emissão de `Phase05ToPhase06Contract`.
3. Adicione o Portão `G6` em `tools/run_forensic_gates.py`, rode em loop `G0` a `G6` na Sandbox Python até `EXIT CODE 0` e entregue todos os arquivos completos da Onda 4 + `materialize_wave4.py`.
```

#### ONDA 5 DE 5 — Fases 06 (Produção), 07 (Apresentação), 08 (Destinação Final), CLI *Plug-and-Analyze* e Homologação Total (`G0`–`G10`)
```text
ONDA 4 homologada. Conclua agora 100% da plataforma na ONDA 5 DE 5 construindo com código completo:
1. Pacote `edrm.phase06_production` COMPLETO consumindo `Phase05ToPhase06Contract`: Compilador determinístico do Parecer Técnico Defensivo nos 7 Blocos Oficiais (incluindo o Protocolo Passo a Passo de Reprodução Independente para contraprova do perito judicial), exportador de `Load Files` seguros (`.DAT`/`.CSV` e `EDRM XML`), validação dupla no Verificador Bloqueante (`0` falhas), manifesto para assinatura destacada ICP-Brasil e `Phase06ToPhase07Contract`.
2. Pacote `edrm.phase07_presentation` COMPLETO consumindo `Phase06ToPhase07Contract`: Gerador automático de Quesitos Periciais ancorados no POP Senasp Vol. 5 (2024) e nos arts. 158-A a 158-F do CPP para cada anomalia detectada no HD, quadros técnicos para petições (STF Tema 977 / STJ Edição 281), compilador do Dossiê Interativo `HTML5` em arquivo único 100% offline/autocontido (Linha do Tempo UTC + Comparador Lado a Lado Relatório Acusatório vs. Prova Bruta + Hashes SHA-256) e `Phase07ToPhase08Contract`.
3. Pacote `edrm.phase08_disposition` COMPLETO consumindo `Phase07ToPhase08Contract`: Expurgo verificado exclusivo de `workspace/staging/` após conferência SHA-256 dos entregáveis, gerador de pacote anti-perda `BuildRecoveryBundleUseCase` (`git bundle` + `MANIFESTO_SHA256.txt`) e sanitizador certificado pós-trânsito em julgado `Nist80088Sanitizer` (NIST SP 800-88 Rev. 2 com trava de dupla confirmação humana explícita e emissão de `CertificateOfDisposition.json`).
4. Camada `edrm.interfaces` (`cli.py` completo com os comandos `init-case`, `plug-hd`, `run-phase`, `plug-and-run-all`, `search` e `verify`, mais `local_api.py` em `127.0.0.1`) e fechamento integral de `edrm/bootstrap/container.py`.
5. Complete `tools/run_forensic_gates.py` com os Portões `G7`, `G8`, `G9` e `G10` (Simulação Ponta a Ponta de um HD Bruto Desconhecido conectado do zero absoluto percorrendo da Camada 00 até a Fase 08 + descoberta dinâmica de SQLite inédito + loop iterativo `04 -> 01` + `0` falhas no Verificador + prova matemática `PreScanSnapshot == PostScanSnapshot`).
6. Execute na sua Sandbox Python todos os 11 portões (`G0` a `G10`) em loop até obter `EXIT CODE 0` em 100% deles e entregue os arquivos completos da Onda 5 junto com o instalador mestre unificado `materialize_elo_platform.py` reconstruindo e verificando por SHA-256 todo o sistema!
```