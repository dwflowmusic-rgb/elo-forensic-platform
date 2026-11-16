# 06 — System Blueprint: Arquitetura Clean, Hexagonal e SOLID (EDRM 2.0 + Delta v2.1)

A plataforma **ELO** implementa uma combinação rigorosa de **Clean Architecture**, **Arquitetura Hexagonal (*Ports & Adapters*)** e **Enterprise SOLID**, onde todas as regras de acoplamento, pureza de camadas e tipagem imutável são verificadas automaticamente pela árvore sintática (`ast`) no **Portão `G1`** antes de qualquer execução.

---

## 1. Diagrama de Contexto e Contêineres (Modelo C4)

```mermaid
flowchart TB
    actor["Perito / Assistente Técnico / Advogado"]
    src[("Mídia Probatória --source\n(HD, Pendrive, .iped, .ufdr, SQLite, SIMBA)\n[SOMENTE LEITURA]")]

    subgraph ELO_SYSTEM["Sistema Forense ELO (Execução Soberana Local)"]
        cli["CLI Unificada Python\n(edrm.interfaces.cli)"]
        loopback["API Loopback Autenticada\n(edrm.interfaces.local_api)\nBind estrito 127.0.0.1 + X-ELO-Session-Token"]
        web["Console Analítico Web Full-Stack\n(server.ts Express + React 19)"]
        container["Composition Root\n(EloForensicContainer)"]
        core["Núcleo Hexagonal Puro\n(Camada 00 + Fases 01..08 + Análise Contínua)"]

        subgraph WS["Diretório Isolado --workspace (5 Zonas)"]
            z_vault[("vault/\nCópias Frias 0o444 +\nblob_shard_00..0f.sqlite")]
            z_staging[("staging/\nDescompactação Segura\n[Expurgado na Fase 08]")]
            z_catalog[("catalog/\nelo_forensic_catalog.sqlite\n(14 Tabelas + FTS5)")]
            z_deliv[("deliverables/\nParecer 7 Blocos, Quesitos,\nLoad Files, Dossiê HTML5")]
            z_audit[("audit/\naudit_ledger.jsonl,\nexecution_manifest.json,\nMANIFESTO_SHA256.txt")]
        end
    end

    actor -->|Comandos Forenses| cli
    actor -->|Inspeção Visual| web
    web -->|Subprocessos Auditados| cli
    cli --> container
    loopback --> container
    container --> core
    core -->|Leitura Streaming RO sob FsWriteBlockerGuard| src
    core --> z_vault
    core --> z_staging
    core --> z_catalog
    core --> z_deliv
    core --> z_audit
```

---

## 2. Anatomia Interna Hexagonal de Cada Pacote de Fase

Todos os 10 módulos verticais em `src/edrm/` (`igrm_governance`, `phase01_identification` a `phase08_disposition` e `continuous_analysis`) obedecem exatamente à mesma topologia concêntrica:

```mermaid
flowchart TB
    subgraph INFRA["Camada Externa: infrastructure/ (Adaptadores Físicos)"]
        A1["Leitores Streaming RO / SQLite mode=ro&immutable=1"]
        A2["Repositórios Catálogo SQLite / Shards Zlib"]
        A3["Compiladores Markdown / HTML5 / Load Files"]
    end

    subgraph APP["Camada Intermediária: application/ (100% Pura)"]
        UC["UseCases (ExecutePhaseXXUseCase)"]
        PORTS["Portas Segregadas (typing.Protocol: 1 a 3 métodos)"]
    end

    subgraph DOM["Camada Interna: domain/ (100% Pura)"]
        ENG["Motores Determinísticos, Políticas e Parsers Puros"]
        REG["Registros Plugáveis (SignatureRegistry / ExtractorRegistry)"]
    end

    subgraph SK["Núcleo Compartilhado: shared_kernel/ (100% Puro)"]
        VO["Value Objects, Contratos Frozen, Enums, Validadores O(n)"]
    end

    INFRA -->|Implementa estruturalmente| PORTS
    UC -->|Depende apenas de| PORTS
    UC -->|Orquestra| DOM
    DOM --> SK
    APP --> SK
    INFRA --> SK
```

### Regras de Pureza Auditadas via AST (`tests/architecture/__init__.py`)
1. **Zero I/O no Centro**: `shared_kernel/`, `domain/` e `application/` são proibidos de importar `os`, `sys`, `shutil`, `glob`, `subprocess`, `sqlite3`, `psycopg`, `zipfile`, `tarfile`, `socket`, `http`, `urllib` ou `requests`.
2. **Isolamento Horizontal Absoluto entre Fases**: Nenhum pacote `phaseXX_*` importa qualquer símbolo de `phaseYY_*`, `igrm_governance` ou `continuous_analysis`. A transição de estado ocorre exclusivamente por objetos `@dataclass(frozen=True, slots=True)` definidos em `edrm.shared_kernel.contracts`.
3. **Realimentação Iterativa Desacoplada (`04 -> 01`)**: Quando `ExecutePhase04ProcessingUseCase` descompacta contêineres em `staging/` e encontra novas peças processuais primárias (ex.: uma `FAV` ou aditamento de `Laudo` dentro de um `.zip`), ele emite um `IterativeDiscoveryFeedbackPayload` através da porta `IterativeDiscoveryFeedbackPort` (`shared_kernel.contracts`), que o `EloForensicContainer` conecta a `ReceiveIterativeFeedbackUseCase` (Fase 01), gerando `revision_number = 2+` sem criar dependência cíclica.

---

## 3. Mapa Completo de Pacotes, Casos de Uso, Portas e Adaptadores

| Pacote Vertical | Motores de Domínio (`domain/`) | Casos de Uso & Portas (`application/`) | Adaptadores Físicos (`infrastructure/`) |
| :--- | :--- | :--- | :--- |
| **`igrm_governance`** | `CaseWorkspaceLayout`, `SourceWriteBlockerPolicy`, `SecrecyNetworkPolicy`, `SelfCalibrationSuite` | `CalibrateToolsUseCase`, `InitializeCaseWorkspaceUseCase` (`WorkspaceProvisionerPort`, `AuditLedgerPort`, `ClockPort`) | `FsWriteBlockerGuard`, `FsWorkspaceProvisionerAdapter`, `AppendOnlyLedgerAdapter`, `SubprocessSandboxSupervisor`, `SystemUtcClockAdapter` |
| **`phase01_identification`** | `SignatureRegistry`, `SchemaDiscoveryEngine`, `PrimaryDocumentClassifierAndExtractor`, `CopyReconciliationEngine`, `ParityMatrixEngine`, `CochranFiniteSampler`, `StateIpedCaseAuditor` | `ExecutePhase01IdentificationUseCase`, `ReceiveIterativeFeedbackUseCase` (`MediaSensorProbePort`, `Phase01CatalogRepositoryPort`, `Phase01ReportCompilerPort`) | `ReadOnlyMediaScannerAdapter`, `SqliteCatalog01RepositoryAdapter`, `Phase01MarkdownCompilerAdapter` |
| **`phase02_preservation`** | `SpofRedundancyEvaluator`, `StateOriginPreservation6AxesEvaluator`, `detect_seal_homograph_or_mismatch` | `ExecutePhase02PreservationUseCase` (`StructuralHealthRunnerPort`, `Phase02PersistenceAndReportPort`) | `ImmutableStructuralHealthAdapter`, `Phase02CatalogAndMarkdownAdapter` |
| **`phase03_collection`** | `AcquisitionPlanner`, `StateCollectionMethodAuditor` | `ExecutePhase03CollectionUseCase` (`VerifiedVaultCopierPort`, `Phase03ManifestAndReportPort`) | `FsyncColdVerifyCopierAdapter`, `Phase03ManifestAndReportAdapter` |
| **`phase04_processing`** | `PriorityTierScheduler` ($P_0 \rightarrow P_4$), `DeNistAndLogicalDedupPolicy`, `PureTabularForensicParsers`, `ExtractorRegistry`, `PureSqliteBinaryForensicCarver`, `PureWindowsLnkBinaryParser` | `ExecutePhase04ProcessingUseCase` (`SafeUnpackAndIpedPort`, `UniversalExtractorRunnerPort`, `Phase04CatalogAndFiveReportsPort`) | `SafeContainerUnpackerAdapter`, `UniversalExtractorRunnerAdapter`, `Phase04CatalogAndFiveReportsAdapter`, `IpedCliExternalBridge`, `StateIpedStorageReaderAdapter`, `ShardedBlobVaultStore`, `ContainerExpansionCheckpointManager`, `StreamingSignatureCarver`, `SQLiteDeletedRecordsInspector`, `WindowsArtifactProvenanceExtractor`, `AudioTranscriptDeduplicatedCache` |
| **`continuous_analysis`** | `DeterministicHashEmbedder`, `ExactMetricSimilarity`, `HybridRrfFusionEngine`, `UnifiedUtcTimelineBuilder`, `PromptInjectionShield`, `BlockingVerifierEngine`, `CochranElusionRuleOf3Qc` | `HybridSearchUseCase`, `GovernedAiInterpretAndVerifyUseCase` (`HybridSearchIndexPort`, `LocalGovernedLlmPort`, `AiAndQcAuditRepositoryPort`) | `SqliteFtsVectorStoreAdapter`, `PostgresPgvectorStoreAdapter`, `LocalLlmEndpointAdapter`, `AiAndQcAuditRepositoryAdapter` |
| **`phase05_review`** | `CompressedRoaringBitset`, `PrivilegeShieldFilter`, `MaterialContradictionDetector`, `EvidentiaryDefectClassifier` | `ExecutePhase05ReviewUseCase` (`Phase05ReviewPersistencePort`) | `Phase05ReviewStoreAdapter` |
| **`phase06_production`** | `SevenBlockExpertOpinionBuilder`, `LoadFileBuilder` | `ExecutePhase06ProductionUseCase` (`Phase06DeliverablesWriterPort`) | `Phase06DeliverablesWriterAdapter` |
| **`phase07_presentation`** | `StrategicInterrogatoryBuilder`, `OfflineHtmlDossierCompiler` | `ExecutePhase07PresentationUseCase` (`Phase07PresenterWriterPort`) | `Phase07PresenterWriterAdapter` |
| **`phase08_disposition`** | `PostJudgmentDispositionPolicy`, `Nist80088Certificate` | `ExecutePhase08DispositionUseCase` (`StagingPurgeAndBundlePort`, `NistSanitizerWriterPort`) | `StagingCleanerAndBundleAdapter`, `Nist80088SanitizerAdapter` |

---

## 4. Orquestração em 5 Filas de Dependência na Fase 04 ($P_0 \rightarrow P_4$)

Introduzido no **Delta v2.1**, o `PriorityTierScheduler` garante que artefatos referenciais (como agendas de contatos `wa.db` ou tabelas de contas) sejam sempre extraídos **antes** dos bancos de mensagens que dependem deles:

```mermaid
flowchart LR
    P0["Fila P0\nMídias Atômicas, Páginas -wal\ne Espaço Não Alocado"]
    P1["Fila P1\nContêineres Expansíveis\n(.zip, .tar, .ufdr, .iped)"]
    P2["Fila P2\nContatos (wa.db), Contas\ne Artefatos .lnk de Sistema"]
    P3["Fila P3\nBancos Primários de Mensageria\n(msgstore.db, E-mails, Chats)"]
    P4["Fila P4\nFusão Cross-Backup, SIMBA,\nCDR/ERB e Timeline Global UTC"]

    P0 -->|Barreira Determinística| P1
    P1 -->|Barreira Determinística| P2
    P2 -->|Mapa @lid -> JID pronto| P3
    P3 -->|Eventos Normalizados| P4
```

---

## 5. Composition Root Sem Estado Global (`EloForensicContainer`)

O arquivo `src/edrm/bootstrap/container.py` é o **único ponto do sistema** autorizado a conhecer simultaneamente todas as fases e adaptadores concretos:
- Instancia cada adaptador sem variáveis globais mutáveis (`Singletons` implícitos são proibidos).
- Envolve toda a execução `01` $\rightarrow$ `08` no gerenciador de contexto `with FsWriteBlockerGuard(...)`, assegurando restauração limpa dos hooks de sistema operacional mesmo diante de exceções abruptas.
- Registra no razão `audit/audit_ledger.jsonl` o evento criptográfico de selagem (`PHASE_01_SEALED` .. `PHASE_08_DISPOSITION_SEALING`) com o `contract_sha256()` canônico de cada transição antes da geração final de `MANIFESTO_SHA256.txt`.
