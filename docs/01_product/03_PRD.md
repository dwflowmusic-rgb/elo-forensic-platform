# 03 — Product Requirements Document (PRD): Plataforma Forense ELO

Este documento especifica os **Requisitos Funcionais (`RF`)** e **Requisitos Não-Funcionais (`RNF`)** implementados e verificados na plataforma **ELO (v2.1.0)**, com rastreabilidade direta aos módulos reais em `src/edrm/` e aos portões de homologação `G0`–`G11`.

---

## 1. Requisitos Funcionais por Camada e Fase (`RF`)

### 1.1 Camada 00 — Governança IGRM v4.1 e Segurança Operacional (`edrm.igrm_governance`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-00.1** | Provisionar isoladamente as 5 zonas obrigatórias de `--workspace` (`vault/`, `staging/`, `catalog/`, `deliverables/`, `audit/`) recusando qualquer sobreposição topológica com `--source` (`WorkspaceOverlapError`). | `CaseWorkspaceLayout`, `FsWorkspaceProvisionerAdapter`, `InitializeCaseWorkspaceUseCase` | `G3`, `G10` |
| **RF-00.2** | Ativar bloqueio de escrita em tempo de execução (`FsWriteBlockerGuard`) interceptando `builtins.open`, `os.*` e `shutil.*` sobre qualquer caminho descendente de `--source`. | `SourceWriteBlockerPolicy`, `FsWriteBlockerGuard` | `G3`, `G10` |
| **RF-00.3** | Executar bateria de auto-calibração **ISO/IEC 27041** antes do processamento do caso (1 controle positivo + 1 controle negativo de mutação numérica + 1 controle negativo de entidade fantasma), abortando com `VerifierCalibrationError` em caso de falha. | `SelfCalibrationSuite`, `CalibrateToolsUseCase` | `G2`, `G3` |
| **RF-00.4** | Impor política de soberania de rede (`SecrecyNetworkPolicy`), bloqueando sockets para destinos fora de `127.0.0.1`/`::1` quando `SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY` estiver ativo (`SecrecySocketViolationError`). | `SecrecyNetworkPolicy`, `FsWriteBlockerGuard` | `G3`, `G11.1` |
| **RF-00.5** | Registrar razão de auditoria *append-only* encadeada por hash (`audit_ledger.jsonl`) e manifesto de execução (`execution_manifest.json`) contendo `codebase_sha256` e `mini_sbom` **NIST SSDF v1.1**. | `AppendOnlyLedgerAdapter`, `write_execution_manifest` | `G3`, `G11.1` |
| **RF-00.6** | Supervisionar subprocessos externos em subpastas isoladas de `staging/` com timeout determinístico e remoção garantida de arquivos temporários em bloco `finally`. | `SubprocessSandboxSupervisor` | `G11.1` |

### 1.2 Fase 01 — Identificação e Autodescoberta (`edrm.phase01_identification`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-01.1** | Capturar fotografia física passiva `PreScanSnapshot` (`os.stat` sem leitura mutável) ordenada lexicograficamente e assinada em `SHA-256`. | `ReadOnlyMediaScannerAdapter.capture_physical_snapshot` | `G3`, `G10` |
| **RF-01.2** | Sondar 100% dos arquivos em *streaming* somente leitura calculando `SHA-256`, lendo os primeiros 16 *Magic Bytes* via `SignatureRegistry` (25 assinaturas) e identificando *extension spoofing* (ex.: `SQLITE3` renomeado como `.jpg` ou `.txt`). | `SignatureRegistry`, `ReadOnlyMediaScannerAdapter.probe_all_files_streaming` | `G3`, `G10` |
| **RF-01.3** | Detectar volumes criptografados sem cabeçalho (`VeraCrypt`, `BitLocker To Go`, `LUKS` *detached*) mediante sonda inteira em *permille* sobre janelas de $64\text{ KiB}$ sem uso de `float`. | `probe_headerless_encryption_bytes` (`compressibility_probe.py`) | `G11.3` |
| **RF-01.4** | Auditar casos portáteis `.iped` entregues pelo Estado detectando perfil utilizado (`fastmode`/`triage`/`forensic`), módulos críticos desabilitados, `deleteIgnoredItems`, contaminação `--downloadInternetData` e contagem de shards `storage-0..15.db`. | `StateIpedCaseAuditor` | `G11.2` |
| **RF-01.5** | Descobrir dinamicamente esquemas inéditos de bancos `SQLite` e tabelas `CSV` (`SchemaDiscoveryEngine`) e localizar peças processuais primárias (`Auto de Apreensão`, `FAV`, `Mandado`, `Laudo`, `Decisão`, `Denúncia`), extraindo itens declarados, custodiantes e divergências internas. | `SchemaDiscoveryEngine`, `PrimaryDocumentClassifierAndExtractor` | `G3`, `G10` |
| **RF-01.6** | Computar a **Matriz Determinística Declarado $\times$ Entregue** nos 7 estados forenses (`ParityState`) e o plano amostral estratificado de Cochran ($Z=1.96, p=0.5, e=0.10$, com 100% dos itens críticos). | `ParityMatrixEngine`, `CochranFiniteSampler` | `G3`, `G10` |
| **RF-01.7** | Suportar realimentação iterativa desacoplada (`ReceiveIterativeFeedbackUseCase` implementando `IterativeDiscoveryFeedbackPort`), gerando novas revisões imutáveis (`revision_number = 2+`) quando novas peças primárias forem descompactadas na Fase 04. | `ReceiveIterativeFeedbackUseCase` | `G5`, `G10` |

### 1.3 Fase 02 — Preservação e Diagnóstico Estrutural (`edrm.phase02_preservation`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-02.1** | Executar diagnóstico estrutural imutável de bancos SQLite (`mode=ro&immutable=1` + `PRAGMA query_only=1` + `PRAGMA quick_check`), identificando arquivos irmãos `-wal`/`-shm` não consolidados, CRCs de contêineres ZIP e revisões incrementais PDF (`%%EOF`). | `ImmutableStructuralHealthAdapter` | `G4`, `G10` |
| **RF-02.2** | Avaliar os **6 Eixos Obrigatórios da Preservação Estatal na Origem** (`PreservationAxis`) e detectar divergências numéricas ou adulterações visuais por caracteres homógrafos Unicode em números de lacres (`seals_in` vs. `seals_out`). | `StateOriginPreservation6AxesEvaluator`, `detect_seal_homograph_or_mismatch` | `G4`, `G10` |
| **RF-02.3** | Mapear Pontos Únicos de Falha (`SpofRiskEntry`) e recomendar o modo defensável de aquisição (`AcquisitionMode`) com emissão de `legal_hold_id`. | `SpofRedundancyEvaluator`, `ExecutePhase02PreservationUseCase` | `G4` |

### 1.4 Fase 03 — Coleta Verificada e Auditoria do Método Estatal (`edrm.phase03_collection`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-03.1** | Adquirir vestígios aprovados para `vault/` com atribuição de `ControlNumber` raiz (`ELO-000001`), sincronização física em disco (`os.fsync`), releitura fria completa do arquivo gravado (`vault_cold_sha256 == source_sha256`, lançando `CollectionHashMismatchError` se divergir) e bloqueio de permissão `0o444`. | `FsyncColdVerifyCopierAdapter`, `AcquisitionPlanner` | `G4`, `G8`, `G10` |
| **RF-03.2** | Auditar o método estatal de coleta (`StateCollectionMethodAuditor`) contra o **CPP arts. 158-C/158-D** e **POP Senasp 5.02** (atuação de perito oficial, exame direto no aparelho original, coleta manual por gravação de tela e trânsito via aplicativos de mensageria). | `StateCollectionMethodAuditor` | `G4`, `G10` |
| **RF-03.3** | Emitir manifesto criptográfico destacado compatível com assinatura ICP-Brasil (`phase03_icp_manifest.json`) e relatório técnico da Fase 03. | `Phase03ManifestAndReportAdapter` | `G4`, `G10` |

### 1.5 Fase 04 — Processamento Universal e Extração Forense (`edrm.phase04_processing`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-04.1** | Tratar as especificações **EDRM Processing 1.0–5.0** como piso funcional flexível e escalonar o inventário nas **5 Filas de Dependência Referencial ($P_0 \rightarrow P_4$)** (`PriorityTierScheduler`), bloqueando auto-clones recursivos. | `PriorityTierScheduler`, `ExecutePhase04ProcessingUseCase` | `G5`, `G11.4` |
| **RF-04.2** | Descompactar contêineres recursivamente para `staging/` com travas Anti-Zip-Bomb (limite de bytes e razão de expansão) e Anti-Path-Traversal (`ContainerSecurityViolationError`), mantendo checkpoints atômicos de retomada (`ContainerExpansionCheckpointManager`). | `validate_safe_archive_member`, `SafeContainerUnpackerAdapter`, `ContainerExpansionCheckpointManager` | `G5`, `G11.4` |
| **RF-04.3** | Aplicar filtro lógico `De-NIST` estritamente restrito ao contêiner pai (nunca suprimindo anexos enviados por usuários) e deduplicação lógica global preservando todos os custodiantes e caminhos de origem. | `DeNistAndLogicalDedupPolicy` | `G5` |
| **RF-04.4** | Ler em modo imutável (`mode=ro&immutable=1`) catálogos `sleuth.db` e descompactar em *streaming* GZIP blobs dos 16 shards `iped/data/storage-0..15.db`, além de operar cofre local em 16 shards `blob_shard_00..0f.sqlite`. | `StateIpedStorageReaderAdapter`, `ShardedBlobVaultStore` | `G11.2`, `G11.4` |
| **RF-04.5** | Realizar *file carving* em *streaming* por autômato `PureAhoCorasickAutomaton` em blocos de $1\text{ MiB}$ preservando estado entre fronteiras, recuperar registros deletados de páginas `freelist`/`-wal` SQLite (**NIST IR 8354**) e extrair proveniência física `DroidBirth MAC` de atalhos Windows `.lnk`. | `StreamingSignatureCarver`, `SQLiteDeletedRecordsInspector`, `WindowsArtifactProvenanceExtractor` | `G11.4`, `G11.5` |
| **RF-04.6** | Normalizar épocas `Unix 1970`, `Cocoa 2001` e `QuickTime 1904` para `UTC` sinalizando eventos pós-apreensão (`is_post_seizure`), resolver contatos WhatsApp `@lid` e mensagens *view-once* via correlação local `wa.db` $\leftrightarrow$ `msgstore.db` e deduplicar transcrições de áudio por `SHA-256`. | `time_normalizer.py`, `resolve_whatsapp_modern_lids_and_view_once`, `AudioTranscriptDeduplicatedCache` | `G5`, `G11.4` |
| **RF-04.7** | Processar lançamentos financeiros `SIMBA/CSV` em centavos inteiros `BIGINT` (`is_inter_file_duplicate`), registros `CDR/ERB` em micrograus inteiros (`impossible_speed_flag`), logs `CGNAT` (`missing_logical_port_defect`), entidades brasileiras/criptoativos (`LinearForensicEntityScanner`) e emitir os **5 Relatórios Oficiais EDRM 4.0**. | `PureTabularForensicParsers`, `validators_br_crypto.py`, `Phase04CatalogAndFiveReportsAdapter` | `G5`, `G11.3` |

### 1.6 Análise Contínua e IA Governada (`edrm.continuous_analysis`)
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-CA.1** | Indexar chunks textuais sanitizados (`PromptInjectionShield`) e filtrados por compressibilidade combinando `SQLite FTS5 BM25` e `DeterministicHashEmbedder` via **Reciprocal Rank Fusion (`RRF`, $k=60$)** em `Decimal`. | `HybridRrfFusionEngine`, `SqliteFtsVectorStoreAdapter`, `HybridSearchUseCase` | `G6`, `G8` |
| **RF-CA.2** | Calcular distância euclidiana e similaridade cosseno algebricamente exatas (`ExactMetricSimilarity` em `Decimal`), garantindo validade estrita da desigualdade triangular. | `ExactMetricSimilarity` | `G11.5` |
| **RF-CA.3** | Governar qualquer saída interpretativa pelo `BlockingVerifierEngine`, exigindo âncora `ControlNumber` + `SHA-256` válida e igualdade exata de todos os números/hashes citados contra o corpus verificado, gravando auditoria em `ai_and_qc_audit_log`. | `BlockingVerifierEngine`, `GovernedAiInterpretAndVerifyUseCase` | `G6`, `G7` |

### 1.7 Fases 05 a 08 — Revisão, Produção, Apresentação e Destinação
| ID | Requisito Funcional Implementado | Módulo / Classe Real | Portão |
| :--- | :--- | :--- | :--- |
| **RF-05.1** | Segregar comunicações protegidas por prerrogativa OAB (`PrivilegeShieldFilter`), operar recortes rápidos via `CompressedRoaringBitset`, detectar contradições materiais Laudo $\times$ Mídia Bruta (`MaterialContradictionDetector`), tipificar nulidades (`EvidentiaryDefectClassifier`) e calcular QC estatístico (Elusão + Regra do 3 $3/n$). | `edrm.phase05_review` | `G6`, `G11.5` |
| **RF-06.1** | Compilar o **Parecer Técnico-Pericial em 7 Blocos** submetido a dupla passagem obrigatória do verificador (`verifier_double_pass_zero_errors == True`), gerar `phase06_reproducao_independente.sh` e exportar *Load Files* `Concordance .DAT` e `EDRM XML`. | `SevenBlockExpertOpinionBuilder`, `LoadFileBuilder`, `ExecutePhase06ProductionUseCase` | `G7`, `G10` |
| **RF-07.1** | Gerar **Quesitos Estratégicos** sob medida ancorados no **POP Senasp Vol. 5 (2024)** (incluindo anomalias `.iped`, SQLite deletado e `.lnk`), Anexo Técnico **STF Tema 977** e **Dossiê Interativo HTML5 Offline** autocontido em arquivo único. | `StrategicInterrogatoryBuilder`, `OfflineHtmlDossierCompiler` | `G7`, `G11.2`, `G11.5` |
| **RF-08.1** | Expurgar integralmente `staging/`, consolidar `MANIFESTO_SHA256.txt` e `elo_case_recovery.bundle`, comprovar `PreScanSnapshot == PostScanSnapshot` e emitir certificado de sanitização pós-trânsito em julgado **NIST SP 800-88 Rev. 2** apenas sob dupla confirmação humana explícita (`HumanAuthorizationRequiredError` caso omitida). | `PostJudgmentDispositionPolicy`, `ExecutePhase08DispositionUseCase` | `G7`, `G10` |

---

## 2. Requisitos Não-Funcionais e Invariantes de Engenharia (`RNF`)

| ID | Categoria | Especificação Verificável | Mecanismo de Imposição |
| :--- | :--- | :--- | :--- |
| **RNF-01** | **Pureza Arquitetural** | Zero imports de `os`, `sys`, `shutil`, `glob`, `subprocess`, `sqlite3`, `psycopg`, `zipfile`, `tarfile`, `socket`, `http`, `urllib` ou `requests` em `shared_kernel/`, `domain/` e `application/`. | Auditoria AST `G1` (`audit_g1_clean_hexagonal_solid_and_forensic_locks`). |
| **RNF-02** | **Isolamento entre Fases** | Zero imports cruzados entre os 10 pacotes de fases (`igrm_governance`, `phase01`..`phase08`, `continuous_analysis`); comunicação exclusiva via `shared_kernel.contracts`. | Auditoria AST `G1` + `EloForensicContainer`. |
| **RNF-03** | **Imutabilidade de Estado** | 100% das entidades, objetos de valor e contratos declarados com `@dataclass(frozen=True, slots=True)` e coleções `tuple`; zero estado global mutável. | Auditoria AST `G1`. |
| **RNF-04** | **Segregação de Interfaces (ISP)** | Todas as portas de saída/entrada declaradas via `typing.Protocol` contendo de `1` a `3` métodos coesos. | Auditoria AST `G1`. |
| **RNF-05** | **Determinismo Aritmético** | Zero uso de `float` ou `hash()` nativo do Python em lógica pericial; `PYTHONHASHSEED=42` nos testes e CLI. | Auditoria AST `G1` + `G2`..`G11`. |
| **RNF-06** | **Higiene de Código Cirúrgico** | Zero `TODO`, `FIXME`, `pass` concreto, `...` concreto ou `NotImplementedError` em todo o repositório. | Auditoria AST `G0` (`audit_g0_code_hygiene`). |
| **RNF-07** | **Segurança NIST SSDF v1.1** | Proibição AST de desserializadores inseguros (`pickle`, `marshal`, `shelve`, `eval`, `exec`, `shell=True`, `verify=False`) e API HTTP restrita a `127.0.0.1` + `X-ELO-Session-Token`. | Auditoria AST `G1` + Teste `G11.1`. |
| **RNF-08** | **Substituibilidade de Liskov** | Adaptadores `InMemory` de teste e adaptadores físicos de produção aprovados exatamente nas mesmas suítes de contrato. | Portão `G8` (`run_all_liskov_contract_suites`). |
| **RNF-09** | **Desempenho Linear em Streaming** | Leitura de arquivos e *carving* em blocos constantes ($64\text{ KiB}$ a $1\text{ MiB}$) e varredura de entidades em $O(n)$ sem backtracking exponencial ReDoS. | `ReadOnlyMediaScannerAdapter`, `StreamingSignatureCarver`, `LinearForensicEntityScanner`. |
| **RNF-10** | **Empacotamento Autocontido** | Reconstrução 100% offline verificada a frio por `SHA-256` tanto da plataforma (`materialize_elo_platform.py`) quanto da documentação (`materialize_docs.py`). | Portão `G9` + `sync_docs_payload.py`. |
