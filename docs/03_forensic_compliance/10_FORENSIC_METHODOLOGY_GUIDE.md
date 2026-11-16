# 10 — Guia de Metodologia Forense e Reconciliação Normativa

Este documento estabelece a fundamentação científico-pericial e jurídica de cada etapa executada pela plataforma **ELO**, mapeando de forma exata os pacotes Python (`src/edrm/`) às normas internacionais e ao direito probatório penal brasileiro.

---

## 1. Reconciliação Normativa Estrita

Para assegurar precisão conceitual em juízo e eliminar ambiguidades bibliográficas:

1. **EDRM 2.0 (Electronic Discovery Reference Model)**: Adota-se a arquitetura macroscópica **EDRM 2.0** (publicada sob licença **CC BY 4.0** pelo consórcio *EDRM.net*), que estrutura o ciclo probatório em Governança Transversal, Fases sequenciais/iterativas (`Identification`, `Preservation`, `Collection`, `Processing`, `Review`, `Production`, `Presentation`, `Disposition`) e `Continuous Analysis`. Toda a engenharia de auditoria criminal brasileira, cálculo determinístico e verificação bloqueante do **ELO** é construção proprietária *Clean-Room* sobre esse referencial conceitual.
2. **IGRM v4.1**: Todas as referências ao modelo de governança da informação seguem estritamente o **"IGRM v4.1 (versao vigente oficial do EDRM)"**, sem atribuição de data fictícia de lançamento em junho/2026.
3. **EDRM Processing Specifications `1.0`–`5.0` como Piso Funcional Flexível (*Floor, Not a Ceiling*)**: Os 5 relatórios clássicos de processamento EDRM (`Intake`, `Deduplication/De-NIST`, `Exceptions`, `Temporal/Financial/Telecom`, `Schema/Feedback`) constituem o **piso mínimo obrigatório** na Fase 04, expandido pela engenharia forense do ELO com as 5 filas de dependência referencial ($P_0 \rightarrow P_4$), inspeção de registros deletados SQLite, *carving* Aho-Corasick e rastreio físico `.lnk`.

---

## 2. Matriz Completa de Mapeamento Metodológico (`00` $\rightarrow$ `08`)

| Camada / Fase ELO | Normas Internacionais Aplicadas | Base Legal e Jurisprudencial Brasileira | Materialização no Código ELO |
| :--- | :--- | :--- | :--- |
| **Camada 00 — Governança** (`igrm_governance`) | **IGRM v4.1**, **ISO/IEC 27041:2015** (adequação e calibração de método), **NIST SP 800-218 (SSDF v1.1)** | **Resolução CNJ n. 615/2025**, **Recomendação CFOAB n. 001/2024** | `SelfCalibrationSuite` (1 positivo + 2 negativos), `FsWriteBlockerGuard`, `SecrecyNetworkPolicy`, `execution_manifest.json`. |
| **Fase 01 — Identificação** (`phase01_identification`) | **ISO/IEC 27037:2012** (identificação de evidência digital potencial) | **CPP art. 158-B, I** (Reconhecimento), **STF Tema 977**, **POP Senasp Vol. 5 (2024)** | `SignatureRegistry` (16 Magic Bytes), `StateIpedCaseAuditor`, `ParityMatrixEngine` (7 estados), `CochranFiniteSampler`. |
| **Fase 02 — Preservação** (`phase02_preservation`) | **ISO/IEC 27037:2012** (isolamento e integridade), **NIST IR 8354** (transações `-wal`) | **CPP art. 158-B, II, III, V, VI** (Isolamento, Fixação, Acondicionamento, Transporte), **art. 158-D** (Lacres e FAV) | `StateOriginPreservation6AxesEvaluator`, `detect_seal_homograph_or_mismatch`, `ImmutableStructuralHealthAdapter` (`mode=ro&immutable=1`). |
| **Fase 03 — Coleta** (`phase03_collection`) | **ISO/IEC 27037:2012** (aquisição verificada) | **CPP art. 158-B, IV e VII**, **art. 158-C** (atribuição do perito oficial), **STJ RHC 184.003/SP**, **POP Senasp 5.02** | `FsyncColdVerifyCopierAdapter` (`os.fsync` + releitura fria `SHA-256` + `0o444`), `StateCollectionMethodAuditor`, `phase03_icp_manifest.json`. |
| **Fase 04 — Processamento** (`phase04_processing`) | **EDRM Processing 1.0–5.0** (piso funcional), **ISO/IEC 27042:2015**, **NIST IR 8354** (SQLite forensics) | **CPP art. 158-B, VIII** (Processamento), **Decreto n. 12.975/2026** (porta lógica CGNAT) | `PriorityTierScheduler` ($P_0 \rightarrow P_4$), `StateIpedStorageReaderAdapter`, `SQLiteDeletedRecordsInspector`, `WindowsArtifactProvenanceExtractor`, `PureTabularForensicParsers` (SIMBA, CDR/ERB, CGNAT). |
| **Análise Contínua** (`continuous_analysis`) | **ISO/IEC 27042:2015** (interpretação reprodutível e continuidade analítica) | **Resolução CNJ n. 615/2025** (auditabilidade e vedação de alucinação) | `HybridRrfFusionEngine` ($k=60$), `ExactMetricSimilarity`, `UnifiedUtcTimelineBuilder`, `PromptInjectionShield`, `BlockingVerifierEngine`. |
| **Fase 05 — Revisão** (`phase05_review`) | **EDRM Statistical QC** (Elusão + Regra do 3 de Hanley & Lippman-Hand) | **Lei n. 8.906/94, art. 7º, II** (inviolabilidade OAB), **CPP art. 157** (provas ilícitas) e **STF Tema 977** | `PrivilegeShieldFilter`, `CompressedRoaringBitset`, `MaterialContradictionDetector`, `EvidentiaryDefectClassifier`, `compute_review_qc_summary`. |
| **Fase 06 — Produção** (`phase06_production`) | **ISO/IEC 27042:2015** (relato pericial verificável por terceiro competente), **Concordance / EDRM XML** | **CPP art. 159, § 5º, II** (parecer do assistente técnico) e **art. 160** | `SevenBlockExpertOpinionBuilder` (dupla passagem obrigatória com 0 erros), `LoadFileBuilder`, `phase06_reproducao_independente.sh`. |
| **Fase 07 — Apresentação** (`phase07_presentation`) | Clareza visual autoexplicativa e rastreabilidade integral de âncoras | **CPP art. 159, § 5º, I** (formulação de quesitos), **POP Senasp Vol. 5 (2024)**, **STF Tema 977** | `StrategicInterrogatoryBuilder`, `OfflineHtmlDossierCompiler` (arquivo único HTML5 offline sem dependências externas). |
| **Fase 08 — Destinação** (`phase08_disposition`) | **NIST SP 800-88 Rev. 2 (set./2025)** (*Guidelines for Media Sanitization*: `Clear`, `Purge`, `Destroy`) | **CPP art. 158-B, IX e X** (Armazenamento e Descarte pós-trânsito em julgado) | `StagingCleanerAndBundleAdapter`, `PostJudgmentDispositionPolicy` (dupla confirmação humana obrigatória), reconexão `PreScan == PostScan`. |

---

## 3. Taxonomias Periciais Implementadas

### 3.1 Os 7 Estados da Matriz de Paridade (`ParityState` — Fase 01)
Cada cruzamento entre um item declarado em documento oficial (`Auto de Apreensão`, `FAV`, `Laudo`) e os arquivos efetivamente encontrados em `--source` resulta em exatamente um estado mutuamente exclusivo:
1. `MATCHED_INTACT_HASH`: Arquivo localizado com tamanho e hash `SHA-256` idênticos ao declarado na origem.
2. `MATCHED_WITHOUT_ORIGIN_HASH`: Arquivo correspondente localizado, porém o Estado omitiu o cálculo de hash na apreensão/coleta (`CPP art. 158-B, III` / `POP Senasp Vol. 5`).
3. `DIVERGENT_HASH_OR_SIZE`: Arquivo correspondente apresenta hash `SHA-256` ou tamanho em bytes diferente do registrado oficialmente (**crítico judicialmente**).
4. `DECLARED_RAW_NOT_DELIVERED`: O espelho bruto consta como apreendido/extraído nos autos, mas não foi disponibilizado na mídia entregue (**violação direta ao STF Tema 977**).
5. `DELIVERED_ENCRYPTED_OR_CORRUPTED`: Arquivo entregue ilegível, truncado ou cifrado sem chave documentada.
6. `DELIVERED_UNDOCUMENTED_IN_AUTOS`: Arquivo presente na mídia sem lastro em Auto de Apreensão ou FAV (*vestígio órfão*).
7. `DEFERRED_AWAITING_PRIMARY_DOC`: Avaliação sobrestada até a extração de peças primárias contidas em contêineres compactados (resolvida na realimentação `04 -> 01`).

### 3.2 Os 6 Eixos Obrigatórios da Preservação Estatal (`PreservationAxis` — Fase 02)
1. `ISOLAMENTO_RADIOELETRICO_E_VOLATILIDADE` (uso de bolsa de Faraday / modo avião e preservação de memória volátil).
2. `ESTADO_ENERGETICO_BLOQUEIO_E_RELOGIO` (registro de aparelho ligado/desligado, bloqueio de tela AFU/BFU e desvio do relógio interno frente a UTC).
3. `CADEIA_DE_LACRES_E_FAV` (continuidade numérica `seals_in == seals_out` e ausência de caracteres homógrafos Unicode).
4. `CERTIFICACAO_DE_HASH_NA_ORIGEM` (existência de hash criptográfico forte calculado no ato da fixação/coleta).
5. `INTEGRIDADE_FISICA_E_LOGICA_DO_VESTIGIO` (ausência de corrupção estrutural e exame exclusivo sobre cópia de trabalho, nunca no dispositivo original).
6. `ACESSIBILIDADE_E_CIFRAGEM` (documentação transparente de credenciais, segundo espaço e partições cifradas).

### 3.3 Estados de Alocação SQLite segundo NIST IR 8354 (`SqliteRowAllocationState` — Fase 04)
Para impedir que fragmentos recuperados de páginas livres sejam confundidos com registros íntegros ativos, todo evento ou artefato extraído de bancos SQLite carrega explicitamente seu estado de alocação:
- `ACTIVE_BTREE_ROW`: Registro íntegro presente em página folha ativa da árvore B-Tree.
- `WAL_UNCOMMITTED_FRAME`: Registro extraído de frame presente no arquivo irmão `-wal` ainda não consolidado no banco principal.
- `CARVED_FREELIST_OR_UNALLOCATED`: Texto/registro recuperado por varredura binária de páginas da `freelist` ou espaço não alocado entre células (`unallocated cell space`).

### 3.4 Estatuto Epistêmico Obrigatório (`EpistemicStatus` — Transversal)
Todo achado, custodiante e linha da matriz diferencia rigorosamente:
- `VERIFIED_FACT`: Comprovado matematicamente nos bytes da mídia (`SHA-256` + `locator`).
- `STATE_ALLEGATION`: Afirmação extraída de peça estatal pendente de comprovação material ou desmentida pelos dados brutos.
- `ANALYTICAL_INFERENCE`: Dedução técnica explícita derivada de fatos verificados sob regra documentada.
- `EXPLICIT_GAP`: Lacuna documental ou probatória formalmente declarada (ex.: ausência de FAV ou porta lógica CGNAT omitida).

---

## 4. Anatomia dos 7 Blocos do Parecer Técnico-Pericial (Fase 06)

O compilador `SevenBlockExpertOpinionBuilder` estrutura `phase06_parecer_tecnico_7_blocos.md` segundo a norma **ISO/IEC 27042** e a praxe forense brasileira:
- **Bloco 1 — Sumário Executivo para o Juízo**: Síntese direta das conclusões críticas e confirmação matemática `PreScanSnapshot == PostScanSnapshot`.
- **Bloco 2 — Objeto, Metodologia Científica e Calibração ISO/IEC 27041**: Identificação do `codebase_sha256`, recibo de auto-calibração e protocolo somente leitura.
- **Bloco 3 — Inventário Físico, Censo de Assinaturas e Paridade Declarado $\times$ Entregue**: Tabelas ancoradas da Fase 01, auditoria `.iped` e *spoofing* de extensões.
- **Bloco 4 — Auditoria da Cadeia de Custódia, 6 Eixos de Preservação e Coleta Estatal**: Achados das Fases 02 e 03, lacres, eventos pós-apreensão e métodos de extração.
- **Bloco 5 — Análise Material, Financeira (`SIMBA`), Telemática (`CDR/ERB/CGNAT`), SQLite Recuperado e `.lnk`**: Resultados determinísticos da Fase 04 em centavos inteiros, micrograus e UTC.
- **Bloco 6 — Confronto de Contradições Materiais, Enquadramento Processual e Controle Estatístico (`Cochran` + `3/n`)**: Síntese da Fase 05 respeitando o sigilo profissional OAB.
- **Bloco 7 — Conclusão Técnica, Manifesto `SHA-256` e Instruções de Reprodução Independente**: Encerramento assinado acompanhado de `phase06_reproducao_independente.sh`.
