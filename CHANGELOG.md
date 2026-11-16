# Changelog — Plataforma Forense ELO

Todos os marcos arquiteturais, evolutivos e correções forenses auditáveis da plataforma **ELO** são documentados neste arquivo seguindo o padrão *Keep a Changelog* e versionamento semântico estrito.

---

## [2.2.0] — 2026-11-15 — Operação Cross-Disk Entre HDs, Banco Organizado, Instalador CLI, MCP Nativo & 6 Skills de Agente (Delta v2.2)

Camada operacional completa para estações forenses multi-disco e integração nativa com agentes coordenadores via protocolo MCP, preservando 100% intactos os pacotes puros e portões anteriores (`G0`–`G11`) e homologada pelo novo **Portão `G12`** (`13/13 PASS`, `EXIT CODE 0`).

### Adicionado (`Added`)
- **Roteador Inteligente Cross-Disk & Wizard Interativo (`src/edrm/interfaces/disk_router_wizard.py`)**:
  - `MountedVolumeDetector` multiplataforma (Windows `A:`–`Z:` + `GetVolumeInformationW` e POSIX `/proc/mounts`) com aritmética inteira exata de bytes (`zero float`).
  - `CrossDiskWorkspaceRouter` com **Trava Anti-Auto-Contaminação** (bloqueando `--dest` ou `--staging` dentro de `--source` ou no mesmo volume físico quando `strict_separate_physical_drive=True`) e `SmartAcquisitionPlanner` decidindo automaticamente entre `FULL_VAULT_COPY` e `REFERENCED_MANIFEST_STREAMING`.
  - Assistente interativo `elo wizard` (`run_interactive_cli_wizard`).
- **Publicador do Banco Mestre Organizado no HD de Destino (`src/edrm/interfaces/organized_db_publisher.py`)**:
  - Materialização automática da árvore padronizada `00_GOVERNANCA_E_AUDITORIA/`, `01_BANCO_ORGANIZADO/`, `02_COFRE_OU_REFERENCIA/` e `03_RELATORIOS_E_DOSSIE/`.
  - Criação de `01_BANCO_ORGANIZADO/case_master_organized.sqlite` com índice textual `FTS5 BM25` (`fts_global_evidence_index`), `SCHEMA_PARA_HUMANO_E_IA.md`, `RESUMO_EXECUTIVO_BANCO.json` e **8 SQL Views Executivas Prontas** (`vw_01_indice_geral_provas` a `vw_08_linha_do_tempo_mestra_utc`).
- **Agente Autopilot Embutido no CLI (`src/edrm/interfaces/ai_autopilot_agent.py`)**:
  - Comando `elo autopilot --source <HD_ORIGEM> --dest <HD_DESTINO> [--staging <HD_TEMP>] [--llm-endpoint http://127.0.0.1:11434]` com calibração ISO 27041, sondagem governada `127.0.0.1` + fallback determinístico offline, execução integral `00`→`08`, limpeza garantida de `--staging` e comprovação `PreScanSnapshot == PostScanSnapshot`.
- **Servidor MCP JSON-RPC 2.0 Nativo via `stdio` (`src/edrm/interfaces/mcp_server.py`)**:
  - Implementação em biblioteca padrão Python 3.12+ pura suportando `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list` e `prompts/get` (compatível com linhas JSON-RPC e enquadramento `Content-Length`).
  - Exposição das **10 Ferramentas Forenses Determinísticas**: `elo_list_mounted_drives`, `elo_autopilot_ingest_hd`, `elo_get_case_overview`, `elo_hybrid_search`, `elo_query_organized_view` (com firewall SQL estrito somente `SELECT`, autorizador SQLite nativo e abertura `mode=ro&immutable=1`), `elo_timeline_window`, `elo_audit_custody_and_parity`, `elo_confront_allegation_vs_raw`, `elo_verify_citation_strict` (`BlockingVerifierEngine`) e `elo_generate_deliverables`.
- **Instalador CLI Real & 6 Skills Operacionais (`install_elo.py` + `src/edrm/interfaces/skills_and_mcp_installer.py`)**:
  - Bootstrapper `install_elo.py` (`--check-env`, `--install`, `--setup-all`) gerando wrappers `bin/elo` / `bin/elo.cmd`, `.mcp.json`, `opencode.json` e instalando as **6 Skills Operacionais** (`elo-plugar-hd`, `elo-panorama-caso`, `elo-investigar-fato`, `elo-auditar-custodia`, `elo-confrontar-laudo`, `elo-parecer-e-quesitos`) em `.claude/skills/` e `.opencode/skills/` com a **Regra do Agente Coordenador Forense**.
  - Novos subcomandos em `edrm.interfaces.cli`: `doctor`, `drives`, `mount`, `wizard`, `autopilot`, `mcp-serve`, `install-skills` e `setup`.

---

## [2.1.0] — 2026-11-15 — Evolução Forense IPED Clean-Room & Segurança NIST SSDF v1.1 (Delta v2.1)

Refatoração aditiva e 100% retrocompatível sobre a base EDRM 2.0 Greenfield, incorporando interoperabilidade limpa com casos portáteis `.iped` estatais, recuperação binária SQLite conforme NIST IR 8354, orquestração em 5 estágios de dependência referencial ($P_0 \rightarrow P_4$), validadores lineares brasileiros/criptoativos e controles de engenharia segura NIST SP 800-218 (SSDF v1.1), homologados pelo novo **Portão `G11`** (`12/12 PASS`, `EXIT CODE 0`).

### Adicionado (`Added`)
- **Núcleo Compartilhado (`edrm.shared_kernel`)**:
  - Enumeradores `ProcessingPriorityTier` ($P_0 \rightarrow P_4$), `SqliteRowAllocationState` (`ACTIVE_BTREE_ROW`, `WAL_UNCOMMITTED_FRAME`, `CARVED_FREELIST_OR_UNALLOCATED`) e `StateIpedProfileRisk` (`FORENSIC_COMPLETE`, `FASTMODE_OR_TRIAGE_OMISSIVE`, `BLIND_HASH_ONLY`, `CUSTOM_MODIFIED`, `NOT_IPED_SOURCE`).
  - Sonda determinística `compressibility_probe.py`: cálculo inteiro em *permille* ($0..1000$, zero `float`) sobre janelas de $64\text{ KiB}$ para detecção de volumes criptografados sem cabeçalho (`VeraCrypt`, `BitLocker To Go`, `LUKS` *detached*) e filtragem de entropia pré-BM25.
  - Motor `validators_br_crypto.py`: autômato `PureAhoCorasickAutomaton` e scanner linear $O(n)$ `LinearForensicEntityScanner` com verificação algébrica exata de dígitos verificadores para **CPF**, **CNPJ** (numérico e alfanumérico), **CNH**, **PIS/PASEP**, **Título de Eleitor TSE**, **RENAVAM**, **Placa Mercosul**, **Boleto Bancário FEBRABAN** (47/48 dígitos, fator de vencimento pós-2025 e valor exato em centavos), **Chave NF-e/DANFE** (44 dígitos Mod-11), **Cartão de Crédito (Luhn)**, endereços **Bitcoin** (Base58Check / Bech32), **Tron**, **Ethereum EIP-55** e sementes mnemônicas **BIP-39** (checksum SHA-256 sobre wordlist canônica de 2048 palavras).
  - Contratos imutáveis retrocompatíveis: `StateIpedAuditReport`, `RecoveredSqliteRecord`, `WindowsLinkProvenanceRecord` e extensões com valores padrão imutáveis em `MediaAutoDiscoveryBlueprint`, `Phase01ToPhase02Contract` e `Phase04ToPhase05Contract`.
  - Novas tabelas no catálogo canônico (`schema_sql.py`): `audio_transcript_cache` e `container_expansion_checkpoints`.
- **Governança e Segurança (`edrm.igrm_governance` & `edrm.interfaces.local_api`)**:
  - Auditoria estática AST NIST SSDF v1.1 (`audit_nist_ssdf_v1_1_ast_security` em `G1` e `G11.1`): proibição formal de `pickle`, `cPickle`, `marshal`, `shelve`, `yaml.load` inseguro, `eval()`, `exec()`, `subprocess(..., shell=True)` e `verify=False` TLS.
  - Emissão de `execution_manifest.json` com bloco `mini_sbom` (`nist_ssdf_version: "1.1"`, versão do interpretador Python, plataforma e `codebase_sha256`).
  - `SubprocessSandboxSupervisor`: execução isolada de ferramentas externas com timeout determinístico, captura de `stdout`/`stderr` e limpeza garantida de subpastas efêmeras em `staging/` via bloco `finally`.
  - `ForensicLoopbackHttpServer` (`src/edrm/interfaces/local_api.py`): interface HTTP vinculada exclusivamente a `127.0.0.1` (rejeitando `0.0.0.0` ou IPs externos com `SecrecySocketViolationError`) e protegida por token efêmero de 256 bits (`X-ELO-Session-Token`) comparado em tempo constante (`hmac.compare_digest`).
- **Identificação (`edrm.phase01_identification`)**:
  - `StateIpedCaseAuditor`: inspeção determinística de casos `.iped` estatais detectando perfis omissivos (`fastmode`, `triage`, `ped`), tarefas críticas desativadas, supressão cega por HashDB, `deleteIgnoredItems`, contaminação online (`--downloadInternetData`) e alerta sobre prova negativa em `filterKeywords`.
  - Sensor integrado de criptografia sem cabeçalho (`HEADERLESS_HIGH_ENTROPY_ENCRYPTED`) acoplado ao scanner em *streaming* `ReadOnlyMediaScannerAdapter`.
- **Processamento Forense Avançado (`edrm.phase04_processing`)**:
  - `PriorityTierScheduler` (`v21_orchestrator.py`): escalonamento estrito nas 5 filas de dependência referencial ($P_0 \rightarrow P_4$) com detecção de clones recursivos (`is_recursive_self_clone`).
  - `StateIpedStorageReaderAdapter`: leitura imutável (`mode=ro&immutable=1` + `PRAGMA query_only = 1`) de `sleuth.db` e descompressão GZIP em *streaming* dos 16 shards `iped/data/storage-0.db` .. `storage-15.db` (`compute_iped_shard_index` pelo primeiro byte do MD5).
  - `ShardedBlobVaultStore`: cofre local deduplicado particionado em 16 shards SQLite (`blob_shard_00..0f.sqlite`) com compressão `zlib`.
  - `ContainerExpansionCheckpointManager`: persistência atômica de progresso de contêineres pais em `container_expansion_checkpoints`, permitindo retomada cirúrgica após falha abrupta sem reprocessar filhos íntegros.
  - `StreamingSignatureCarver`: *file carving* por `PureAhoCorasickAutomaton` em blocos de $1\text{ MiB}$ preservando estado do autômato exatamente na fronteira entre blocos adjacentes.
  - `PureSqliteBinaryForensicCarver` & `SQLiteDeletedRecordsInspector`: varredura binária de páginas SQLite B-Tree, páginas `freelist`/espaço não alocado e frames `-wal` não consolidados conforme **NIST IR 8354**, rotulando cada achado com `SqliteRowAllocationState`.
  - `PureWindowsLnkBinaryParser` & `WindowsArtifactProvenanceExtractor`: decodificação binária MS-SHLLINK (`.lnk`) extraindo `MachineID`, `VolumeSerial`, `DroidVolume` e `DroidBirth` (`MAC Address` físico de 6 bytes do adaptador de origem).
  - Resolução cruzada WhatsApp moderno (`extract_contacts_from_wa_db` + `resolve_whatsapp_modern_lids_and_view_once`): correlação `wa.db` $\leftrightarrow$ `msgstore.db` para identificadores `@lid` e marcação de mensagens efêmeras *view-once* sem qualquer requisição externa à internet.
  - `AudioTranscriptDeduplicatedCache`: cache persistente indexado por `SHA-256` do áudio bruto evitando retrabalho em áudios reencaminhados.
- **Análise Contínua, Revisão e Apresentação (`continuous_analysis`, `phase05_review`, `phase07_presentation`)**:
  - `CompressedRoaringBitset`: álgebra de conjuntos comprimida em *containers* de 16 bits ($2^{16}$) com união, interseção e diferença imutáveis para recortes instantâneos na Fase 05.
  - `ExactMetricSimilarity`: distância euclidiana quadrática exata e similaridade cosseno com `Decimal.sqrt()` de 28 casas decimais, preservando rigorosamente a desigualdade triangular ($d(x, z) \le d(x, y) + d(y, z)$).
  - Expansão de `StrategicInterrogatoryBuilder` na Fase 07 para formular automaticamente quesitos periciais específicos diante de omissões em casos `.iped` estatais, registros SQLite deletados recuperados e vínculos físicos `DroidBirth MAC` em atalhos `.lnk`.
- **Suíte Documental Enterprise e Empacotador Verificado (`materialize_docs.py`)**:
  - Criação dos 18 documentos corporativos completos (`README.md`, `CHANGELOG.md`, `docs/INDEX.md` e `docs/01_product/` a `docs/04_operations/`) + empacotador autocontido `materialize_docs.py` com conferência `SHA-256` a frio.

### Reconciliado (`Changed`)
- **Reconciliação Normativa Estrita**:
  - Padronização de todas as menções à governança EDRM como `"IGRM v4.1 (versao vigente oficial do EDRM)"`, sem atribuição de data de lançamento em junho/2026.
  - Explicitação das especificações EDRM Processing `1.0`–`5.0` como **piso funcional flexível** (*floor, not a ceiling*) expandido pelas filas $P_0 \rightarrow P_4$.

---

## [2.0.0] — 2026-11-15 — Plataforma ELO Greenfield Completa (Ondas 1 a 5 — Portões G0 a G10)

Construção integral *Clean-Room* da plataforma forense **ELO** cobrindo todas as camadas do ciclo **EDRM 2.0** (`00` a `08` + `Análise Contínua`) e Console Analítico Web Interativo.

### Adicionado (`Added`)
- **Onda 1 — Fundação Arquitetural, Kernel Compartilhado, Camada 00 e Fase 01 (`G0`–`G3`)**:
  - Objetos de valor imutáveis (`Sha256Hash`, `ByteSize`, `CentsAmount`, `MicroDegreesCoord`, `UtcTimestamp`, `SafeOsPath`, `ControlNumber`, `SourceAnchor`), normalizador multi-época (`1970`, `2001` Cocoa, `1904` QuickTime) e parser monetário exato `parse_money_to_cents`.
  - Camada 00 (`igrm_governance`): `FsWriteBlockerGuard`, isolamento das 5 zonas de `--workspace`, bloqueio de sockets sob sigilo judicial, ledger *append-only* encadeado por hash e bateria de auto-calibração `ISO/IEC 27041`.
  - Fase 01 (`phase01_identification`): sonda binária de 16 *Magic Bytes* (`SignatureRegistry`), detecção de *extension spoofing*, descoberta dinâmica de esquemas SQLite/CSV (`SchemaDiscoveryEngine`), extração de peças primárias, Matriz de Paridade em 7 estados (`ParityMatrixEngine`) e amostragem estratificada de Cochran (`CochranFiniteSampler`).
- **Onda 2 — Fase 02 (Preservação) e Fase 03 (Coleta Verificada) (`G4`)**:
  - Fase 02 (`phase02_preservation`): auditoria dos 6 Eixos Obrigatórios da Preservação Estatal, detecção de caracteres homógrafos Unicode e quebras numéricas de lacres (`detect_seal_homograph_or_mismatch`), saúde estrutural SQLite (`PRAGMA quick_check` imutável e detecção de frames `-wal`) e mapa de risco SPOF.
  - Fase 03 (`phase03_collection`): cópia seletiva/integral para `vault/` com `os.fsync`, releitura fria `SHA-256` (`FsyncColdVerifyCopierAdapter`), trava `chmod 0o444`, manifesto ICP destacado e auditoria do método estatal de coleta (CPP arts. 158-C/158-D).
- **Onda 3 — Fase 04 (Processamento Universal) e Análise Contínua (`G5`–`G6`)**:
  - Fase 04 (`phase04_processing`): descompactação recursiva segura (Anti-Zip-Bomb e Anti-Path-Traversal), De-NIST restrito ao contêiner pai, deduplicação lógica global preservando custodiantes/caminhos, parsers determinísticos SIMBA (`BIGINT` centavos), CDR/ERB (velocidade geodésica impossível) e CGNAT (porta lógica de origem — Decreto n. 12.975/2026), realimentação iterativa `04 -> 01` e emissão dos 5 Relatórios Oficiais EDRM 4.0.
  - Análise Contínua (`continuous_analysis`): motor híbrido `HybridRrfFusionEngine` ($k = 60$, `BM25 FTS5` + `DeterministicHashEmbedder`), `PromptInjectionShield` e `BlockingVerifierEngine`.
- **Onda 4 — Fases 05, 06, 07 e 08 (`G7`)**:
  - Fase 05 (`phase05_review`): filtro de prerrogativa profissional OAB (`PrivilegeShieldFilter`), detector de contradições materiais Laudo $\times$ Mídia Bruta (`MaterialContradictionDetector`), enquadramento de nulidades e controle estatístico de Elusão + Regra do 3 ($3/n$).
  - Fase 06 (`phase06_production`): compilador do Parecer Técnico-Pericial em 7 Blocos com dupla passagem obrigatória do Verificador (`0` erros), script shell de reprodutibilidade independente e Load Files (`Concordance .DAT` e `EDRM XML`).
  - Fase 07 (`phase07_presentation`): gerador de Quesitos Estratégicos sob medida (POP Senasp Vol. 5 — 2024), Anexo Técnico **STF Tema 977** e compilador do Dossiê Interativo HTML5 Offline em arquivo único autocontido.
  - Fase 08 (`phase08_disposition`): expurgo verificável de `staging/`, selagem de `MANIFESTO_SHA256.txt` e `elo_case_recovery.bundle`, reconexão `PreScanSnapshot == PostScanSnapshot` e sanitização pós-trânsito em julgado **NIST SP 800-88 Rev. 2** com dupla confirmação humana.
- **Onda 5 — Testes de Substituição de Liskov, E2E HD Sintético, Instalador SHA-256 e Console Web (`G8`–`G10`)**:
  - Suíte Liskov `InMemory` vs. Adaptadores Físicos (`G8`), instalador autocontido `materialize_elo_platform.py` (`G9`), teste ponta a ponta em HD sintético desconhecido (`G10`) e Console Forense Web Full-Stack (`server.ts` + React 19).
