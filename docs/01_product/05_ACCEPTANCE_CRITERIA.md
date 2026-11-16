# 05 — Critérios de Aceitação e Definição de Pronto (DoD): Plataforma Forense ELO

Nenhum módulo, refatoração ou execução pericial na plataforma **ELO** é considerado concluído sem satisfazer simultaneamente os **Critérios Globais de Engenharia (`DoD` de Software)** e os **Critérios Matemáticos de Aceitação por Fase (`00` a `08`)**.

---

## 1. Definição Global de Pronto (*Global Definition of Done*)

Uma entrega de código na plataforma ELO somente é aceita quando **todas** as 7 condições abaixo são comprovadas empiricamente em console:

1. **Higiene Sintática Absoluta (`Portão G0`)**: `0` ocorrências de `TODO`, `FIXME`, `pass` concreto, reticências `...` fora de `typing.Protocol` ou `NotImplementedError` em 100% dos arquivos `.py` do repositório.
2. **Isolamento Arquitetural e Travas AST (`Portão G1`)**:
   - `shared_kernel/`, `domain/` e `application/` com `0` imports de módulos de infraestrutura/SO/rede.
   - `0` imports diretos cruzados entre quaisquer pacotes de fases (`igrm_governance`, `phase01`..`phase08`, `continuous_analysis`).
   - Todas as portas definidas via `typing.Protocol` com `1` a `3` métodos.
   - Todos os contratos, entidades e objetos de valor decorados com `@dataclass(frozen=True, slots=True)`.
   - `0` usos de `float` ou `hash()` volátil nas camadas nucleares.
   - `0` violações **NIST SSDF v1.1** (`pickle`, `marshal`, `shelve`, `eval`, `exec`, `shell=True`, `verify=False`).
3. **Auto-Calibração Prévia Aprovada (`Portão G2`)**: `CalibrationReceipt.positive_control_passed == True`, `negative_numeric_mutation_blocked == True` e `negative_phantom_entity_blocked == True`.
4. **Equivalência de Substituição de Liskov (`Portão G8`)**: 100% dos testes de contrato produzem resultados idênticos tanto nos dublês `InMemory*Fake` quanto nos adaptadores físicos reais.
5. **Empacotamento Autocontido Verificado a Frio (`Portão G9`)**: `materialize_elo_platform.py --target <tmp> --verify` e `materialize_docs.py --target <tmp> --verify` retornam `"verified": true` e `"mismatches": []`.
6. **Invariante Probatório Supremo (`Portão G10` e `G11`)**: `PreScanSnapshot.snapshot_sha256 == PostScanSnapshot.snapshot_sha256` (`zero_source_mutation_confirmed == True`) após execução completa `00` $\rightarrow$ `08`.
7. **Console Analítico Web Sem Erros**: `npm run build` e `npm run lint` com `EXIT CODE 0`, testes unitários TypeScript aprovados e zero erros de runtime/overflow horizontal em navegador real.

---

## 2. Critérios de Aceitação por Fase e Entregáveis Obrigatórios

### Camada 00 — Governança IGRM v4.1 (`CaseGovernanceContract`)
- [x] As 5 pastas (`vault`, `staging`, `catalog`, `deliverables`, `audit`) existem fisicamente e nenhuma delas reside dentro de `--source`.
- [x] Qualquer chamada `open(arquivo_em_source, "w")` ou `"a"` ou `"r+"` dentro do bloco `FsWriteBlockerGuard` lança imediatamente `ReadOnlyViolationError`.
- [x] Qualquer conexão socket para IP diferente de `127.0.0.1`/`::1` sob `JUDICIAL_SECRECY_LOCAL_ONLY` lança `SecrecySocketViolationError`.
- [x] `audit/audit_ledger.jsonl` e `audit/execution_manifest.json` (com `mini_sbom.nist_ssdf_version == "1.1"`) gravados e verificáveis.

### Fase 01 — Identificação (`Phase01ToPhase02Contract`)
- [x] 100% dos arquivos de `--source` inventariados com `size_bytes` inteiro, `sha256_hex` de 64 hexadecimais minúsculos e `magic_signature` de 16 bytes.
- [x] Arquivos com extensão falsa (ex.: cabeçalho `SQLite format 3\x00` salvo como `.jpg`) marcados com `extension_spoofed == True`.
- [x] Casos portáteis `.iped` auditados em `state_iped_audit` (`StateIpedAuditReport`), classificando perfis omissivos (`FASTMODE_OR_TRIAGE_OMISSIVE`) e contaminação de internet.
- [x] Volumes de entropia uniforme sem cabeçalho detectados em `headerless_encrypted_candidates` via *permille* inteiro de $64\text{ KiB}$.
- [x] Cada item declarado e cada arquivo entregue classificado deterministicamente em um dos 7 estados de `ParityState`.
- [x] Plano de Cochran calculado com `Decimal` (100% dos itens críticos + amostra finita aleatória reproduzível por semente fixa).
- [x] Entregável gravado: `deliverables/phase01_identification_report.md` (assinado em `SHA-256`).

### Fase 02 — Preservação (`Phase02ToPhase03Contract`)
- [x] Bancos SQLite inspecionados exclusivamente via `file:...?mode=ro&immutable=1` + `PRAGMA query_only = 1;` sem criar `-journal`, `-wal` ou `-shm` na origem.
- [x] Presença de arquivo irmão `-wal` com frames não consolidados sinalizada em `has_unconsolidated_wal_frames == True`.
- [x] Todos os 6 eixos de `PreservationAxis` avaliados para cada vestígio declarado; lacres com troca numérica ou homógrafo Unicode (ex.: `O` cirílico/latino vs. `0`) marcados com `homograph_or_seal_mismatch == True`.
- [x] Entregável gravado: `deliverables/phase02_preservation_report.md`.

### Fase 03 — Coleta (`Phase03ToPhase04Contract`)
- [x] Cada item copiado para `vault/` recebe `ControlNumber` sequencial determinístico (`ELO-000001`, `ELO-000002`, ...), sofre `os.fsync()` no descritor de arquivo, é relido a frio do disco (`vault_cold_sha256 == source_sha256`) e travado em `0o444` (`vault_locked_readonly == True`).
- [x] Coletas estatais por filmagem de tela ou transitadas por mensageiros sinalizadas com `high_risk_flag == True`.
- [x] Entregáveis gravados: `deliverables/phase03_icp_manifest.json` e `deliverables/phase03_collection_report.md`.

### Fase 04 — Processamento (`Phase04ToPhase05Contract`)
- [x] Execução comprovada em ordem monotônica nas 5 filas de dependência `P0` $\rightarrow$ `P1` $\rightarrow$ `P2` $\rightarrow$ `P3` $\rightarrow$ `P4` (`tier_execution_order`).
- [x] Pacotes maliciosos contendo `../` (*Zip-Slip*) ou razão/volume excessivo (*Zip-Bomb*) bloqueados com `ContainerSecurityViolationError` antes de gravar fora de `staging/`.
- [x] Retomada incremental comprovada em `container_expansion_checkpoints`: contêiner pai interrompido é reprocessado até completar todos os filhos; contêiner concluído não sofre retrabalho.
- [x] Shards `storage-0..15.db` de casos `.iped` lidos em *streaming* GZIP somente leitura.
- [x] *Carving* `StreamingSignatureCarver` encontra assinaturas que cruzam exatamente a fronteira de $1\text{ MiB}$ (`1.048.576` bytes).
- [x] Registros deletados SQLite recuperados e rotulados com `SqliteRowAllocationState.CARVED_FREELIST_OR_UNALLOCATED` ou `WAL_UNCOMMITTED_FRAME`; atalhos `.lnk` decodificados com `droid_birth_mac_address`.
- [x] Realimentação `04 -> 01` incrementa `updated_phase01_bundle.revision_number >= 2` sempre que novas peças primárias são encontradas dentro de contêineres descompactados.
- [x] Emissão obrigatória dos **5 Relatórios Oficiais EDRM 4.0** em `deliverables/`:
  1. `phase04_01_intake_inventory.md`
  2. `phase04_02_deduplication_denist.md`
  3. `phase04_03_exceptions_deadletter.md`
  4. `phase04_04_temporal_financial_telecom.md`
  5. `phase04_05_schema_and_feedback_summary.md`

### Análise Contínua e Fase 05 — Revisão (`Phase05ToPhase06Contract`)
- [x] Comunicações advogado-cliente identificadas e segregadas em `privileged_excluded_cns` (excluídas do conjunto de produção).
- [x] Contradições materiais entre alegação estatal e prova bruta quantificadas (incluindo `financial_inflation_cents` inteiro).
- [x] Controle estatístico de qualidade aprovado (`qc_summary.qc_passed == True`) reportando limite superior exato da Regra do 3 ($3/n$).
- [x] Entregável gravado: `deliverables/phase05_review_report.md`.

### Fase 06 — Produção (`Phase06ToPhase07Contract`)
- [x] Parecer Técnico-Pericial estruturado obrigatoriamente nos **7 Blocos Periciais** (`Bloco 1` a `Bloco 7`) e aprovado em **dupla passagem** pelo `BlockingVerifierEngine` (`verifier_double_pass_zero_errors == True`).
- [x] Entregáveis gravados:
  1. `deliverables/phase06_parecer_tecnico_7_blocos.md`
  2. `deliverables/phase06_reproducao_independente.sh`
  3. `deliverables/phase06_loadfile_concordance.dat`
  4. `deliverables/phase06_loadfile_edrm.xml`
  5. `deliverables/phase06_icp_detached_manifest.json`

### Fase 07 — Apresentação (`Phase07ToPhase08Contract`)
- [x] Quesitos estratégicos numerados gerados sob medida para cada anomalia concreta detectada no caso (divergência de hash, lacre homógrafo, pós-apreensão, omissão `.iped`, SQLite deletado, `.lnk`).
- [x] Dossiê HTML5 Offline compilado em arquivo único sem links para scripts/estilos externos (`0` dependências CDN).
- [x] Entregáveis gravados:
  1. `deliverables/phase07_quesitos_estrategicos.md`
  2. `deliverables/phase07_anexo_tema977_stf.md`
  3. `deliverables/phase07_dossie_interativo_offline.html`

### Fase 08 — Destinação (`FinalDispositionReceipt`)
- [x] Diretório `staging/` completamente esvaziado (`0` arquivos remanescentes) após verificação da integridade de `deliverables/` e `vault/`.
- [x] `audit/MANIFESTO_SHA256.txt` conferido com `edrm.interfaces.cli verify` retornando `{"verified": true, "mismatches": []}`.
- [x] `source_pre_post_snapshot_identical == True`.
- [x] Sanitização pós-trânsito em julgado **NIST SP 800-88 Rev. 2** bloqueada por padrão e só executada mediante nome do operador humano + frase exata de confirmação (`CONFIRMO_TRANSITO_EM_JULGADO_E_DESCARTE_DEFINITIVO`).
