# ELO — Plataforma Forense Determinística Plug-and-Analyze (EDRM 2.0 + Delta v2.2)

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-1E3A8A?style=flat-square)
![Arquitetura](https://img.shields.io/badge/Arquitetura-Clean%20%2B%20Hexagonal%20%2B%20SOLID-0F766E?style=flat-square)
![EDRM 2.0](https://img.shields.io/badge/Framework-EDRM%202.0%20%2B%20IGRM%20v4.1-334155?style=flat-square)
![Portões Forenses](https://img.shields.io/badge/Port%C3%B5es%20G0--G12-13%2F13%20PASS%20(EXIT%200)-15803D?style=flat-square)
![MCP & Skills](https://img.shields.io/badge/MCP%20JSON--RPC%202.0-10%20Tools%20%2B%206%20Skills-7C2D12?style=flat-square)

**ELO** é uma plataforma de engenharia pericial e auditoria probatória digital construída em *Clean-Room* (Python 3.12+ e console analítico Full-Stack TypeScript/React), projetada para operar em regime **100% Plug-and-Analyze**: ao receber uma ou mais mídias probatórias brutas somente leitura (`--source`) e um diretório de trabalho isolado (`--workspace`), o motor percorre autonomamente desde a **Camada 00 (Governança IGRM v4.1)** até a **Fase 08 (Destinação e Sanitização NIST SP 800-88 Rev. 2)**, comprovando matematicamente `PreScanSnapshot == PostScanSnapshot` (zero mutação de bytes ou metadados na evidência original).

---

## 1. Visão Geral Executiva e Diferenciais Periciais

A plataforma ELO resolve o problema central da paridade de armas na persecução penal digital brasileira (**CPP arts. 158-A a 158-F**, **art. 159, §§ 5º e 6º**, **STF Tema 977**, **STJ RHC 184.003/SP** e **POP Senasp Vol. 5 — 2024**): confrontar determinísticamente o que os autos estatais declaram contra o que foi efetivamente entregue em mídia bruta, casos portáteis `.iped`, despejos Cellebrite `.ufdr`/`.ufdx`, bancos SQLite com `-wal`/`freelist`, planilhas financeiras SIMBA, registros telefônicos CDR/ERB e logs CGNAT.

### Os 8 Pilares Periciais Determinísticos (Auditados via AST em `G0`–`G11`)
1. **Imutabilidade Física Absoluta (`FsWriteBlockerGuard`)**: Interceptação em tempo de execução de `builtins.open`, `os.*` e `shutil.*`, bloqueando qualquer abertura gravável na mídia `--source` (`ReadOnlyViolationError`) e conferindo `PreScanSnapshot == PostScanSnapshot`.
2. **Zero Ponto Flutuante (`Zero Float Lock`)**: Proibição estrita de `float` (auditada na árvore sintática AST em `G1`) para valores monetários (`CentsAmount` / `BIGINT` em centavos), tamanhos em bytes (`ByteSize`), coordenadas geográficas (`MicroDegreesCoord` em micrograus inteiros), entropia/compressibilidade (`permille` inteiro $0..1000$) e estatísticas (`Decimal` exato).
3. **Criptografia Determinística Reprodutível**: Proibição do `hash()` volátil do Python; uso exclusivo de `hashlib.sha256` em *streaming* e serialização JSON canônica ordenada (`canonical_json_sha256`), com semente fixa (`PYTHONHASHSEED=42`).
4. **Leitura SQLite Estritamente Imutável**: Todo banco probatório externo (`msgstore.db`, `wa.db`, `sleuth.db` e os 16 shards `storage-0..15.db` do IPED) é aberto exclusivamente via URI `file:...?mode=ro&immutable=1` combinada com `PRAGMA query_only = 1;`.
5. **Software 1.0 Governando IA (`BlockingVerifierEngine`)**: Modelos de linguagem jamais calculam hashes, somas financeiras, datas UTC ou tamanhos em bytes. Qualquer síntese textual passa por dupla passagem do Verificador Determinístico Bloqueante (rejeitando desvios numéricos ou entidades fantasma) e pelo escudo `PromptInjectionShield`.
6. **Auto-Calibração Prévia ISO/IEC 27041**: Antes de tocar qualquer vestígio real na Camada 00, `SelfCalibrationSuite` executa 1 controle positivo e 2 controles negativos obrigatórios (mutação numérica e entidade alucinada), emitindo `CalibrationReceipt` assinado em SHA-256.
7. **Interoperabilidade Clean-Room IPED & Recuperação NIST IR 8354 (Delta v2.1)**: Auditoria automática de perfis omissivos em casos `.iped` estatais (`StateIpedCaseAuditor`), leitura direta dos 16 shards GZIP `storage-0..15.db`, inspeção binária de registros apagados em `freelist`/espaço não alocado SQLite (`SQLiteDeletedRecordsInspector`), rastreio físico `DroidBirth` MAC Address em `.lnk` e orquestração de dependências em 5 filas ($P_0 \rightarrow P_4$).
8. **Soberania Local e NIST SSDF v1.1**: Sob `SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY` (Resolução CNJ n. 615/2025 e Recomendação CFOAB n. 001/2024), conexões externas de socket são bloqueadas (`SecrecySocketViolationError`) e a API local vincula-se exclusivamente a `127.0.0.1` exigindo cabeçalho efêmero `X-ELO-Session-Token` validado por `hmac.compare_digest`.

---

## 2. Arquitetura Macroscópica (Ciclo EDRM 2.0 + Realimentação Iterativa)

```mermaid
flowchart LR
    SRC[("Mídia Bruta --source\n(Somente Leitura)")]
    G00["Camada 00: IGRM v4.1\nFsWriteBlockerGuard + ISO 27041"]
    P01["Fase 01: Identificação\nMagic 16B + Paridade 7 Estados\nStateIpedCaseAuditor + Cochran"]
    P02["Fase 02: Preservação\n6 Eixos + Homógrafos + SQLite -wal"]
    P03["Fase 03: Coleta\nCópia Cofre + fsync + SHA-256 Frio"]
    P04["Fase 04: Processamento\nFilas P0->P4 + Shards IPED + Carving\nSIMBA + CDR/ERB + CGNAT + .lnk"]
    CA["Análise Contínua\nRRF (k=60) + RoaringBitset\nExactMetric + BlockingVerifier"]
    P05["Fase 05: Revisão\nSigilo OAB + Contradições\nElusão + Regra do 3 (3/n)"]
    P06["Fase 06: Produção\nParecer 7 Blocos (Dupla Passagem)\nConcordance .DAT + EDRM XML"]
    P07["Fase 07: Apresentação\nQuesitos POP Senasp 2024\nAnexo Tema 977 + Dossiê HTML5"]
    P08["Fase 08: Destinação\nExpurgo staging/ + MANIFESTO_SHA256\nNIST SP 800-88 Rev. 2"]

    SRC -->|os.stat + Streaming RO| G00
    G00 -->|CaseGovernanceContract| P01
    P01 -->|Phase01ToPhase02Contract| P02
    P02 -->|Phase02ToPhase03Contract| P03
    P03 -->|Phase03ToPhase04Contract| P04
    P04 <-->|Indexação & Verificação| CA
    P04 -.->|IterativeDiscoveryFeedbackPayload\n(Novas Peças Descompactadas -> Rev 2+)| P01
    P04 -->|Phase04ToPhase05Contract| P05
    P05 <-->|QC Estatístico| CA
    P05 -->|Phase05ToPhase06Contract| P06
    P06 -->|Phase06ToPhase07Contract| P07
    P07 -->|Phase07ToPhase08Contract| P08
    P08 -->|PreScanSnapshot == PostScanSnapshot| G00
```

---

## 3. Estrutura do Repositório e das 5 Zonas do Workspace

### Árvore do Código-Fonte
```text
/
├── AGENTS.md / CLAUDE.md              # Constituição arquitetural e diretrizes imutáveis
├── README.md                          # Portal principal do repositório
├── OPERATORS_MANUAL.md                # Manual prático do operador forense (.iped, Manifesto, Quesitos, Cross-Disk & MCP)
├── CHANGELOG.md                       # Histórico auditável (EDRM 2.0 Waves 1-5 + Delta v2.1 + Delta v2.2)
├── pyproject.toml                     # Empacotamento Python 3.12+ (script CLI `elo`)
├── install_elo.py                     # Bootstrapper CLI real (--check-env, --install, --setup-all, .mcp.json & 6 Skills)
├── materialize_elo_platform.py        # Instalador autocontido da plataforma (verificado SHA-256)
├── materialize_docs.py                # Empacotador autocontido da suíte documental (SHA-256)
├── server.ts                          # Servidor Express + Vite do Console Forense Interativo
├── src/
│   ├── edrm/                          # Motor Forense Python Clean/Hexagonal
│   │   ├── shared_kernel/             # Contratos imutáveis, VOs, enums, schema SQL, validadores BR/Cripto
│   │   ├── igrm_governance/           # Camada 00 — IGRM v4.1, Write-Blocker, Calibração ISO 27041, NIST SSDF
│   │   ├── phase01_identification/    # Fase 01 — Magic Bytes, Paridade 7 estados, Cochran, Auditor IPED
│   │   ├── phase02_preservation/      # Fase 02 — 6 Eixos, Lacres Homógrafos, Saúde SQLite -wal, SPOF
│   │   ├── phase03_collection/        # Fase 03 — Aquisição Fsync/Cold-SHA256, Auditor Coleta Estatal
│   │   ├── phase04_processing/        # Fase 04 — Orquestrador P0->P4, Shards IPED, Carving, SIMBA, .lnk
│   │   ├── continuous_analysis/       # Análise Contínua — RRF k=60, Timeline UTC, Verificador Bloqueante
│   │   ├── phase05_review/            # Fase 05 — Filtro OAB, Contradições Materiais, RoaringBitset, QC 3/n
│   │   ├── phase06_production/        # Fase 06 — Parecer 7 Blocos, Script Reprodutibilidade, Load Files
│   │   ├── phase07_presentation/      # Fase 07 — Quesitos POP Senasp 2024, Tema 977, Dossiê HTML5 Offline
│   │   ├── phase08_disposition/       # Fase 08 — Expurgo staging/, Manifesto SHA-256, NIST SP 800-88 Rev. 2
│   │   ├── bootstrap/container.py     # Composition Root (Injeção de Dependência sem estado global)
│   │   └── interfaces/                # CLI, Roteador Cross-Disk, Publicador 8 Views, Autopilot, MCP Server & Skills
│   ├── components/                    # Visões do Console Web (Homologação, Paridade, Timeline, Parecer)
│   ├── types/forensic.ts              # Contratos TypeScript espelhados 1:1 com a CLI Python
│   └── utils/forensicModel.ts         # Formatadores determinísticos BRL/Bytes/Fases
├── tools/
│   ├── run_forensic_gates.py          # Executor unificado dos 13 Portões Forenses (G0 a G12)
│   ├── sync_installer_payload.py      # Gerador determinístico de materialize_elo_platform.py
│   └── sync_docs_payload.py           # Gerador determinístico de materialize_docs.py
├── tests/                             # Testes AST (architecture), Liskov (contract), unitários (G2-G7, G11, G12) e E2E
└── docs/                              # Suíte Completa de Documentação Enterprise (16 documentos + INDEX)
```

### Isolamento das 5 Zonas Físicas de `--workspace`
Todo caso processado cria exclusivamente 5 subdiretórios isolados fora da árvore de `--source` (qualquer sobreposição dispara `WorkspaceOverlapError`):
- `vault/`: Cofre probatório com cópias verificadas a frio (`os.fsync` + releitura integral SHA-256) e trava somente leitura (`0o444`), além dos shards locais `blob_shard_00..0f.sqlite`.
- `staging/`: Área efêmera de descompactação segura (Anti-Zip-Bomb e Anti-Path-Traversal) e execução supervisionada, **integralmente expurgada na Fase 08**.
- `catalog/`: Banco relacional canônico `elo_forensic_catalog.sqlite` (15 objetos DDL: 14 tabelas relacionais + índice virtual `FTS5`).
- `deliverables/`: Peças técnicas finais assinadas (Relatórios Fases 01–05, 5 Relatórios Oficiais EDRM 4.0, Parecer Técnico em 7 Blocos, Script de Reprodutibilidade, Load Files `.dat`/`.xml`, Quesitos Estratégicos, Anexo Tema 977 e Dossiê HTML5 Offline autocontido).
- `audit/`: Razão imutável *append-only* (`audit_ledger.jsonl`), manifesto de execução com Mini-SBOM NIST SSDF v1.1 (`execution_manifest.json`), `MANIFESTO_SHA256.txt` e pacote `elo_case_recovery.bundle`.

---

## 4. Início Rápido (Quickstart)

### Pré-requisitos
- **Python 3.12+** (biblioteca padrão completa; zero dependências externas obrigatórias para o motor forense central).
- **Node.js 20+ / npm** (opcional, apenas para o Console Analítico Web na porta `3000`).

### 1. Instalação Única da Estação Forense (`install_elo.py --setup-all`) e Homologação (`G0` a `G12`)
```bash
# Diagnostica Python 3.12+/FTS5, discos, gera bin/elo, .mcp.json e instala as 6 Skills (Claude Code & OpenCode)
python3 install_elo.py --setup-all

# Executa os 13 portões forenses cumulativos (G0 a G12)
PYTHONPATH=src:. PYTHONHASHSEED=42 python3 tools/run_forensic_gates.py
```
Saída esperada: `RESULTADO GLOBAL: HOMOLOGADO (EXIT CODE 0)` (`13/13 PASS`).

### 2. Abertura Cross-Disk Entre HDs (`elo wizard` / `elo autopilot`) e Banco Organizado (8 SQL Views)
```bash
# Assistente interativo listando HDs conectados ou execução direta em 1 comando:
PYTHONPATH=src PYTHONHASHSEED=42 python3 -m edrm.interfaces.cli autopilot \
  --case-id CASO-PENAL-2026-001 \
  --source /mnt/hd_prova_bruta_ro \
  --dest /mnt/segundo_hd_casos/caso_001
```
Materializa no segundo HD `01_BANCO_ORGANIZADO/case_master_organized.sqlite` (com `FTS5 BM25` + 8 SQL Views executivas prontas e `SCHEMA_PARA_HUMANO_E_IA.md`), mantendo `0` mutações no HD de prova!

### 3. Busca Híbrida RRF (`BM25 FTS5 + Vetorial Determinístico`) e Verificação Fria
```bash
# Consulta híbrida ancorada no catálogo do caso
PYTHONPATH=src python3 -m edrm.interfaces.cli search \
  --workspace /var/elo_cases/caso_001 \
  --query "transferencia SIMBA conta laranja" \
  --top-n 10

# Revalidação criptográfica a frio de todos os artefatos contra MANIFESTO_SHA256.txt
PYTHONPATH=src python3 -m edrm.interfaces.cli verify \
  --workspace /var/elo_cases/caso_001
```

### 4. Materialização Limpa (Instalador do Código e Instalador da Documentação)
```bash
# Reconstruir toda a plataforma Python com verificação SHA-256 a frio
python3 materialize_elo_platform.py --target /tmp/elo_clean_install --verify

# Reconstruir toda a suíte documental (18 documentos) com verificação SHA-256 a frio
python3 materialize_docs.py --target /tmp/elo_docs_bundle --verify
```

---

## 5. Mapa Completo da Documentação Enterprise (`/docs`)

Acesse o portal navegável em **[`docs/INDEX.md`](docs/INDEX.md)** ou vá diretamente ao documento desejado:

| Domínio | Documento | Escopo Técnico |
| :--- | :--- | :--- |
| **Produto & Planejamento** | [`01_PROJECT_CHARTER.md`](docs/01_product/01_PROJECT_CHARTER.md) | Termo de abertura, problema jurídico-pericial, escopo, premissas e *stakeholders*. |
| **Produto & Planejamento** | [`02_EXECUTIVE_BRIEFING.md`](docs/01_product/02_EXECUTIVE_BRIEFING.md) | Visão executiva para magistrados, advogados criminalistas, defensores, MP e peritos. |
| **Produto & Planejamento** | [`03_PRD.md`](docs/01_product/03_PRD.md) | Requisitos funcionais (`RF`) e não-funcionais (`RNF`) rastreáveis de `00` a `08`. |
| **Produto & Planejamento** | [`04_ROADMAP_AND_BACKLOG.md`](docs/01_product/04_ROADMAP_AND_BACKLOG.md) | Ondas construtivas `1`–`5`, evolução `Delta v2.1` e épicos futuros sem acoplamento. |
| **Produto & Planejamento** | [`05_ACCEPTANCE_CRITERIA.md`](docs/01_product/05_ACCEPTANCE_CRITERIA.md) | Definição de Pronto (`DoD`) e critérios matemáticos de aceite por fase e entregável. |
| **Arquitetura & Dados** | [`06_SYSTEM_BLUEPRINT.md`](docs/02_architecture/06_SYSTEM_BLUEPRINT.md) | Diagramas C4/Hexagonal, isolamento AST entre fases e *Composition Root*. |
| **Arquitetura & Dados** | [`07_DATA_MODEL_AND_CONTRACTS.md`](docs/02_architecture/07_DATA_MODEL_AND_CONTRACTS.md) | DER das 15 estruturas SQLite, 16 shards de blobs e dicionário dos 40 contratos. |
| **Arquitetura & Dados** | [`08_ADR_CATALOG.md`](docs/02_architecture/08_ADR_CATALOG.md) | Registro de Decisões Arquiteturais (`ADR-001` a `ADR-008`) e *trade-offs*. |
| **Arquitetura & Dados** | [`09_CLI_AND_API_REFERENCE.md`](docs/02_architecture/09_CLI_AND_API_REFERENCE.md) | Manual exato da CLI `edrm.interfaces.cli`, API `127.0.0.1` e rotas Web Lab. |
| **Metodologia & Qualidade** | [`10_FORENSIC_METHODOLOGY_GUIDE.md`](docs/03_forensic_compliance/10_FORENSIC_METHODOLOGY_GUIDE.md) | Reconciliação EDRM 2.0, IGRM v4.1, ISO 27037/27041/27042, NIST e CPP. |
| **Metodologia & Qualidade** | [`11_SECURITY_AND_COMPLIANCE.md`](docs/03_forensic_compliance/11_SECURITY_AND_COMPLIANCE.md) | Modelo STRIDE, travas Write-Blocker/Socket, Anti-Prompt-Injection e NIST SSDF v1.1. |
| **Metodologia & Qualidade** | [`12_TESTING_AND_QUALITY_GATES.md`](docs/03_forensic_compliance/12_TESTING_AND_QUALITY_GATES.md) | Guia dos 12 portões `G0`–`G11`, Cochran, Elusão, Regra do 3 ($3/n$) e Liskov. |
| **Operação & Extensão** | [`OPERATORS_MANUAL.md`](OPERATORS_MANUAL.md) | Guia prático do operador forense: leitura do `StateIpedCaseAuditor`, divergências de hash no manifesto e geração de quesitos automáticos. |
| **Operação & Extensão** | [`13_OPERATOR_PLAYBOOK.md`](docs/04_operations/13_OPERATOR_PLAYBOOK.md) | Procedimento Operacional Padrão (POP) prático passo a passo em casos reais. |
| **Operação & Extensão** | [`14_RUNBOOK_AND_RECOVERY.md`](docs/04_operations/14_RUNBOOK_AND_RECOVERY.md) | Catálogo de exceções tipadas, retomada de checkpoints e *Disaster Recovery*. |
| **Operação & Extensão** | [`15_DEVELOPER_EXTENSION_GUIDE.md`](docs/04_operations/15_DEVELOPER_EXTENSION_GUIDE.md) | Como criar novas assinaturas, extratores e adaptadores respeitando SOLID/AST. |
