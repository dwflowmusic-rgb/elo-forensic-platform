# 01 — Project Charter: Plataforma Forense ELO (EDRM 2.0 + Delta v2.1)

| Metadado | Especificação Oficial |
| :--- | :--- |
| **Código do Projeto** | `ELO-FORENSIC-EDRM20-V21` |
| **Paradigma Operacional** | 100% *Plug-and-Analyze* (`--source` somente leitura $\rightarrow$ `--workspace` isolado em 5 zonas) |
| **Arquitetura Base** | Clean Architecture + Hexagonal (*Ports & Adapters*) + Enterprise SOLID (auditada via AST) |
| **Referencial Normativo** | EDRM 2.0 (CC BY 4.0), IGRM v4.1 (versão vigente oficial do EDRM), ISO/IEC 27037/27041/27042, NIST IR 8354, NIST SP 800-88 Rev. 2, NIST SSDF v1.1, CPP arts. 158-A a 158-F e art. 159, §§ 5º–6º |
| **Status de Homologação** | Produção Homologada (`12/12` Portões Forenses `G0`–`G11` aprovados com `EXIT CODE 0`) |

---

## 1. Declaração do Problema Jurídico-Pericial

No contencioso penal contemporâneo — especialmente em operações envolvendo lavagem de capitais, crimes financeiros, interceptações telemáticas, quebras de sigilo bancário (`SIMBA`), registros de radiofrequência (`CDR/ERB`), logs de conexão (`CGNAT`) e extrações de dispositivos móveis (`Cellebrite .ufdr`/`.ufdx`, bancos `SQLite` e casos portáteis `.iped`) — verifica-se uma **assimetria estrutural severa** entre o volume de mídias acauteladas pelo Estado e a capacidade técnica de auditoria independente das partes:

1. **Discrepância entre o Declarado nos Autos e o Efetivamente Entregue**: Autos de Apreensão, Fichas de Acompanhamento de Vestígio (`FAV`) e Laudos Periciais frequentemente omitem hashes de origem, entregam apenas recortes parciais ou relatórios estáticos sem o espelho bruto (violando o **STF Tema 977** e a jurisprudência do **STJ no RHC 184.003/SP**), ou apresentam lacres divergentes e adulterações visuais por caracteres homógrafos.
2. **Perfis Omissivos em Processamentos Estatais (`.iped`)**: Entregas em casos portáteis `.iped` processados sob perfis céleres (`fastmode`, `triage`) podem desabilitar carving binário, suprimir itens via HashDB sem transparência, ativar `deleteIgnoredItems` ou contaminar o ambiente probatório com downloads externos (`--downloadInternetData`).
3. **Erros Aritméticos e Temporais Silenciosos**: Ferramentas genéricas utilizam ponto flutuante IEEE-754 (`float`) para somar transações financeiras (introduzindo desvios de centavos), ignoram a duplicidade inter-arquivos em remessas bancárias sobrepostas do SIMBA e misturam épocas temporais distintas (`Unix 1970`, `Apple Cocoa 2001`, `QuickTime 1904`) sem normalização explícita para `UTC`.
4. **Risco de Mutação Acidental da Prova e Alucinação de IA**: Abrir bancos SQLite probatórios sem trava `immutable=1` altera cabeçalhos/journals no disco original, destruindo o hash `SHA-256` da evidência; paralelamente, o uso não governado de LLMs em peças técnicas gera citações inexistentes ou distorce valores numéricos, em afronta direta à **Resolução CNJ n. 615/2025**.

---

## 2. Missão e Objetivos Mensuráveis do Projeto

A missão da plataforma **ELO** é fornecer um motor pericial determinístico, soberano (100% local sob segredo de justiça) e matematicamente auditável que transforme qualquer mídia probatória desconhecida em um dossiê técnico-jurídico irrepreensível, sem alterar um único bit da fonte original.

| ID | Objetivo Estratégico | Métrica Determinística de Sucesso (Auditada em Código) |
| :--- | :--- | :--- |
| **OBJ-01** | Garantir **imutabilidade física absoluta** da mídia probatória original (`--source`). | `PreScanSnapshot.snapshot_sha256 == PostScanSnapshot.snapshot_sha256` em 100% das execuções (`FsWriteBlockerGuard`). |
| **OBJ-02** | Eliminar 100% de imprecisão aritmética em moeda, bytes, coordenadas e entropia. | `0` ocorrências de `float` nas camadas nucleares; moeda em `BIGINT` centavos (`CentsAmount`), coordenadas em micrograus (`MicroDegreesCoord`) e entropia em *permille* inteiro. |
| **OBJ-03** | Auditar exaustivamente a paridade de armas e a cadeia de custódia estatal. | Classificação automática nos **7 estados da Matriz de Paridade**, **6 Eixos de Preservação**, **auditoria `.iped` estatal** e enquadramento no CPP/Tema 977. |
| **OBJ-04** | Submeter qualquer camada analítica ou síntese de IA ao governo estrito de Software 1.0. | Calibração prévia **ISO/IEC 27041** (`1` positivo + `2` negativos) + **Dupla Passagem** do `BlockingVerifierEngine` com `0` reivindicações rejeitadas na peça final. |
| **OBJ-05** | Assegurar reprodutibilidade independente por terceiro perito oficial ou assistente técnico. | Emissão automática de `phase06_reproducao_independente.sh`, `MANIFESTO_SHA256.txt` e instaladores autocontidos verificados por `SHA-256` (`materialize_elo_platform.py` e `materialize_docs.py`). |

---

## 3. Fronteiras de Escopo (*In-Scope* vs. *Out-of-Scope*)

### 3.1 Escopo Incluído (*In-Scope*)
- **Ciclo Completo EDRM 2.0 (`00` a `08` + `Análise Contínua`)**:
  - **Camada 00 (`igrm_governance`)**: Isolamento das 5 zonas do workspace, bloqueador de escrita em software, bloqueio de sockets sob segredo de justiça, calibração ISO/IEC 27041, ledger *append-only* encadeado e manifesto de execução com Mini-SBOM NIST SSDF v1.1.
  - **Fase 01 (`phase01_identification`)**: Sonda binária de 16 *Magic Bytes*, detecção de *extension spoofing*, sonda de criptografia sem cabeçalho ($64\text{ KiB}$ *permille*), descoberta dinâmica de esquemas SQLite/CSV, extração de peças primárias, auditoria de casos `.iped` estatais, Matriz de Paridade (7 estados) e plano amostral estratificado de Cochran.
  - **Fase 02 (`phase02_preservation`)**: Diagnóstico imutável de bancos SQLite (`PRAGMA quick_check` e frames `-wal`), detecção de homógrafos em lacres, avaliação dos 6 Eixos da Preservação Estatal e mapa SPOF.
  - **Fase 03 (`phase03_collection`)**: Aquisição seletiva/integral para `vault/` com `os.fsync`, releitura fria `SHA-256`, trava `0o444`, manifesto ICP destacado e auditoria do método estatal de coleta.
  - **Fase 04 (`phase04_processing`)**: Orquestração em 5 filas de dependência ($P_0 \rightarrow P_4$), checkpoints de contêineres pais, leitura imutável dos 16 shards `.iped` (`storage-0..15.db`), *carving* em *streaming* Aho-Corasick ($1\text{ MiB}$), recuperação de registros deletados SQLite (`freelist`/`-wal`), extração de proveniência `.lnk` (`DroidBirth MAC`), resolução WhatsApp `@lid`/*view-once*, parsers SIMBA/CDR-ERB/CGNAT, validadores BR/Cripto/BIP-39, cache de transcrição de áudio por `SHA-256`, realimentação iterativa `04 -> 01` e 5 Relatórios Oficiais EDRM 4.0.
  - **Análise Contínua (`continuous_analysis`)**: Busca híbrida `RRF (k=60)` combinando `SQLite FTS5 BM25` e `DeterministicHashEmbedder`, similaridade métrica exata (`ExactMetricSimilarity`), linha do tempo UTC unificada, escudo `PromptInjectionShield` e `BlockingVerifierEngine`.
  - **Fase 05 (`phase05_review`)**: Escudo de prerrogativas OAB (`PrivilegeShieldFilter`), álgebra de conjuntos `CompressedRoaringBitset`, detector de contradições materiais Laudo $\times$ Prova Bruta, enquadramento de nulidades e QC estatístico (Elusão + Regra do 3 $3/n$).
  - **Fase 06 (`phase06_production`)**: Parecer Técnico-Pericial em 7 Blocos validado em dupla passagem, script de reprodutibilidade e *Load Files* (`Concordance .DAT` e `EDRM XML`).
  - **Fase 07 (`phase07_presentation`)**: Quesitos estratégicos ancorados no POP Senasp Vol. 5 (2024), Anexo Técnico STF Tema 977 e Dossiê Interativo HTML5 Offline em arquivo único.
  - **Fase 08 (`phase08_disposition`)**: Expurgo de `staging/`, emissão de `MANIFESTO_SHA256.txt` e `elo_case_recovery.bundle`, reconexão `PreScanSnapshot == PostScanSnapshot` e sanitização pós-trânsito em julgado **NIST SP 800-88 Rev. 2** mediante dupla confirmação humana.
- **Interfaces**: CLI unificada (`edrm.interfaces.cli`), servidor HTTP local `127.0.0.1` autenticado (`edrm.interfaces.local_api`) e Console Analítico Web Interativo (`server.ts` + React).

### 3.2 Fora do Escopo (*Out-of-Scope*)
- **Quebra criptográfica ofensiva (*brute-force* de senhas ou exploração de vulnerabilidades de hardware/bootloader)**: Arquivos cifrados sem chave legítima são documentados formalmente na `DeadLetterExceptionRecord` e auditados nos 6 Eixos da Fase 02, jamais submetidos a ataques destrutivos.
- **Alteração ou reparo in-place de mídias probatórias**: O ELO jamais executa `VACUUM`, `REINDEX` ou *checkpointing* de `-wal` sobre a mídia `--source` ou sobre as cópias seladas em `vault/`.
- **Ingestão de dados externos da internet durante o processamento**: Proibido buscar avatares, mapas online, tiles geográficos ou metadados remotos que possam vazar indicadores do caso sob segredo de justiça ou contaminar a prova.

---

## 4. Premissas, Restrições e Governança

1. **Soberania de Execução Offline**: Sob o nível padrão `SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY`, todo o ciclo opera 100% offline na máquina pericial controlada pelo operador.
2. **Independência Tecnológica do Núcleo**: O motor Python `src/edrm` utiliza exclusivamente módulos nativos auditáveis da biblioteca padrão do Python 3.12+, eliminando riscos de cadeia de suprimentos (*supply-chain attacks*) em dependências transitivas opacas.
3. **Isolamento Arquitetural Estrito**: As camadas `domain/` e `application/` permanecem 100% livres de I/O, sistema operacional, SQLite ou rede, e nenhuma fase importa diretamente outra fase (auditado pelo Portão `G1` a cada build).

---

## 5. Matriz de Partes Interessadas (*Stakeholders*)

| Parte Interessada | Papel no Ecossistema | Entregável Primário Consumido |
| :--- | :--- | :--- |
| **Assistente Técnico da Defesa / Acusação** | Operação pericial, formulação de quesitos e parecer contraditório (CPP art. 159, § 5º). | Catálogo SQLite, Parecer em 7 Blocos, Quesitos POP Senasp 2024 e `MANIFESTO_SHA256.txt`. |
| **Advogado Criminalista / Defensor Público** | Impugnação de quebras de cadeia de custódia, omissões estatais e contradições materiais. | Dossiê HTML5 Offline, Anexo Técnico STF Tema 977 e Relatório da Fase 05. |
| **Magistrado e Assessores Judiciais** | Valoração racional da confiabilidade epistêmica do vestígio e aferição de paridade de armas. | Parecer Técnico-Pericial (Bloco 1 — Sumário Executivo e Bloco 3 — Achados Verificados). |
| **Perito Oficial Criminal** | Reprodução independente dos achados, resposta aos quesitos técnicos e conferência cruzada. | `phase06_reproducao_independente.sh`, *Load Files* (`.dat`/`.xml`) e âncoras `SHA-256`. |
| **Auditor de Segurança / Compliance** | Homologação de integridade do software, ausência de vazamentos e descarte pós-processual. | Relatório dos Portões `G0`–`G11`, `execution_manifest.json` (Mini-SBOM) e Certificado NIST SP 800-88 Rev. 2. |
