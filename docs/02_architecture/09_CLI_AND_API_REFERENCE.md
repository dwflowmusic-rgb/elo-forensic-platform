# 09 — Referência Completa de CLI e APIs: Plataforma Forense ELO

Este manual documenta exatamente todos os subcomandos, parâmetros, códigos de saída e payloads JSON das interfaces oficiais da plataforma **ELO**:
1. **CLI Forense Unificada Python** (`python3 -m edrm.interfaces.cli` / executável `elo`).
2. **Servidor HTTP Loopback Soberano Python** (`edrm.interfaces.local_api.ForensicLoopbackHttpServer`).
3. **API REST do Console Analítico Web** (`server.ts` na porta `3000`).
4. **Utilitários de Homologação e Empacotamento** (`tools/run_forensic_gates.py`, `materialize_elo_platform.py` e `materialize_docs.py`).

---

## 1. CLI Forense Unificada (`edrm.interfaces.cli`)

### Invocação Padrão
```bash
PYTHONPATH=src PYTHONHASHSEED=42 python3 -m edrm.interfaces.cli <subcomando> [opções]
```
*(Ou diretamente `elo <subcomando> [opções]` quando instalado via `pip install -e .` a partir de `pyproject.toml`.)*

### 1.1 Subcomando `init-case`
Provisiona as 5 zonas isoladas do workspace (`vault`, `staging`, `catalog`, `deliverables`, `audit`), valida ausência de sobreposição com `--source`, executa a calibração **ISO/IEC 27041** e grava o contrato inicial de governança.

| Flag | Tipo | Obrigatório | Descrição |
| :--- | :--- | :--- | :--- |
| `--case-id` | `str` | Sim | Identificador único do caso (ex.: `CASO-PENAL-2026-01`). |
| `--source` | `str` (repetível) | Sim | Caminho de mídia probatória somente leitura (pode ser informado múltiplas vezes para múltiplos HDs/pendrives). |
| `--workspace` | `str` | Sim | Diretório limpo fora da árvore de `--source`. |

**Exemplo**:
```bash
PYTHONPATH=src python3 -m edrm.interfaces.cli init-case \
  --case-id OPERACAO-VERITAS-01 \
  --source /mnt/hd_apreendido_01 \
  --source /mnt/pendrive_fav_02 \
  --workspace /var/elo_workspaces/veritas_01
```
**Saída (`stdout`, Exit Code `0`)**: Objeto JSON canônico `CaseGovernanceContract` contendo `run_id`, diretórios resolvidos, `codebase_sha256` e `calibration_receipt`.

---

### 1.2 Subcomando `plug-hd`
Inicializa o workspace (Camada 00) e executa imediatamente a **Fase 01 (Identificação, Censo Binário de 16 Magic Bytes, Auditoria `.iped`, Matriz de Paridade em 7 Estados e Plano de Cochran)**.

| Flag | Tipo | Obrigatório | Descrição |
| :--- | :--- | :--- | :--- |
| `--case-id` | `str` | Sim | Identificador do caso. |
| `--source` | `str` (repetível) | Sim | Uma ou mais fontes probatórias somente leitura. |
| `--workspace` | `str` | Sim | Diretório isolado do caso. |

**Saída (`stdout`, Exit Code `0`)**:
```json
{
  "case_id": "OPERACAO-VERITAS-01",
  "phase01_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

---

### 1.3 Subcomando `run-phase`
Executa o pipeline controlado sob `FsWriteBlockerGuard` reportando o marcador de fase solicitada (`1` a `8`).

| Flag | Tipo | Obrigatório | Descrição |
| :--- | :--- | :--- | :--- |
| `--phase` | `int` (`{1..8}`) | Sim | Número inteiro da fase alvo (`1` a `8`). |
| `--case-id` | `str` | Sim | Identificador do caso. |
| `--source` | `str` (repetível) | Sim | Mídia(s) probatória(s). |
| `--workspace` | `str` | Sim | Diretório isolado do caso. |

**Saída (`stdout`, Exit Code `0`)**: `{"executed_up_to_phase": 4, "run_id": "..."}`.

---

### 1.4 Subcomando `plug-and-run-all` (Comando Principal *Plug-and-Analyze*)
Executa autonomamente da **Camada 00** até a **Fase 08** sob bloqueio de escrita, indexa todos os chunks na Busca Híbrida `RRF`, realiza realimentação iterativa `04 -> 01`, submete o Parecer em 7 Blocos à dupla passagem do Verificador Bloqueante, gera o Dossiê HTML5 Offline, expurga `staging/` e confirma `PreScanSnapshot == PostScanSnapshot`.

| Flag | Tipo | Obrigatório | Padrão | Descrição |
| :--- | :--- | :--- | :--- | :--- |
| `--case-id` | `str` | Não | `CASO-PENAL-EDRM2` | Identificador do caso pericial. |
| `--source` | `str` (repetível) | Sim | — | Uma ou mais mídias probatórias somente leitura. |
| `--workspace` | `str` | Sim | — | Diretório isolado de saída (5 zonas). |
| `--json` | `flag` | Não | `False` | Emite JSON compacto em linha única (sem indentação) ideal para integração programática. |

**Estrutura do JSON Retornado (`serialize_full_result_summary`)**:
- `case_id`, `run_id`, `workspace_root`, `codebase_sha256`, `calibration_receipt`
- `pre_scan_snapshot_sha256`, `post_scan_snapshot_sha256`, `zero_source_mutation_confirmed` (`bool`)
- `phase01_initial_revision`, `phase01_final_revision`, `extension_census`, `signature_census`, `spoofed_files`, `encrypted_or_corrupted_files`, `dynamic_schemas`, `custodians`, `divergences`, `parity_matrix`, `cochran_plan`, `state_iped_audit`
- `six_axes_findings`, `structural_findings`, `vault_entries`, `state_collection_findings`
- `processing_metrics` (`total_inventory_items`, `denisted_parent_count`, `logical_duplicates_count`, `post_seizure_events_count`, `pdf_multi_eof_count`, `financial_duplicates_count`, `impossible_erb_jumps_count`, `cgnat_missing_port_count`, `recovered_deleted_sqlite_rows_count`, `physical_link_tracker_findings_count`, `tier_execution_order`, `indexed_chunks_count`)
- `timeline_events`, `recovered_sqlite_records`, `link_provenance_records`, `financial_entries`, `telecom_records`, `cgnat_records`, `dead_letter_items`
- `material_contradictions`, `classified_nullities`, `qc_summary`
- `expert_opinion_path`, `expert_opinion_sha256`, `reproduction_script_path`, `quesitos`, `offline_html_dossier_path`, `offline_html_dossier_sha256`, `all_deliverables`
- `disposition` (`staging_purged_files_count`, `staging_purged_bytes`, `vault_intact_verified`, `manifest_sha256_path`, `recovery_bundle_path`, `nist_certificate_path`)

---

### 1.5 Subcomando `search`
Consulta o índice híbrido **Reciprocal Rank Fusion (`RRF`, $k=60$)** combinando `SQLite FTS5 BM25` e `DeterministicHashEmbedder` em `catalog/elo_forensic_catalog.sqlite`.

| Flag | Tipo | Obrigatório | Padrão | Descrição |
| :--- | :--- | :--- | :--- | :--- |
| `--workspace` | `str` | Sim | — | Workspace já processado contendo `catalog/elo_forensic_catalog.sqlite`. |
| `--query` | `str` | Sim | — | Consulta textual ou identificadores periciais. |
| `--top-n` | `int` | Não | `10` | Quantidade máxima de resultados ranqueados. |

**Saída (`stdout`, Exit Code `0`)**: Lista JSON de hits contendo `chunk_id`, `origin_cn`, `locator`, `rrf_score` (`Decimal` serializado como `str`), `lexical_rank`, `vector_rank`, `origin_sha256` e `text_clean`.

---

### 1.6 Subcomando `verify`
Revalida a frio todos os arquivos listados em `audit/MANIFESTO_SHA256.txt`, recalculando `hashlib.sha256` diretamente do disco.

| Flag | Tipo | Obrigatório | Descrição |
| :--- | :--- | :--- | :--- |
| `--workspace` | `str` | Sim | Diretório do caso selado na Fase 08. |

**Códigos de Saída**:
- `0`: `{"verified": true, "checked_files": 26, "mismatches": []}`
- `1`: Manifesto ausente ou qualquer arquivo ausente/adulterado (`MISSING:<rel_path>` ou `HASH_DIFF:<rel_path>`).

---

## 2. API HTTP Loopback Soberana (`edrm.interfaces.local_api`)

Projetada segundo **NIST SSDF PW.1.3** e **Recomendação CFOAB n. 001/2024**:
- **Instanciação**: `create_loopback_http_server(host="127.0.0.1", port=0, default_workspace="/caminho/ws")`
- **Trava de Bind**: Qualquer `host != "127.0.0.1"` (como `"0.0.0.0"`) lança imediatamente `SecrecySocketViolationError`.
- **Autenticação Obrigatória**: Todas as rotas exigem o cabeçalho HTTP `X-ELO-Session-Token: <server.session_token>` validado em tempo constante via `hmac.compare_digest`. Requisições sem token ou com token inválido recebem `HTTP 401 Unauthorized`.

| Método & Rota | Query Params | Resposta `200 OK` | Códigos de Erro |
| :--- | :--- | :--- | :--- |
| `GET /health` | — | `{"status": "ok", "bind": "127.0.0.1", "authenticated": true}` | `401` (token ausente/inválido) |
| `GET /search` | `q=<texto>&workspace=<dir>` | `{"results": [{ "chunk_id", "origin_cn", "locator", "rrf_score", "text_clean", "origin_sha256" }]}` | `400` (`workspace` ausente), `401` (token inválido), `404` (rota desconhecida) |

---

## 3. API REST do Console Analítico Web (`server.ts` — Porta `3000`)

O servidor Express + Vite (`server.ts`) orquestra o motor Python em subdiretórios isolados `/tmp/elo_web_lab` para inspeção interativa no navegador:

| Método & Endpoint | Corpo / Query | Função Executada no Motor Python |
| :--- | :--- | :--- |
| `GET /api/bootstrap` | — | Retorna estado inicial pré-aquecido (`gatesReport`, `activeCase`, `installerInfo` e `docsInstallerInfo`). |
| `POST /api/gates/run` | — | Executa `python3 tools/run_forensic_gates.py --json` (`PYTHONHASHSEED=42`) e retorna os 12 portões `G0`–`G11`. |
| `POST /api/cases/run-synthetic` | `{"caseId": "..."}` | Materializa HD forense sintético inédito, roda `plug-and-run-all --json` + `verify` a frio e retorna dossiê completo. |
| `POST /api/cases/verify-manifest` | — | Reexecuta `python3 -m edrm.interfaces.cli verify --workspace <ativo>` a frio. |
| `GET /api/cases/search` | `?q=<termo>&topN=10` | Executa `python3 -m edrm.interfaces.cli search` sobre o workspace ativo. |
| `GET /api/download/installer` | — | Faz download do instalador autocontido da plataforma (`materialize_elo_platform.py`). |
| `GET /api/download/docs-installer` | — | Faz download do empacotador autocontido da documentação (`materialize_docs.py`). |
| `GET /api/download/dossier` | — | Faz download de `phase07_dossie_interativo_offline.html` gerado na Fase 07. |

---

## 4. Utilitários CLI de Homologação e Empacotamento

| Comando | Flags Suportadas | Comportamento e Código de Saída |
| :--- | :--- | :--- |
| `python3 install_elo.py` | `--check-env \| --install \| --setup-all [--target-dir <DIR>]` | Diagnostica ambiente, gera wrappers `bin/elo` / `bin/elo.cmd`, calibra ISO 27041, grava `.mcp.json` / `opencode.json` e instala as 6 Skills Operacionais. |
| `python3 tools/run_forensic_gates.py` | `[--json]` | Executa sequencialmente os 13 portões `G0` a `G12`. Retorna `0` somente se 13/13 passarem; `1` caso contrário. |
| `python3 materialize_elo_platform.py` | `--target <DIR> [--verify]` | Reconstrói todos os módulos Python, `install_elo.py`, `.mcp.json` e as 6 Skills da plataforma ELO em `<DIR>`, grava `MANIFESTO_INSTALACAO_SHA256.txt` e valida hashes a frio (`0` se íntegro). |
| `python3 materialize_docs.py` | `--target <DIR> [--verify]` | Reconstrói toda a árvore `docs/**` + `README.md` + `OPERATORS_MANUAL.md` + `CHANGELOG.md` + `AGENTS.md` em `<DIR>`, grava `MANIFESTO_DOCS_SHA256.txt` e valida hashes a frio (`0` se íntegro). |

---

## 5. Subcomandos Operacionais Cross-Disk & Servidor MCP JSON-RPC 2.0 (Delta v2.2)

### 5.1 Subcomandos Adicionais em `edrm.interfaces.cli`
- `elo doctor [--llm-endpoint http://127.0.0.1:11434]`: Diagnóstico rápido de Python, SQLite, volumes montados e endpoint LLM loopback.
- `elo drives` / `elo mount`: Lista todos os HDs e pontos de montagem conectados com bytes livres/totais inteiros (`zero float`).
- `elo wizard [--plan-only]`: Assistente interativo de terminal para seleção segura entre HD de Prova (`--source`), HD de Destino (`--dest`) e HD opcional `--staging`.
- `elo autopilot --source <HD_ORIGEM> --dest <HD_DESTINO> [--staging <HD_TEMP>] [--case-id <ID>] [--strict-separate-drive]`: Executa autonomamente Calibração ISO 27041, Fases `00`→`08` e publica `01_BANCO_ORGANIZADO/case_master_organized.sqlite` (8 SQL Views + FTS5) no outro HD com `0` mutações na prova.
- `elo mcp-serve [--dest <DIR_PADRAO>]`: Inicia o Servidor MCP oficial JSON-RPC 2.0 via `stdio`.
- `elo install-skills [--target-dir <DIR>]` / `elo setup [--target-dir <DIR>]`: Instala `.mcp.json`, `opencode.json` e as 6 Skills Operacionais em `.claude/skills/` e `.opencode/skills/`.

### 5.2 As 10 Ferramentas Forenses Determinísticas do Servidor MCP (`mcp_server.py`)
1. `elo_list_mounted_drives` — Enumera volumes/HDs conectados e espaço disponível exato.
2. `elo_autopilot_ingest_hd` — Ingestão completa Cross-Disk (`--source` RO $\rightarrow$ `--dest` organizado).
3. `elo_get_case_overview` — Lê `RESUMO_EXECUTIVO_BANCO.json` e contagens ao vivo das 8 Views.
4. `elo_hybrid_search` — Busca híbrida `RRF` (`BM25 FTS5` + vetorial determinística) no Banco Organizado.
5. `elo_query_organized_view` — Consulta paginada somente leitura (`mode=ro&immutable=1` + autorizador C SQLite + firewall estrito apenas `SELECT`) sobre as 8 Views executivas.
6. `elo_timeline_window` — Eventos multi-fonte em janela cronológica `UTC` (`vw_08_linha_do_tempo_mestra_utc`).
7. `elo_audit_custody_and_parity` — Quebras de custódia, auditoria `.iped` e provas sonegadas (**STF Tema 977**).
8. `elo_confront_allegation_vs_raw` — Confronta afirmação estatal contra mensagens com contexto vizinho, duplicidades `SIMBA` e anomalias `ERB`/`CGNAT`.
9. `elo_verify_citation_strict` — Barreira `BlockingVerifierEngine` conferindo `ControlNumber`, `SHA-256`, valores inteiros e citações `«literais»`.
10. `elo_generate_deliverables` — Manifesto verificado por `SHA-256` dos entregáveis em `03_RELATORIOS_E_DOSSIE/`.

