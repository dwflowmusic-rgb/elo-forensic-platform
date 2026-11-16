# 13 — Manual Operacional do Perito e Assistente Técnico (Operator Playbook)

Este Procedimento Operacional Padrão (**POP-ELO**) orienta passo a passo o perito oficial ou assistente técnico na condução de uma auditoria probatória real desde o recebimento da mídia acautelada até a protocolização judicial dos entregáveis assinados.

---

## 1. Preparação do Ambiente Forense Soberano

### 1.1 Verificação de Homologação da Estação Pericial
Antes de conectar qualquer mídia probatória, valide a integridade integral do código-fonte e dos 12 portões forenses na estação offline:

```bash
# 1. Opcional: instalar em diretório limpo verificado por SHA-256
python3 materialize_elo_platform.py --target /opt/elo_forensic --verify

# 2. Homologar todos os 12 portões (G0 a G11) com semente determinística
PYTHONPATH=/opt/elo_forensic/src:/opt/elo_forensic PYTHONHASHSEED=42 \
  python3 /opt/elo_forensic/tools/run_forensic_gates.py
```
> **Regra Bloqueante**: Prossiga **exclusivamente** se o console exibir `RESULTADO GLOBAL: 12/12 portoes aprovados | EXIT CODE 0`.

### 1.2 Montagem Segura da Mídia Original (`--source`)
1. Conecte o HD/SSD/Pendrive preferencialmente através de um bloqueador físico de escrita (*Hardware Write-Blocker* Tableau / WiebeTech) **e** monte o sistema de arquivos em modo somente leitura no sistema operacional:
   ```bash
   sudo mkdir -p /mnt/midia_acautelada_01
   sudo mount -o ro,noatime,nodev,nosuid /dev/sdb1 /mnt/midia_acautelada_01
   ```
2. Mesmo quando a mídia já consiste em uma pasta copiada dos autos eletrônicos (ex.: download de PJe/eproc ou entrega em balcão), o motor **ELO** aplica automaticamente seu bloqueador lógico `FsWriteBlockerGuard` e confere `PreScanSnapshot == PostScanSnapshot`.
3. Escolha um diretório `--workspace` em unidade de armazenamento rápida (NVMe local) **completamente fora** de `/mnt/midia_acautelada_01`.

---

## 2. Roteiro Passo a Passo de Processamento do Caso

### Cenário A: Execução Integral Automatizada (*Plug-and-Analyze*)
Recomendado para 95% dos casos criminais (mídias mistas contendo peças PDF/TXT, contêineres `.zip`/`.ufdr`, casos `.iped`, bancos `SQLite`, quebras `SIMBA` e planilhas `CDR/ERB`):

```bash
PYTHONPATH=src PYTHONHASHSEED=42 python3 -m edrm.interfaces.cli plug-and-run-all \
  --case-id AUTOS-0004582-91.2026.8.26.0050 \
  --source /mnt/midia_acautelada_01 \
  --workspace /var/elo_cases/autos_0004582 \
  > /var/elo_cases/autos_0004582_sumario.json
```

Ao término da execução, confira imediatamente os três indicadores vitais no JSON gerado:
```bash
python3 -c '
import json, pathlib
d = json.loads(pathlib.Path("/var/elo_cases/autos_0004582_sumario.json").read_text())
print("Zero Mutação na Fonte :", d["zero_source_mutation_confirmed"])
print("PreScan  SHA-256      :", d["pre_scan_snapshot_sha256"])
print("PostScan SHA-256      :", d["post_scan_snapshot_sha256"])
print("Revisão Final Fase 01 :", d["phase01_final_revision"])
print("QC Fase 05 Aprovado   :", d["qc_summary"]["qc_passed"])
'
```

---

### Cenário B: Triagem Inicial Rápida de Paridade (Apenas Camada 00 + Fase 01)
Útil quando o advogado precisa verificar em minutos se o espelho bruto declarado na `FAV` / `Auto de Apreensão` foi efetivamente entregue na mídia antes de esgotar-se um prazo processual curto:

```bash
PYTHONPATH=src PYTHONHASHSEED=42 python3 -m edrm.interfaces.cli plug-hd \
  --case-id TRIAGEM-TEMA977 \
  --source /mnt/midia_acautelada_01 \
  --workspace /var/elo_cases/triagem_tema977
```
Inspecione imediatamente o relatório `deliverables/phase01_identification_report.md` para identificar linhas com `DECLARED_RAW_NOT_DELIVERED` ou `DIVERGENT_HASH_OR_SIZE`.

---

### Cenário C: Auditoria de Caso Portátil `.iped` Entregue pelo Estado
Quando `--source` aponta para uma pasta contendo `IPED-SearchApp.exe`, `sleuth.db` e `iped/data/storage-0..15.db`:
1. Execute `plug-and-run-all` normalmente apontando `--source` para a raiz do caso `.iped`.
2. O `StateIpedCaseAuditor` (Fase 01) preencherá o objeto `state_iped_audit` indicando:
   - `profile_risk`: se foi usado `FASTMODE_OR_TRIAGE_OMISSIVE` ou `BLIND_HASH_ONLY`;
   - `disabled_critical_tasks`: tarefas periciais omitidas (ex.: carving ou expansão de contêineres);
   - `delete_ignored_items_active`: se houve deleção lógica irreversível de itens ignorados;
   - `internet_download_contamination`: se o processamento estatal baixou recursos externos.
3. Na Fase 04, `StateIpedStorageReaderAdapter` lerá `sleuth.db` e os 16 shards GZIP em `mode=ro&immutable=1` sem abrir o aplicativo Java original.
4. Na Fase 07, `deliverables/phase07_quesitos_estrategicos.md` trará quesitos específicos questionando cada omissão detectada no perfil estatal.

---

## 3. Investigação Analítica e Busca Híbrida (`RRF k=60`)

Com o caso processado, realize consultas combinando precisão léxica (`BM25 FTS5`) e semântica determinística (`DeterministicHashEmbedder`):

```bash
# Busca por termos financeiros, nomes, contas ou eventos específicos
PYTHONPATH=src python3 -m edrm.interfaces.cli search \
  --workspace /var/elo_cases/autos_0004582 \
  --query "remessa SIMBA duplicada transferencia PIX" \
  --top-n 15
```
Cada resultado exibe `origin_cn` (`ControlNumber`), `locator` exato (linha/tabela/página) e `origin_sha256` pronto para citação direta em petição ou parecer.

---

## 4. Conferência Criptográfica Fria e Protocolização dos Entregáveis

Antes de juntar os documentos aos autos judiciais, execute a verificação fria contra `audit/MANIFESTO_SHA256.txt`:

```bash
PYTHONPATH=src python3 -m edrm.interfaces.cli verify \
  --workspace /var/elo_cases/autos_0004582
```
Resultado exigido (`Exit Code 0`):
```json
{"verified": true, "checked_files": 26, "mismatches": []}
```

### Checklist de Peças em `deliverables/` Prontas para Juntada Processual
| Arquivo Gerado | Finalidade Processual |
| :--- | :--- |
| `phase06_parecer_tecnico_7_blocos.md` | **Parecer Técnico-Pericial Principal** (CPP art. 159, § 5º, II), validado em dupla passagem com zero erros. |
| `phase07_quesitos_estrategicos.md` | **Rol de Quesitos Técnicos** (CPP art. 159, § 5º, I) ancorados no POP Senasp Vol. 5 (2024). |
| `phase07_anexo_tema977_stf.md` | **Anexo Técnico de Paridade de Armas (STF Tema 977)** demonstrando omissões de mídia bruta ou quebras de custódia. |
| `phase07_dossie_interativo_offline.html` | **Dossiê Visual Interativo Offline** em arquivo único para despacho em gabinete (abre sem internet). |
| `phase06_reproducao_independente.sh` | **Script de Reprodutibilidade** permitindo à perícia oficial ou ao juízo recalcular todos os hashes. |
| `phase06_loadfile_concordance.dat` / `.xml` | **Load Files Padrão Indústria** para intercâmbio com plataformas e-Discovery externas. |
| `audit/MANIFESTO_SHA256.txt` | **Lista Mestra de Hashes SHA-256** selando todos os entregáveis, cofre e catálogo. |
