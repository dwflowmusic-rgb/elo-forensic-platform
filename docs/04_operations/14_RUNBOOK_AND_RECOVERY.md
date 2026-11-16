# 14 — Runbook de Incidentes, Exceções Tipadas e Recuperação de Desastres

A plataforma **ELO** proíbe blocos `except` silenciosos: qualquer violação de imutabilidade, corrupção de cópia, tentativa de conexão externa sob segredo de justiça ou divergência factual levanta uma **exceção tipada determinística** derivada de `ForensicPlatformError` (`src/edrm/shared_kernel/exceptions.py`).

Este documento detalha o diagnóstico e a resposta operacional para cada classe de incidente, a retomada de contêineres interrompidos e o procedimento de *Disaster Recovery*.

---

## 1. Catálogo Completo das 12 Exceções Forenses Tipadas

| Classe de Exceção | Causa Raiz Exata | Ação Imediata Recomendada ao Operador |
| :--- | :--- | :--- |
| **`ReadOnlyViolationError`** | Código ou biblioteca tentou abrir arquivo em `--source` com modo de escrita (`w`, `a`, `x`, `+`) ou invocar operação mutável (`unlink`, `rename`, `chmod`, `utime`). | Nenhuma alteração ocorreu (a chamada foi bloqueada antes do syscall). Verifique se algum script externo apontou saída para dentro de `--source`. |
| **`SourceMutationDetectedError`** | Divergência matemática entre `PreScanSnapshot` e `PostScanSnapshot` (ex.: outro processo do sistema operacional montou `--source` em modo `rw` e gravou metadados `Thumbs.db`/`.DS_Store`). | Desmonte imediatamente a mídia e remonte com `mount -o ro,noatime`; documente o evento externo e reexecute em novo `--workspace`. |
| **`WorkspaceOverlapError`** | O diretório `--workspace` coincide com `--source` ou está aninhado dentro/acima dele de forma conflitante. | Informe um `--workspace` em partição/pasta totalmente disjunta de `--source`. |
| **`VerifierCalibrationError`** | Falha em um dos 3 controles obrigatórios da bateria prévia **ISO/IEC 27041** (`SelfCalibrationSuite`). | Interrompa o uso da estação; reexecute `python3 materialize_elo_platform.py --verify` e `tools/run_forensic_gates.py` para verificar integridade dos binários Python. |
| **`BlockingVerificationError`** | O `BlockingVerifierEngine` bloqueou afirmação contendo número divergente, hash adulterado ou `ControlNumber` inexistente no catálogo. | Inspecione `ai_and_qc_audit_log` no catálogo SQLite para auditar a afirmação bloqueada; jamais desative o verificador. |
| **`SecrecySocketViolationError`** | Tentativa de abrir socket externo sob `JUDICIAL_SECRECY_LOCAL_ONLY` ou instanciar `ForensicLoopbackHttpServer` fora de `"127.0.0.1"`. | Confirme que integrações locais usam estritamente `127.0.0.1` e o cabeçalho `X-ELO-Session-Token`. |
| **`CollectionHashMismatchError`** | Após `os.fsync()`, a releitura fria do arquivo gravado em `vault/` produziu `SHA-256` diferente de `source_sha256` (falha física de RAM ECC ou setor defeituoso no disco de destino). | Substitua a unidade de armazenamento onde reside `--workspace`, verifique `dmesg`/`smartctl` e repita a aquisição. |
| **`ContainerSecurityViolationError`** | Contêiner `.zip`/`.tar` excedeu o teto de bytes/razão de expansão (*Zip-Bomb*) ou tentou gravar caminho relativo escapando de `staging/` (`../`, *Zip-Slip*). | O item malicioso é contido com segurança; registre o artefato como evidência de tentativa de sabotagem/ofuscação na `DeadLetterExceptionRecord`. |
| **`BudgetCircuitBreakerError`** | Limite orçamentário de recursos/tokens excedido em processamento auxiliar. | Ajuste o lote amostral ou execute exclusivamente em modo determinístico local. |
| **`HumanAuthorizationRequiredError`** | Tentativa de acionar sanitização pós-trânsito em julgado **NIST SP 800-88 Rev. 2** sem `human_operator_name` ou sem a frase exata `CONFIRMO_TRANSITO_EM_JULGADO_E_DESCARTE_DEFINITIVO`. | Só forneça a dupla confirmação após juntada nos autos da certidão formal de trânsito em julgado (CPP art. 158-B, X). |
| **`InvalidForensicValueError`** | Violação de invariante em Objeto de Valor (ex.: `Sha256Hash` sem 64 hexadecimais, `ByteSize` negativo/float ou coordenada fora de $[-180^\circ, +180^\circ]$). | Verifique a formatação do dado de entrada ou formato corrompido da planilha de origem. |
| **`ForensicPlatformError`** | Classe base raiz de todas as exceções controladas da plataforma ELO. | Consulte o traceback tipado e o último evento gravado em `audit/audit_ledger.jsonl`. |

---

## 2. Retomada Resiliente após Queda de Energia na Fase 04

Durante a descompactação de contêineres volumosos (`.zip`, `.ufdr`), o `ContainerExpansionCheckpointManager` grava transações SQLite atômicas na tabela `container_expansion_checkpoints`:

```sql
SELECT parent_cn, state, expected_children, unpacked_children, completed_all_children, updated_at_utc
FROM container_expansion_checkpoints;
```

- **Contêineres já finalizados (`completed_all_children = 1` e `state = 'COMPLETED'`)**: não sofrem retrabalho desnecessário na retomada.
- **Contêineres interrompidos no meio (`completed_all_children = 0` ou `state = 'IN_PROGRESS'`)**: são detectados automaticamente por `verify_incomplete_parent_containers()`, têm seus resíduos parciais em `staging/` limpos de forma determinística e são reexpandidos integralmente para que nenhum filho deixe de ser extraído.

---

## 3. Recuperação de Desastres (*Disaster Recovery*) e Revalidação Fria

Ao encerrar a Fase 08, o adaptador `StagingCleanerAndBundleAdapter` gera dois artefatos críticos em `audit/`:
1. `audit/MANIFESTO_SHA256.txt`: lista ordenada `<sha256_hex>  <caminho_relativo>` cobrindo todos os entregáveis de `deliverables/`, os itens adquiridos em `vault/`, o catálogo `catalog/elo_forensic_catalog.sqlite`, `audit_ledger.jsonl` e `execution_manifest.json`.
2. `audit/elo_case_recovery.bundle`: manifesto JSON autocontido consolidando metadados de governança, lista de entregáveis e inventário criptográfico.

### Procedimento de Auditoria Pós-Incidente em Armazenamento Frio
```bash
# 1. Conferir integridade de 100% do workspace arquivado
PYTHONPATH=src python3 -m edrm.interfaces.cli verify --workspace /arquivo_frio/caso_001

# 2. Conferir encadeamento sequencial do razão imutável audit_ledger.jsonl
python3 -c '
import json, pathlib
lines = pathlib.Path("/arquivo_frio/caso_001/audit/audit_ledger.jsonl").read_text().splitlines()
for idx, raw in enumerate(lines, 1):
    rec = json.loads(raw)
    assert rec["seq"] == idx, f"Quebra de sequência na linha {idx}"
print(f"Razão íntegro: {len(lines)} eventos encadeados verificados.")
'
```

---

## 4. Rito de Sanitização Pós-Trânsito em Julgado (NIST SP 800-88 Rev. 2)

Enquanto perdurar a ação penal ou prazo recursal, o cofre `vault/` e os entregáveis `deliverables/` permanecem **estritamente preservados** (`post_judgment_nist=False`).

Somente após o trânsito em julgado certificado nos autos e determinação expressa de descarte (**CPP art. 158-B, X**), a política `PostJudgmentDispositionPolicy` permite emitir o Certificado **NIST SP 800-88 Rev. 2 (`PURGE_CRYPTOGRAPHIC_ERASE` / `CLEAR` / `DESTROY_VERIFIED`)** exigindo cumulativamente:
1. `execute_post_judgment_nist=True`;
2. `human_operator_name` preenchido com identificação civil/funcional do responsável;
3. `second_confirmation_phrase == "CONFIRMO_TRANSITO_EM_JULGADO_E_DESCARTE_DEFINITIVO"`.
