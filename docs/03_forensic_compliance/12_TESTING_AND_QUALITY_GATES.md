# 12 — Engenharia de Testes, Estatística Forense e Portões de Qualidade (`G0` a `G11`)

A plataforma **ELO** substitui revisões manuais subjetivas por um pipeline determinístico de **12 Portões Forenses Bloqueantes (`G0` a `G11`)** orquestrados por `tools/run_forensic_gates.py`. Qualquer falha em qualquer portão resulta imediatamente em `EXIT CODE 1`.

---

## 1. Fundamentos Matemáticos de Calibração, Verificação e Amostragem

### 1.1 Auto-Calibração ISO/IEC 27041 (`SelfCalibrationSuite` — Portão `G2`)
Conforme a **ISO/IEC 27041:2015**, o instrumento de verificação deve provar que está funcionando corretamente **antes** de avaliar evidências reais. A suíte injeta três vetores sintéticos fixos no `BlockingVerifierEngine`:
1. **Controle Positivo (`positive_control_passed`)**: Afirmação fielmente ancorada em `ELO-CAL-0001` com valor exato `150000` e hash real $\rightarrow$ **DEVE APROVAR**.
2. **Controle Negativo 1 — Mutação Numérica (`negative_numeric_mutation_blocked`)**: Afirmação alterando um único algarismo (`150000` $\rightarrow$ `150001`) mantendo a âncora válida $\rightarrow$ **DEVE BLOQUEAR**.
3. **Controle Negativo 2 — Entidade/Âncora Fantasma (`negative_phantom_entity_blocked`)**: Afirmação citando `ControlNumber` ou `SHA-256` inexistente no corpus $\rightarrow$ **DEVE BLOQUEAR**.

Se qualquer um dos três controles falhar, `CalibrateToolsUseCase` lança `VerifierCalibrationError` e impede a inicialização do caso.

### 1.2 Amostragem Estratificada Finita de Cochran (`CochranFiniteSampler` — Fases 01 e 05)
- **Estrato Crítico (`100%` de Inspeção)**: Todo vestígio com divergência de hash, omissão de mídia bruta, acesso pós-apreensão ou anomalia de lacre é auditado em **100%** (zero erro amostral para anomalias críticas).
- **Estrato Não-Crítico (População Finita $N$)**: Aplica-se a fórmula clássica de Cochran calculada inteiramente em `decimal.Decimal` ($Z = 1{,}96$ para 95% de confiança, $p = 0{,}5$ máxima variância conservadora, margem $e = 0{,}10$):
  $$n_0 = \frac{Z^2 \cdot p \cdot (1 - p)}{e^2}, \qquad n = \left\lceil \frac{n_0}{1 + \frac{n_0 - 1}{N}} \right\rceil$$
  A seleção dos itens usa gerador determinístico inicializado com semente inteira fixa (`random_seed = 42`), garantindo reprodutibilidade exata da amostra por outro perito.

### 1.3 Teste de Elusão e Regra do 3 de Hanley & Lippman-Hand ($3/n$ — Fase 05)
Sobre o conjunto descartado/não selecionado na revisão (`elusion_inspected_n = n` itens inspecionados), quando **zero erros (`0` falsos negativos)** são observados, o limite superior do intervalo de confiança de 95% para a taxa residual de omissão é dado pela **Regra do 3** (*Hanley & Lippman-Hand, JAMA 1983*):
$$\text{Limite Superior}_{95\%} = \frac{3}{n}$$
Calculado em `Decimal` por `CochranElusionRuleOf3Qc` e gravado em `QualityControlSummary`.

### 1.4 Testes de Equivalência de Substituição de Liskov (`LSP` — Portão `G8`)
Para provar que os testes rápidos em memória refletem fielmente o mundo físico, `tests/contract/__init__.py` executa **exatamente os mesmos cenários e asserções** contra pares de implementações:
1. `InMemoryWorkspaceProvisionerFake` $\equiv$ `FsWorkspaceProvisionerAdapter`
2. `InMemoryAuditLedgerFake` $\equiv$ `AppendOnlyLedgerAdapter`
3. `InMemoryVerifiedVaultCopierFake` $\equiv$ `FsyncColdVerifyCopierAdapter`
4. `InMemoryHybridSearchIndexFake` $\equiv$ `SqliteFtsVectorStoreAdapter`

---

## 2. Catálogo Completo dos 12 Portões Forenses (`G0` a `G11`)

Execute a bateria completa com:
```bash
PYTHONPATH=src:. PYTHONHASHSEED=42 python3 tools/run_forensic_gates.py
```

| Portão | Título Oficial | O Que é Verificado Empiricamente | Arquivo de Teste |
| :--- | :--- | :--- | :--- |
| **`G0`** | Higiene Sintática e Zero Placeholders | Varre a AST e linhas de 100% dos arquivos `.py` exigindo `0` ocorrências de `TODO`, `FIXME`, `pass` concreto, `...` concreto ou `NotImplementedError`. | `tests/architecture/__init__.py` |
| **`G1`** | Clean Architecture, Hexagonal, SOLID, Zero Float & NIST SSDF | Audita pureza de `shared_kernel`/`domain`/`application` (zero I/O), zero imports cruzados entre fases, portas `Protocol` (1–3 métodos), `@dataclass(frozen=True, slots=True)`, zero `float`/`hash()` e bloqueios AST **NIST SSDF v1.1**. | `tests/architecture/__init__.py` |
| **`G2`** | Auto-Calibração ISO/IEC 27041 | Valida os 3 controles (1 positivo + 2 negativos) de `SelfCalibrationSuite` e assinatura `SHA-256` do `CalibrationReceipt`. | `tests/unit/__init__.py` |
| **`G3`** | Camada 00 (IGRM v4.1) & Fase 01 (Identificação) | Testa `FsWriteBlockerGuard` (`ReadOnlyViolationError`), bloqueio de sockets externos, sobreposição de workspace, 16 *Magic Bytes*, *extension spoofing*, Matriz de Paridade em 7 estados e Cochran. | `tests/unit/__init__.py` |
| **`G4`** | Fase 02 (Preservação) & Fase 03 (Coleta Fria) | Testa saúde SQLite imutável (`mode=ro&immutable=1` + frames `-wal`), detecção de homógrafos em lacres, cópia com `os.fsync` + releitura fria `SHA-256` e auditoria da coleta estatal. | `tests/unit/__init__.py` |
| **`G5`** | Fase 04 (Processamento Universal) | Testa piso funcional EDRM 1.0–5.0, bloqueio de *Zip-Bomb* e *Path Traversal*, De-NIST somente no pai, deduplicação lógica global, épocas `1970`/`2001`/`1904`, SIMBA em `BIGINT` centavos, CDR/ERB, CGNAT e realimentação `04 -> 01`. | `tests/unit/__init__.py` |
| **`G6`** | Análise Contínua & Fase 05 (Revisão) | Testa fusão híbrida `RRF (k=60)`, `PromptInjectionShield`, `BlockingVerifierEngine`, escudo de sigilo OAB, detector de contradições materiais e Regra do 3 ($3/n$). | `tests/unit/__init__.py` |
| **`G7`** | Fases 06, 07 e 08 (Produção, Apresentação e Destinação) | Testa Parecer em 7 Blocos com dupla passagem `0` erros, *Load Files* `.dat`/`.xml`, Quesitos POP Senasp 2024, Dossiê HTML5 Offline, expurgo de `staging/` e dupla confirmação **NIST SP 800-88 Rev. 2**. | `tests/unit/__init__.py` |
| **`G8`** | Princípio de Substituição de Liskov (`LSP`) | Comprova comportamento idêntico entre dublês `InMemory*Fake` e adaptadores físicos de disco/SQLite. | `tests/contract/__init__.py` |
| **`G9`** | Instalador Autocontido Verificado (`SHA-256`) | Executa `materialize_elo_platform.py --target <tmp> --verify` em diretório temporário limpo e confere `SHA-256` a frio de todos os módulos instalados. | `tools/run_forensic_gates.py` |
| **`G10`** | E2E Plug-and-Analyze em HD Sintético Desconhecido | Materializa um HD forense complexo (peças primárias, `.zip` aninhado com nova FAV disparando `Rev 2`, SQLite com `-wal` e extensão falsa `.jpg`, SIMBA duplicado, ERB com salto impossível, CGNAT sem porta), roda `00 -> 08` e comprova `PreScanSnapshot == PostScanSnapshot`. | `tests/e2e_synthetic/__init__.py` |
| **`G11`** | Evolução Delta v2.1 (IPED Clean-Room & NIST SSDF v1.1) | Subdividido em 5 baterias: `G11.1` (NIST SSDF + `127.0.0.1` `X-ELO-Session-Token` + sandbox `finally`), `G11.2` (`.iped` 16 shards GZIP RO + `StateIpedCaseAuditor` + Quesitos), `G11.3` (sonda *permille* $64\text{ KiB}$ sem `float` + validadores CPF/CNPJ/TSE/Boleto/DANFE/Luhn/BTC/ETH/BIP-39), `G11.4` (filas $P_0 \rightarrow P_4$ + checkpoint de contêineres + carving Aho-Corasick na fronteira de $1\text{ MiB}$ + cache áudio `SHA-256` + WhatsApp `@lid`/*view-once*), `G11.5` (SQLite `freelist`/`-wal` NIST IR 8354 + `.lnk` `DroidBirth MAC` + `CompressedRoaringBitset` + `ExactMetricSimilarity`). | `tests/unit/test_g11_v21.py` |

---

## 3. Saída JSON Auditável dos Portões (`--json`)

Para integração em pipelines CI/CD ou no Console Web:
```bash
PYTHONPATH=src:. PYTHONHASHSEED=42 python3 tools/run_forensic_gates.py --json
```
Retorna estrutura determinística com `all_passed: true`, `exit_code: 0` e métricas individuais `elapsed_ms` e `detail` para cada um dos 12 portões `G0`..`G11`.
