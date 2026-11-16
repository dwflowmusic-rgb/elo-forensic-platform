# ELO — Constituição Arquitetural (EDRM 2.0 Greenfield)

## 1. Missão e Paradigma Plug-and-Analyze
A plataforma **ELO** opera em modo 100% *Plug-and-Analyze*: recebe mídias probatórias brutas em `--source` (protegidas por `SourceWriteBlockerGuard`) e um diretório limpo `--workspace` (isolado nas 5 zonas `vault/`, `staging/`, `catalog/`, `deliverables/`, `audit/`).

## 2. Regras Arquiteturais Inegociáveis (Auditadas em G0–G10)
1. **Clean Architecture & Hexagonal (Ports & Adapters)**:
   - `domain/` e `application/` são 100% puros (zero imports de `os`, `sys`, `shutil`, `glob`, `subprocess`, `sqlite3`, `psycopg`, `zipfile`, `tarfile`, `socket`, `http`, `urllib`, `requests`).
   - Isolamento estrito entre fases (`igrm_governance`, `phase01_identification` a `phase08_disposition` e `continuous_analysis`): zero imports cruzados. Transições ocorrem exclusivamente via contratos imutáveis em `edrm.shared_kernel.contracts`, conectados em `edrm.bootstrap.container`.
2. **SOLID Enterprise**:
   - Portas segregadas via `typing.Protocol` (1 a 3 métodos coesos).
   - Entidades, objetos de valor e contratos imutáveis com `@dataclass(frozen=True, slots=True)`.
   - Registros extensíveis (`SignatureRegistry`, `ExtractorRegistry`) para formatos inéditos.
3. **8 Pilares Periciais Determinísticos**:
   - Zero ponto flutuante para dinheiro, bytes ou coordenadas (`int`/`BIGINT` em centavos e micrograus; `Decimal` para cálculos estatísticos).
   - Zero `hash()` volátil do Python; uso exclusivo de `hashlib.sha256`.
   - Bancos SQLite probatórios abertos exclusivamente com `file:...?mode=ro&immutable=1` e `PRAGMA query_only = 1;`.
   - Conferência matemática obrigatória `PreScanSnapshot == PostScanSnapshot`.
   - Auto-calibração prévia ISO/IEC 27041 (1 controle positivo + 2 controles negativos) e Verificador Determinístico Bloqueante com 0 falhas.

## 3. Execução e Homologação
- Portões forenses G0 a G10: `python3 tools/run_forensic_gates.py`
- CLI unificada: `PYTHONPATH=src python3 -m edrm.interfaces.cli plug-and-run-all --source <midia> --workspace <caso>`
- Materializador verificado por SHA-256: `python3 materialize_elo_platform.py --target <destino> --verify`
