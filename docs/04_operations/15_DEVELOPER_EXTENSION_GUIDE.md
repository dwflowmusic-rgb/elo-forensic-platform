# 15 — Guia de Extensão para Engenheiros (Developer Extension Guide)

A plataforma **ELO** foi projetada sob o **Princípio Aberto/Fechado (`Open/Closed Principle — OCP`)**: novos formatos de arquivos binários, novos extratores forenses e novos adaptadores de infraestrutura são incorporados por registro declarativo, **sem alterar casos de uso prontos** e mantendo 100% de aprovação nos portões `G0` a `G11`.

---

## 1. Regras Inegociáveis antes de Escrever Qualquer Linha de Código

Qualquer novo módulo em `src/edrm/` será inspecionado automaticamente pela árvore sintática (`AST`) nos portões `G0` e `G1`. Siga rigorosamente estas 6 leis:

1. **Zero I/O em `shared_kernel/`, `domain/` e `application/`**: Jamais importe `os`, `sys`, `shutil`, `glob`, `subprocess`, `sqlite3`, `psycopg`, `zipfile`, `tarfile`, `socket`, `http`, `urllib` ou `requests` fora de `infrastructure/`, `bootstrap/` ou `interfaces/`.
2. **Zero Imports Cruzados entre Fases**: Um módulo em `phase04_processing` nunca importa `phase01_identification` ou `continuous_analysis`. Se precisar trafegar novos dados entre fases, adicione um campo opcional com valor padrão imutável (`tuple = ()` ou `None`) no contrato correspondente em `edrm.shared_kernel.contracts`.
3. **Imutabilidade Total**: Toda classe de dados ou contrato deve usar `@dataclass(frozen=True, slots=True)` e tuplas imutáveis `tuple[..., ...]` em vez de `list` ou `dict` mutáveis.
4. **Portas Segregadas (`ISP`)**: Toda porta em `application/` deve herdar de `typing.Protocol` e conter no máximo **1 a 3 métodos coesos**.
5. **Zero `float` e Zero `hash()` Volátil**: Use `int` (`ByteSize`, `CentsAmount`, `MicroDegreesCoord`, *permille* $0..1000$), `Decimal` para estatísticas/distâncias e `hashlib.sha256` para hashes.
6. **Zero Placeholders e Segurança NIST SSDF v1.1**: Nunca escreva `TODO`, `FIXME`, `pass` em classe concreta, `...` fora de `Protocol`, nem utilize `pickle`, `marshal`, `shelve`, `eval`, `exec`, `shell=True` ou `verify=False`.

---

## 2. Como Registrar uma Nova Assinatura Binária (`SignatureRegistry` — Fase 01)

A classe `SignatureRegistry` (`src/edrm/phase01_identification/domain/__init__.py`) avalia regras determinísticas `SignatureRule` sobre o cabeçalho em bytes do arquivo sondado.

### Passo 1: Adicionar o membro em `MagicSignature` (`src/edrm/shared_kernel/enums.py`)
```python
class MagicSignature(ForensicEnum):
    # ... membros existentes ...
    WINDOWS_EVTX_LOG = "WINDOWS_EVTX_LOG"
```

### Passo 2: Registrar a `SignatureRule` em `SignatureRegistry`
```python
from edrm.phase01_identification.domain import SignatureRegistry, SignatureRule
from edrm.shared_kernel.enums import MagicSignature

registry = SignatureRegistry()
registry.register(
    SignatureRule(
        signature=MagicSignature.WINDOWS_EVTX_LOG,
        offset=0,
        magic_bytes=b"ElfFile\x00",
        expected_extensions=(".evtx",),
    )
)
```
Automaticamente, qualquer arquivo cujo cabeçalho comece com `b"ElfFile\x00"` mas tenha extensão `.txt` ou `.jpg` será sinalizado com `extension_spoofed=True` na Fase 01, sem modificar `ExecutePhase01IdentificationUseCase`!

---

## 3. Como Criar e Pluguar um Novo Extrator Forense (`ExtractorRegistry` — Fase 04)

Na Fase 04, parsers puros vivem em `src/edrm/phase04_processing/domain/` (operando apenas sobre `bytes` ou `str`), enquanto a leitura somente leitura do arquivo em disco fica isolada em `src/edrm/phase04_processing/infrastructure/`.

### Passo 1: Escrever o Parser Puro em `domain/` (100% Testável em Memória)
```python
from dataclasses import dataclass
from edrm.shared_kernel.contracts import AnchoredTextChunk
from edrm.shared_kernel.value_objects import sha256_text


@dataclass(frozen=True, slots=True)
class EvtxParsedSummary:
    """Resumo imutavel de cabecalho Windows EVTX decodificado em memoria."""

    chunk_count: int
    next_record_id: int


def parse_evtx_header_bytes(raw_header: bytes, origin_cn: str, origin_path: str, origin_sha256: str) -> AnchoredTextChunk | None:
    """Decodifica os primeiros 48 bytes de um log binario Windows .evtx sem I/O."""
    if len(raw_header) < 48 or raw_header[:8] != b"ElfFile\x00":
        return None
    next_record_id = int.from_bytes(raw_header[24:32], "little", signed=False)
    chunk_count = int.from_bytes(raw_header[42:44], "little", signed=False)
    summary_text = f"EVTX next_record_id={next_record_id} chunk_count={chunk_count}"
    return AnchoredTextChunk(
        chunk_id=f"CHK-{sha256_text(origin_cn + summary_text)[:12]}",
        origin_cn=origin_cn,
        origin_path=origin_path,
        locator="evtx:header:0..48",
        text_clean=summary_text,
        injection_neutralized=False,
        origin_sha256=origin_sha256,
    )
```

### Passo 2: Registrar no `ExtractorRegistry`
```python
from edrm.phase04_processing.domain import ExtractorRegistry, RegisteredExtractorSpec
from edrm.shared_kernel.enums import MagicSignature

extractor_registry = ExtractorRegistry()
extractor_registry.register(
    RegisteredExtractorSpec(
        name="windows_evtx_header_extractor",
        supported_signatures=(MagicSignature.WINDOWS_EVTX_LOG,),
        supported_extensions=(".evtx",),
    )
)
```

---

## 4. Como Implementar um Novo Adaptador Respeitando Liskov (`LSP`)

Sempre que criar uma nova porta `typing.Protocol` em `application/` ou um novo adaptador físico em `infrastructure/`:
1. Crie o dublê determinístico correspondente `InMemory*Fake` em `tests/fakes/__init__.py`.
2. Adicione uma função de contrato compartilhada em `tests/contract/__init__.py` que receba a interface `Protocol` abstrata e execute exatamente as mesmas chamadas contra o `InMemory*Fake` e contra o adaptador físico real (usando `tempfile.TemporaryDirectory()`).
3. Conecte o adaptador concreto exclusivamente em `src/edrm/bootstrap/container.py` (`EloForensicContainer`).

---

## 5. Ciclo Obrigatório de Validação Local antes de Concluir

Após qualquer extensão de código ou documentação, execute os quatro comandos de homologação na ordem abaixo:

```bash
# 1. Sincronizar instaladores autocontidos (código e documentação)
python3 tools/sync_installer_payload.py
python3 tools/sync_docs_payload.py

# 2. Rodar todos os 12 Portões Forenses (G0 a G11) — exige EXIT CODE 0
PYTHONPATH=src:. PYTHONHASHSEED=42 python3 tools/run_forensic_gates.py

# 3. Verificar desempacotamento limpo a frio dos instaladores
python3 materialize_elo_platform.py --target /tmp/verify_elo_code --verify && rm -rf /tmp/verify_elo_code
python3 materialize_docs.py --target /tmp/verify_elo_docs --verify && rm -rf /tmp/verify_elo_docs

# 4. Validar testes unitários e tipagem do Console Web
npx --yes tsx --test src/utils/forensicModel.test.ts
npm run lint && npm run build
```
