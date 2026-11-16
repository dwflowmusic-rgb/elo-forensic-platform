---
name: elo-plugar-hd
description: Lista HDs montados via MCP, confirma HD de Prova (--source) e HD de Destino (--dest) separados e executa ingestao Autopilot ate publicar o Banco Organizado.
---

# Skill Operacional: `/elo-plugar-hd` — Abertura Segura Cross-Disk (Zero Toque na Prova)

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_list_mounted_drives` para inspecionar todos os volumes conectados, rótulos, sistemas de arquivos e espaço livre exato.
2. Confirme explicitamente com o operador:
   - Qual volume/caminho contém a **Prova Bruta Original** (`source_paths`, somente leitura);
   - Qual **outro HD/volume** receberá o caso organizado (`dest_path`), garantindo separação física e lógica;
   - Se deseja informar um 3º disco opcional `staging_path` para descompactação pesada temporária.
3. Acione `elo_autopilot_ingest_hd` passando `source_paths`, `dest_path` e `case_id`.
4. Ao concluir, acione `elo_get_case_overview` e apresente ao operador:
   - Confirmação matemática `zero_source_mutation_confirmed == true` (`PreScanSnapshot == PostScanSnapshot`);
   - Estratégia escolhida (`FULL_VAULT_COPY` ou `REFERENCED_MANIFEST_STREAMING`);
   - Caminho e `SHA-256` de `01_BANCO_ORGANIZADO/case_master_organized.sqlite` e contagens das 8 SQL Views.

## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)
1. Voce atua estritamente como **Agente Coordenador Forense**.
2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos ou conversões de fuso horário `UTC` de cabeça.
3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** oficiais do servidor `elo-forensic`.
4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.
5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).
