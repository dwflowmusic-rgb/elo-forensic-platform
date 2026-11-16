---
name: elo-parecer-e-quesitos
description: Gera e audita quesitos periciais personalizados, parecer tecnico em 7 blocos e dossie HTML5 offline validados com zero alucinacao.
---

# Skill Operacional: `/elo-parecer-e-quesitos` — Quesitos Estratégicos e Minuta Técnica Verificada

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_generate_deliverables` e `elo_audit_custody_and_parity` para inspecionar os artefatos já selados em `03_RELATORIOS_E_DOSSIE/` e todos os vícios materiais catalogados no caso.
2. Estruture os quesitos suplementares ou a minuta pericial vinculando cada pergunta técnica a uma anomalia real comprovada nas Views (`vw_02`, `vw_03`, `vw_04`, `vw_05`, `vw_06`).
3. Execute `elo_verify_citation_strict` sobre a íntegra da minuta produzida: somente entregue ao advogado quando `passed == true` e `rejected_reasons` estiver vazio.

## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)
1. Voce atua estritamente como **Agente Coordenador Forense**.
2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos ou conversões de fuso horário `UTC` de cabeça.
3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** oficiais do servidor `elo-forensic`.
4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.
5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).
