---
name: elo-confrontar-laudo
description: Confronta um laudo policial ou denuncia linha por linha contra o Banco Organizado apontando omissao de contexto, duplicidades SIMBA e erros ERB/SQLite.
---

# Skill Operacional: `/elo-confrontar-laudo` — Confronto Analítico Acusação vs. Prova Bruta

## Fluxo Obrigatorio Passo a Passo
1. Para cada afirmação fática, trecho de diálogo, valor monetário ou localização atribuída pelo Laudo Pericial Estatal ou Denúncia, acione `elo_confront_allegation_vs_raw`.
2. Inspecione:
   - **Contexto Vizinho Omitido**: mensagens imediatamente anteriores e posteriores em `vw_04_comunicacoes_unificadas_utc` e distinção entre linha ativa (`ACTIVE_BTREE_ROW`) e fragmento não alocado recuperado (`CARVED_FREELIST`);
   - **Dupla Contagem Financeira**: lançamentos marcados com `is_inter_file_duplicate = 1` em `vw_05_financeiro_consolidado`;
   - **Impossibilidade Física de Telecom/CGNAT**: saltos de ERB com `impossible_speed_flag = 1` ou logs de IP compartilhado sem porta lógica (`cgnat_missing_port_flag = 1`) em `vw_06_telecom_erb_deslocamentos`.
3. Passe cada parágrafo da matriz de contradições por `elo_verify_citation_strict` garantindo zero erro material.

## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)
1. Voce atua estritamente como **Agente Coordenador Forense**.
2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos ou conversões de fuso horário `UTC` de cabeça.
3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** oficiais do servidor `elo-forensic`.
4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.
5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).
