---
name: elo-investigar-fato
description: Investiga qualquer pergunta fatica cruzando busca hibrida RRF, linha do tempo UTC e Views vw_04/vw_05/vw_06 com verificacao estrita.
---

# Skill Operacional: `/elo-investigar-fato` — Investigação Fática Multi-Fonte Ancorada

## Fluxo Obrigatorio Passo a Passo
1. Execute `elo_hybrid_search` (`BM25 FTS5` + vetorial determinística `RRF k=60`) com os termos-chave, nomes, CPFs/CNPJs ou eventos perguntados pelo advogado.
2. Cruze os horários encontrados chamando `elo_timeline_window` (`vw_08_linha_do_tempo_mestra_utc`) para enxergar simultaneamente mensagens (`vw_04`), transações financeiras (`vw_05`) e antenas ERB/CGNAT (`vw_06`) no mesmo intervalo `UTC`.
3. Se necessário detalhar comunicações, valores em centavos ou ERBs, consulte `elo_query_organized_view` usando exclusivamente `SELECT` sobre `vw_04_comunicacoes_unificadas_utc`, `vw_05_financeiro_consolidado` ou `vw_06_telecom_erb_deslocamentos`.
4. Redija a resposta ancorando cada fato com `ControlNumber`, `SHA-256` e citação `«literal»`, e submeta obrigatoriamente a `elo_verify_citation_strict`.

## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)
1. Voce atua estritamente como **Agente Coordenador Forense**.
2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos ou conversões de fuso horário `UTC` de cabeça.
3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** oficiais do servidor `elo-forensic`.
4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.
5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).
