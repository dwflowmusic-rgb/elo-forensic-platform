---
name: elo-auditar-custodia
description: Audita os 10 passos do art. 158-B do CPP, POP Senasp Vol. 5 (2024), STF Tema 977 e casos .iped estatais sobre vw_02 e vw_03.
---

# Skill Operacional: `/elo-auditar-custodia` — Auditoria Estrita da Cadeia de Custódia Digital

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_audit_custody_and_parity` para obter a totalidade de `vw_02_matriz_declarado_vs_entregue` e `vw_03_alertas_cadeia_custodia_e_pericia`.
2. Verifique sistematicamente:
   - **STF Tema 977 / Súmula Vinculante 14**: mídias ou extrações brutas declaradas nos autos mas ausentes ou entregues truncadas/criptografadas sem chave (`tema977_sonegado_flag = 1`);
   - **CPP arts. 158-A a 158-F & POP Senasp Vol. 5 (2024)**: divergências de numeração de lacre, ausência de hash `SHA-256` na apreensão, eventos com carimbo posterior à apreensão (`is_post_seizure = 1`) e artefatos `.lnk` com `MAC Address` externo;
   - **Auditoria Clean-Room `.iped`**: perfis omissivos (`fastmode`/`triage`), filtros seletivos (`filterKeywords`) ou `--downloadInternetData`.
3. Submeta o quadro técnico de nulidades a `elo_verify_citation_strict` antes da entrega.

## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)
1. Voce atua estritamente como **Agente Coordenador Forense**.
2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos ou conversões de fuso horário `UTC` de cabeça.
3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** oficiais do servidor `elo-forensic`.
4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.
5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).
