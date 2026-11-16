"""Instalador deterministico de configuracao `.mcp.json` e 6 Skills Operacionais de Agente (Delta v2.2)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

COORDINATOR_RULE_BLOCK: str = (
    "## Regra Inegociavel do Modelo Coordenador Forense (Software 1.0 Governando IA)\n"
    "1. Voce atua estritamente como **Agente Coordenador Forense**.\n"
    "2. **Jamais** abra bancos SQLite brutos manualmente, **jamais** escreva scripts Python/Bash improvisados "
    "para varrer mídias probatórias e **jamais** calcule hashes `SHA-256`, somas financeiras em centavos "
    "ou conversões de fuso horário `UTC` de cabeça.\n"
    "3. Delegue **100%** da leitura, busca híbrida `RRF`, janelas cronológicas e consultas SQL às **10 ferramentas MCP** "
    "oficiais do servidor `elo-forensic`.\n"
    "4. Toda citação probatória deve trazer `ControlNumber`, `SHA-256`, `locator` e trecho entre `«aspas angulares»`.\n"
    "5. Antes de entregar qualquer conclusão jurídica ou técnica ao advogado/perito, submeta o texto final "
    "obrigatoriamente à ferramenta `elo_verify_citation_strict` e só apresente se `passed == true` (`0` rejeições).\n"
)

OPERATIONAL_SKILLS_SPECS: tuple[tuple[str, str, str], ...] = (
    (
        "elo-plugar-hd",
        "Lista HDs montados via MCP, confirma HD de Prova (--source) e HD de Destino (--dest) separados e executa ingestao Autopilot ate publicar o Banco Organizado.",
        """# Skill Operacional: `/elo-plugar-hd` — Abertura Segura Cross-Disk (Zero Toque na Prova)

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
""",
    ),
    (
        "elo-panorama-caso",
        "Resume instantaneamente o Banco Organizado recem-criado no HD de destino (custodiantes, volume, provas sonegadas e alertas criticos).",
        """# Skill Operacional: `/elo-panorama-caso` — Radiografia Executiva Imediata do Caso

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_get_case_overview` informando o `dest_path` do caso organizado no segundo HD.
2. Chame `elo_audit_custody_and_parity` para levantar todas as divergências entre peças policiais/autos e os arquivos efetivamente entregues.
3. Consulte `elo_query_organized_view` sobre `vw_01_indice_geral_provas` (amostra inicial) para identificar custodiantes, tipos binários reais (*Magic Bytes*) e extensões camufladas.
4. Valide o resumo redigido em `elo_verify_citation_strict` antes de responder ao usuário.
""",
    ),
    (
        "elo-investigar-fato",
        "Investiga qualquer pergunta fatica cruzando busca hibrida RRF, linha do tempo UTC e Views vw_04/vw_05/vw_06 com verificacao estrita.",
        """# Skill Operacional: `/elo-investigar-fato` — Investigação Fática Multi-Fonte Ancorada

## Fluxo Obrigatorio Passo a Passo
1. Execute `elo_hybrid_search` (`BM25 FTS5` + vetorial determinística `RRF k=60`) com os termos-chave, nomes, CPFs/CNPJs ou eventos perguntados pelo advogado.
2. Cruze os horários encontrados chamando `elo_timeline_window` (`vw_08_linha_do_tempo_mestra_utc`) para enxergar simultaneamente mensagens (`vw_04`), transações financeiras (`vw_05`) e antenas ERB/CGNAT (`vw_06`) no mesmo intervalo `UTC`.
3. Se necessário detalhar comunicações, valores em centavos ou ERBs, consulte `elo_query_organized_view` usando exclusivamente `SELECT` sobre `vw_04_comunicacoes_unificadas_utc`, `vw_05_financeiro_consolidado` ou `vw_06_telecom_erb_deslocamentos`.
4. Redija a resposta ancorando cada fato com `ControlNumber`, `SHA-256` e citação `«literal»`, e submeta obrigatoriamente a `elo_verify_citation_strict`.
""",
    ),
    (
        "elo-auditar-custodia",
        "Audita os 10 passos do art. 158-B do CPP, POP Senasp Vol. 5 (2024), STF Tema 977 e casos .iped estatais sobre vw_02 e vw_03.",
        """# Skill Operacional: `/elo-auditar-custodia` — Auditoria Estrita da Cadeia de Custódia Digital

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_audit_custody_and_parity` para obter a totalidade de `vw_02_matriz_declarado_vs_entregue` e `vw_03_alertas_cadeia_custodia_e_pericia`.
2. Verifique sistematicamente:
   - **STF Tema 977 / Súmula Vinculante 14**: mídias ou extrações brutas declaradas nos autos mas ausentes ou entregues truncadas/criptografadas sem chave (`tema977_sonegado_flag = 1`);
   - **CPP arts. 158-A a 158-F & POP Senasp Vol. 5 (2024)**: divergências de numeração de lacre, ausência de hash `SHA-256` na apreensão, eventos com carimbo posterior à apreensão (`is_post_seizure = 1`) e artefatos `.lnk` com `MAC Address` externo;
   - **Auditoria Clean-Room `.iped`**: perfis omissivos (`fastmode`/`triage`), filtros seletivos (`filterKeywords`) ou `--downloadInternetData`.
3. Submeta o quadro técnico de nulidades a `elo_verify_citation_strict` antes da entrega.
""",
    ),
    (
        "elo-confrontar-laudo",
        "Confronta um laudo policial ou denuncia linha por linha contra o Banco Organizado apontando omissao de contexto, duplicidades SIMBA e erros ERB/SQLite.",
        """# Skill Operacional: `/elo-confrontar-laudo` — Confronto Analítico Acusação vs. Prova Bruta

## Fluxo Obrigatorio Passo a Passo
1. Para cada afirmação fática, trecho de diálogo, valor monetário ou localização atribuída pelo Laudo Pericial Estatal ou Denúncia, acione `elo_confront_allegation_vs_raw`.
2. Inspecione:
   - **Contexto Vizinho Omitido**: mensagens imediatamente anteriores e posteriores em `vw_04_comunicacoes_unificadas_utc` e distinção entre linha ativa (`ACTIVE_BTREE_ROW`) e fragmento não alocado recuperado (`CARVED_FREELIST`);
   - **Dupla Contagem Financeira**: lançamentos marcados com `is_inter_file_duplicate = 1` em `vw_05_financeiro_consolidado`;
   - **Impossibilidade Física de Telecom/CGNAT**: saltos de ERB com `impossible_speed_flag = 1` ou logs de IP compartilhado sem porta lógica (`cgnat_missing_port_flag = 1`) em `vw_06_telecom_erb_deslocamentos`.
3. Passe cada parágrafo da matriz de contradições por `elo_verify_citation_strict` garantindo zero erro material.
""",
    ),
    (
        "elo-parecer-e-quesitos",
        "Gera e audita quesitos periciais personalizados, parecer tecnico em 7 blocos e dossie HTML5 offline validados com zero alucinacao.",
        """# Skill Operacional: `/elo-parecer-e-quesitos` — Quesitos Estratégicos e Minuta Técnica Verificada

## Fluxo Obrigatorio Passo a Passo
1. Chame `elo_generate_deliverables` e `elo_audit_custody_and_parity` para inspecionar os artefatos já selados em `03_RELATORIOS_E_DOSSIE/` e todos os vícios materiais catalogados no caso.
2. Estruture os quesitos suplementares ou a minuta pericial vinculando cada pergunta técnica a uma anomalia real comprovada nas Views (`vw_02`, `vw_03`, `vw_04`, `vw_05`, `vw_06`).
3. Execute `elo_verify_citation_strict` sobre a íntegra da minuta produzida: somente entregue ao advogado quando `passed == true` e `rejected_reasons` estiver vazio.
""",
    ),
)


class SkillsAndMcpInstaller:
    """Materializa `.mcp.json` e as 6 Skills Operacionais em `.claude/skills/` e `.opencode/skills/`."""

    @classmethod
    def install_into_directory(
        cls,
        target_root: Path,
        platform_repo_root: Path | None = None,
        python_executable: str | None = None,
    ) -> dict[str, object]:
        """Grava `.mcp.json` e os 12 arquivos `SKILL.md` (6 Claude Code + 6 OpenCode) com verificacao SHA-256."""
        resolved_target = target_root.resolve()
        resolved_target.mkdir(parents=True, exist_ok=True)

        repo_root = (
            platform_repo_root.resolve()
            if platform_repo_root is not None
            else Path(__file__).resolve().parents[3]
        )
        src_dir = repo_root / "src"
        py_cmd = python_executable if python_executable else sys.executable

        mcp_config = {
            "mcpServers": {
                "elo-forensic": {
                    "command": py_cmd,
                    "args": ["-m", "edrm.interfaces.cli", "mcp-serve"],
                    "env": {
                        "PYTHONPATH": str(src_dir),
                        "PYTHONHASHSEED": "42",
                    },
                }
            }
        }
        mcp_json_path = resolved_target / ".mcp.json"
        cls._write_fsync(
            mcp_json_path,
            json.dumps(mcp_config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

        opencode_config = {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                "elo-forensic": {
                    "type": "local",
                    "command": [py_cmd, "-m", "edrm.interfaces.cli", "mcp-serve"],
                    "environment": {
                        "PYTHONPATH": str(src_dir),
                        "PYTHONHASHSEED": "42",
                    },
                    "enabled": True,
                }
            },
        }
        opencode_json_path = resolved_target / "opencode.json"
        cls._write_fsync(
            opencode_json_path,
            json.dumps(opencode_config, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )

        claude_skills_created: list[str] = []
        opencode_skills_created: list[str] = []
        hashes: dict[str, str] = {}

        for skill_name, skill_desc, skill_body in OPERATIONAL_SKILLS_SPECS:
            rendered = cls._render_skill_markdown(skill_name, skill_desc, skill_body)

            claude_file = resolved_target / ".claude" / "skills" / skill_name / "SKILL.md"
            cls._write_fsync(claude_file, rendered)
            claude_skills_created.append(str(claude_file))
            hashes[claude_file.relative_to(resolved_target).as_posix()] = hashlib.sha256(
                claude_file.read_bytes()
            ).hexdigest()

            opencode_file = resolved_target / ".opencode" / "skills" / skill_name / "SKILL.md"
            cls._write_fsync(opencode_file, rendered)
            opencode_skills_created.append(str(opencode_file))
            hashes[opencode_file.relative_to(resolved_target).as_posix()] = hashlib.sha256(
                opencode_file.read_bytes()
            ).hexdigest()

        hashes[".mcp.json"] = hashlib.sha256(mcp_json_path.read_bytes()).hexdigest()
        hashes["opencode.json"] = hashlib.sha256(opencode_json_path.read_bytes()).hexdigest()

        return {
            "target_root": str(resolved_target),
            "mcp_json_path": str(mcp_json_path),
            "opencode_json_path": str(opencode_json_path),
            "skills_names": [s[0] for s in OPERATIONAL_SKILLS_SPECS],
            "claude_skills_files": claude_skills_created,
            "opencode_skills_files": opencode_skills_created,
            "sha256_manifest": hashes,
        }

    @staticmethod
    def _render_skill_markdown(name: str, description: str, body: str) -> str:
        frontmatter = (
            "---\n"
            f"name: {name}\n"
            f"description: {description}\n"
            "---\n\n"
        )
        return frontmatter + body.strip() + "\n\n" + COORDINATOR_RULE_BLOCK

    @staticmethod
    def _write_fsync(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
