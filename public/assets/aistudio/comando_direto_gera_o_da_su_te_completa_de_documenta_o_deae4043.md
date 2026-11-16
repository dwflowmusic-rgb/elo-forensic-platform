# COMANDO PARA O GOOGLE AI STUDIO — GERAÇÃO DA DOCUMENTAÇÃO COMPLETA DO SISTEMA

Copie e cole o bloco abaixo na mesma conversa do **Google AI Studio** onde o programa foi concluído:

```text
O código do sistema está concluído. Agora atue como Staff Technical Writer, Principal Software Architect e Perito Forense Digital para gerar a **SUÍTE COMPLETA DE DOCUMENTAÇÃO ENTERPRISE** do projeto.

### DIRETRIZES DE EXECUÇÃO
1. **FONTE ÚNICA DA VERDADE = CÓDIGO REAL:** Antes de escrever, inspecione na sua Sandbox todos os pacotes, classes, schemas SQL, contratos, validadores, comandos CLI e portões de teste que você realmente implementou. Documente com 100% de fidelidade ao código existente (zero comandos fictícios, zero placeholders, zero resumos superficiais).
2. **QUALIDADE VISUAL E TÉCNICA:** Escreva documentação clara, densa e profissional em Markdown estruturado, incluindo diagramas `Mermaid` reais (arquitetura, fluxo das fases, sequência e banco de dados), tabelas de referência e exemplos reais de execução.
3. **ENTREGA SEM CORTES + EMPACOTADOR:** Gere todos os documentos completos e crie um script `materialize_docs.py` (com verificação `SHA-256`) que recrie automaticamente toda a pasta `docs/` mais os arquivos da raiz no meu ambiente local. Se o limite de tokens de saída exigir, divida em 2 partes completas sem abreviar nenhum arquivo.

---

### LISTA COMPLETA DE DOCUMENTOS PARA ANALISAR E GERAR

#### A. Raiz do Repositório
1. `README.md` — Porta de entrada completa do projeto (visão geral *Plug-and-Analyze*, diferenciais, requisitos, instalação rápida, comandos principais, estrutura de pastas e links para toda a documentação).
2. `CHANGELOG.md` — Histórico estruturado de versões, ondas implementadas e evoluções incorporadas.

#### B. Produto, Visão e Planejamento (`docs/01_product/`)
3. `01_PROJECT_CHARTER.md` — Termo de Abertura (justificativa, objetivos, limites inegociáveis, governança e partes envolvidas).
4. `02_EXECUTIVE_BRIEFING.md` — Briefing completo (a dor real na prova digital, o problema resolvido, como o sistema opera hoje e resultados entregues).
5. `03_PRD.md` — *Product Requirements Document* completo (escopo funcional de ponta a ponta das fases `00` a `08`, requisitos não-funcionais, regras de negócio, fluxos de usuário e fora de escopo).
6. `04_ROADMAP_AND_BACKLOG.md` — Roadmap estratégico de evolução (curto, médio e longo prazo: integrações, escala industrial, GPU/IA local, novos parsers, interface visual) e Backlog técnico priorizado.
7. `05_ACCEPTANCE_CRITERIA.md` — Matriz de Critérios de Aceite (*Definition of Done*) mapeada diretamente para cada módulo e para os portões automáticos de teste.

#### C. Engenharia, Blueprint e Dados (`docs/02_architecture/`)
8. `06_SYSTEM_BLUEPRINT.md` — Blueprint Arquitetural Completo (Clean Architecture, Hexagonal Ports & Adapters, SOLID, isolamento entre fases, diagramas C4/componentes/fluxo de dados em Mermaid).
9. `07_DATA_MODEL_AND_CONTRACTS.md` — Dicionário de Dados completo, diagramas ER, todas as tabelas SQLite/shards e todos os Contratos Imutáveis de Transição entre Fases.
10. `08_ADR_CATALOG.md` — Catálogo de *Architecture Decision Records* documentando o porquê das principais decisões técnicas adotadas no código.
11. `09_CLI_AND_API_REFERENCE.md` — Manual técnico exato de todos os comandos CLI, argumentos, flags, variáveis de configuração, códigos de retorno e endpoints da API local (`127.0.0.1`).

#### D. Metodologia Forense, Segurança e Qualidade (`docs/03_forensic_compliance/`)
12. `10_FORENSIC_METHODOLOGY_GUIDE.md` — Fundamentação Metodológica e Jurídico-Pericial (mapeamento de cada fase do software para o EDRM 2.0, IGRM v4.1, ISO/IEC 27037/27041/27042, NIST SP 800-88 Rev. 2, cadeia de custódia do CPP e POP Senasp Vol. 5 — 2024).
13. `11_SECURITY_AND_COMPLIANCE.md` — Arquitetura de Segurança, *Threat Model*, bloqueio físico/lógico de escrita na prova, NIST SSDF v1.1, defesa contra *Prompt Injection* e conformidade de sigilo (CNJ e CFOAB).
14. `12_TESTING_AND_QUALITY_GATES.md` — Estratégia de Testes, Auto-Calibração, funcionamento do Verificador Determinístico Bloqueante, Amostragem Estatística (Cochran/Elusão/Regra do 3) e guia dos portões `run_forensic_gates.py`.

#### E. Operação, Uso Prático e Expansão (`docs/04_operations/`)
15. `13_OPERATOR_PLAYBOOK.md` — Guia Prático Passo a Passo de Uso Real (do momento de plugar um HD bruto desconhecido até a emissão dos relatórios, parecer pericial em 7 blocos, quesitos e dossiê HTML5 *offline*).
16. `14_RUNBOOK_AND_RECOVERY.md` — Runbook de Produção, retomada após interrupção/queda de energia, leitura da fila de exceções (`DeadLetterStore`), auditoria *Antes vs. Depois* e restauração de backup (`git bundle`).
17. `15_DEVELOPER_EXTENSION_GUIDE.md` — Guia de Manutenção e Extensão (como criar novos extratores, assinaturas binárias e validadores sem quebrar a arquitetura nem os testes AST).
18. `docs/INDEX.md` — Sumário central navegável organizando todos os 17 documentos por perfil de leitura (Advogado/Perito, Operador, Arquiteto/Desenvolvedor e Auditor Externo).

Inspecione o código na Sandbox agora, gere toda a documentação completa acima, valide na Sandbox que todos os arquivos foram gravados e verificados com sucesso e me entregue tudo junto com o `materialize_docs.py`.
```