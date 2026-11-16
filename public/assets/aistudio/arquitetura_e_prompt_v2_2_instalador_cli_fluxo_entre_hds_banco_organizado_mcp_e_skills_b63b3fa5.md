# ARQUITETURA OPERACIONAL E PROMPT DE ATUALIZAÇÃO (DELTA v2.2) — INSTALADOR CLI, ROTEAMENTO ENTRE HDs, BANCO ORGANIZADO, SERVIDOR MCP E SKILLS DE AGENTE

## 1. DIAGNÓSTICO DIRETO: O QUE JÁ EXISTE NO PROGRAMA HOJE $\times$ O QUE VAMOS COMPLETAR AGORA

A sua pergunta tocou exatamente na **ponte entre ter um motor forense pronto e ter uma estação de trabalho automatizada de verdade**. Veja com transparência total o que o programa já tinha até a versão anterior e o que ainda faltava (e que vamos injetar agora no **Delta v2.2**):

| Item que Você Perguntou | Já Existe Hoje no Código? | Como Está Hoje $\times$ O Que Entra Agora na Atualização v2.2 |
| :--- | :---: | :--- |
| **1. Ler um HD de prova e criar a estrutura inteira em OUTRO HD?** | **Parcial** | **Já tinha** os parâmetros `--source` (HD da prova em somente leitura) e `--workspace` (pasta de saída). **O que faltava e entra agora:** um **Roteador Inteligente de Discos (`elo wizard` / `elo mount`)** que detecta sozinho todos os HDs conectados (letra, nome, serial e espaço livre), impede que você crie o caso dentro do próprio HD de prova, escolhe automaticamente se copia tudo ou usa *leitura referenciada* conforme o espaço livre do 2º HD (permitindo até um 3º HD opcional só para rascunho pesado `--staging`) e organiza tudo sozinho no outro HD. |
| **2. Devolver no outro HD um Banco de Dados Organizado pronto para consulta?** | **Parcial** | **Já tinha** tabelas técnicas internas de processamento (`evidence_inventory_tree`, `hybrid_search_chunks`). **O que faltava e entra agora:** um **Publicador de Banco Mestre Organizado (`01_BANCO_ORGANIZADO/case_master_organized.sqlite`)** no HD de destino, limpo, autocontido, indexado com busca textual instantânea (`FTS5`) e já entregue com **8 Visões Executivas Prontas (`SQL Views`)** para você, um perito ou uma IA consultarem mensagens, valores financeiros, ERBs, lacres, omissões da polícia e linha do tempo UTC sem precisar entender tabelas internas. |
| **3. Instalador real funcionando em CLI com IA?** | **Não tinha completo** | **Só tinha** o `materialize_*.py` (que apenas desempacotava os arquivos `.py`). **O que entra agora:** um **Instalador & Bootstrapper CLI Real (`install_elo.py` + comando `elo setup`)** que cria o ambiente virtual, registra o comando `elo` no terminal, detecta `Ollama`/modelos locais, `FFmpeg`, `Tesseract` e `IPED`, configura o **Modo Autopilot com IA (`elo autopilot`)** e já instala automaticamente o Servidor MCP e as Skills no seu computador. |
| **4. Servidor MCP (*Model Context Protocol*), Skills de Uso e Agente?** | **Não tinha** | **Não existia!** Havia apenas o `AGENTS.md` de regras de programação. **O que entra agora:** (a) um **Servidor MCP Forense Nativo (`mcp_server.py`)** em Python puro que expõe o ELO e o Banco Organizado como ferramentas oficiais para Claude Code, OpenCode, Cursor ou Claude Desktop; (b) **6 Skills de Uso Operacional (`SKILL.md`)** prontas para investigar o caso por conversa; e (c) o **Perfil de Agente Coordenador Forense**, onde a IA forte planeja e aciona as ferramentas MCP do ELO sem ler gigabytes no contexto e sem alucinar dados. |

---

## 2. COMO PASSA A FUNCIONAR NA PRÁTICA QUANDO VOCÊ PLUGAR OS HDs

### 2.1 Fluxo Físico Entre os HDs (Zero Toque na Prova $\rightarrow$ Banco Organizado no Outro HD)

```text
[HD 1: PROVA BRUTA ORIGINAL] (Ex.: D:\ ou E:\Provas)
  |-- Bloqueado por SourceWriteBlockerGuard (100% Somente Leitura, 0 bits alterados)
  |-- Leitura em streaming de 4 MiB + Magic Bytes + SQLite immutable=1
         |
         |---> (Opcional: HD 3 de Rascunho Pesado --staging, ex.: F:\_temp_staging,
         |      apagado automaticamente ao final para poupar espaco do HD 2)
         v
[HD 2: DESTINO DO CASO ESCOLHIDO POR VOCE] (Ex.: G:\Casos\Operacao_Alfa\)
  |-- 00_GOVERNANCA_E_AUDITORIA/     -> Fotos Antes==Depois do HD 1, Manifesto SHA-256, Logs IA e Bundle
  |-- 01_BANCO_ORGANIZADO/           -> O CORACAO DA ENTREGA:
  |     |-- case_master_organized.sqlite   (Banco unico limpo, normalizado, FTS5 + 8 Views Prontas)
  |     |-- SCHEMA_PARA_HUMANO_E_IA.md     (Mapa completo de tabelas, colunas e exemplos de consulta)
  |     +-- RESUMO_EXECUTIVO_BANCO.json    (Contagens totais auditadas para o Agente MCP)
  |-- 02_COFRE_OU_REFERENCIA/        -> Manifesto criptografico dos originais (com copia ou referencia leve)
  +-- 03_RELATORIOS_E_DOSSIE/        -> Relatorios EDRM Fases 01-08, Parecer 7 Blocos, Quesitos e HTML5 Offline
```

### 2.2 O Que Vem Dentro do `case_master_organized.sqlite` no Outro HD

Assim que a leitura do HD de prova termina, o segundo HD recebe o banco organizado com integridade `ACID`, valores em centavos inteiros, horários em `UTC` e **8 Visões Prontas (`SQL Views`)** para consulta imediata:

1. `vw_01_indice_geral_provas` — Todos os arquivos do HD de prova com `ControlNumber`, caminho original, `SHA-256`, tamanho, tipo binário real (*Magic Bytes*), extensão camuflada, custodiante e se é duplicata.
2. `vw_02_matriz_declarado_vs_entregue` — Tudo o que o Estado declarou em Autos/FAVs/Laudos confrontado com o que realmente veio no HD (destacando na hora provas brutas sonegadas — Tema 977/STF).
3. `vw_03_alertas_cadeia_custodia_e_pericia` — Todos os vícios detectados: lacres divergentes, falta de hash policial, mensagens/arquivos pós-apreensão, PDFs com revisões ocultas (`%%EOF > 1`), origem externa em atalhos `.lnk` (`MAC Address`) e casos `.iped` rodados em modo incompleto (`fastmode`/`triage`).
4. `vw_04_comunicacoes_unificadas_utc` — Mensagens de WhatsApp (Android/iOS/UFED), Telegram, e-mails e chats em ordem cronológica `UTC`, separando claramente linhas ativas (`ACTIVE_BTREE_ROW`) de registros apagados recuperados (`CARVED_FREELIST`).
5. `vw_05_financeiro_consolidado` — Lançamentos `SIMBA`, `OFX`, extratos, boletos e chaves `DANFE` validados com valor exato em centavos e em formato decimal legível, apontando duplicidades entre arquivos.
6. `vw_06_telecom_erb_deslocamentos` — Chamadas, dados `CDR`, localização das antenas `ERB`, azimutes, logs `CGNAT` sem porta lógica e alertas de velocidade humana impossível.
7. `vw_07_transcricoes_audio_ancoradas` — Todas as falas transcritas com carimbo exato de milissegundos (`inicio_ms`, `fim_ms`) ligadas ao `SHA-256` do áudio original.
8. `vw_08_linha_do_tempo_mestra_utc` — A visão suprema do caso: cruza na mesma régua segundo a segundo mensagens, ligações, antenas, transferências bancárias, edições de arquivos e atos policiais!

### 2.3 Como Funcionam o Instalador CLI, o MCP, as Skills e o Agente Juntos

1. **Instalação Única (`python install_elo.py --setup-all`):** Configura o comando `elo`, verifica suas ferramentas locais, grava o arquivo `.mcp.json` e instala as **6 Skills** em `.claude/skills/` e `.opencode/skills/`.
2. **Abertura do HD (Guiada ou Automática):**
   * **Interativa no Terminal:** Você digita `elo wizard` $\rightarrow$ o programa mostra na tela os HDs plugados, você escolhe na lista qual é o HD da prova (ex.: `D:\`), escolhe em qual outro HD quer salvar o caso (ex.: `E:\Caso_Novo`), e o **Autopilot com IA** faz todo o resto sozinho!
   * **Direta em 1 Linha ou por Voz/Chat no Agente:** Você abre o Claude Code ou OpenCode e digita `/elo-plugar-hd` dizendo *"Leia as provas brutas do HD D: e monte o caso organizado em E:\Casos\Operacao_X"*.
3. **Uso Investigativo via MCP + Skills:** Depois que o banco organizado está pronto no outro HD, o seu agente (Claude Code / OpenCode) consulta o caso usando as ferramentas determinísticas do **Servidor MCP** (`elo_hybrid_search`, `elo_query_organized_views`, `elo_timeline_window`, `elo_verify_citation_strict`), respondendo qualquer pergunta jurídica sua em segundos com hash `SHA-256`, página/minuto e citação literal conferida!

---

## 3. PROMPT COMPLETO DE ATUALIZAÇÃO DO SISTEMA (DELTA v2.2) PARA COLAR NO GOOGLE AI STUDIO

> **Dica de Ordem:** Cole este prompt no **Google AI Studio** **antes** (ou logo depois, para atualizar também os manuais) da geração da documentação, pois assim o próprio `README`, o `Blueprint` e o `Operator Playbook` já sairão documentando o Instalador CLI, o Roteador entre HDs, o Banco Organizado, o Servidor MCP e as Skills!

```text
ATUALIZAÇÃO EVOLUTIVA NÃO-DESTRUTIVA (DELTA v2.2) — INSTALADOR CLI INTELIGENTE, ROTEAMENTO CROSS-DISK ENTRE HDs, BANCO DE DADOS ORGANIZADO, SERVIDOR MCP NATIVO, SKILLS DE USO E AGENTE AUTOPILOT

Mantenha 100% intactos todos os pacotes de domínio, extratores, validadores, contratos e portões (`G0` a `G11`) já construídos nesta sessão. Sua missão agora é adicionar a **Camada Completa de Operação Real, Automação com IA, MCP e Roteamento Entre HDs**, seguindo Google Python Style Guide, princípios de Andrej Karpathy (Software 1.0 determinístico governando a IA, zero código morto, zero placeholders) e Enterprise SOLID (Clean/Hexagonal mantida intacta — novas peças entram em `edrm/interfaces/`, `edrm/application/` e na raiz operacional).

Implemente com 100% do código completo (zero `TODO`, zero `pass`, zero esqueletos) os 6 componentes abaixo:

### 1. ROTEADOR INTELIGENTE ENTRE HDs E SELETOR INTERATIVO (`src/edrm/interfaces/disk_router_wizard.py`)
- Implemente `MountedVolumeDetector` (compatível com Windows letras `A:`–`Z:` + `GetVolumeInformation` / `shutil.disk_usage` e Linux `/proc/mounts` / pontos de montagem), listando cada disco conectado com caminho, rótulo, sistema de arquivos, capacidade total e bytes livres exatos (`int`).
- Implemente `CrossDiskWorkspaceRouter`:
  1. Recebe um ou mais caminhos de prova bruta (`--source`, ex.: HD 1) e o diretório de destino em outro disco/local (`--dest` / `--workspace`, ex.: HD 2), mais `--staging` opcional (HD 3 para descompactação temporária pesada).
  2. **Trava Anti-Auto-Contaminação:** Bloqueia imediatamente com erro explícito se `--dest` ou `--staging` estiverem dentro de `--source` (ou no mesmo volume físico de prova quando `strict_separate_physical_drive = True`), garantindo que o HD da prova jamais receba um único arquivo criado pelo sistema.
  3. **Decisão Automática de Espaço (`SmartAcquisitionPlanner`):** Compara o tamanho total das provas em `--source` com o espaço livre real em `--dest`:
     - Se houver folga segura para cópia completa, oferece/seleciona `FULL_VAULT_COPY`;
     - Se `--source` for maior que o espaço livre de `--dest` (ex.: HD de prova de `1 TB` e HD de destino com `250 GB` livres), ativa automaticamente `REFERENCED_MANIFEST_STREAMING`: lê o HD de prova em streaming somente leitura, processa contêineres por micro-lotes limpando o `staging` a cada lote e entrega no HD de destino todo o catálogo criptográfico `SHA-256` e o Banco de Dados Organizado completo sem estourar o disco!
- Implemente o Assistente Interativo de Terminal (`run_interactive_cli_wizard`) para quando o usuário rodar `elo wizard` sem argumentos, guiando passo a passo a escolha do HD de Origem, do HD de Destino e do Modo de IA.

### 2. PUBLICADOR DO BANCO DE DADOS MESTRE ORGANIZADO NO HD DE DESTINO (`src/edrm/interfaces/organized_db_publisher.py`)
- Ao concluir (ou a cada fase em modo incremental) a leitura do HD de origem, materialize dentro do HD de destino a estrutura padronizada e limpa:
  - `00_GOVERNANCA_E_AUDITORIA/`
  - `01_BANCO_ORGANIZADO/case_master_organized.sqlite`
  - `01_BANCO_ORGANIZADO/SCHEMA_PARA_HUMANO_E_IA.md`
  - `01_BANCO_ORGANIZADO/RESUMO_EXECUTIVO_BANCO.json`
  - `02_COFRE_OU_REFERENCIA/`
  - `03_RELATORIOS_E_DOSSIE/`
- Dentro de `case_master_organized.sqlite`, além das tabelas normalizadas integradas e do índice textual `FTS5 BM25` (`fts_global_evidence_index`), crie automaticamente **8 SQL Views Executivas Prontas e Documentadas**:
  1. `vw_01_indice_geral_provas` (visão consolidada de arquivos, caminho no HD original, `SHA-256`, bytes, Magic Bytes, camuflagem de extensão, custodiante e deduplicação);
  2. `vw_02_matriz_declarado_vs_entregue` (confronto direto peças primárias vs. arquivos físicos do HD, destacando omissões brutas STF Tema 977);
  3. `vw_03_alertas_cadeia_custodia_e_pericia` (lacres divergentes, ausência de hash na origem, eventos pós-apreensão, PDFs com `%%EOF > 1`, divergência de `MAC Address` em `.lnk`, criptografia sem senha e auditoria de casos `.iped` estatais);
  4. `vw_04_comunicacoes_unificadas_utc` (chats móveis, e-mails e mensagens em UTC, distinguindo `ACTIVE_BTREE_ROW` de registros apagados/recuperados);
  5. `vw_05_financeiro_consolidado` (lançamentos SIMBA/OFX/boletos/DANFE em centavos `BIGINT`, valor formatado textual `R$` sem `float` e flag de duplicidade inter-arquivos);
  6. `vw_06_telecom_erb_deslocamentos` (CDRs, ERBs em micrograus, azimute, CGNAT sem porta lógica e flag de velocidade fisicamente impossível);
  7. `vw_07_transcricoes_audio_ancoradas` (segmentos de fala ancorados em milissegundos e `SHA-256` do áudio);
  8. `vw_08_linha_do_tempo_mestra_utc` (união cronológica multi-fonte em UTC de todos os fatos do caso).
- Gere automaticamente `SCHEMA_PARA_HUMANO_E_IA.md` listando todas as tabelas, as 8 Views, suas colunas e consultas SQL prontas para uso imediato.

### 3. AGENTE AUTOPILOT COM IA EMBUTIDO NO CLI (`src/edrm/interfaces/ai_autopilot_agent.py`)
- Implemente o comando `elo autopilot --source <HD_ORIGEM> --dest <HD_DESTINO> [--staging <HD_TEMP>] [--llm-endpoint http://127.0.0.1:11434]`:
  - Funciona 100% automatizado: executa a calibração ISO 27041, aciona a Sonda Determinística no HD de origem, usa o Agente Analítico Local (com fallback heurístico determinístico se nenhum servidor LLM local estiver aberto no momento!) para diagnosticar a anatomia do HD desconhecido, mapear peças processuais primárias e propor `DynamicSchemaBlueprint` para bancos SQLite inéditos, executa de ponta a ponta as Fases `00` a `08`, alimenta `01_BANCO_ORGANIZADO/case_master_organized.sqlite` no HD de destino, valida tudo no Verificador Determinístico Bloqueante (`0` falhas) e comprova ao final `PreScanSnapshot == PostScanSnapshot` no HD de origem!

### 4. SERVIDOR MCP (*MODEL CONTEXT PROTOCOL*) NATIVO (`src/edrm/interfaces/mcp_server.py`)
- Implemente um servidor **MCP oficial JSON-RPC 2.0 via `stdio`** em Python 3.12+ puro (suportando os métodos padrão do protocolo `initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `resources/list`, `resources/read` e `prompts/list` / `prompts/get`, sem exigir bibliotecas externas quebradiças!).
- Exponha via MCP **10 Ferramentas Forenses Determinísticas e Seguras** para que qualquer agente externo (Claude Code, OpenCode, Cursor, Gemini CLI) opere o sistema e consulte o Banco Organizado do outro HD sem jamais tocar em código bruto nem estourar janela de contexto:
  1. `elo_list_mounted_drives` — Lista os HDs/volumes conectados e espaço disponível.
  2. `elo_autopilot_ingest_hd` — Dispara a leitura completa de `--source` gravando a estrutura e o banco organizado em `--dest`.
  3. `elo_get_case_overview` — Lê `RESUMO_EXECUTIVO_BANCO.json` e contagens das 8 Views do caso aberto.
  4. `elo_hybrid_search` — Executa busca híbrida `RRF` (`BM25 FTS5` + vetorial) sobre o banco organizado devolvendo trechos com `ControlNumber`, `SHA-256` e `locator`.
  5. `elo_query_organized_view` — Consulta paginada e somente leitura (`mode=ro&immutable=1` + bloqueio estrito apenas `SELECT` sobre as Views/tabelas autorizadas) nas 8 Views executivas.
  6. `elo_timeline_window` — Recupera todos os eventos multi-fonte em uma janela UTC específica (`start_utc` a `end_utc`).
  7. `elo_audit_custody_and_parity` — Retorna todas as quebras de cadeia de custódia, alertas POP Senasp 2024 e provas brutas declaradas mas não entregues.
  8. `elo_confront_allegation_vs_raw` — Confronta uma afirmação de laudo/denúncia contra os dados brutos do banco organizado (incluindo contexto vizinho de mensagens).
  9. `elo_verify_citation_strict` — Aciona a Barreira Vermelha (`BlockingVerifierEngine`) para validar matematicamente se um parágrafo escrito pelo agente possui hashes, números e citações `«literais»` 100% fiéis ao banco antes de entregar ao advogado!
  10. `elo_generate_deliverables` — Compila sob demanda os relatórios, Quesitos Estratégicos, Parecer em 7 Blocos e Dossiê HTML5 Offline no HD de destino.

### 5. PACOTE DE SKILLS DE USO OPERACIONAL E AGENTE COORDENADOR (`src/edrm/interfaces/skills_and_mcp_installer.py`)
- Construa um módulo gerador determinístico que instala/exporta no projeto e/ou workspace do usuário:
  1. Arquivo `.mcp.json` (e instruções equivalentes para OpenCode/Claude Code) apontando diretamente para `python -m edrm.interfaces.cli mcp-serve`.
  2. **6 Skills Operacionais Prontas** (gravadas tanto em `.claude/skills/<nome>/SKILL.md` quanto em `.opencode/skills/<nome>/SKILL.md`):
     - `elo-plugar-hd`: guia o agente a listar os discos via MCP, confirmar HD de Prova (`--source`) e HD de Destino (`--dest`) e rodar o processamento completo até entregar o Banco Organizado.
     - `elo-panorama-caso`: resume instantaneamente o Banco Organizado recém-criado no outro HD (custodiantes, volume, provas faltantes e alertas críticos).
     - `elo-investigar-fato`: investiga qualquer pergunta fática do advogado cruzando `elo_hybrid_search`, `elo_timeline_window` e `vw_04`/`vw_05`/`vw_06`, obrigando passagem final em `elo_verify_citation_strict`.
     - `elo-auditar-custodia`: audita os 10 passos do art. 158-B do CPP, POP Senasp Vol. 5 (2024), Tema 977/STF e casos `.iped` sobre `vw_02` e `vw_03`.
     - `elo-confrontar-laudo`: audita um laudo policial ou denúncia linha por linha contra o Banco Organizado apontando omissões de contexto, duplicidades financeiras e erros de ERB/SQLite.
     - `elo-parecer-e-quesitos`: gera quesitos periciais personalizados e minuta técnica validada com zero alucinação.
  3. **Regra do Modelo Coordenador embutida nas Skills:** Todas as 6 Skills instruem explicitamente o modelo principal a atuar como **Coordenador Forense** (nunca abre bancos gigantes na unha, nunca calcula hashes/somas de cabeça e nunca escreve scripts improvisados: delega 100% das buscas e cálculos às tools MCP do ELO e valida toda resposta em `elo_verify_citation_strict`).

### 6. INSTALADOR CLI COMPLETO (`install_elo.py` na raiz + Subcomandos unificados em `cli.py`)
- Crie na raiz do projeto o instalador executável em linha de comando `install_elo.py` com suporte a:
  - `python install_elo.py --check-env`: faz diagnóstico completo da máquina (Python 3.12+, SQLite FTS5, discos montados e espaço livre, presença opcional de `Ollama`, `Tesseract`, `FFmpeg`, `IPED`, `Git`).
  - `python install_elo.py --install`: instala o pacote (`pip install -e .` ou wrapper `elo` / `elo.cmd` funcional mesmo offline), roda o auto-teste rápido de calibração ISO 27041, gera `.mcp.json` e instala as 6 Skills em `.claude/skills/` e `.opencode/skills/`.
- Atualize `edrm/interfaces/cli.py` para expor de forma limpa todos os comandos: `elo doctor`, `elo drives`, `elo wizard`, `elo autopilot`, `elo mcp-serve`, `elo install-skills`, além de `init-case`, `plug-hd`, `run-phase`, `plug-and-run-all`, `search` e `verify`.

### 7. PORTÃO AUTOMÁTICO `G12` NA SANDBOX PYTHON (`tools/run_forensic_gates.py`)
Adicione o **Portão `G12` — Homologação Operacional Cross-Disk, Banco Organizado, Instalador CLI, MCP & Skills** e execute todos os portões (`G0` a `G12`) na sua Sandbox Python até obter `EXIT CODE 0` comprovado:
1. **`G12.1` (Simulação Real de 2 HDs Separados):** Cria `simulated_hd_prova_A/` (com provas brutas sintéticas) e `simulated_hd_destino_B/` vazio; testa que tentar apontar `--dest` dentro de `simulated_hd_prova_A/` é bloqueado imediatamente; em seguida roda `elo autopilot --source simulated_hd_prova_A --dest simulated_hd_destino_B` e confirma criação de toda a árvore e de `01_BANCO_ORGANIZADO/case_master_organized.sqlite` com `0` mutações em `simulated_hd_prova_A/`.
2. **`G12.2` (Auditoria das 8 SQL Views e FTS5 no Outro HD):** Abre `case_master_organized.sqlite` em `mode=ro&immutable=1`, executa `SELECT` real nas 8 Views (`vw_01` a `vw_08`) e uma busca `MATCH` em `fts_global_evidence_index`, validando retorno estruturado íntegro e existência de `SCHEMA_PARA_HUMANO_E_IA.md`.
3. **`G12.3` (Teste Real do Servidor MCP JSON-RPC 2.0):** Dispara requisições reais `initialize`, `tools/list` e `tools/call` (`elo_get_case_overview`, `elo_hybrid_search`, `elo_query_organized_view`, `elo_verify_citation_strict`) contra `mcp_server.py`, comprovando protocolo MCP 100% funcional e bloqueio de qualquer tentativa de `DROP`/`INSERT` em `elo_query_organized_view`.
4. **`G12.4` (Teste do Instalador CLI e das 6 Skills):** Executa `install_elo.py --check-env` e a instalação em diretório temporário, verificando a criação de `.mcp.json` e dos 6 arquivos `SKILL.md` em `.claude/skills/` e `.opencode/skills/`.

Grave todos os módulos novos/atualizados na Sandbox, execute `python tools/run_forensic_gates.py` até `EXIT CODE 0` em `G0`–`G12` e entregue os arquivos completos junto com o script `materialize_elo_platform.py` atualizado e verificado por `SHA-256`!
```