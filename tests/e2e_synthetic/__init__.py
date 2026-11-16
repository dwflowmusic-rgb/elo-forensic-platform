"""Gerador do HD Forense Sintetico Desconhecido para Homologacao Ponta a Ponta (Portao G10)."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import wave
import zipfile


def materialize_synthetic_unknown_forensic_hd(hd_root: Path) -> Path:
    """Cria um HD Forense Sintetico Desconhecido completo contendo os artefatos (a) a (h) da Secao 7.

    Artefatos gerados:
      (a) Auto de Apreensao e Laudo Oficial com divergencia de lacre e omissao de .ufdr bruto,
          alem de citacao truncada fora de contexto;
      (b) Banco SQLite de WhatsApp Android (msgstore.db) com mensagem enviada 2 horas APOS a apreensao
          e dialogo completo revelando contexto omitido pelo laudo;
      (c) Segundo banco SQLite de aplicativo inedito (ledger_vault_custom.sqlite) descoberto
          dinamicamente pelo motor de schemas;
      (d) Arquivo SQLite camuflado com extensao .dll (system32_cache.dll);
      (e) PDF nativo com 2 marcadores %%EOF (atualizacao incremental suspeita);
      (f) Dois arquivos financeiros SIMBA/CSV com lancamento duplicado inter-arquivos (R$ 1.540,90);
      (g) Registros CDR/ERB com salto fisicamente impossivel e log CGNAT sem porta logica;
      (h) Arquivo criptografado sem senha (cofre_secreto.enc) + pacote ZIP aninhado contendo uma
          FAV descompactada na Fase 04 que dispara o loop iterativo 04 -> 01!

    Args:
        hd_root: Diretorio raiz representando a midia --source conectada.

    Returns:
        Caminho resolvido do HD sintetico.
    """
    hd_root.mkdir(parents=True, exist_ok=True)
    (hd_root / "01_autos_oficiais").mkdir(exist_ok=True)
    (hd_root / "02_extracoes_moveis").mkdir(exist_ok=True)
    (hd_root / "03_quebras_simba_telecom").mkdir(exist_ok=True)
    (hd_root / "04_pacotes_acautelados").mkdir(exist_ok=True)

    auto_text = """AUTO DE APREENSAO E APRESENTACAO POLICIAL
CUSTODIANTE: Marcos Aurelio Silveira
CPF: 123.456.789-00
DATA_HORA_APREENSAO: 2026-05-10T14:00:00Z

ITEM: CELULAR_01
MARCA: Samsung
MODELO: Galaxy S24
SERIE: RQ8X99120A
IMEI_CHASSI: 359881100223344
IMEI_MEMORIA: 359881100223344
ICCID: 89550210000998877
SEGUNDO_ESPACO: EXPLICIT_GAP
ESTADO_BLOQUEIO: AFU
ISOLAMENTO_RF: NAO
LACRE_ENTRADA: LACRE-900100
LACRE_SAIDA: LACRE-900101
COPIA_TRABALHO: NAO
HASH_ORIGEM: EXPLICIT_GAP
HASH_LISTA_MESTRE: EXPLICIT_GAP
FORMATO_BRUTO_ESPERADO: extracao_integral_s24.ufdr
PERITO_OFICIAL: NAO
METODO_COLETA: GRAVACAO DE TELA MANUAL
TRANSITO_MENSAGEIRO: SIM

ITEM: MIDIA_SQLITE_MSG
MARCA: Kingston
MODELO: Pendrive 64GB
SERIE: KG-7781
LACRE_ENTRADA: LACRE-900200
ISOLAMENTO_RF: SIM
ESTADO_BLOQUEIO: DESLIGADO
COPIA_TRABALHO: SIM
HASH_ORIGEM: EXPLICIT_GAP
FORMATO_BRUTO_ESPERADO: msgstore.db
PERITO_OFICIAL: SIM
METODO_COLETA: LOGICA
TRANSITO_MENSAGEIRO: NAO
"""
    (hd_root / "01_autos_oficiais" / "auto_apreensao_inicial.txt").write_text(
        auto_text, encoding="utf-8"
    )

    laudo_text = """LAUDO PERICIAL DE INFORMATICA FORENSE N. 4410/2026
CUSTODIANTE: Marcos Aurelio Silveira
CPF: 123.456.789-00
DATA_HORA_APREENSAO: 2026-05-10T14:00:00Z

ITEM: CELULAR_01
MARCA: Samsung
MODELO: Galaxy S24
LACRE_ENTRADA: LACRE-999999
FORMATO_BRUTO_ESPERADO: extracao_integral_s24.ufdr
PERITO_OFICIAL: SIM
METODO_COLETA: LOGICA

CONCLUSAO PRELIMINAR:
Consta dialogo suspeito com CITACAO_CHAT: "vou transferir o valor hoje" comprovando ilicito.
"""
    (hd_root / "01_autos_oficiais" / "laudo_pericial_4410.txt").write_text(
        laudo_text, encoding="utf-8"
    )

    msgstore_path = hd_root / "02_extracoes_moveis" / "msgstore.db"
    conn_wa = sqlite3.connect(str(msgstore_path))
    try:
        with conn_wa:
            conn_wa.execute(
                "CREATE TABLE messages (timestamp INTEGER, sender_jid TEXT, text_data TEXT)"
            )
            conn_wa.execute(
                "INSERT INTO messages VALUES (?, ?, ?)",
                (
                    1778415000000,
                    "5511999990001@s.whatsapp.net",
                    "Referente ao aluguel legitimo do imovel comercial de maio com nota fiscal:",
                ),
            )
            conn_wa.execute(
                "INSERT INTO messages VALUES (?, ?, ?)",
                (
                    1778415060000,
                    "5511999990001@s.whatsapp.net",
                    "vou transferir o valor hoje conforme contrato assinado na imobiliaria",
                ),
            )
            conn_wa.execute(
                "INSERT INTO messages VALUES (?, ?, ?)",
                (
                    1778415120000,
                    "5511988880002@s.whatsapp.net",
                    "Perfeito, emito o recibo fiscal assim que compensar.",
                ),
            )
            conn_wa.execute(
                "INSERT INTO messages VALUES (?, ?, ?)",
                (
                    1778428800000,
                    "AGENTE_EXTERNO_POS_APREENSAO",
                    "Mensagem inserida 2 horas APOS a apreensao policial de 14:00Z!",
                ),
            )
    finally:
        conn_wa.close()

    unknown_db_path = hd_root / "02_extracoes_moveis" / "ledger_vault_custom.sqlite"
    conn_dyn = sqlite3.connect(str(unknown_db_path))
    try:
        with conn_dyn:
            conn_dyn.execute(
                "CREATE TABLE custom_audit_notes (event_utc TEXT, author_user TEXT, memo_payload TEXT)"
            )
            conn_dyn.execute(
                "INSERT INTO custom_audit_notes VALUES (?, ?, ?)",
                ("2026-05-09T18:30:00Z", "contabilidade_interna", "Conciliacao bancaria regular R$ 1.540,90"),
            )
    finally:
        conn_dyn.close()

    spoofed_dll_path = hd_root / "02_extracoes_moveis" / "system32_cache.dll"
    conn_spoof = sqlite3.connect(str(spoofed_dll_path))
    try:
        with conn_spoof:
            conn_spoof.execute("CREATE TABLE hidden_logs (created_utc TEXT, actor_id TEXT, body_text TEXT)")
            conn_spoof.execute(
                "INSERT INTO hidden_logs VALUES (?, ?, ?)",
                ("2026-05-10T10:00:00Z", "sys_probe", "Banco SQLite camuflado como biblioteca .dll"),
            )
    finally:
        conn_spoof.close()

    pdf_2eof_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Page >> (Termo Original Assinado em Cartorio) endobj\n"
        b"%%EOF\n"
        b"3 0 obj << /Type /Page /ModDate (D:20260511090000Z) >> (Aditivo Incremental Posterior) endobj\n"
        b"%%EOF\n"
    )
    (hd_root / "01_autos_oficiais" / "termo_incremental_2eof.pdf").write_bytes(pdf_2eof_bytes)

    simba_1 = (
        "BANCO;AGENCIA;CONTA;TITULAR_CPF_CNPJ;ORIGEM_DESTINO_CPF_CNPJ;DATA_LANCAMENTO;NATUREZA;VALOR\n"
        "001;1234;99887-1;123.456.789-00;98.765.432/0001-10;2026-05-08T11:20:00Z;D;R$ 1.540,90\n"
    )
    simba_2 = (
        "BANCO;AGENCIA;CONTA;TITULAR_CPF_CNPJ;ORIGEM_DESTINO_CPF_CNPJ;DATA_LANCAMENTO;NATUREZA;VALOR\n"
        "001;1234;99887-1;123.456.789-00;98.765.432/0001-10;2026-05-08T11:20:00Z;D;R$ 1.540,90\n"
        "001;1234;99887-1;123.456.789-00;11.222.333/0001-81;2026-05-09T09:15:00Z;D;R$ 320,00\n"
    )
    (hd_root / "03_quebras_simba_telecom" / "simba_extrato_lote01.csv").write_text(simba_1, encoding="utf-8")
    (hd_root / "03_quebras_simba_telecom" / "simba_extrato_remessa_repetida.csv").write_text(
        simba_2, encoding="utf-8"
    )
    (hd_root / "01_autos_oficiais" / "auto_apreensao_copia_identica.txt").write_text(
        auto_text, encoding="utf-8"
    )

    cdr_csv = (
        "CALLER;CALLEE;IMEI;START_TIME;DURATION_SEC;CGI;LATITUDE;LONGITUDE;AZIMUTE\n"
        "5511999990001;5511988880002;359881100223344;2026-05-10T12:00:00Z;45;724-05-011-1001;-23.550520;-46.633308;90\n"
        "5511999990001;5511988880002;359881100223344;2026-05-10T12:00:10Z;30;724-05-021-9009;-22.906847;-43.172896;270\n"
    )
    (hd_root / "03_quebras_simba_telecom" / "cdr_anatel_operadora.csv").write_text(cdr_csv, encoding="utf-8")

    cgnat_csv = (
        "SHARED_IP;SOURCE_PORT;TS_UTC\n"
        "177.44.200.10;;2026-05-10T12:05:00Z\n"
        "177.44.200.10;54321;2026-05-10T12:06:00Z\n"
    )
    (hd_root / "03_quebras_simba_telecom" / "provedor_cgnat_logs.csv").write_text(
        cgnat_csv, encoding="utf-8"
    )

    enc_bytes = bytes((i * 73 + 19) % 256 for i in range(1024))
    (hd_root / "04_pacotes_acautelados" / "cofre_secreto.enc").write_bytes(enc_bytes)

    wav_path = hd_root / "04_pacotes_acautelados" / "interceptacao_trecho01.wav"
    with wave.open(str(wav_path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(b"\x10\x00" * 4000)

    nested_zip = hd_root / "04_pacotes_acautelados" / "apenso_digital_custodia.zip"
    fav_inside_zip = """FICHA DE ACOMPANHAMENTO DE VESTIGIO - FAV COMPLEMENTAR
CUSTODIANTE: Marcos Aurelio Silveira
DATA_HORA_APREENSAO: 2026-05-10T14:00:00Z

VESTIGIO: HD_EXTERNO_OMITIDO_02
MARCA: Seagate
MODELO: Expansion 2TB
LACRE_ENTRADA: LACRE-900555
FORMATO_BRUTO_ESPERADO: imagem_bruta_hd_2tb.e01
HASH_ORIGEM: EXPLICIT_GAP
PERITO_OFICIAL: SIM
METODO_COLETA: FISICA
"""
    with zipfile.ZipFile(nested_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fav_descoberta_em_container.txt", fav_inside_zip)

    return hd_root.resolve()
