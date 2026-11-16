"""Transcricao incremental de audios via Groq Whisper API para case_master_organized.sqlite."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import sqlite3
import urllib.error
import urllib.request
import uuid

AUDIO_EXTS = (".wav", ".mp3", ".ogg", ".opus", ".m4a", ".aac", ".flac", ".webm", ".mp4")
GROQ_TRANSCRIPTION_URL = "https://api.groq.com/openai/v1/audio/transcriptions"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _multipart_post(
    url: str,
    api_key: str,
    fields: dict[str, str],
    file_field: str,
    file_path: Path,
) -> dict:
    boundary = f"----EloGroqBoundary{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for k, v in fields.items():
        parts.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                f"{v}\r\n"
            ).encode("utf-8")
        )
    mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    file_bytes = file_path.read_bytes()
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'
            f"Content-Type: {mime}\r\n\r\n"
        ).encode("utf-8")
    )
    parts.append(file_bytes)
    parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)

    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "ELO-Forensic-Platform/2.2",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def transcribe_folder_to_db(
    audio_dir: Path,
    dest_root: Path,
    api_key: str,
    model: str = "whisper-large-v3-turbo",
    language: str = "pt",
    limit: int = 0,
) -> dict:
    org_db = dest_root / "01_BANCO_ORGANIZADO" / "case_master_organized.sqlite"
    if not org_db.exists():
        return {"ok": False, "error": f"Banco organizado nao encontrado: {org_db}"}
    if not audio_dir.exists():
        return {"ok": False, "error": f"Pasta de audios nao encontrada: {audio_dir}"}

    audio_files = [
        p for p in sorted(audio_dir.rglob("*"))
        if p.is_file() and p.suffix.lower() in AUDIO_EXTS
    ]
    if limit > 0:
        audio_files = audio_files[:limit]

    files_transcribed = 0
    segments_inserted = 0
    errors: list[dict[str, str]] = []

    conn = sqlite3.connect(str(org_db), timeout=15.0)
    try:
        for fpath in audio_files:
            file_sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
            origin_cn = f"ELO-AUDIO-{file_sha[:10].upper()}"
            rel_str = fpath.relative_to(audio_dir).as_posix()

            existing = conn.execute(
                "SELECT COUNT(*) FROM org_audio_transcript_segments WHERE origin_sha256 = ?",
                (file_sha,),
            ).fetchone()[0]
            if existing and int(existing) > 0:
                continue

            try:
                resp = _multipart_post(
                    GROQ_TRANSCRIPTION_URL,
                    api_key=api_key,
                    fields={
                        "model": model,
                        "language": language,
                        "response_format": "verbose_json",
                    },
                    file_field="file",
                    file_path=fpath,
                )
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")[:300]
                errors.append({"file": rel_str, "error": f"HTTP {exc.code}: {err_body}"})
                continue
            except Exception as exc:
                errors.append({"file": rel_str, "error": str(exc)})
                continue

            segments = resp.get("segments") or []
            full_text = str(resp.get("text", "")).strip()
            if not segments and full_text:
                segments = [{"start": 0.0, "end": 0.0, "text": full_text}]

            if not segments:
                continue
            files_transcribed += 1

            for idx, seg in enumerate(segments, start=1):
                seg_text = str(seg.get("text", "")).strip()
                if not seg_text:
                    continue
                start_ms = int(float(seg.get("start", 0.0)) * 1000)
                end_ms = int(float(seg.get("end", 0.0)) * 1000)
                seg_id = "SEG-" + hashlib.sha256(f"{file_sha}|{idx}|{start_ms}".encode("utf-8")).hexdigest()[:16].upper()
                locator = f"audio:{rel_str}#{start_ms}-{end_ms}ms"

                conn.execute(
                    """
                    INSERT INTO org_audio_transcript_segments (
                        segment_id, origin_cn, origin_path, start_ms, end_ms,
                        speaker_label, transcript_text, origin_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(segment_id) DO NOTHING
                    """,
                    (seg_id, origin_cn, rel_str, start_ms, end_ms, "SPEAKER", seg_text, file_sha),
                )
                chk_id = "CHK-AUD-" + seg_id[4:]
                cur = conn.execute(
                    """
                    INSERT INTO org_anchored_chunks (
                        chunk_id, origin_cn, origin_path, locator,
                        text_clean, injection_neutralized, origin_sha256
                    ) VALUES (?, ?, ?, ?, ?, 1, ?)
                    ON CONFLICT(chunk_id) DO NOTHING
                    """,
                    (chk_id, origin_cn, rel_str, locator, seg_text, file_sha),
                )
                if cur.rowcount and cur.rowcount > 0:
                    segments_inserted += 1
                    conn.execute(
                        """
                        INSERT INTO fts_global_evidence_index (
                            doc_ref, origin_cn, source_domain, locator, origin_sha256, content_text
                        ) VALUES (?, ?, 'GROQ_WHISPER', ?, ?, ?)
                        """,
                        (chk_id, origin_cn, locator, file_sha, seg_text),
                    )
        conn.commit()
    finally:
        conn.close()

    audit_entry = {
        "ts_utc": _utc_now(),
        "audio_dir": str(audio_dir),
        "total_audio_files_found": len(audio_files),
        "files_transcribed": files_transcribed,
        "segments_inserted": segments_inserted,
        "errors_count": len(errors),
        "errors_sample": errors[:5],
    }
    audit_file = dest_root / "00_GOVERNANCA_E_AUDITORIA" / "groq_transcription_audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as afh:
        afh.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
        afh.flush()
        os.fsync(afh.fileno())

    return {"ok": True, **audit_entry}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Transcreve audios via Groq Whisper para o banco ELO.")
    parser.add_argument("--audio-dir", required=True, help="Pasta com arquivos de audio (.wav/.mp3/.ogg).")
    parser.add_argument("--dest", required=True, help="Diretorio do caso em F:\\.")
    parser.add_argument("--model", default="whisper-large-v3-turbo")
    parser.add_argument("--language", default="pt")
    parser.add_argument("--limit", type=int, default=0, help="Limite opcional de arquivos por lote.")
    args = parser.parse_args(argv)

    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        print(json.dumps({"ok": False, "error": "Defina a variavel de ambiente GROQ_API_KEY."}))
        return 1

    res = transcribe_folder_to_db(
        audio_dir=Path(args.audio_dir),
        dest_root=Path(args.dest),
        api_key=api_key,
        model=args.model,
        language=args.language,
        limit=args.limit,
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
