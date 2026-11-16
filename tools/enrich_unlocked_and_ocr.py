"""Re-ingestao incremental de ZIPs desbloqueados + enriquecedor OCR (fitz/Tesseract) em F:\\."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
from typing import Any
import zipfile

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None  # type: ignore[assignment]

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None  # type: ignore[assignment]
    Image = None  # type: ignore[assignment]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_tesseract_bin() -> str | None:
    found = shutil.which("tesseract")
    if found:
        return found
    for cand in (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    ):
        if Path(cand).exists():
            return cand
    return None


def _safe_rel(raw_name: str) -> Path:
    norm = raw_name.replace("\\", "/").lstrip("/")
    p = PurePosixPath(norm)
    parts = [part for part in p.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts) or ":" in parts[0]:
        raise ValueError(f"Caminho inseguro no ZIP: {raw_name}")
    return Path(*parts)


def _unpack_nested_zips(desbloqueados_dir: Path) -> int:
    unpacked_count = 0
    for zp in sorted(desbloqueados_dir.rglob("*.zip")):
        target_dir = zp.parent / f"_nested_{zp.stem[:40]}"
        if target_dir.exists():
            continue
        try:
            with zipfile.ZipFile(zp, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or (info.flag_bits & 0x1):
                        continue
                    rel_p = _safe_rel(info.filename)
                    out_f = target_dir / rel_p
                    out_f.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, open(out_f, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    unpacked_count += 1
        except Exception:
            continue
    return unpacked_count


def _chunk_text(text: str, max_chars: int = 1800) -> list[str]:
    clean = " ".join(text.split())
    if not clean:
        return []
    return [clean[i : i + max_chars] for i in range(0, len(clean), max_chars)]


def _extract_pdf_segments(
    source: Path | bytes,
    native_prefix: str,
    ocr_prefix: str,
    tesseract_bin: str | None,
) -> tuple[list[tuple[str, str]], int]:
    """Extrai texto nativo de PDF (arquivo ou bytes) e aplica Tesseract 200 DPI nas paginas sem texto."""
    if fitz is None:
        return [], 0
    segments: list[tuple[str, str]] = []
    ocr_pages = 0
    try:
        doc = fitz.open(stream=source, filetype="pdf") if isinstance(source, (bytes, bytearray)) else fitz.open(str(source))
        try:
            for pg_idx, page in enumerate(doc, start=1):
                pg_txt = page.get_text("text").strip()
                locator = f"{native_prefix}#p.{pg_idx}"
                if not pg_txt and pytesseract is not None and Image is not None and tesseract_bin:
                    pix = page.get_pixmap(dpi=200)
                    img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                    pg_txt = pytesseract.image_to_string(img, lang="por+eng").strip()
                    locator = f"{ocr_prefix}#p.{pg_idx}"
                    ocr_pages += 1
                if pg_txt:
                    segments.append((locator, pg_txt))
        finally:
            doc.close()
    except Exception:
        pass
    return segments, ocr_pages


def _extract_image_segments(
    source: Path | bytes,
    ocr_prefix: str,
    tesseract_bin: str | None,
) -> tuple[list[tuple[str, str]], int]:
    """Executa OCR Tesseract (por+eng) em imagem (arquivo ou bytes)."""
    if pytesseract is None or Image is None or not tesseract_bin:
        return [], 0
    try:
        img_input: Any = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
        with Image.open(img_input) as img:
            ocr_txt = pytesseract.image_to_string(img, lang="por+eng").strip()
        if ocr_txt:
            return [(ocr_prefix, ocr_txt)], 1
    except Exception:
        pass
    return [], 0


def _read_nested_zip_bytes(root_zip_path: Path, inner_parts: list[str]) -> bytes | None:
    """Navega recursivamente em memoria por ZIPs aninhados em vault\\ (ignorando Office/JAR)."""
    if not inner_parts or root_zip_path.suffix.lower() != ".zip" or not root_zip_path.is_file():
        return None
    for container in inner_parts[:-1]:
        if Path(container).suffix.lower() != ".zip":
            return None

    def _descend(zf: zipfile.ZipFile, parts: list[str]) -> bytes | None:
        target = parts[0].replace("\\", "/").lstrip("/")
        try:
            data = zf.read(target)
        except KeyError:
            target_alt = parts[0].lstrip("/")
            try:
                data = zf.read(target_alt)
            except KeyError:
                return None
        if len(parts) == 1:
            return data
        with zipfile.ZipFile(io.BytesIO(data), "r") as inner_zf:
            return _descend(inner_zf, parts[1:])

    try:
        with zipfile.ZipFile(root_zip_path, "r") as root_zf:
            return _descend(root_zf, inner_parts)
    except Exception:
        return None


def _insert_segments_incremental(
    conn: sqlite3.Connection,
    segments: list[tuple[str, str]],
    origin_cn: str,
    origin_path: str,
    file_sha: str,
    chunk_prefix: str,
    source_domain: str,
) -> int:
    """Insere chunks de forma 100% incremental em org_anchored_chunks e FTS."""
    inserted = 0
    for locator, seg_text in segments:
        for idx, chk in enumerate(_chunk_text(seg_text), start=1):
            chk_id = (
                f"{chunk_prefix}-"
                + hashlib.sha256(f"{file_sha}|{locator}|{idx}".encode("utf-8")).hexdigest()[:16].upper()
            )
            cur = conn.execute(
                """
                INSERT INTO org_anchored_chunks (
                    chunk_id, origin_cn, origin_path, locator,
                    text_clean, injection_neutralized, origin_sha256
                ) VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(chunk_id) DO NOTHING
                """,
                (chk_id, origin_cn, origin_path, locator, chk, file_sha),
            )
            if cur.rowcount and cur.rowcount > 0:
                inserted += 1
                conn.execute(
                    """
                    INSERT INTO fts_global_evidence_index (
                        doc_ref, origin_cn, source_domain, locator, origin_sha256, content_text
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (chk_id, origin_cn, source_domain, locator, file_sha, chk),
                )
    return inserted


def enrich_unlocked_and_ocr(dest_root: Path, include_vault_ocr: bool = False) -> dict[str, Any]:
    org_db = dest_root / "01_BANCO_ORGANIZADO" / "case_master_organized.sqlite"
    desbloq_dir = dest_root / "02_COFRE_OU_REFERENCIA" / "desbloqueados"
    if not org_db.exists():
        return {"ok": False, "error": f"Banco organizado nao encontrado: {org_db}"}
    if not include_vault_ocr and not desbloq_dir.exists():
        return {"ok": False, "error": f"Pasta desbloqueados nao encontrada: {desbloq_dir}"}

    tesseract_bin = _find_tesseract_bin()
    if pytesseract is not None and tesseract_bin:
        pytesseract.pytesseract.tesseract_cmd = tesseract_bin

    nested_files = _unpack_nested_zips(desbloq_dir) if desbloq_dir.exists() else 0

    files_processed = 0
    chunks_inserted = 0
    ocr_pages_processed = 0
    vault_files_processed = 0
    vault_nested_zip_files_processed = 0
    vault_chunks_inserted = 0
    vault_ocr_pages_processed = 0
    vault_skipped_missing = 0

    conn = sqlite3.connect(str(org_db), timeout=10.0)
    try:
        if desbloq_dir.exists():
            for fpath in sorted(desbloq_dir.rglob("*")):
                if not fpath.is_file():
                    continue
                if fpath.name == "UNLOCK_SHA256_MANIFEST.json":
                    continue
                ext = fpath.suffix.lower()
                if ext not in (".pdf", ".csv", ".txt", ".md", ".png", ".jpg", ".jpeg", ".tif", ".tiff"):
                    continue

                file_sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
                rel_str = fpath.relative_to(desbloq_dir).as_posix()
                origin_cn = f"ELO-UNLOCKED-{file_sha[:10].upper()}"
                extracted_segments: list[tuple[str, str]] = []

                if ext == ".pdf":
                    extracted_segments, pdf_ocr = _extract_pdf_segments(
                        fpath,
                        f"desbloqueado:{rel_str}",
                        f"ocr_desbloqueado:{rel_str}",
                        tesseract_bin,
                    )
                    ocr_pages_processed += pdf_ocr
                elif ext in (".csv", ".txt", ".md"):
                    raw_txt = fpath.read_text(encoding="utf-8", errors="replace")[:2_000_000]
                    if raw_txt.strip():
                        extracted_segments.append((f"desbloqueado:{rel_str}", raw_txt))
                elif ext in (".png", ".jpg", ".jpeg", ".tif", ".tiff"):
                    extracted_segments, img_ocr = _extract_image_segments(
                        fpath,
                        f"ocr_imagem:{rel_str}",
                        tesseract_bin,
                    )
                    ocr_pages_processed += img_ocr

                if not extracted_segments:
                    continue
                files_processed += 1
                chunks_inserted += _insert_segments_incremental(
                    conn,
                    extracted_segments,
                    origin_cn=origin_cn,
                    origin_path=rel_str,
                    file_sha=file_sha,
                    chunk_prefix="CHK-UNL",
                    source_domain="UNLOCKED_AND_OCR",
                )

        if include_vault_ocr:
            vault_dir = (dest_root / "_elo_engine_workspace" / "vault").resolve()
            root_paths = {
                r_cn: r_path
                for r_cn, r_path in conn.execute(
                    "SELECT control_number, vault_or_ref_path FROM org_inventory_files WHERE parent_control_number IS NULL"
                ).fetchall()
                if r_path
            }
            vault_rows = conn.execute(
                """
                SELECT control_number, origin_rel_path, vault_or_ref_path, sha256_hex, magic_signature
                FROM org_inventory_files
                WHERE duplicate_of_cn IS NULL
                  AND magic_signature IN ('PNG_IMAGE', 'JPEG_IMAGE', 'PDF_DOCUMENT')
                ORDER BY control_number
                """
            ).fetchall()

            for control_number, origin_rel_path, vault_or_ref_path, sha256_hex, magic_sig in vault_rows:
                source_data: Path | bytes | None = None
                from_nested_zip = False
                if vault_or_ref_path:
                    fpath = Path(vault_or_ref_path)
                    if fpath.is_file():
                        source_data = fpath

                if source_data is None and origin_rel_path and "!/" in origin_rel_path:
                    root_cn = control_number.split(".", 1)[0]
                    root_ref = root_paths.get(root_cn)
                    if root_ref:
                        root_zip = Path(root_ref)
                        try:
                            is_in_vault = root_zip.resolve().is_relative_to(vault_dir)
                        except Exception:
                            is_in_vault = False
                        if is_in_vault and root_zip.is_file():
                            inner_parts = origin_rel_path.split("!/")[1:]
                            nested_bytes = _read_nested_zip_bytes(root_zip, inner_parts)
                            if nested_bytes is not None:
                                source_data = nested_bytes
                                from_nested_zip = True

                if source_data is None:
                    vault_skipped_missing += 1
                    continue

                if sha256_hex:
                    file_sha = sha256_hex
                elif isinstance(source_data, Path):
                    file_sha = hashlib.sha256(source_data.read_bytes()).hexdigest()
                else:
                    file_sha = hashlib.sha256(source_data).hexdigest()

                rel_label = origin_rel_path or (source_data.name if isinstance(source_data, Path) else control_number)
                extracted_segments = []

                if magic_sig == "PDF_DOCUMENT":
                    extracted_segments, pdf_ocr = _extract_pdf_segments(
                        source_data,
                        f"vault:{rel_label}",
                        f"vault_ocr:{rel_label}",
                        tesseract_bin,
                    )
                    vault_ocr_pages_processed += pdf_ocr
                    ocr_pages_processed += pdf_ocr
                elif magic_sig in ("PNG_IMAGE", "JPEG_IMAGE"):
                    extracted_segments, img_ocr = _extract_image_segments(
                        source_data,
                        f"vault_ocr_imagem:{rel_label}",
                        tesseract_bin,
                    )
                    vault_ocr_pages_processed += img_ocr
                    ocr_pages_processed += img_ocr

                if not extracted_segments:
                    continue
                vault_files_processed += 1
                if from_nested_zip:
                    vault_nested_zip_files_processed += 1
                files_processed += 1
                ins = _insert_segments_incremental(
                    conn,
                    extracted_segments,
                    origin_cn=control_number,
                    origin_path=rel_label,
                    file_sha=file_sha,
                    chunk_prefix="CHK-VLT",
                    source_domain="VAULT_OCR",
                )
                vault_chunks_inserted += ins
                chunks_inserted += ins

        conn.commit()
        total_chunks = conn.execute("SELECT COUNT(*) FROM org_anchored_chunks").fetchone()[0]
        total_fts = conn.execute("SELECT COUNT(*) FROM fts_global_evidence_index").fetchone()[0]
    finally:
        conn.close()

    audit_entry = {
        "ts_utc": _utc_now(),
        "include_vault_ocr": include_vault_ocr,
        "nested_zip_files_unpacked": nested_files,
        "files_processed": files_processed,
        "chunks_inserted": chunks_inserted,
        "ocr_pages_processed": ocr_pages_processed,
        "vault_files_processed": vault_files_processed,
        "vault_nested_zip_files_processed": vault_nested_zip_files_processed,
        "vault_chunks_inserted": vault_chunks_inserted,
        "vault_ocr_pages_processed": vault_ocr_pages_processed,
        "vault_skipped_missing": vault_skipped_missing,
        "total_org_anchored_chunks": total_chunks,
        "total_fts_global_evidence_index": total_fts,
        "tesseract_available": bool(tesseract_bin),
        "fitz_available": fitz is not None,
    }
    audit_file = dest_root / "00_GOVERNANCA_E_AUDITORIA" / "enrichment_audit.jsonl"
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_file, "a", encoding="utf-8") as afh:
        afh.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
        afh.flush()
        os.fsync(afh.fileno())

    return {"ok": True, **audit_entry}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-ingere ZIPs desbloqueados e executa OCR em F:\\.")
    parser.add_argument("--dest", required=True, help="Diretorio do caso no HD destino.")
    parser.add_argument(
        "--include-vault-ocr",
        action="store_true",
        help="Executa OCR incremental em arquivos canonicos (PNG/JPEG/PDF) presentes em vault\\.",
    )
    parser.add_argument(
        "--vault",
        action="store_true",
        help="Alias para habilitar --include-vault-ocr.",
    )
    args = parser.parse_args(argv)
    res = enrich_unlocked_and_ocr(
        Path(args.dest),
        include_vault_ocr=bool(args.include_vault_ocr or args.vault),
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
