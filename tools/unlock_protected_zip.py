"""Consulta de senhas (Senhas.md) e desbloqueio forense nao-bloqueante de ZIPs em F:\\."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any
import zipfile

try:
    import pyzipper  # Suporta WinZip AES-256 (compress_type=99)
except ImportError:
    pyzipper = None  # type: ignore[assignment]

MAX_MEMBER_BYTES = 512 * 1024 * 1024  # 512 MiB por membro


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_member_rel(raw_name: str) -> Path:
    norm = raw_name.replace("\\", "/").lstrip("/")
    p = PurePosixPath(norm)
    parts = [part for part in p.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts) or ":" in parts[0]:
        raise ValueError(f"Caminho inseguro dentro do ZIP: {raw_name}")
    return Path(*parts)


def parse_senhas_md(senhas_md_path: Path) -> list[dict[str, str]]:
    """Extrai tabela Markdown de arquivos ZIP e senhas em modo somente leitura."""
    if not senhas_md_path.exists():
        return []
    entries: list[dict[str, str]] = []
    row_re = re.compile(r"^\|\s*`?([^`|]+?\.zip)`?\s*\|\s*([^|]+?)\s*\|\s*`?([^`|]+?)`?\s*\|$", re.IGNORECASE)
    for line in senhas_md_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = row_re.match(line.strip())
        if m:
            entries.append(
                {
                    "filename": m.group(1).strip(),
                    "operation": m.group(2).strip(),
                    "password": m.group(3).strip(),
                }
            )
    return entries


def build_or_read_lookup(dest_root: Path, senhas_md_path: Path | None) -> dict[str, dict[str, str]]:
    """Grava/atualiza arquivo de consulta zip_credentials_lookup.json no destino F:\\."""
    gov_dir = dest_root / "00_GOVERNANCA_E_AUDITORIA"
    gov_dir.mkdir(parents=True, exist_ok=True)
    lookup_file = gov_dir / "zip_credentials_lookup.json"

    lookup: dict[str, dict[str, str]] = {}
    if lookup_file.exists():
        try:
            raw = json.loads(lookup_file.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                lookup.update(raw)
        except (OSError, ValueError):
            pass

    if senhas_md_path is not None and senhas_md_path.exists():
        for item in parse_senhas_md(senhas_md_path):
            lookup[item["filename"]] = {
                "operation": item["operation"],
                "password": item["password"],
                "source_doc": str(senhas_md_path),
            }
        lookup_file.write_text(
            json.dumps(lookup, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return lookup


def read_unlock_audit(dest_root: Path) -> dict[str, dict[str, Any]]:
    audit_file = dest_root / "00_GOVERNANCA_E_AUDITORIA" / "zip_unlock_audit.jsonl"
    records: dict[str, dict[str, Any]] = {}
    if not audit_file.exists():
        return records
    for line in audit_file.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
            if isinstance(obj, dict) and obj.get("status") in ("UNLOCKED", "IGNORED"):
                records[str(obj.get("zip_path", ""))] = obj
        except ValueError:
            continue
    return records


def ignore_zip_in_audit(zip_path: Path, dest_root: Path, reason: str) -> dict[str, Any]:
    """Registra decisao auditavel do operador para ignorar um ZIP protegido."""
    gov_dir = dest_root / "00_GOVERNANCA_E_AUDITORIA"
    gov_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts_utc": _utc_now(),
        "status": "IGNORED",
        "zip_path": str(zip_path),
        "filename": zip_path.name,
        "reason": reason or "Ignorado pelo operador (duplicata ou nao pertinente).",
    }
    audit_file = gov_dir / "zip_unlock_audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as afh:
        afh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        afh.flush()
        os.fsync(afh.fileno())
    return {"ignored": True, **entry}


def scan_protected_zips(
    source_roots: tuple[Path, ...],
    dest_root: Path,
    senhas_md_path: Path | None,
) -> dict[str, Any]:
    lookup = build_or_read_lookup(dest_root, senhas_md_path)
    unlocked_map = read_unlock_audit(dest_root)
    items: list[dict[str, Any]] = []

    for root in source_roots:
        if not root.exists():
            continue
        for zp in sorted(root.rglob("*.zip")):
            try:
                with open(zp, "rb") as fh:
                    with zipfile.ZipFile(fh, "r") as zf:
                        enc_members = [m.filename for m in zf.infolist() if (m.flag_bits & 0x1)]
            except Exception:
                continue
            if not enc_members:
                continue
            zp_str = str(zp)
            lookup_hit = lookup.get(zp.name)
            audit_hit = unlocked_map.get(zp_str)
            item_status = str(audit_hit.get("status")) if audit_hit else "LOCKED_ALERT"
            items.append(
                {
                    "zip_path": zp_str,
                    "filename": zp.name,
                    "encrypted_members_count": len(enc_members),
                    "sample_members": enc_members[:5],
                    "has_lookup_password": lookup_hit is not None,
                    "operation": lookup_hit.get("operation", "") if lookup_hit else "",
                    "status": item_status,
                    "extracted_dir": audit_hit.get("extracted_dir", "") if audit_hit else "",
                    "unlocked_at_utc": audit_hit.get("ts_utc", "") if audit_hit else "",
                    "extracted_files_count": audit_hit.get("extracted_files_count", 0) if audit_hit else 0,
                }
            )

    return {
        "checked_at_utc": _utc_now(),
        "lookup_file": str(dest_root / "00_GOVERNANCA_E_AUDITORIA" / "zip_credentials_lookup.json"),
        "total_protected_zips": len(items),
        "locked_count": sum(1 for i in items if i["status"] == "LOCKED_ALERT"),
        "unlocked_count": sum(1 for i in items if i["status"] == "UNLOCKED"),
        "ignored_count": sum(1 for i in items if i["status"] == "IGNORED"),
        "items": items,
    }


def unlock_zip_to_dest(
    zip_path: Path,
    dest_root: Path,
    password: str | None,
    use_lookup: bool,
    senhas_md_path: Path | None,
) -> dict[str, Any]:
    if not zip_path.exists() or not zip_path.is_file():
        return {"unlocked": False, "error": f"Arquivo ZIP nao encontrado: {zip_path}"}

    lookup = build_or_read_lookup(dest_root, senhas_md_path)
    pwd_effective = password or ""
    if use_lookup and not pwd_effective:
        hit = lookup.get(zip_path.name)
        if hit:
            pwd_effective = hit.get("password", "")

    if not pwd_effective:
        return {"unlocked": False, "error": "Nenhuma senha informada ou encontrada no arquivo de consulta."}

    zip_hasher = hashlib.sha256()
    with open(zip_path, "rb") as fh:
        while chunk := fh.read(1048576):
            zip_hasher.update(chunk)
    zip_sha256 = zip_hasher.hexdigest()

    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", zip_path.stem)[:60]
    out_dir = dest_root / "02_COFRE_OU_REFERENCIA" / "desbloqueados" / f"{slug}_{zip_sha256[:8]}"
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted_records: list[dict[str, Any]] = []
    pwd_bytes = pwd_effective.encode("utf-8")
    zip_cls = pyzipper.AESZipFile if pyzipper is not None else zipfile.ZipFile
    try:
        with open(zip_path, "rb") as raw_fh:
            with zip_cls(raw_fh, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    rel_p = _safe_member_rel(info.filename)
                    target_file = out_dir / rel_p
                    target_file.parent.mkdir(parents=True, exist_ok=True)

                    h = hashlib.sha256()
                    written = 0
                    with zf.open(info, mode="r", pwd=pwd_bytes) as src_stream, open(target_file, "wb") as dst_fh:
                        while chunk := src_stream.read(262144):
                            written += len(chunk)
                            if written > MAX_MEMBER_BYTES:
                                raise ValueError(f"Membro excedeu 512 MiB: {rel_p}")
                            h.update(chunk)
                            dst_fh.write(chunk)
                        dst_fh.flush()
                        os.fsync(dst_fh.fileno())
                    extracted_records.append(
                        {
                            "rel_path": rel_p.as_posix(),
                            "size_bytes": written,
                            "sha256_hex": h.hexdigest(),
                        }
                    )
    except RuntimeError as exc:
        return {"unlocked": False, "error": f"Senha incorreta ou falha criptografica: {exc}"}
    except Exception as exc:
        return {"unlocked": False, "error": str(exc)}

    manifest_path = out_dir / "UNLOCK_SHA256_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(
            {
                "zip_path": str(zip_path),
                "zip_sha256": zip_sha256,
                "unlocked_at_utc": _utc_now(),
                "extracted_files": extracted_records,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    audit_entry = {
        "ts_utc": _utc_now(),
        "status": "UNLOCKED",
        "zip_path": str(zip_path),
        "filename": zip_path.name,
        "zip_sha256": zip_sha256,
        "extracted_dir": str(out_dir),
        "extracted_files_count": len(extracted_records),
        "manifest_path": str(manifest_path),
    }
    audit_file = dest_root / "00_GOVERNANCA_E_AUDITORIA" / "zip_unlock_audit.jsonl"
    with open(audit_file, "a", encoding="utf-8") as afh:
        afh.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
        afh.flush()
        os.fsync(afh.fileno())

    return {"unlocked": True, **audit_entry}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consulta e desbloqueio forense de ZIPs com senha.")
    parser.add_argument("--dest", required=True, help="Diretorio do caso no HD destino (ex.: F:\\ELO_CASOS\\CASO_001).")
    parser.add_argument("--source", action="append", default=[], help="Raizes de origem somente leitura.")
    parser.add_argument("--senhas-md", default=os.environ.get("ELO_SENHAS_MD", ""), help="Arquivo Senhas.md opcional.")
    parser.add_argument("--scan", action="store_true", help="Lista ZIPs protegidos e gera arquivo de consulta.")
    parser.add_argument("--zip-path", default=None, help="Caminho do ZIP a desbloquear ou ignorar.")
    parser.add_argument("--password", default=None, help="Senha informada manualmente.")
    parser.add_argument("--use-lookup", action="store_true", help="Usa senha do arquivo de consulta.")
    parser.add_argument("--ignore", action="store_true", help="Marca ZIP como ignorado no log auditavel.")
    parser.add_argument("--reason", default="", help="Motivo opcional ao ignorar o arquivo.")
    args = parser.parse_args(argv)

    dest_root = Path(args.dest)
    senhas_path = Path(args.senhas_md) if args.senhas_md else None

    if args.scan:
        sources = tuple(Path(s) for s in (args.source or [r"E:\_DEFESA_COPIA_HD3_2026-09-21", r"E:\ANALISE_HD"]))
        res = scan_protected_zips(sources, dest_root, senhas_path)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.zip_path and args.ignore:
        res = ignore_zip_in_audit(Path(args.zip_path), dest_root, str(args.reason))
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.zip_path:
        res = unlock_zip_to_dest(
            zip_path=Path(args.zip_path),
            dest_root=dest_root,
            password=args.password,
            use_lookup=bool(args.use_lookup),
            senhas_md_path=senhas_path,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("unlocked") else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
