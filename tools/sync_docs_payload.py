"""Empacotador deterministico da suite completa de documentacao (materialize_docs.py)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import zlib

DOC_ROOT_FILES: tuple[str, ...] = (
    "README.md",
    "CHANGELOG.md",
    "AGENTS.md",
    "OPERATORS_MANUAL.md",
)

DOC_RELATIVE_DIRS: tuple[str, ...] = (
    "docs",
)


def collect_documentation_files(repo_root: Path) -> dict[str, bytes]:
    """Coleta todos os documentos Markdown oficiais da plataforma ELO em ordem deterministica."""
    collected: dict[str, bytes] = {}
    for root_file in DOC_ROOT_FILES:
        path = repo_root / root_file
        if path.is_file():
            collected[root_file] = path.read_bytes()

    for rel_dir in DOC_RELATIVE_DIRS:
        base = repo_root / rel_dir
        if not base.is_dir():
            continue
        for item in sorted(base.rglob("*")):
            if item.is_file():
                rel_posix = item.relative_to(repo_root).as_posix()
                collected[rel_posix] = item.read_bytes()
    return collected


def build_self_contained_docs_installer_source(files_map: dict[str, bytes]) -> str:
    """Gera o codigo-fonte Python 100% autocontido de materialize_docs.py com verificacao SHA-256."""
    entries: list[dict[str, str | int]] = []
    for rel_path in sorted(files_map):
        raw = files_map[rel_path]
        entries.append(
            {
                "path": rel_path,
                "size_bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "b64": base64.b64encode(raw).decode("ascii"),
            }
        )

    packed_json = json.dumps(entries, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    compressed_b64 = base64.b64encode(zlib.compress(packed_json, level=9)).decode("ascii")
    chunks = [compressed_b64[i : i + 100] for i in range(0, len(compressed_b64), 100)]
    formatted_chunks = "\n".join(f'    "{chunk}"' for chunk in chunks)

    return f'''"""Empacotador autocontido verificado por SHA-256 da Suite Completa de Documentacao ELO."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import zlib

EMBEDDED_DOCS_BUNDLE_ZLIB_B64: str = (
{formatted_chunks}
)


def decode_embedded_docs_manifest() -> list[dict[str, object]]:
    """Descompacta o pacote documental embutido em memoria sem depender de arquivos externos."""
    compressed = base64.b64decode(EMBEDDED_DOCS_BUNDLE_ZLIB_B64.encode("ascii"))
    raw_json = zlib.decompress(compressed).decode("utf-8")
    loaded = json.loads(raw_json)
    if not isinstance(loaded, list):
        raise ValueError("Manifesto documental embutido corrompido.")
    return loaded


def materialize_docs_to_target(target_dir: Path, verify: bool = True) -> dict[str, object]:
    """Reconstroi integralmente docs/**, README.md e CHANGELOG.md em target_dir e confere SHA-256 a frio."""
    entries = decode_embedded_docs_manifest()
    target_dir.mkdir(parents=True, exist_ok=True)

    expected_hashes: dict[str, str] = {{}}
    for entry in entries:
        rel_path = str(entry["path"])
        exp_sha = str(entry["sha256"])
        raw_bytes = base64.b64decode(str(entry["b64"]).encode("ascii"))
        calc_mem_sha = hashlib.sha256(raw_bytes).hexdigest()
        if calc_mem_sha != exp_sha:
            raise ValueError(f"Divergencia interna no payload documental para {{rel_path}}")

        expected_hashes[rel_path] = exp_sha
        dest_file = target_dir / rel_path
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        with open(dest_file, "wb") as fh:
            fh.write(raw_bytes)
            fh.flush()
            os.fsync(fh.fileno())

    self_file = Path(__file__).resolve()
    if self_file.is_file():
        self_bytes = self_file.read_bytes()
        expected_hashes["materialize_docs.py"] = hashlib.sha256(self_bytes).hexdigest()
        dest_self = target_dir / "materialize_docs.py"
        if dest_self.resolve() != self_file:
            shutil.copy2(self_file, dest_self)

    manifest_lines = [f"{{sha}}  {{rel}}" for rel, sha in sorted(expected_hashes.items())]
    manifest_file = target_dir / "MANIFESTO_DOCS_SHA256.txt"
    manifest_file.write_text("\\n".join(manifest_lines) + "\\n", encoding="utf-8")

    mismatches: list[str] = []
    if verify:
        for rel_path, exp_sha in sorted(expected_hashes.items()):
            installed = target_dir / rel_path
            if not installed.is_file():
                mismatches.append(f"MISSING:{{rel_path}}")
                continue
            cold_sha = hashlib.sha256(installed.read_bytes()).hexdigest()
            if cold_sha != exp_sha:
                mismatches.append(f"MISMATCH:{{rel_path}}:{{cold_sha}}!={{exp_sha}}")

    return {{
        "target_dir": str(target_dir.resolve()),
        "materialized_docs_count": len(expected_hashes),
        "verified": (len(mismatches) == 0),
        "mismatches": mismatches,
    }}


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada CLI do empacotador autocontido da documentacao ELO."""
    parser = argparse.ArgumentParser(
        description="Empacotador Autocontido Verificado por SHA-256 da Suite Documental ELO"
    )
    parser.add_argument("--target", required=True, help="Diretorio destino para reconstrucao limpa")
    parser.add_argument("--verify", action="store_true", help="Confere SHA-256 de 100% dos documentos a frio")
    args = parser.parse_args(argv)

    report = materialize_docs_to_target(Path(args.target), verify=args.verify)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
'''


def main() -> int:
    """Sincroniza materialize_docs.py com todos os artefatos Markdown atuais do repositorio."""
    repo_root = Path(__file__).resolve().parents[1]
    files_map = collect_documentation_files(repo_root)
    installer_code = build_self_contained_docs_installer_source(files_map)
    out_path = repo_root / "materialize_docs.py"
    out_path.write_text(installer_code, encoding="utf-8")
    installer_sha = hashlib.sha256(out_path.read_bytes()).hexdigest()
    print(
        json.dumps(
            {
                "embedded_docs_count": len(files_map),
                "docs_installer_path": str(out_path),
                "docs_installer_sha256": installer_sha,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
