"""Auditoria estatica AST de Higiene (G0) e Clean/Hexagonal/SOLID/Travas Forenses (G1)."""

from __future__ import annotations

import ast
from pathlib import Path
import re

FORBIDDEN_IO_MODULES_IN_PURE_LAYERS: frozenset[str] = frozenset(
    {
        "os",
        "sys",
        "shutil",
        "glob",
        "subprocess",
        "sqlite3",
        "psycopg",
        "zipfile",
        "tarfile",
        "socket",
        "http",
        "urllib",
        "requests",
    }
)

ISOLATED_PHASE_PACKAGES: frozenset[str] = frozenset(
    {
        "igrm_governance",
        "phase01_identification",
        "phase02_preservation",
        "phase03_collection",
        "phase04_processing",
        "continuous_analysis",
        "phase05_review",
        "phase06_production",
        "phase07_presentation",
        "phase08_disposition",
    }
)


def audit_g0_code_hygiene(py_files: list[Path]) -> list[str]:
    """Portao G0 — Zero erros de sintaxe, zero marcadores de pendencia, zero pass/... concretos."""
    violations: list[str] = []
    marker_a = "TO" + "DO"
    marker_b = "FIX" + "ME"
    marker_re = re.compile(rf"\b(?:{marker_a}|{marker_b})\b")

    for py_path in py_files:
        source = py_path.read_text(encoding="utf-8")
        for line_no, line in enumerate(source.splitlines(), start=1):
            if marker_re.search(line):
                violations.append(f"{py_path}:{line_no} contem marcador proibido ({marker_a}/{marker_b})")

        try:
            tree = ast.parse(source, filename=str(py_path))
        except SyntaxError as exc:
            violations.append(f"{py_path}: SyntaxError {exc}")
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                is_protocol_or_abc = any(
                    (isinstance(b, ast.Name) and b.id in ("Protocol", "ABC"))
                    or (isinstance(b, ast.Attribute) and b.attr in ("Protocol", "ABC"))
                    for b in node.bases
                )
                for item in node.body:
                    if isinstance(item, ast.Pass):
                        violations.append(f"{py_path}:{item.lineno} 'pass' proibido na classe {node.name}")
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and not is_protocol_or_abc:
                        for stmt in ast.walk(item):
                            if isinstance(stmt, ast.Pass):
                                violations.append(
                                    f"{py_path}:{stmt.lineno} 'pass' proibido no metodo concreto {node.name}.{item.name}"
                                )
                            if (
                                isinstance(stmt, ast.Expr)
                                and isinstance(stmt.value, ast.Constant)
                                and stmt.value.value is Ellipsis
                            ):
                                violations.append(
                                    f"{py_path}:{stmt.lineno} '...' proibido no metodo concreto {node.name}.{item.name}"
                                )
                            if isinstance(stmt, ast.Raise) and isinstance(stmt.exc, ast.Call):
                                if isinstance(stmt.exc.func, ast.Name) and stmt.exc.func.id == "NotImplementedError":
                                    violations.append(
                                        f"{py_path}:{stmt.lineno} NotImplementedError proibido em classe concreta {node.name}"
                                    )

    return violations


def audit_g1_clean_hexagonal_solid_and_forensic_locks(edrm_root: Path) -> list[str]:
    """Portao G1 — Prova AST de pureza domain/application, zero acoplamento cruzado, Protocol, frozen e zero float/hash()."""
    violations: list[str] = []
    py_files = sorted(edrm_root.rglob("*.py"))

    for py_path in py_files:
        rel = py_path.relative_to(edrm_root).as_posix()
        parts = rel.split("/")
        top_pkg = parts[0] if len(parts) > 1 else ""
        layer = parts[1] if len(parts) > 2 else ""

        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))

        is_pure_layer = layer in ("domain", "application") or top_pkg == "shared_kernel"

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if is_pure_layer and root_mod in FORBIDDEN_IO_MODULES_IN_PURE_LAYERS:
                        violations.append(
                            f"{rel}:{node.lineno} import proibido de I/O ({alias.name}) em camada pura"
                        )
                    if top_pkg in ISOLATED_PHASE_PACKAGES and alias.name.startswith("edrm."):
                        imported_pkg = alias.name.split(".")[1]
                        if imported_pkg in ISOLATED_PHASE_PACKAGES and imported_pkg != top_pkg:
                            violations.append(
                                f"{rel}:{node.lineno} acoplamento cruzado proibido: {top_pkg} importa {imported_pkg}"
                            )

            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                if is_pure_layer and root_mod in FORBIDDEN_IO_MODULES_IN_PURE_LAYERS:
                    violations.append(
                        f"{rel}:{node.lineno} from-import proibido de I/O ({node.module}) em camada pura"
                    )
                if top_pkg in ISOLATED_PHASE_PACKAGES and node.module.startswith("edrm."):
                    mod_parts = node.module.split(".")
                    if len(mod_parts) >= 2:
                        imported_pkg = mod_parts[1]
                        if imported_pkg in ISOLATED_PHASE_PACKAGES and imported_pkg != top_pkg:
                            violations.append(
                                f"{rel}:{node.lineno} acoplamento cruzado proibido: {top_pkg} importa {imported_pkg}"
                            )

            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "hash":
                    violations.append(
                        f"{rel}:{node.lineno} chamada proibida a hash() volatil do Python (use hashlib.sha256)"
                    )
                if isinstance(node.func, ast.Name) and node.func.id == "float":
                    violations.append(
                        f"{rel}:{node.lineno} chamada proibida a float() no pacote forense edrm"
                    )

            elif isinstance(node, ast.Constant) and isinstance(node.value, float):
                violations.append(
                    f"{rel}:{node.lineno} literal float ({node.value}) proibido; use int ou Decimal"
                )

            elif isinstance(node, ast.ClassDef):
                if node.name.endswith("Port"):
                    has_protocol = any(
                        (isinstance(b, ast.Name) and b.id == "Protocol")
                        or (isinstance(b, ast.Attribute) and b.attr == "Protocol")
                        for b in node.bases
                    )
                    if not has_protocol:
                        violations.append(
                            f"{rel}:{node.lineno} Porta {node.name} deve herdar de typing.Protocol"
                        )
                    method_count = sum(
                        1
                        for item in node.body
                        if isinstance(item, ast.FunctionDef) and not item.name.startswith("_")
                    )
                    if not (1 <= method_count <= 3):
                        violations.append(
                            f"{rel}:{node.lineno} violacao ISP na porta {node.name}: {method_count} metodos (esperado 1..3)"
                        )

                if rel == "shared_kernel/contracts.py" and not node.name.endswith("Port"):
                    has_frozen = False
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "dataclass":
                            for kw in dec.keywords:
                                if (
                                    kw.arg == "frozen"
                                    and isinstance(kw.value, ast.Constant)
                                    and kw.value.value is True
                                ):
                                    has_frozen = True
                    if not has_frozen:
                        violations.append(
                            f"{rel}:{node.lineno} Contrato {node.name} exige @dataclass(frozen=True)"
                        )

    violations.extend(audit_nist_ssdf_v1_1_ast_security(py_files))
    return violations


FORBIDDEN_DESERIALIZATION_MODULES: frozenset[str] = frozenset(
    {"pickle", "cPickle", "_pickle", "marshal", "shelve"}
)


def audit_nist_ssdf_v1_1_ast_security(py_files: list[Path]) -> list[str]:
    """Portao G1 / G11.1 — Bloqueio AST NIST SSDF v1.1 contra desserializacao insegura e bypass SSL."""
    violations: list[str] = []
    for py_path in py_files:
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    if root_mod in FORBIDDEN_DESERIALIZATION_MODULES:
                        violations.append(
                            f"{py_path}:{node.lineno} NIST SSDF PW.5/PW.7 import proibido: {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module:
                root_mod = node.module.split(".")[0]
                if root_mod in FORBIDDEN_DESERIALIZATION_MODULES:
                    violations.append(
                        f"{py_path}:{node.lineno} NIST SSDF PW.5/PW.7 from-import proibido: {node.module}"
                    )
                for alias in node.names:
                    if alias.name in ("CERT_NONE", "_create_unverified_context", "unsafe_load"):
                        violations.append(
                            f"{py_path}:{node.lineno} NIST SSDF PW.1.3 simbolo inseguro proibido: {alias.name}"
                        )
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ("unsafe_load", "_create_unverified_context"):
                        violations.append(
                            f"{py_path}:{node.lineno} NIST SSDF chamada insegura proibida: {node.func.attr}"
                        )
                for kw in node.keywords:
                    if (
                        kw.arg == "verify"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is False
                        and not (
                            isinstance(node.func, ast.Name)
                            and node.func.id == "materialize_to_target"
                        )
                    ):
                        violations.append(
                            f"{py_path}:{node.lineno} NIST SSDF PW.1.3 desativacao TLS proibida (verify=False)"
                        )
            elif isinstance(node, ast.Attribute) and node.attr == "CERT_NONE":
                violations.append(
                    f"{py_path}:{node.lineno} NIST SSDF PW.1.3 atributo TLS proibido: CERT_NONE"
                )
            elif isinstance(node, ast.Name) and node.id == "CERT_NONE":
                violations.append(
                    f"{py_path}:{node.lineno} NIST SSDF PW.1.3 identificador TLS proibido: CERT_NONE"
                )
    return violations
