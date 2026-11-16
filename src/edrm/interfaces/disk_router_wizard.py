"""Roteador inteligente Cross-Disk entre HDs e Assistente Interativo CLI (Delta v2.2)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import shutil
import stat
from typing import Callable

from edrm.shared_kernel.exceptions import InvalidForensicValueError, WorkspaceOverlapError
from edrm.shared_kernel.value_objects import SafeOsPath

IGNORED_POSIX_FS_TYPES: frozenset[str] = frozenset(
    {
        "proc",
        "sysfs",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "pstore",
        "securityfs",
        "debugfs",
        "tracefs",
        "configfs",
        "fusectl",
        "mqueue",
        "hugetlbfs",
        "autofs",
        "binfmt_misc",
        "nsfs",
        "bpf",
    }
)

ORGANIZED_DEST_SUBDIRS: tuple[str, ...] = (
    "00_GOVERNANCA_E_AUDITORIA",
    "01_BANCO_ORGANIZADO",
    "02_COFRE_OU_REFERENCIA",
    "03_RELATORIOS_E_DOSSIE",
)


@dataclass(frozen=True, slots=True)
class MountedVolumeInfo:
    """Metadados fisicos e espaco em bytes inteiros de cada volume/HD detectado."""

    mount_path: str
    label: str
    filesystem: str
    device_id: int
    total_bytes: int
    free_bytes: int
    used_bytes: int
    is_readonly_mount: bool


@dataclass(frozen=True, slots=True)
class CrossDiskRoutingPlan:
    """Plano auditavel de roteamento entre HD de Prova (--source), HD Destino (--dest) e Staging."""

    source_paths: tuple[str, ...]
    dest_root: str
    internal_engine_workspace: str
    staging_dir_effective: str
    external_staging_used: bool
    source_total_files: int
    source_total_bytes: int
    dest_free_bytes: int
    required_full_copy_bytes: int
    acquisition_strategy: str
    separate_physical_device: bool
    standardized_zones: dict[str, str]


class MountedVolumeDetector:
    """Detector multiplataforma (Windows A:-Z: e POSIX /proc/mounts) de discos e volumes conectados."""

    @classmethod
    def detect_volumes(cls) -> tuple[MountedVolumeInfo, ...]:
        """Lista todos os discos/volumes montados com bytes totais e livres exatos (int)."""
        if os.name == "nt":
            return cls._detect_windows_volumes()
        return cls._detect_posix_volumes()

    @classmethod
    def _detect_windows_volumes(cls) -> tuple[MountedVolumeInfo, ...]:
        volumes: list[MountedVolumeInfo] = []
        for code in range(ord("A"), ord("Z") + 1):
            drive = f"{chr(code)}:\\"
            p = Path(drive)
            if not p.exists():
                continue
            try:
                usage = shutil.disk_usage(drive)
                st = os.stat(drive)
            except OSError:
                continue
            label, fs_name = cls._query_windows_volume_meta(drive)
            volumes.append(
                MountedVolumeInfo(
                    mount_path=drive,
                    label=label or f"DRIVE_{chr(code)}",
                    filesystem=fs_name or "NTFS_OR_EXFAT",
                    device_id=int(st.st_dev),
                    total_bytes=int(usage.total),
                    free_bytes=int(usage.free),
                    used_bytes=int(usage.used),
                    is_readonly_mount=not os.access(drive, os.W_OK),
                )
            )
        return tuple(volumes)

    @staticmethod
    def _query_windows_volume_meta(drive: str) -> tuple[str, str]:
        try:
            import ctypes

            windll_obj = getattr(ctypes, "windll", None)
            if windll_obj is None:
                return ("", "")
            vol_buf = ctypes.create_unicode_buffer(261)
            fs_buf = ctypes.create_unicode_buffer(261)
            ok = windll_obj.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive),
                vol_buf,
                ctypes.sizeof(vol_buf),
                None,
                None,
                None,
                fs_buf,
                ctypes.sizeof(fs_buf),
            )
            if ok:
                return (str(vol_buf.value), str(fs_buf.value))
        except Exception:
            return ("", "")
        return ("", "")

    @classmethod
    def _detect_posix_volumes(cls) -> tuple[MountedVolumeInfo, ...]:
        candidates: list[tuple[str, str, str]] = []
        proc_mounts = Path("/proc/mounts")
        seen_mounts: set[str] = set()

        if proc_mounts.is_file():
            try:
                raw_lines = proc_mounts.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in raw_lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    dev_spec, mnt_raw, fs_type, opts = parts[0], parts[1], parts[2], parts[3]
                    mnt = mnt_raw.replace("\\040", " ")
                    if fs_type in IGNORED_POSIX_FS_TYPES and mnt != "/":
                        continue
                    if mnt in seen_mounts:
                        continue
                    seen_mounts.add(mnt)
                    candidates.append((mnt, dev_spec, f"{fs_type}:{opts}"))
            except OSError:
                candidates.append(("/", "rootfs", "posix:rw"))
        else:
            candidates.append(("/", "rootfs", "posix:rw"))

        for extra_dir in ("/mnt", "/media", "/Volumes"):
            ep = Path(extra_dir)
            if ep.is_dir():
                for child in sorted(ep.iterdir()):
                    c_str = str(child)
                    if child.is_dir() and c_str not in seen_mounts:
                        seen_mounts.add(c_str)
                        candidates.append((c_str, child.name, "mounted_subdir:rw"))

        volumes: list[MountedVolumeInfo] = []
        for mnt, dev_spec, fs_meta in candidates:
            mp = Path(mnt)
            if not mp.exists() or not mp.is_dir():
                continue
            try:
                usage = shutil.disk_usage(mnt)
                st = os.stat(mnt)
            except OSError:
                continue
            if int(usage.total) <= 0:
                continue
            fs_type, _, opts = fs_meta.partition(":")
            opt_tokens = set(opts.split(",")) if opts else set()
            ro_flag = ("ro" in opt_tokens) or (not os.access(mnt, os.W_OK))
            label = mp.name if mp.name else (dev_spec.rsplit("/", 1)[-1] or "ROOT")
            volumes.append(
                MountedVolumeInfo(
                    mount_path=mnt,
                    label=label,
                    filesystem=fs_type,
                    device_id=int(st.st_dev),
                    total_bytes=int(usage.total),
                    free_bytes=int(usage.free),
                    used_bytes=int(usage.used),
                    is_readonly_mount=ro_flag,
                )
            )
        return tuple(volumes)


class SmartAcquisitionPlanner:
    """Decide entre FULL_VAULT_COPY e REFERENCED_MANIFEST_STREAMING em aritmetica inteira (zero float)."""

    MIN_SAFETY_BUFFER_BYTES: int = 67_108_864  # 64 MiB fixos de margem operacional

    @classmethod
    def choose_strategy(cls, source_total_bytes: int, dest_free_bytes: int) -> tuple[str, int]:
        """Calcula folga segura inteira (120% dos dados + 64 MiB) e escolhe a estrategia."""
        if source_total_bytes < 0 or dest_free_bytes < 0:
            raise InvalidForensicValueError("Bytes de origem e espaco livre devem ser inteiros nao negativos.")
        overhead_20pct = source_total_bytes // 5
        required_for_full_copy = source_total_bytes + overhead_20pct + cls.MIN_SAFETY_BUFFER_BYTES
        if dest_free_bytes >= required_for_full_copy:
            return ("FULL_VAULT_COPY", required_for_full_copy)
        return ("REFERENCED_MANIFEST_STREAMING", required_for_full_copy)


class CrossDiskWorkspaceRouter:
    """Valida isolamento fisico/logico entre HDs e prepara roteamento Cross-Disk seguro."""

    @classmethod
    def measure_sources_readonly(cls, source_paths: tuple[str, ...]) -> tuple[int, int, tuple[Path, ...]]:
        """Soma quantidade de arquivos e bytes totais em --source usando apenas os.stat passivo."""
        if not source_paths:
            raise InvalidForensicValueError("Pelo menos um caminho --source deve ser informado.")
        resolved_sources: list[Path] = []
        total_files = 0
        total_bytes = 0
        is_win = os.name == "nt"

        for raw_src in source_paths:
            src_p = Path(raw_src).resolve()
            if not src_p.exists():
                raise InvalidForensicValueError(f"Midia de origem --source inexistente: {raw_src}")
            resolved_sources.append(src_p)
            if src_p.is_file():
                ext_f = SafeOsPath(str(src_p)).to_os_extended(is_windows=is_win)
                st = os.stat(ext_f, follow_symlinks=False)
                total_files += 1
                total_bytes += int(st.st_size)
            else:
                for item in sorted(src_p.rglob("*")):
                    if item.is_file() and not item.is_symlink():
                        ext_f = SafeOsPath(str(item)).to_os_extended(is_windows=is_win)
                        st = os.stat(ext_f, follow_symlinks=False)
                        if stat.S_ISREG(st.st_mode):
                            total_files += 1
                            total_bytes += int(st.st_size)
        return (total_files, total_bytes, tuple(resolved_sources))

    @staticmethod
    def _nearest_existing_ancestor(target: Path) -> Path:
        curr = target
        while not curr.exists():
            parent = curr.parent
            if parent == curr:
                break
            curr = parent
        return curr

    @classmethod
    def _assert_disjoint_from_sources(
        cls,
        candidate: Path,
        candidate_label: str,
        resolved_sources: tuple[Path, ...],
        strict_separate_physical_drive: bool,
    ) -> bool:
        separate_dev = True
        cand_anchor = cls._nearest_existing_ancestor(candidate)
        cand_dev = int(os.stat(cand_anchor).st_dev)

        for src in resolved_sources:
            if candidate == src or src in candidate.parents or candidate in src.parents:
                raise WorkspaceOverlapError(
                    f"TRAVA ANTI-AUTO-CONTAMINACAO: {candidate_label} ({candidate}) sobrepoe "
                    f"ou reside dentro da midia de prova --source ({src})."
                )
            src_dev = int(os.stat(src).st_dev)
            if os.name == "nt":
                same_drive = candidate.drive.upper() == src.drive.upper() and bool(src.drive)
            else:
                same_drive = cand_dev == src_dev
            if same_drive:
                separate_dev = False
                if strict_separate_physical_drive:
                    raise WorkspaceOverlapError(
                        f"TRAVA DE VOLUME FISICO SEPARADO: {candidate_label} ({candidate}) "
                        f"compartilha o mesmo dispositivo fisico da prova ({src})."
                    )
        return separate_dev

    @classmethod
    def plan_and_validate_route(
        cls,
        source_paths: tuple[str, ...],
        dest_path: str,
        staging_path: str | None = None,
        strict_separate_physical_drive: bool = False,
        simulated_dest_free_bytes: int | None = None,
    ) -> CrossDiskRoutingPlan:
        """Valida disjungao total entre HDs e calcula o plano CrossDiskRoutingPlan."""
        total_files, total_bytes, resolved_sources = cls.measure_sources_readonly(source_paths)
        dest_resolved = Path(dest_path).resolve()

        separate_dev = cls._assert_disjoint_from_sources(
            candidate=dest_resolved,
            candidate_label="--dest",
            resolved_sources=resolved_sources,
            strict_separate_physical_drive=strict_separate_physical_drive,
        )

        internal_ws = dest_resolved / "_elo_engine_workspace"
        if staging_path is not None and staging_path.strip():
            stg_resolved = Path(staging_path).resolve()
            cls._assert_disjoint_from_sources(
                candidate=stg_resolved,
                candidate_label="--staging",
                resolved_sources=resolved_sources,
                strict_separate_physical_drive=strict_separate_physical_drive,
            )
            if stg_resolved == dest_resolved:
                raise WorkspaceOverlapError("--staging dedicado nao pode coincidir com a raiz --dest.")
            staging_effective = str(stg_resolved)
            external_staging = True
        else:
            staging_effective = str(internal_ws / "staging")
            external_staging = False

        if simulated_dest_free_bytes is not None:
            free_bytes = int(simulated_dest_free_bytes)
        else:
            anchor = cls._nearest_existing_ancestor(dest_resolved)
            free_bytes = int(shutil.disk_usage(anchor).free)

        strategy, req_bytes = SmartAcquisitionPlanner.choose_strategy(
            source_total_bytes=total_bytes,
            dest_free_bytes=free_bytes,
        )

        zones = {name: str(dest_resolved / name) for name in ORGANIZED_DEST_SUBDIRS}
        return CrossDiskRoutingPlan(
            source_paths=tuple(str(p) for p in resolved_sources),
            dest_root=str(dest_resolved),
            internal_engine_workspace=str(internal_ws),
            staging_dir_effective=staging_effective,
            external_staging_used=external_staging,
            source_total_files=total_files,
            source_total_bytes=total_bytes,
            dest_free_bytes=free_bytes,
            required_full_copy_bytes=req_bytes,
            acquisition_strategy=strategy,
            separate_physical_device=separate_dev,
            standardized_zones=zones,
        )


def format_bytes_human_int(num_bytes: int) -> str:
    """Formata bytes usando apenas divisao inteira (zero float)."""
    if num_bytes >= 1_073_741_824:
        gib = num_bytes // 1_073_741_824
        rem_mib = (num_bytes % 1_073_741_824) // 1_048_576
        return f"{gib} GiB ({rem_mib} MiB)"
    if num_bytes >= 1_048_576:
        return f"{num_bytes // 1_048_576} MiB"
    if num_bytes >= 1024:
        return f"{num_bytes // 1024} KiB"
    return f"{num_bytes} B"


def run_interactive_cli_wizard(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    execute_immediately: bool = True,
) -> dict[str, object]:
    """Assistente interativo de terminal (`elo wizard`) guiando escolha de HDs e Modo Autopilot."""
    volumes = MountedVolumeDetector.detect_volumes()
    output_fn("=" * 78)
    output_fn("ELO WIZARD — ROTEADOR INTELIGENTE ENTRE HDs (ZERO TOQUE NA PROVA)")
    output_fn("=" * 78)
    for idx, vol in enumerate(volumes, start=1):
        ro_tag = "RO" if vol.is_readonly_mount else "RW"
        output_fn(
            f"  [{idx}] {vol.mount_path} | Rotulo={vol.label} | FS={vol.filesystem} ({ro_tag}) "
            f"| Livre={format_bytes_human_int(vol.free_bytes)} / Total={format_bytes_human_int(vol.total_bytes)}"
        )
    output_fn("-" * 78)

    raw_src = input_fn("1. Informe o caminho do HD/Pasta de PROVA BRUTA (--source): ").strip()
    raw_dest = input_fn("2. Informe o caminho em OUTRO HD para gravar o Caso Organizado (--dest): ").strip()
    raw_stg = input_fn("3. [Opcional] Informe um 3o HD para rascunho pesado (--staging) ou ENTER: ").strip()
    raw_case = input_fn("4. Identificador do Caso [CASO-WIZARD-EDRM]: ").strip() or "CASO-WIZARD-EDRM"
    raw_llm = (
        input_fn("5. Endpoint LLM Local [http://127.0.0.1:11434 ou ENTER p/ deterministico]: ").strip()
        or "http://127.0.0.1:11434"
    )

    plan = CrossDiskWorkspaceRouter.plan_and_validate_route(
        source_paths=(raw_src,),
        dest_path=raw_dest,
        staging_path=raw_stg if raw_stg else None,
    )
    output_fn(
        f"Plano Validado -> Estrategia={plan.acquisition_strategy} | "
        f"Arquivos={plan.source_total_files} ({format_bytes_human_int(plan.source_total_bytes)})"
    )

    result_payload: dict[str, object] = {
        "case_id": raw_case,
        "llm_endpoint": raw_llm,
        "routing_plan": asdict(plan),
    }

    if execute_immediately:
        from edrm.interfaces.ai_autopilot_agent import EloAutopilotAgent

        agent = EloAutopilotAgent()
        autopilot_res = agent.run_autopilot(
            case_id=raw_case,
            source_paths=(raw_src,),
            dest_path=raw_dest,
            staging_path=raw_stg if raw_stg else None,
            llm_endpoint=raw_llm,
        )
        result_payload["autopilot_result"] = autopilot_res

    return result_payload
