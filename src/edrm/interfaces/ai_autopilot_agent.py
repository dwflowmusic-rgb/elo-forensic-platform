"""Agente Autopilot com IA Local Governada e Fallback Deterministico no CLI (Delta v2.2)."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from edrm.bootstrap.container import EloForensicContainer
from edrm.igrm_governance.domain import SecrecyNetworkPolicy
from edrm.interfaces.disk_router_wizard import CrossDiskWorkspaceRouter
from edrm.interfaces.organized_db_publisher import OrganizedDatabasePublisher
from edrm.shared_kernel.enums import SecrecyLevel


class EloAutopilotAgent:
    """Executa autonomamente Calibracao ISO 27041 -> Sonda -> Fases 00..08 -> Banco Organizado Cross-Disk."""

    def __init__(self, container: EloForensicContainer | None = None) -> None:
        self._container = container if container is not None else EloForensicContainer()

    @staticmethod
    def probe_local_llm_endpoint(
        llm_endpoint: str,
        secrecy_level: SecrecyLevel = SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY,
    ) -> dict[str, object]:
        """Valida soberania 127.0.0.1 e verifica disponibilidade opcional de servidor LLM local (ex.: Ollama)."""
        parsed_url = urlparse.urlparse(llm_endpoint)
        host = parsed_url.hostname or llm_endpoint
        SecrecyNetworkPolicy(secrecy_level=secrecy_level).assert_endpoint_allowed(host)
        tags_url = llm_endpoint.rstrip("/") + "/api/tags"
        req = urlrequest.Request(tags_url, method="GET")
        try:
            with urlrequest.urlopen(req, timeout=1) as resp:
                raw = resp.read(65_536).decode("utf-8", errors="replace")
                parsed = json.loads(raw)
                models = [
                    str(m.get("name", ""))
                    for m in (parsed.get("models") or [])
                    if isinstance(m, dict)
                ]
                return {
                    "mode": "LOCAL_LLM_GOVERNED",
                    "endpoint": llm_endpoint,
                    "reachable": True,
                    "detected_models": models,
                }
        except (urlerror.URLError, TimeoutError, OSError, ValueError):
            return {
                "mode": "DETERMINISTIC_HEURISTIC_FALLBACK",
                "endpoint": llm_endpoint,
                "reachable": False,
                "detected_models": [],
            }

    def run_autopilot(
        self,
        source_paths: tuple[str, ...],
        dest_path: str,
        case_id: str = "CASO-AUTOPILOT-EDRM22",
        staging_path: str | None = None,
        llm_endpoint: str = "http://127.0.0.1:11434",
        secrecy_level: SecrecyLevel = SecrecyLevel.JUDICIAL_SECRECY_LOCAL_ONLY,
        strict_separate_physical_drive: bool = False,
        simulated_dest_free_bytes: int | None = None,
    ) -> dict[str, object]:
        """Orquestra ponta a ponta a leitura somente leitura de --source e entrega organizada em --dest."""
        routing_plan = CrossDiskWorkspaceRouter.plan_and_validate_route(
            source_paths=source_paths,
            dest_path=dest_path,
            staging_path=staging_path,
            strict_separate_physical_drive=strict_separate_physical_drive,
            simulated_dest_free_bytes=simulated_dest_free_bytes,
        )

        calibration_receipt = self._container.calibrate_uc.execute()
        llm_status = self.probe_local_llm_endpoint(llm_endpoint=llm_endpoint, secrecy_level=secrecy_level)

        Path(routing_plan.dest_root).mkdir(parents=True, exist_ok=True)
        if routing_plan.external_staging_used:
            ext_stg = Path(routing_plan.staging_dir_effective)
            ext_stg.mkdir(parents=True, exist_ok=True)

        try:
            pipeline_res = self._container.plug_and_run_all(
                case_id=case_id,
                source_paths=routing_plan.source_paths,
                workspace_path=routing_plan.internal_engine_workspace,
                secrecy_level=secrecy_level,
            )

            organized_summary = OrganizedDatabasePublisher.publish(
                pipeline_result=pipeline_res,
                routing_plan=routing_plan,
            )
        finally:
            if routing_plan.external_staging_used:
                ext_stg_clean = Path(routing_plan.staging_dir_effective)
                if ext_stg_clean.exists():
                    for child in sorted(ext_stg_clean.rglob("*"), reverse=True):
                        if child.is_file() or child.is_symlink():
                            os.chmod(str(child), 0o600)
                            child.unlink()
                        elif child.is_dir():
                            shutil.rmtree(str(child), ignore_errors=True)

        p01_final = pipeline_res.phase04.updated_phase01_bundle
        trace_payload = {
            "case_id": case_id,
            "run_id": pipeline_res.governance.run_id,
            "calibration_receipt": asdict(calibration_receipt),
            "llm_diagnostics": llm_status,
            "routing_plan": asdict(routing_plan),
            "dynamic_schemas_discovered": [asdict(ds) for ds in p01_final.discovery_blueprint.dynamic_schemas],
            "verifier_double_pass_zero_errors": pipeline_res.phase06.verifier_double_pass_zero_errors,
            "zero_source_mutation_confirmed": pipeline_res.phase08.source_pre_post_snapshot_identical,
            "organized_database": organized_summary,
        }

        trace_file = (
            Path(routing_plan.standardized_zones["00_GOVERNANCA_E_AUDITORIA"])
            / "AUTOPILOT_EXECUTION_TRACE.json"
        )
        with open(trace_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(trace_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

        return trace_payload
