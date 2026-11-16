"""Interface HTTP estritamente vinculada a 127.0.0.1 com token efemero de sessao (NIST SSDF PW.1.3 / CFOAB 001/2024)."""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
from urllib.parse import parse_qs, urlparse

from edrm.bootstrap.container import EloForensicContainer
from edrm.shared_kernel.exceptions import SecrecySocketViolationError

SESSION_TOKEN_HEADER: str = "X-ELO-Session-Token"


class ForensicLoopbackHttpServer(HTTPServer):
    """Servidor HTTP local 127.0.0.1 encapsulando container e token efemero sem estado global."""

    def __init__(
        self,
        server_address: tuple[str, int],
        container: EloForensicContainer,
        default_workspace: str = "",
        session_token: str | None = None,
    ) -> None:
        if server_address[0] != "127.0.0.1":
            raise SecrecySocketViolationError(
                f"ForensicLoopbackHttpServer aceita bind exclusivamente em 127.0.0.1: {server_address[0]!r}"
            )
        super().__init__(server_address, LocalForensicApiHandler)
        self.forensic_container = container
        self.default_workspace = default_workspace
        self.session_token: str = session_token if session_token else secrets.token_urlsafe(32)


class LocalForensicApiHandler(BaseHTTPRequestHandler):
    """Manipulador HTTP local estrito exigindo cabecalho X-ELO-Session-Token em todas as rotas."""

    def do_GET(self) -> None:
        """Processa GET /health e GET /search?q=... exigindo token de sessao valido."""
        srv = self.server
        if not isinstance(srv, ForensicLoopbackHttpServer):
            self._send_json(500, {"error": "servidor invalido"})
            return

        provided_token = self.headers.get(SESSION_TOKEN_HEADER, "")
        if not provided_token or not hmac.compare_digest(provided_token, srv.session_token):
            self._send_json(401, {"error": "X-ELO-Session-Token ausente ou invalido"})
            return

        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok", "bind": "127.0.0.1", "authenticated": True})
            return

        if parsed.path == "/search":
            qs = parse_qs(parsed.query)
            q = (qs.get("q") or [""])[0]
            ws = (qs.get("workspace") or [srv.default_workspace])[0]
            if not ws:
                self._send_json(400, {"error": "workspace obrigatorio"})
                return
            db_path = str(Path(ws).resolve() / "catalog" / "elo_forensic_catalog.sqlite")
            hits = srv.forensic_container.hybrid_search_uc.search(db_path, q, top_n=15)
            payload = [
                {
                    "chunk_id": h.chunk.chunk_id,
                    "origin_cn": h.chunk.origin_cn,
                    "locator": h.chunk.locator,
                    "rrf_score": str(h.rrf_score),
                    "text_clean": h.chunk.text_clean,
                    "origin_sha256": h.chunk.origin_sha256,
                }
                for h in hits
            ]
            self._send_json(200, {"results": payload})
            return

        self._send_json(404, {"error": "rota nao encontrada"})

    def log_message(self, format: str, *args: object) -> None:
        """Suprime escrita desnecessaria em stderr durante operacao pericial."""
        _ = (format, args)

    def _send_json(self, code: int, obj: dict[str, object]) -> None:
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def create_loopback_http_server(
    host: str = "127.0.0.1",
    port: int = 0,
    container: EloForensicContainer | None = None,
    default_workspace: str = "",
    session_token: str | None = None,
) -> ForensicLoopbackHttpServer:
    """Cria servidor HTTP local bloqueando qualquer bind fora de 127.0.0.1 e gerando X-ELO-Session-Token."""
    if host != "127.0.0.1":
        raise SecrecySocketViolationError(
            f"API Forense local recusa bind fora de 127.0.0.1: {host!r}"
        )
    resolved_container = container if container is not None else EloForensicContainer()
    return ForensicLoopbackHttpServer(
        (host, port),
        resolved_container,
        default_workspace=default_workspace,
        session_token=session_token,
    )
