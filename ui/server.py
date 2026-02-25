import argparse
import json
import os
import pathlib
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

try:
    from ui import service
except Exception:  # pragma: no cover
    import service  # type: ignore

STATIC_DIR = pathlib.Path(__file__).resolve().parent / "static"
PASSCODE_ENV = "AIRG_UI_PASSCODE"


class UIHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path: str) -> str:
        path = path.split("?", 1)[0].split("#", 1)[0]
        rel = path.lstrip("/") or "index.html"
        return str((STATIC_DIR / rel).resolve())

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _require_passcode(self) -> bool:
        expected = os.environ.get(PASSCODE_ENV, "").strip()
        if not expected:
            return True
        provided = self.headers.get("X-UI-PASSCODE", "").strip()
        if provided == expected:
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
        return False

    def do_GET(self):
        if self.path == "/api/policy":
            if not self._require_passcode():
                return
            policy = service.load_policy()
            catalog = service.load_catalog()
            ok, details = service.validate_policy(policy)
            self._json(
                HTTPStatus.OK,
                {
                    "policy": policy,
                    "normalized": details.get("normalized") if ok else None,
                    "valid": ok,
                    "hash": service.policy_hash(policy),
                    "tier_map": service.command_tier_map(policy),
                    "all_commands": service.all_known_commands(policy, catalog),
                    "descriptions": service.command_descriptions(catalog),
                },
            )
            return

        if self.path == "/api/catalog":
            if not self._require_passcode():
                return
            self._json(HTTPStatus.OK, service.load_catalog())
            return

        return super().do_GET()

    def do_POST(self):
        if self.path not in {"/api/policy/validate", "/api/policy/apply"}:
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return
        if not self._require_passcode():
            return

        length = int(self.headers.get("Content-Length", "0"))
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode() or "{}")
            candidate = payload["policy"]
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON payload; expected {'policy': {...}}"})
            return

        if self.path == "/api/policy/validate":
            ok, details = service.validate_policy(candidate)
            self._json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, **details})
            return

        actor = self.headers.get("X-Actor", "local-ui")
        ok, details = service.validate_and_apply(candidate, actor=actor)
        self._json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, **details})


def main() -> None:
    parser = argparse.ArgumentParser(description="Local policy control-plane UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), UIHandler)
    print(f"Control plane UI listening on http://{args.host}:{args.port}")
    if os.environ.get(PASSCODE_ENV):
        print(f"Passcode auth enabled via {PASSCODE_ENV}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
