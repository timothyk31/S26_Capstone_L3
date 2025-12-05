#!/usr/bin/env python3
import os
import sys
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import requests
from datetime import datetime

# Config
UPSTREAM_BASE = os.environ.get("UPSTREAM_BASE", "https://openrouter.ai")
LISTEN_HOST = os.environ.get("MITM_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("MITM_PORT", "8079"))
LOG_PATH = os.environ.get("MITM_LOG", os.path.join("adaptive_qa_work", "llm_mitm.txt"))
MAX_BODY = int(os.environ.get("MITM_MAX_BODY", "200000"))  # 200KB per body

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
_log_lock = threading.Lock()

def _mask_auth(hdrs: dict) -> dict:
    out = {}
    for k, v in hdrs.items():
        if k.lower() == "authorization" and isinstance(v, str):
            if len(v) > 16:
                out[k] = v[:12] + "..." + v[-4:]
            else:
                out[k] = "***"
        else:
            out[k] = v
    return out

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def _write_log_text(text: str):
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(text)

def _extract_prompt(body_text: str) -> str:
    try:
        j = json.loads(body_text)
    except Exception:
        return body_text
    # OpenAI-style chat payload
    msgs = j.get("messages")
    if isinstance(msgs, list) and msgs:
        # Find last user message
        for m in reversed(msgs):
            if isinstance(m, dict) and m.get("role") == "user":
                content = m.get("content")
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    parts = []
                    for p in content:
                        if isinstance(p, dict):
                            t = p.get("text")
                            if isinstance(t, str):
                                parts.append(t)
                    if parts:
                        return "\n".join(parts)
                return json.dumps(content, ensure_ascii=False)
    # Fallback common keys
    if "prompt" in j:
        try:
            return j["prompt"] if isinstance(j["prompt"], str) else json.dumps(j["prompt"], ensure_ascii=False)
        except Exception:
            pass
    return body_text

def _extract_response(resp_text: str) -> str:
    try:
        j = json.loads(resp_text)
    except Exception:
        return resp_text
    # OpenAI-style chat response
    choices = j.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0] or {}
        msg = first.get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for p in content:
                if isinstance(p, dict):
                    t = p.get("text")
                    if isinstance(t, str):
                        parts.append(t)
            if parts:
                return "\n".join(parts)
        # Some providers use 'text'
        if isinstance(first.get("text"), str):
            return first["text"]
    # Fallback
    return resp_text

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b""
        body = self.rfile.read(length)
        return body

    def _forward(self, method: str):
        parsed = urlparse(self.path)
        upstream_url = f"{UPSTREAM_BASE}{self.path}"

        # Read request body
        body = self._read_body()
        req_headers = {k: v for k, v in self.headers.items()}
        # Remove hop-by-hop headers
        for h in ["Host", "Content-Length", "Connection", "Accept-Encoding"]:
            req_headers.pop(h, None)
        # Force identity encoding from upstream (no compression)
        req_headers["Accept-Encoding"] = "identity"

        # Prepare prompt preview (keep minimal)
        try:
            body_preview = body[:MAX_BODY].decode("utf-8", errors="replace")
        except Exception:
            body_preview = "<binary>"
        prompt_text = _extract_prompt(body_preview)

        # Forward
        try:
            resp = requests.request(
                method,
                upstream_url,
                headers=req_headers,
                data=body if body else None,
                stream=False,
                timeout=120,
            )
        except requests.RequestException as e:
            err = {
                "timestamp": _now(),
                "direction": "error",
                "path": self.path,
                "error": str(e),
            }
            _write_log(err)
            self.send_response(502, "Bad Gateway")
            out = f"Proxy error: {e}".encode("utf-8")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return

        # Log response body (minimal)
        resp_body = resp.content or b""
        try:
            resp_preview = resp_body[:MAX_BODY].decode("utf-8", errors="replace")
        except Exception:
            resp_preview = "<binary>"
        response_text = _extract_response(resp_preview)
        ok = 200 <= resp.status_code < 300
        # Plain text log entry
        entry = []
        entry.append("----- {} status={} success={} -----\n".format(_now(), resp.status_code, "true" if ok else "false"))
        entry.append("PROMPT:\n")
        entry.append(prompt_text if isinstance(prompt_text, str) else str(prompt_text))
        if not str(prompt_text).endswith("\n"):
            entry.append("\n")
        entry.append("\nRESPONSE:\n")
        entry.append(response_text if isinstance(response_text, str) else str(response_text))
        if not str(response_text).endswith("\n"):
            entry.append("\n")
        entry.append("\n")
        _write_log_text("".join(entry))

        # Relay response
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ("content-length", "transfer-encoding", "connection", "content-encoding"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        if resp_body:
            self.wfile.write(resp_body)

    def do_GET(self):
        return self._forward("GET")

    def do_POST(self):
        return self._forward("POST")

    def log_message(self, fmt, *args):
        # Silence default console logs; logs go to file
        return

def main():
    server = HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"MITM proxy listening on http://{LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_BASE}")
    print(f"Logging to {LOG_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()


