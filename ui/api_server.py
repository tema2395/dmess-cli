import argparse
import asyncio
import json
import signal
import sys
from pathlib import Path
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.keys import ed_public_key_to_b64, load_identity, public_key_to_b64
from network.discovery import DiscoveryService
from network.transport import Transport
from network.relay_transport import RelayTransport


class ChatBackend:
    def __init__(self, display_name: Optional[str], keys_dir: str, relay_host: Optional[str], relay_port: int) -> None:
        self.identity = load_identity(display_name=display_name, keys_dir=keys_dir)
        self.mode = "relay" if relay_host else "local"
        self.ws_clients: List[WebSocket] = []
        self.discovery: Optional[DiscoveryService] = None
        self.transport: Optional[Transport] = None
        self.relay_transport = None
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.peers_cache: Dict[str, Optional[str]] = {}

    async def start(self, port: int) -> None:
        if self.mode == "relay":
            async def on_message(peer_id: str, text: str, peer_name: Optional[str]) -> None:
                label = peer_name or self.peers_cache.get(peer_id) or peer_id[:12]
                await self.broadcast({"type": "msg", "from": peer_id, "from_label": label, "text": text})

            self.relay_transport = RelayTransport(
                identity=self.identity,
                host=self.relay_host,  # type: ignore
                port=self.relay_port,
                on_message=on_message,
            )
            await self.relay_transport.start()
        else:
            async def on_message(peer_id: str, text: str, peer_name: Optional[str] = None) -> None:
                name = peer_name
                if self.discovery and peer_id in self.discovery.peers:
                    name = self.discovery.peers[peer_id].name
                label = name or peer_id[:12]
                await self.broadcast({"type": "msg", "from": peer_id, "from_label": label, "text": text})

            self.discovery = DiscoveryService(
                peer_id=self.identity.fingerprint,
                public_key_b64=public_key_to_b64(self.identity.public_key),
                port=port,
                display_name=self.identity.display_name,
            )
            self.transport = Transport(identity=self.identity, on_message=on_message)
            listen_port = await self.transport.start(port=port)
            self.discovery.port = listen_port
            await self.discovery.start()

    async def stop(self) -> None:
        if self.discovery:
            await self.discovery.stop()
        if self.transport:
            await self.transport.stop()
        if self.relay_transport:
            await self.relay_transport.stop()

    async def broadcast(self, payload: dict) -> None:
        stale: List[WebSocket] = []
        for ws in self.ws_clients:
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            if ws in self.ws_clients:
                self.ws_clients.remove(ws)

    async def list_peers(self) -> List[Dict[str, Optional[str]]]:
        if self.mode == "relay":
            self.peers_cache = await self.relay_transport.list_peers()  # type: ignore
            return [
                {"id": pid, "name": name, "sig_key": self.relay_transport.peer_sig_keys.get(pid)}
                for pid, name in self.peers_cache.items()
            ]
        if not self.discovery:
            return []
        return [
            {"id": p.peer_id, "name": p.name, "host": p.host, "port": p.port, "sig_key": None}
            for p in self.discovery.peers.values()
        ]

    async def send_text(self, target: str, text: str) -> None:
        if self.mode == "relay":
            peer_id = self._resolve_from_cache(target)
            if not peer_id:
                # refresh and retry
                await self.list_peers()
                peer_id = self._resolve_from_cache(target)
            if not peer_id:
                raise HTTPException(status_code=404, detail="Peer not found at relay")
            await self.relay_transport.send_text(peer_id, text)  # type: ignore
            return

        if not self.discovery or not self.transport:
            raise HTTPException(status_code=400, detail="Local transport not ready")
        peer = self._resolve_local(target)
        if not peer:
            raise HTTPException(status_code=404, detail="Peer not found via mDNS")
        if peer.peer_id not in self.transport.connections:
            await self.transport.connect(peer.peer_id, peer.host, peer.port, peer.public_key_b64)
        await self.transport.send_text(peer.peer_id, text)

    def _resolve_local(self, target: str):
        if not self.discovery:
            return None
        if target in self.discovery.peers:
            return self.discovery.peers[target]
        candidates = [p for pid, p in self.discovery.peers.items() if pid.startswith(target)]
        if len(candidates) == 1:
            return candidates[0]
        name_matches = [p for p in self.discovery.peers.values() if p.name and p.name.lower() == target.lower()]
        if len(name_matches) == 1:
            return name_matches[0]
        return None

    def _resolve_from_cache(self, target: str) -> Optional[str]:
        if target in self.peers_cache:
            return target
        candidates = [pid for pid in self.peers_cache if pid.startswith(target)]
        if len(candidates) == 1:
            return candidates[0]
        named = [pid for pid, name in self.peers_cache.items() if name and name.lower() == target.lower()]
        if len(named) == 1:
            return named[0]
        return None


def create_app(display_name: Optional[str], keys_dir: str, relay_host: Optional[str], relay_port: int, port: int) -> FastAPI:
    app = FastAPI()
    backend = ChatBackend(display_name=display_name, keys_dir=keys_dir, relay_host=relay_host, relay_port=relay_port)
    app.state.backend = backend

    @app.on_event("startup")
    async def _startup() -> None:
        await backend.start(port=port)

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await backend.stop()

    static_dir = ROOT / "frontend"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index_page():
        return FileResponse(static_dir / "index.html")

    @app.get("/api/peers")
    async def peers():
        items = await backend.list_peers()
        return JSONResponse({"peers": items})

    @app.get("/api/self")
    async def self_info():
        return {
            "peer_id": backend.identity.fingerprint,
            "mode": backend.mode,
            "sig_key": ed_public_key_to_b64(backend.identity.ed_public_key),
        }

    @app.post("/api/send")
    async def send(payload: dict):
        peer = payload.get("peer")
        text = payload.get("text")
        if not peer or not text:
            raise HTTPException(status_code=400, detail="peer and text required")
        try:
            await backend.send_text(str(peer), str(text))
        except RuntimeError as exc:
            if "ack timeout" in str(exc):
                raise HTTPException(status_code=504, detail="ack timeout (peer offline or relay unreachable)")
            raise
        return {"status": "ok"}

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        backend.ws_clients.append(websocket)
        await websocket.send_json(
            {
                "type": "welcome",
                "peer_id": backend.identity.fingerprint,
                "mode": backend.mode,
                "sig_key": ed_public_key_to_b64(backend.identity.ed_public_key),
            }
        )
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            if websocket in backend.ws_clients:
                backend.ws_clients.remove(websocket)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="dMess web API")
    parser.add_argument("--name", help="Display name", default=None)
    parser.add_argument("--keys-dir", default="keys", help="Directory for identity keys")
    parser.add_argument("--port", type=int, default=0, help="Listen port for local TCP (0 random)")
    parser.add_argument("--relay-host", help="Relay server host (enables relay mode)")
    parser.add_argument("--relay-port", type=int, default=7000, help="Relay server port")
    parser.add_argument("--http-host", default="0.0.0.0", help="HTTP bind host")
    parser.add_argument("--http-port", type=int, default=8000, help="HTTP bind port")
    args = parser.parse_args()

    app = create_app(
        display_name=args.name,
        keys_dir=args.keys_dir,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        port=args.port,
    )

    # handle Ctrl+C gracefully
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    loop.add_signal_handler(signal.SIGTERM, stop_event.set)

    config = uvicorn.Config(app, host=args.http_host, port=args.http_port, log_level="info")
    server = uvicorn.Server(config)

    async def _serve():
        await server.serve()

    loop.run_until_complete(_serve())


if __name__ == "__main__":
    main()
