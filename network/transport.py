import asyncio
import base64
import json
import logging
import contextlib
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional

from crypto.e2e import decrypt_message, derive_shared_key, encrypt_message
from crypto.keys import Identity, public_key_from_b64, public_key_to_b64

log = logging.getLogger(__name__)


@dataclass
class PeerConnection:
    peer_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    shared_key: bytes
    name: Optional[str] = None


class Transport:
    """
    TCP transport with a minimal X25519/AES-GCM handshake.
    """

    def __init__(
        self,
        identity: Identity,
        on_message: Callable[[str, str], Awaitable[None]],
    ) -> None:
        self.identity = identity
        self.on_message = on_message
        self.server: Optional[asyncio.base_events.Server] = None
        self.connections: Dict[str, PeerConnection] = {}
        self.listening_port: Optional[int] = None

    async def start(self, host: str = "0.0.0.0", port: int = 0) -> int:
        self.server = await asyncio.start_server(self._handle_client, host, port)
        sockets = self.server.sockets or []
        if sockets:
            self.listening_port = sockets[0].getsockname()[1]
        return self.listening_port or port

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for conn in list(self.connections.values()):
            conn.writer.close()
            with contextlib.suppress(Exception):
                await conn.writer.wait_closed()
        self.connections.clear()

    async def connect(self, peer_id: str, host: str, port: int, peer_public_key_b64: str) -> PeerConnection:
        if peer_id in self.connections:
            return self.connections[peer_id]
        reader, writer = await asyncio.open_connection(host, port)
        await self._send_json(
            writer,
            {
                "type": "hello",
                "id": self.identity.fingerprint,
                "public_key": public_key_to_b64(self.identity.public_key),
                "name": self.identity.display_name,
            },
        )
        raw = await asyncio.wait_for(reader.readline(), timeout=5)
        data = json.loads(raw.decode("utf-8"))
        if data.get("type") != "welcome":
            raise RuntimeError("invalid handshake")
        if data.get("public_key") and data["public_key"] != peer_public_key_b64:
            log.warning("public key mismatch for peer %s", peer_id)
        shared_key = derive_shared_key(
            self.identity.private_key, public_key_from_b64(data["public_key"])
        )
        conn = PeerConnection(peer_id=peer_id, reader=reader, writer=writer, shared_key=shared_key, name=data.get("name"))
        self.connections[peer_id] = conn
        asyncio.create_task(self._recv_loop(conn))
        return conn

    async def send_text(self, peer_id: str, message: str) -> None:
        conn = self.connections.get(peer_id)
        if not conn:
            raise RuntimeError(f"peer {peer_id} not connected")
        nonce, ciphertext = encrypt_message(message, conn.shared_key)
        await self._send_json(
            conn.writer,
            {
                "type": "msg",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
        )

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            data = json.loads(raw.decode("utf-8"))
            if data.get("type") != "hello":
                writer.close()
                await writer.wait_closed()
                return
            peer_id = data["id"]
            peer_public_key = public_key_from_b64(data["public_key"])
            shared_key = derive_shared_key(self.identity.private_key, peer_public_key)
            await self._send_json(
                writer,
                {
                    "type": "welcome",
                    "id": self.identity.fingerprint,
                    "public_key": public_key_to_b64(self.identity.public_key),
                    "name": self.identity.display_name,
                },
            )
            conn = PeerConnection(peer_id=peer_id, reader=reader, writer=writer, shared_key=shared_key, name=data.get("name"))
            self.connections[peer_id] = conn
            await self._recv_loop(conn)
        except Exception as exc:
            log.warning("client handling failed: %s", exc)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            if "peer_id" in locals() and peer_id in self.connections:
                del self.connections[peer_id]

    async def _recv_loop(self, conn: PeerConnection) -> None:
        try:
            while True:
                raw = await conn.reader.readline()
                if not raw:
                    break
                data = json.loads(raw.decode("utf-8"))
                if data.get("type") != "msg":
                    continue
                nonce = base64.b64decode(data["nonce"])
                ciphertext = base64.b64decode(data["ciphertext"])
                plaintext = decrypt_message(nonce, ciphertext, conn.shared_key)
                await self.on_message(conn.peer_id, plaintext)
        except Exception as exc:
            log.warning("connection closed (%s): %s", conn.peer_id, exc)
        finally:
            conn.writer.close()
            with contextlib.suppress(Exception):
                await conn.writer.wait_closed()
            self.connections.pop(conn.peer_id, None)

    @staticmethod
    async def _send_json(writer: asyncio.StreamWriter, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8") + b"\n"
        writer.write(data)
        await writer.drain()
