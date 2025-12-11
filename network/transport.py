import asyncio
import base64
import json
import logging
import contextlib
import time
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, Optional

from crypto.e2e import decrypt_message, derive_shared_key, encrypt_message
from crypto.keys import (
    Identity,
    ed_public_key_from_b64,
    ed_public_key_to_b64,
    public_key_from_b64,
    public_key_to_b64,
)
from crypto.signatures import sign_message, verify_message

log = logging.getLogger(__name__)


@dataclass
class PeerConnection:
    peer_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    shared_key: bytes
    sig_public_b64: str
    name: Optional[str] = None
    last_pong: float = time.time()


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
        self.pending_acks: Dict[str, asyncio.Future] = {}
        self.keepalives: Dict[str, asyncio.Task] = {}

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
            await self._cleanup_connection(conn)
        self.connections.clear()
        self.keepalives.clear()

    async def connect(self, peer_id: str, host: str, port: int, peer_public_key_b64: str) -> PeerConnection:
        if peer_id in self.connections:
            return self.connections[peer_id]
        reader, writer = await asyncio.open_connection(host, port)
        hello = {
            "type": "hello",
            "id": self.identity.fingerprint,
            "public_key": public_key_to_b64(self.identity.public_key),
            "name": self.identity.display_name,
            "sig_key": ed_public_key_to_b64(self.identity.ed_public_key),
        }
        hello["sig"] = _sign_payload(hello, self.identity.ed_private_key)
        await self._send_json(writer, hello)
        raw = await asyncio.wait_for(reader.readline(), timeout=5)
        data = json.loads(raw.decode("utf-8"))
        if data.get("type") != "welcome":
            raise RuntimeError("invalid handshake")
        if data.get("public_key") and data["public_key"] != peer_public_key_b64:
            log.warning("public key mismatch for peer %s", peer_id)
        if not _verify_handshake(data, data.get("sig_key", ""), allow_missing=False):
            raise RuntimeError("handshake signature invalid")
        shared_key = derive_shared_key(
            self.identity.private_key, public_key_from_b64(data["public_key"])
        )
        conn = PeerConnection(
            peer_id=peer_id,
            reader=reader,
            writer=writer,
            shared_key=shared_key,
            sig_public_b64=data.get("sig_key", ""),
            name=data.get("name"),
        )
        self.connections[peer_id] = conn
        self.keepalives[peer_id] = asyncio.create_task(self._keepalive(conn))
        asyncio.create_task(self._recv_loop(conn))
        return conn

    async def send_text(self, peer_id: str, message: str) -> None:
        conn = self.connections.get(peer_id)
        if not conn:
            raise RuntimeError(f"peer {peer_id} not connected")
        msg_id = str(uuid.uuid4())
        nonce, ciphertext = encrypt_message(message, conn.shared_key)
        payload = {
            "type": "msg",
            "id": msg_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "sig": base64.b64encode(
                sign_message(nonce + ciphertext, self.identity.ed_private_key)
            ).decode("ascii"),
        }
        attempt = 0
        max_attempts = 3
        while attempt < max_attempts:
            await self._send_json(conn.writer, payload)
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            self.pending_acks[msg_id] = fut
            try:
                await asyncio.wait_for(fut, timeout=3)
                return
            except asyncio.TimeoutError:
                attempt += 1
                self.pending_acks.pop(msg_id, None)
                if attempt >= max_attempts:
                    raise RuntimeError("ack timeout")
                continue

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
            peer_sig_key_b64 = data.get("sig_key", "")
            shared_key = derive_shared_key(self.identity.private_key, peer_public_key)
            if not _verify_handshake(data, peer_sig_key_b64, allow_missing=False):
                writer.close()
                await writer.wait_closed()
                return
            await self._send_json(
                writer,
                {
                    "type": "welcome",
                    "id": self.identity.fingerprint,
                    "public_key": public_key_to_b64(self.identity.public_key),
                    "name": self.identity.display_name,
                    "sig_key": ed_public_key_to_b64(self.identity.ed_public_key),
                    "sig": _sign_payload(
                        {
                            "type": "welcome",
                            "id": self.identity.fingerprint,
                            "public_key": public_key_to_b64(self.identity.public_key),
                            "name": self.identity.display_name,
                            "sig_key": ed_public_key_to_b64(self.identity.ed_public_key),
                        },
                        self.identity.ed_private_key,
                    ),
                },
            )
            conn = PeerConnection(
                peer_id=peer_id,
                reader=reader,
                writer=writer,
                shared_key=shared_key,
                sig_public_b64=peer_sig_key_b64,
                name=data.get("name"),
            )
            self.connections[peer_id] = conn
            self.keepalives[peer_id] = asyncio.create_task(self._keepalive(conn))
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
                if data.get("type") == "ack":
                    ack_id = data.get("id")
                    signature_b64 = data.get("sig", "")
                    if conn.sig_public_b64 and ack_id and signature_b64:
                        sig_ok = verify_message(
                            ack_id.encode("utf-8"),
                            base64.b64decode(signature_b64),
                            ed_public_key_from_b64(conn.sig_public_b64),
                        )
                        if sig_ok:
                            fut = self.pending_acks.pop(ack_id, None)
                            if fut and not fut.done():
                                fut.set_result(True)
                    continue
                if data.get("type") == "ping":
                    await self._send_json(conn.writer, {"type": "pong"})
                    continue
                if data.get("type") == "pong":
                    conn.last_pong = time.time()
                    continue
                if data.get("type") != "msg":
                    continue
                nonce = base64.b64decode(data["nonce"])
                ciphertext = base64.b64decode(data["ciphertext"])
                signature_b64 = data.get("sig", "")
                if not conn.sig_public_b64:
                    log.warning("missing peer signature key for %s", conn.peer_id)
                    continue
                sig_ok = verify_message(
                    nonce + ciphertext,
                    base64.b64decode(signature_b64),
                    ed_public_key_from_b64(conn.sig_public_b64),
                )
                if not sig_ok:
                    log.warning("signature verification failed for peer %s", conn.peer_id)
                    continue
                plaintext = decrypt_message(nonce, ciphertext, conn.shared_key)
                await self.on_message(conn.peer_id, plaintext)
                if data.get("id"):
                    await self._send_json(
                        conn.writer,
                        {
                            "type": "ack",
                            "id": data["id"],
                            "sig": base64.b64encode(
                                sign_message(data["id"].encode("utf-8"), self.identity.ed_private_key)
                            ).decode("ascii"),
                        },
                    )
        except Exception as exc:
            log.warning("connection closed (%s): %s", conn.peer_id, exc)
        finally:
            await self._cleanup_connection(conn)

    @staticmethod
    async def _send_json(writer: asyncio.StreamWriter, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8") + b"\n"
        writer.write(data)
        await writer.drain()

    async def _cleanup_connection(self, conn: PeerConnection) -> None:
        conn.writer.close()
        with contextlib.suppress(Exception):
            await conn.writer.wait_closed()
        self.connections.pop(conn.peer_id, None)
        if conn.peer_id in self.keepalives:
            self.keepalives[conn.peer_id].cancel()
            self.keepalives.pop(conn.peer_id, None)
        for mid, fut in list(self.pending_acks.items()):
            if not fut.done():
                fut.cancel()
            self.pending_acks.pop(mid, None)

    async def _keepalive(self, conn: PeerConnection) -> None:
        try:
            while True:
                await asyncio.sleep(10)
                # if no pong for 30s, drop connection
                if time.time() - conn.last_pong > 30:
                    raise RuntimeError("keepalive timeout")
                await self._send_json(conn.writer, {"type": "ping"})
        except Exception:
            await self._cleanup_connection(conn)


def _sign_payload(payload: dict, private_key) -> str:
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return base64.b64encode(sign_message(blob, private_key)).decode("ascii")


def _verify_handshake(payload: dict, sig_key_b64: str, allow_missing: bool) -> bool:
    sig = payload.get("sig")
    if not sig:
        return allow_missing
    try:
        pub = ed_public_key_from_b64(sig_key_b64)
    except Exception:
        return False
    unsigned = {k: v for k, v in payload.items() if k != "sig"}
    blob = json.dumps(unsigned, sort_keys=True).encode("utf-8")
    return verify_message(blob, base64.b64decode(sig), pub)
