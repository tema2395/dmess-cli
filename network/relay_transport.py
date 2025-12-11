import asyncio
import base64
import json
import logging
import uuid
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


class RelayTransport:
    """
    Client transport over a TCP relay server.
    """

    def __init__(
        self,
        identity: Identity,
        host: str,
        port: int,
        on_message: Callable[[str, str, Optional[str]], Awaitable[None]],
    ) -> None:
        self.identity = identity
        self.host = host
        self.port = port
        self.on_message = on_message
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.shared_keys: Dict[str, bytes] = {}
        self.peer_keys: Dict[str, str] = {}
        self.peer_sig_keys: Dict[str, str] = {}
        self.pending: Dict[str, asyncio.Future] = {}
        self.pending_acks: Dict[str, asyncio.Future] = {}
        self.keepalive_task: Optional[asyncio.Task] = None
        self.last_pong: float = 0.0

    async def start(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self._send(
            {
                "type": "register",
                "id": self.identity.fingerprint,
                "public_key": public_key_to_b64(self.identity.public_key),
                "name": self.identity.display_name,
                "sig_key": ed_public_key_to_b64(self.identity.ed_public_key),
            }
        )
        ack = await asyncio.wait_for(self.reader.readline(), timeout=5)
        data = json.loads(ack.decode("utf-8"))
        if data.get("type") != "registered":
            raise RuntimeError("Failed to register with relay")
        asyncio.create_task(self._recv_loop())
        self.keepalive_task = asyncio.create_task(self._keepalive())

    async def stop(self) -> None:
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass
        if self.keepalive_task:
            self.keepalive_task.cancel()

    async def list_peers(self) -> Dict[str, Optional[str]]:
        req_id = str(uuid.uuid4())
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self.pending[req_id] = fut
        await self._send({"type": "list", "req_id": req_id})
        result = await asyncio.wait_for(fut, timeout=5)
        peers = result.get("peers", [])
        mapped = {p["id"]: p.get("name") for p in peers}
        return mapped

    async def send_text(self, peer_id: str, message: str) -> None:
        key = await self._ensure_shared_key(peer_id)
        nonce, ciphertext = encrypt_message(message, key)
        msg_id = str(uuid.uuid4())
        payload = {
            "type": "msg",
            "to": peer_id,
            "id": msg_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "sig": base64.b64encode(
                sign_message(nonce + ciphertext, self.identity.ed_private_key)
            ).decode("ascii"),
        }
        attempt = 0
        max_attempts = 3
        timeout = 5
        while attempt < max_attempts:
            await self._send(payload)
            fut: asyncio.Future = asyncio.get_event_loop().create_future()
            self.pending_acks[msg_id] = fut
            try:
                await asyncio.wait_for(fut, timeout=timeout)
                return
            except asyncio.TimeoutError:
                attempt += 1
                self.pending_acks.pop(msg_id, None)
                if attempt >= max_attempts:
                    raise RuntimeError("ack timeout")
                continue

    async def _ensure_shared_key(self, peer_id: str) -> bytes:
        if peer_id in self.shared_keys:
            return self.shared_keys[peer_id]
        peer_pk_b64 = await self._get_peer_public_key(peer_id)
        key = derive_shared_key(self.identity.private_key, public_key_from_b64(peer_pk_b64))
        self.shared_keys[peer_id] = key
        return key

    async def _get_peer_public_key(self, peer_id: str) -> str:
        if peer_id in self.peer_keys:
            return self.peer_keys[peer_id]
        req_id = str(uuid.uuid4())
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self.pending[req_id] = fut
        await self._send({"type": "lookup", "peer_id": peer_id, "req_id": req_id})
        result = await asyncio.wait_for(fut, timeout=5)
        if not result.get("found"):
            raise RuntimeError(f"Peer {peer_id} not connected to relay")
        pk = result["public_key"]
        sig_key = result.get("sig_key")
        self.peer_keys[peer_id] = pk
        if sig_key:
            self.peer_sig_keys[peer_id] = sig_key
        return pk

    async def _recv_loop(self) -> None:
        assert self.reader
        while True:
            raw = await self.reader.readline()
            if not raw:
                break
            data = json.loads(raw.decode("utf-8"))
            mtype = data.get("type")
            if mtype in ("peer_info", "peers"):
                req_id = data.get("req_id")
                fut = self.pending.pop(req_id, None)
                if fut and not fut.done():
                    fut.set_result(data)
                continue
            if mtype == "ack":
                ack_id = data.get("id")
                sig_b64 = data.get("sig", "")
                sender_sig = data.get("from_sig_key")
                sender = data.get("from")
                if sender_sig:
                    self.peer_sig_keys[sender] = sender_sig
                if sender and ack_id and sig_b64 and sender in self.peer_sig_keys:
                    sig_ok = verify_message(
                        ack_id.encode("utf-8"),
                        base64.b64decode(sig_b64),
                        ed_public_key_from_b64(self.peer_sig_keys[sender]),
                    )
                    if sig_ok:
                        fut = self.pending_acks.pop(ack_id, None)
                        if fut and not fut.done():
                            fut.set_result(True)
                continue
            if mtype == "msg":
                sender = data["from"]
                sender_name = data.get("from_name")
                sender_pk = data.get("from_pk")
                sender_sig = data.get("from_sig_key")
                if sender_pk:
                    self.peer_keys[sender] = sender_pk
                    self.shared_keys[sender] = derive_shared_key(
                        self.identity.private_key, public_key_from_b64(sender_pk)
                    )
                if sender_sig:
                    self.peer_sig_keys[sender] = sender_sig
                key = await self._ensure_shared_key(sender)
                nonce = base64.b64decode(data["nonce"])
                ciphertext = base64.b64decode(data["ciphertext"])
                sig_b64 = data.get("sig", "")
                sig_ok = False
                if sender in self.peer_sig_keys and sig_b64:
                    sig_ok = verify_message(
                        nonce + ciphertext,
                        base64.b64decode(sig_b64),
                        ed_public_key_from_b64(self.peer_sig_keys[sender]),
                    )
                if not sig_ok:
                    log.warning("signature verification failed for relay peer %s", sender)
                    continue
                plaintext = decrypt_message(nonce, ciphertext, key)
                await self.on_message(sender, plaintext, sender_name)
                if data.get("id"):
                    await self._send(
                        {
                            "type": "ack",
                            "to": sender,
                            "id": data["id"],
                            "sig": base64.b64encode(
                                sign_message(data["id"].encode("utf-8"), self.identity.ed_private_key)
                            ).decode("ascii"),
                        }
                    )
                continue
            if mtype == "error":
                log.warning("Relay error: %s", data.get("message"))
                continue
            if mtype == "pong":
                self.last_pong = time.time()
                continue
        log.info("Relay connection closed")

    async def _send(self, payload: dict) -> None:
        if not self.writer:
            raise RuntimeError("Relay not connected")
        data = json.dumps(payload).encode("utf-8") + b"\n"
        self.writer.write(data)
        await self.writer.drain()

    async def _keepalive(self) -> None:
        self.last_pong = time.time()
        try:
            while True:
                await asyncio.sleep(10)
                if time.time() - self.last_pong > 30:
                    raise RuntimeError("relay keepalive timeout")
                await self._send({"type": "ping"})
        except Exception:
            if self.writer:
                self.writer.close()
                try:
                    await self.writer.wait_closed()
                except Exception:
                    pass
