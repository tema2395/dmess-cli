import argparse
import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Dict, Optional

log = logging.getLogger(__name__)


@dataclass
class Client:
    peer_id: str
    name: Optional[str]
    public_key: str
    sig_key: str
    writer: asyncio.StreamWriter


class RelayServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 7000) -> None:
        self.host = host
        self.port = port
        self.server: Optional[asyncio.AbstractServer] = None
        self.clients: Dict[str, Client] = {}

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        log.info("Relay server listening on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for client in list(self.clients.values()):
            client.writer.close()
            try:
                await client.writer.wait_closed()
            except Exception:
                pass
        self.clients.clear()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_host, peer_port = writer.get_extra_info("peername")[:2]
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=10)
            if not raw:
                writer.close()
                await writer.wait_closed()
                return
            data = json.loads(raw.decode("utf-8"))
            if data.get("type") != "register":
                writer.close()
                await writer.wait_closed()
                return
            peer_id = data["id"]
            name = data.get("name")
            public_key = data["public_key"]
            sig_key = data.get("sig_key", "")
            client = Client(peer_id=peer_id, name=name, public_key=public_key, sig_key=sig_key, writer=writer)
            self.clients[peer_id] = client
            log.info("Registered %s (%s:%s)", peer_id, peer_host, peer_port)
            await self._send(writer, {"type": "registered"})

            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line.decode("utf-8"))
                mtype = msg.get("type")
                if mtype == "msg":
                    await self._forward_message(peer_id, msg)
                elif mtype == "ack":
                    await self._forward_ack(peer_id, msg)
                elif mtype == "lookup":
                    await self._send_peer_info(writer, msg)
                elif mtype == "list":
                    await self._send_peers(writer, msg)
                elif mtype == "ping":
                    await self._send(writer, {"type": "pong"})
        except Exception as exc:
            log.warning("Client error (%s:%s): %s", peer_host, peer_port, exc)
        finally:
            self.clients.pop(peer_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            log.info("Disconnected %s", peer_id)

    async def _forward_message(self, sender_id: str, msg: dict) -> None:
        target_id = msg.get("to")
        target = self.clients.get(target_id)
        sender = self.clients.get(sender_id)
        if not target:
            await self._send_error(sender, f"Peer {target_id} not connected")
            return
        payload = {
            "type": "msg",
            "from": sender_id,
            "from_name": sender.name if sender else None,
            "from_pk": sender.public_key if sender else None,
            "from_sig_key": sender.sig_key if sender else None,
            "nonce": msg.get("nonce"),
            "ciphertext": msg.get("ciphertext"),
            "sig": msg.get("sig"),
        }
        await self._send(target.writer, payload)

    async def _forward_ack(self, sender_id: str, msg: dict) -> None:
        target_id = msg.get("to")
        target = self.clients.get(target_id)
        sender = self.clients.get(sender_id)
        if not target:
            await self._send_error(sender, f"Peer {target_id} not connected")
            return
        payload = {
            "type": "ack",
            "from": sender_id,
            "from_sig_key": sender.sig_key if sender else None,
            "id": msg.get("id"),
            "sig": msg.get("sig"),
        }
        await self._send(target.writer, payload)

    async def _send_peer_info(self, writer: asyncio.StreamWriter, msg: dict) -> None:
        req_id = msg.get("req_id")
        target_id = msg.get("peer_id")
        peer = self.clients.get(target_id)
        if not peer:
            await self._send(writer, {"type": "peer_info", "req_id": req_id, "found": False})
            return
        await self._send(
            writer,
            {
                "type": "peer_info",
                "req_id": req_id,
                "found": True,
                "peer_id": peer.peer_id,
                "public_key": peer.public_key,
                "name": peer.name,
                "sig_key": peer.sig_key,
            },
        )

    async def _send_peers(self, writer: asyncio.StreamWriter, msg: dict) -> None:
        req_id = msg.get("req_id")
        peers = [{"id": c.peer_id, "name": c.name} for c in self.clients.values()]
        await self._send(writer, {"type": "peers", "req_id": req_id, "peers": peers})

    async def _send_error(self, client: Optional[Client], message: str) -> None:
        if not client:
            return
        await self._send(client.writer, {"type": "error", "message": message})

    @staticmethod
    async def _send(writer: asyncio.StreamWriter, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8") + b"\n"
        writer.write(data)
        await writer.drain()


async def main() -> None:
    parser = argparse.ArgumentParser(description="dMess simple relay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7000)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    server = RelayServer(host=args.host, port=args.port)
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
