import argparse
import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.keys import load_identity, public_key_to_b64
from network.discovery import DiscoveryService
from network.transport import Transport

console = Console()


async def run_chat(display_name: Optional[str], port: int, keys_dir: str) -> None:
    identity = load_identity(display_name=display_name, keys_dir=keys_dir)
    transport = Transport(identity=identity, on_message=on_message)
    listen_port = await transport.start(port=port)

    discovery = DiscoveryService(
        peer_id=identity.fingerprint,
        public_key_b64=public_key_to_b64(identity.public_key),
        port=listen_port,
        display_name=display_name,
    )
    await discovery.start()

    console.print(f"[bold green]dMess local[/] — peer {identity.fingerprint[:12]} listening on {listen_port}")
    console.print("Commands: /peers | /connect <peer_id> | /send <peer_id> <text> | /exit")

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, stop_event.set)

    while not stop_event.is_set():
        try:
            line = await asyncio.to_thread(input, "> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.startswith("/exit"):
            break
        if line.startswith("/peers"):
            peers = discovery.peers
            if not peers:
                console.print("No peers discovered yet")
            else:
                for peer in peers.values():
                    title = peer.name or peer.peer_id[:12]
                    console.print(f"- {title} {peer.peer_id} @ {peer.host}:{peer.port}")
            continue
        if line.startswith("/connect"):
            parts = line.split()
            if len(parts) < 2:
                console.print("Usage: /connect <peer_id>")
                continue
            target = parts[1]
            peer = discovery.peers.get(target)
            if not peer:
                candidates = [p for pid, p in discovery.peers.items() if pid.startswith(target)]
                if len(candidates) == 1:
                    peer = candidates[0]
                elif len(candidates) > 1:
                    console.print("Peer id is ambiguous, provide more characters")
                    continue
                else:
                    console.print(f"Peer {target} not found via mDNS")
                    continue
            await transport.connect(peer.peer_id, peer.host, peer.port, peer.public_key_b64)
            console.print(f"Connected to {peer.name or peer.peer_id[:12]} at {peer.host}:{peer.port}")
            continue
        if line.startswith("/send"):
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                console.print("Usage: /send <peer_id> <text>")
                continue
            peer_id, text = parts[1], parts[2]
            try:
                await transport.send_text(peer_id, text)
            except Exception as exc:
                console.print(f"[red]Send failed:[/] {exc}")
            continue
        console.print("Unknown command. Use /peers, /connect, /send, /exit")

    await discovery.stop()
    await transport.stop()


async def on_message(peer_id: str, text: str) -> None:
    console.print(f"[blue]<{peer_id[:12]}>[/] {text}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local-only dMess CLI (mDNS + TCP)")
    parser.add_argument("--name", help="Display name for peers", default=None)
    parser.add_argument("--port", type=int, default=0, help="Listen port (0 for random)")
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Directory to store identity keys (use a different one per peer on same machine)",
    )
    args = parser.parse_args()
    asyncio.run(run_chat(display_name=args.name, port=args.port, keys_dir=args.keys_dir))


if __name__ == "__main__":
    main()
