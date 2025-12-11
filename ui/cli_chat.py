import argparse
import asyncio
import signal
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from crypto.keys import load_identity, public_key_to_b64
from network.discovery import DiscoveryService, PeerInfo
from network.transport import Transport

console = Console()


def resolve_peer(target: str, discovery: DiscoveryService) -> Tuple[Optional[PeerInfo], Optional[str]]:
    # Exact id
    if target in discovery.peers:
        return discovery.peers[target], None
    # Prefix match by id
    candidates = [p for pid, p in discovery.peers.items() if pid.startswith(target)]
    if len(candidates) == 1:
        return candidates[0], None
    if len(candidates) > 1:
        return None, "Peer id is ambiguous, provide more characters"
    # Name match (case-insensitive)
    name_matches = [p for p in discovery.peers.values() if p.name and p.name.lower() == target.lower()]
    if len(name_matches) == 1:
        return name_matches[0], None
    if len(name_matches) > 1:
        return None, "Peer name is ambiguous, match by id prefix"
    return None, f"Peer {target} not found via mDNS"


def _resolve_from_cache(target: str, peers_cache: Dict[str, Optional[str]]) -> Optional[str]:
    if target in peers_cache:
        return target
    candidates = [pid for pid in peers_cache if pid.startswith(target)]
    if len(candidates) == 1:
        return candidates[0]
    named = [pid for pid, name in peers_cache.items() if name and name.lower() == target.lower()]
    if len(named) == 1:
        return named[0]
    return None


async def run_chat(
    display_name: Optional[str],
    port: int,
    keys_dir: str,
    relay_host: Optional[str],
    relay_port: int,
) -> None:
    identity = load_identity(display_name=display_name, keys_dir=keys_dir)
    mode = "relay" if relay_host else "local"
    relay_transport = None
    discovery = None
    peers_cache: Dict[str, Optional[str]] = {}

    if mode == "relay":
        from network.relay_transport import RelayTransport

        async def on_message(peer_id: str, text: str, peer_name: Optional[str]) -> None:
            label = peer_name or peers_cache.get(peer_id) or peer_id[:12]
            console.print(f"[blue]<{label}>[/] {text}")

        relay_transport = RelayTransport(
            identity=identity,
            host=relay_host,
            port=relay_port,
            on_message=on_message,
        )
        await relay_transport.start()
        console.print(f"[bold green]dMess relay[/] — peer {identity.fingerprint[:12]} via {relay_host}:{relay_port}")
        console.print("Commands: /peers | /use <peer> | /send <peer> <text> | /send <text> (after /use) | /id | /exit")
    else:
        discovery = DiscoveryService(
            peer_id=identity.fingerprint,
            public_key_b64=public_key_to_b64(identity.public_key),
            port=port,
            display_name=display_name,
        )

        async def on_message(peer_id: str, text: str, peer_name: Optional[str] = None) -> None:
            name = peer_name
            if discovery and peer_id in discovery.peers:
                name = discovery.peers[peer_id].name
            label = name or peer_id[:12]
            console.print(f"[blue]<{label}>[/] {text}")

        transport = Transport(identity=identity, on_message=on_message)
        listen_port = await transport.start(port=port)
        # restart discovery with actual listen port
        discovery.port = listen_port
        await discovery.start()

        console.print(f"[bold green]dMess local[/] — peer {identity.fingerprint[:12]} listening on {listen_port}")
        console.print("Commands: /peers | /connect <peer|name|prefix> | /send <peer|name|prefix> <text> | /use <peer|name|prefix> | /connected | /id | /exit")

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, stop_event.set)
    last_peer: Optional[str] = None

    while not stop_event.is_set():
        try:
            line = await asyncio.to_thread(input, "> ")
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.startswith("/exit"):
            break
        if line.startswith("/id"):
            console.print(f"Peer id: {identity.fingerprint}")
            console.print(f"Ed25519 pub: {ed_public_key_to_b64(identity.ed_public_key)}")
            continue
        if mode == "relay":
            if line.startswith("/peers"):
                peers_cache = await relay_transport.list_peers()  # type: ignore
                if not peers_cache:
                    console.print("No peers online at relay")
                else:
                    for pid, name in peers_cache.items():
                        title = name or pid[:12]
                        console.print(f"- {title} {pid}")
                continue
            if line.startswith("/use"):
                parts = line.split()
                if len(parts) < 2:
                    console.print("Usage: /use <peer|prefix>")
                    continue
                target = parts[1]
                peer_id = _resolve_from_cache(target, peers_cache)
                if not peer_id:
                    console.print("Peer not found at relay. Try /peers first.")
                    continue
                last_peer = peer_id
                console.print(f"Default peer set to {peers_cache.get(peer_id) or peer_id[:12]}")
                continue
            if line.startswith("/send"):
                parts = line.split(maxsplit=2)
                if len(parts) == 2 and last_peer:
                    peer_id = last_peer
                    text = parts[1]
                elif len(parts) == 3:
                    target = parts[1]
                    peer_id = _resolve_from_cache(target, peers_cache)
                    if not peer_id:
                        console.print("Peer not found at relay. Run /peers to refresh.")
                        continue
                    text = parts[2]
                    last_peer = peer_id
                else:
                    console.print("Usage: /send <peer|prefix> <text> or /send <text> (after /use)")
                    continue
                try:
                    await relay_transport.send_text(peer_id, text)  # type: ignore
                except Exception as exc:
                    console.print(f"[red]Send failed:[/] {exc}")
                continue
            console.print("Unknown command. Use /peers, /use, /send, /exit")
        else:
            if line.startswith("/peers"):
                peers = discovery.peers  # type: ignore
                if not peers:
                    console.print("No peers discovered yet")
                else:
                    for peer in peers.values():
                        title = peer.name or peer.peer_id[:12]
                        console.print(f"- {title} {peer.peer_id} @ {peer.host}:{peer.port}")
                continue
            if line.startswith("/connected"):
                if not transport.connections:  # type: ignore
                    console.print("No active connections")
                else:
                    for pid, conn in transport.connections.items():  # type: ignore
                        title = conn.name or pid[:12]
                        console.print(f"* {title} {pid} (shared key set)")
                continue
            if line.startswith("/use"):
                parts = line.split()
                if len(parts) < 2:
                    console.print("Usage: /use <peer|name|prefix>")
                    continue
                peer, err = resolve_peer(parts[1], discovery)  # type: ignore
                if err:
                    console.print(err)
                    continue
                last_peer = peer.peer_id
                console.print(f"Default peer set to {peer.name or peer.peer_id[:12]}")
                continue
            if line.startswith("/connect"):
                parts = line.split()
                if len(parts) < 2:
                    console.print("Usage: /connect <peer|name|prefix>")
                    continue
                peer, err = resolve_peer(parts[1], discovery)  # type: ignore
                if err:
                    console.print(err)
                    continue
                await transport.connect(peer.peer_id, peer.host, peer.port, peer.public_key_b64)  # type: ignore
                last_peer = peer.peer_id
                console.print(f"Connected to {peer.name or peer.peer_id[:12]} at {peer.host}:{peer.port}")
                continue
            if line.startswith("/send"):
                parts = line.split(maxsplit=2)
                if len(parts) == 2 and last_peer:
                    peer_id = last_peer
                    text = parts[1]
                elif len(parts) == 3:
                    target = parts[1]
                    peer, err = resolve_peer(target, discovery)  # type: ignore
                    if err:
                        console.print(err)
                        continue
                    peer_id = peer.peer_id
                    text = parts[2]
                    last_peer = peer_id
                else:
                    console.print("Usage: /send <peer|name|prefix> <text> or /send <text> (after /use or previous send)")
                    continue
                try:
                    await transport.send_text(peer_id, text)  # type: ignore
                except Exception as exc:
                    console.print(f"[red]Send failed:[/] {exc}")
                continue
            console.print("Unknown command. Use /peers, /connected, /use, /connect, /send, /exit")

    if discovery:
        await discovery.stop()
    if mode == "local":
        await transport.stop()  # type: ignore
    if mode == "relay":
        await relay_transport.stop()  # type: ignore


def main() -> None:
    parser = argparse.ArgumentParser(description="dMess CLI (local mDNS or relay)")
    parser.add_argument("--name", help="Display name for peers", default=None)
    parser.add_argument("--port", type=int, default=0, help="Listen port (0 for random in local mode)")
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Directory to store identity keys (use a different one per peer on same machine)",
    )
    parser.add_argument("--relay-host", help="Relay server host (enables relay mode)")
    parser.add_argument("--relay-port", type=int, default=7000, help="Relay server port")
    args = parser.parse_args()
    asyncio.run(
        run_chat(
            display_name=args.name,
            port=args.port,
            keys_dir=args.keys_dir,
            relay_host=args.relay_host,
            relay_port=args.relay_port,
        )
    )


if __name__ == "__main__":
    main()
