import socket
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from zeroconf import IPVersion, ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf


SERVICE_TYPE = "_dmess._tcp.local."


@dataclass
class PeerInfo:
    peer_id: str
    host: str
    port: int
    public_key_b64: str
    name: Optional[str] = None


class _Listener(ServiceListener):
    def __init__(self, on_update: Callable[[PeerInfo], None]) -> None:
        self.on_update = on_update

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        info = zeroconf.get_service_info(service_type, name)
        if not info:
            return
        peer = _service_info_to_peer(info)
        if peer:
            self.on_update(peer)

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self.add_service(zeroconf, service_type, name)

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        # No-op removal to avoid NotImplementedError from zeroconf callbacks
        return


def _service_info_to_peer(info: ServiceInfo) -> Optional[PeerInfo]:
    if not info.addresses:
        return None
    address = socket.inet_ntoa(info.addresses[0])
    peer_id = info.properties.get(b"id", b"").decode("utf-8")
    public_key_b64 = info.properties.get(b"pk", b"").decode("utf-8")
    name = info.properties.get(b"name", b"").decode("utf-8") or None
    return PeerInfo(peer_id=peer_id, host=address, port=info.port, public_key_b64=public_key_b64, name=name)


class DiscoveryService:
    """
    mDNS-based peer discovery. Broadcasts our peer id and public key, collects others.
    """

    def __init__(
        self,
        peer_id: str,
        public_key_b64: str,
        port: int,
        display_name: Optional[str] = None,
    ) -> None:
        self.peer_id = peer_id
        self.public_key_b64 = public_key_b64
        self.port = port
        self.display_name = display_name
        self.azc: Optional[AsyncZeroconf] = None
        self.browser: Optional[ServiceBrowser] = None
        self.peers: Dict[str, PeerInfo] = {}

    async def start(self) -> None:
        address = _get_local_ip()
        self.azc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        properties = {"id": self.peer_id, "pk": self.public_key_b64}
        if self.display_name:
            properties["name"] = self.display_name
        short_id = f"{self.peer_id[:12]}-{self.peer_id[-4:]}"
        info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(address)],
            port=self.port,
            properties=properties,
        )
        await self.azc.async_register_service(info)
        listener = _Listener(self._on_peer)
        self.browser = ServiceBrowser(self.azc.zeroconf, SERVICE_TYPE, listener)

    async def stop(self) -> None:
        if self.azc:
            try:
                await self.azc.async_unregister_all_services()
            finally:
                await self.azc.async_close()
        self.peers.clear()

    def _on_peer(self, peer: PeerInfo) -> None:
        if peer.peer_id == self.peer_id:
            return
        self.peers[peer.peer_id] = peer


def _get_local_ip() -> str:
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except OSError:
        return "127.0.0.1"
