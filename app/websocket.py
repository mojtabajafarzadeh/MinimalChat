"""WebSocket connection manager. One disconnected client never crashes the server.

Each socket records who it belongs to (user_id) and, in encrypted-channel
mode, the channel session id (sid). Delivery goes through _send_one, which
seals the payload with that socket's own channel key, so a private message
only ever reaches the sender and the recipient -- never a global broadcast.

Fan-out is concurrent (asyncio.gather) with a per-socket timeout: sending to
one slow client must not stall delivery to the rest, and a public broadcast to
hundreds of sockets must not monopolise the event loop.
"""
import asyncio

from fastapi import WebSocket

from . import enc

SEND_TIMEOUT = 5.0  # seconds a single socket send may take before we drop it


class ConnectionManager:
    def __init__(self) -> None:
        self.active: set[WebSocket] = set()
        self.peers: dict[WebSocket, dict] = {}
        self.lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_id: int, sid: str | None = None) -> None:
        await ws.accept()
        async with self.lock:
            self.active.add(ws)
            self.peers[ws] = {"user_id": user_id, "sid": sid, "sock": None}

    async def disconnect(self, ws: WebSocket) -> None:
        async with self.lock:
            self.active.discard(ws)
            self.peers.pop(ws, None)

    def peer(self, ws: WebSocket) -> dict:
        return self.peers.get(ws) or {}

    async def _send_one(self, ws: WebSocket, message: dict) -> None:
        peer = self.peers.get(ws) or {}
        sid = peer.get("sid")
        sock = peer.get("sock")
        try:
            if sid and sock:
                frame = {"e": enc.seal_ws(sock, message)}
            else:
                frame = message
            await asyncio.wait_for(ws.send_json(frame), timeout=SEND_TIMEOUT)
        except Exception:
            # Slow, broken or gone: drop the socket, never stall the others.
            await self.disconnect(ws)

    async def _send_all(self, connections: list, message: dict) -> None:
        if not connections:
            return
        await asyncio.gather(
            *(self._send_one(ws, message) for ws in connections),
            return_exceptions=True,
        )

    async def broadcast(self, message: dict) -> None:
        """Send to every connected client (public room only)."""
        async with self.lock:
            connections = list(self.active)
        await self._send_all(connections, message)

    async def send_to_user(self, user_id: int, message: dict) -> None:
        """Deliver only to currently connected sockets of one user."""
        async with self.lock:
            connections = [ws for ws, peer in self.peers.items()
                           if peer.get("user_id") == user_id]
        await self._send_all(connections, message)


manager = ConnectionManager()