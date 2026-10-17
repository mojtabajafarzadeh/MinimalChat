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

    async def connect(self, ws: WebSocket, user_id: int, sid: str | None = None,
                      client_ip: str = "", per_user: int = 0,
                      per_ip: int = 0) -> bool:
        """Register a socket, enforcing the connection budget atomically.

        Returns False when the budget is already spent; the socket is accepted
        and then closed with 4429 in that case, and never enters `peers`.

        Two things are deliberately in ONE critical section:

        - Check and register together. Checking in a separate call first let
          concurrent connects each observe a free slot and all register
          afterwards, so the cap was bypassable by opening sockets in parallel
          (I-02).

        - Accept and close the rejection together. Closing *before* accepting
          loses the code: the ASGI server turns it into a bare HTTP 403
          handshake rejection, which the browser reports as 1006 and cannot
          distinguish from an ordinary drop. Accepting first and then closing
          delivers the real 4429, which the client stops on instead of retrying
          forever against a limit it cannot get under.

        The budget is counted rather than incremented, so it stays correct if a
        caller ever reserves a slot and fails before registering.

        The cost is that accept() runs while the lock is held, so a burst of
        connects is serialised on that one I/O call. At this scale it is noise;
        if the app ever grew to thousands of simultaneous connects it would be
        the first thing to move, and the way to move it is to accept outside
        the lock and register under it -- which reintroduces the window above,
        so it would need a reservation counter instead of a recount.
        """
        async with self.lock:
            over_budget = False
            if per_user > 0:
                held = sum(1 for p in self.peers.values()
                           if p.get("user_id") == user_id)
                if held >= per_user:
                    over_budget = True
            if per_ip > 0 and client_ip:
                held = sum(1 for p in self.peers.values()
                           if p.get("ip") == client_ip)
                if held >= per_ip:
                    over_budget = True

            # accept() fails when the client disappears mid-handshake. That
            # is routine, not an error worth a traceback, and the socket was
            # never registered so there is nothing to clean up -- the old
            # reject() swallowed it for the same reason.
            try:
                await ws.accept()
            except Exception:
                return False
            if over_budget:
                try:
                    await ws.close(code=4429)
                except Exception:
                    pass
                return False

            self.active.add(ws)
            self.peers[ws] = {"user_id": user_id, "sid": sid, "sock": None,
                              "ip": client_ip}
        return True

    async def disconnect(self, ws: WebSocket) -> None:
        async with self.lock:
            self.active.discard(ws)
            self.peers.pop(ws, None)

    def peer(self, ws: WebSocket) -> dict:
        return self.peers.get(ws) or {}

    def online_user_ids(self) -> set[int]:
        """User ids with at least one live socket on this process.

        Only knows about connections held by THIS process, so it is accurate
        when WORKERS=1 (the default) and incomplete with several workers --
        a user connected to another worker will look offline here.
        """
        return {peer.get("user_id") for peer in self.peers.values()
                if peer.get("user_id") is not None}

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