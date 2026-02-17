"""TCP control channel (port 53219) — session management."""

from __future__ import annotations

import asyncio
import logging
import struct
from datetime import datetime

from scansnap.packets import (
    CLIENT_NOTIFY_PORT,
    ReserveRequest,
    ReleaseRequest,
    GetWifiStatusRequest,
    GetWifiStatusResponse,
    WelcomePacket,
)

log = logging.getLogger(__name__)


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """Read exactly n bytes from stream."""
    buf = bytearray()
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


class ControlSession:
    """Manages a TCP control channel connection to the scanner."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        # Read the welcome packet
        welcome_data = await _read_exact(reader, WelcomePacket.size())
        WelcomePacket.unpack(welcome_data)
        log.debug("Received welcome from %s:%d", self.host, self.port)
        return reader, writer

    async def _send_recv(self, data: bytes) -> bytes:
        """Open a new connection, send data, read response, close."""
        reader, writer = await self._connect()
        try:
            writer.write(data)
            await writer.drain()
            # Read response length first (4 bytes)
            len_data = await _read_exact(reader, 4)
            resp_len = int.from_bytes(len_data, "big")
            rest = await _read_exact(reader, resp_len - 4)
            return len_data + rest
        finally:
            writer.close()
            await writer.wait_closed()

    async def register(self, token: bytes) -> bytes:
        """Register with the scanner. Returns the raw response (16-byte ack)."""
        req = ReleaseRequest(token=token, action=1)
        log.info("Registering with scanner...")
        reader, writer = await self._connect()
        try:
            writer.write(req.pack())
            await writer.drain()
            # Register response is a 16-byte ack, not length-prefixed
            resp = await _read_exact(reader, 16)
            log.info("Registration response: %d bytes, hex=%s", len(resp), resp.hex())
            return resp
        finally:
            writer.close()
            await writer.wait_closed()

    async def configure(
        self,
        token: bytes,
        client_ip: str,
        notify_port: int = CLIENT_NOTIFY_PORT,
        identity: str = "",
    ) -> bytes:
        """Send client configuration to the scanner."""
        req = ReserveRequest(
            token=token,
            client_ip=client_ip,
            notify_port=notify_port,
            identity=identity,
            timestamp=datetime.now(),
        )
        log.info("Configuring session (ip=%s, port=%d)...", client_ip, notify_port)
        resp = await self._send_recv(req.pack())
        log.info("Configure response: %d bytes", len(resp))
        return resp

    async def try_configure(
        self,
        token: bytes,
        client_ip: str,
        notify_port: int = CLIENT_NOTIFY_PORT,
        identity: str = "",
    ) -> bool:
        """Send ReserveRequest and return True if accepted, False if rejected."""
        resp = await self.configure(token, client_ip, notify_port, identity)
        status = struct.unpack_from("!i", resp, 8)[0]
        if status == 0:
            log.info("Pairing accepted")
            return True
        log.info("Pairing rejected (status=%d)", status)
        return False

    async def check_status(self, token: bytes) -> GetWifiStatusResponse:
        """Check connection status."""
        req = GetWifiStatusRequest(token=token)
        resp = await self._send_recv(req.pack())
        status = GetWifiStatusResponse.unpack(resp)
        log.debug("Status: state=%d", status.state)
        return status

    async def deregister(self, token: bytes) -> bytes:
        """Deregister from the scanner."""
        req = ReleaseRequest(token=token, action=0)
        log.info("Deregistering...")
        reader, writer = await self._connect()
        try:
            writer.write(req.pack())
            await writer.drain()
            resp = await _read_exact(reader, 16)
            log.info("Deregistration response: %d bytes", len(resp))
            return resp
        finally:
            writer.close()
            await writer.wait_closed()
