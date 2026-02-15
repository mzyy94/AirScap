"""UDP device discovery and event notification."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct

from scansnap.packets import (
    BROADCAST_PORT,
    CLIENT_DISCOVERY_PORT,
    CLIENT_NOTIFY_PORT,
    DISCOVERY_PORT,
    MAGIC,
    BroadcastAdvertisement,
    DeviceInfo,
    DiscoveryRequest,
    EventNotification,
)

log = logging.getLogger(__name__)


def _get_local_ip() -> str:
    """Get the local IP address used for LAN communication."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.168.0.1", 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


class _BroadcastProtocol(asyncio.DatagramProtocol):
    """Receives scanner broadcast advertisements on UDP:53220."""

    def __init__(self, future: asyncio.Future[BroadcastAdvertisement]):
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            adv = BroadcastAdvertisement.unpack(data)
            log.info("Broadcast from %s: device_ip=%s", addr, adv.device_ip)
            if not self._future.done():
                self._future.set_result(adv)
        except ValueError:
            pass


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    """Sends discovery requests and receives device info on UDP:52217/55264."""

    def __init__(self, future: asyncio.Future[DeviceInfo]):
        self._future = future
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 20 or data[0:4] != MAGIC:
            return
        # Short heartbeat ACK (12 bytes) — ignore
        if len(data) == 12:
            log.debug("Heartbeat ACK from %s", addr)
            return
        # Full device info (132 bytes)
        if len(data) >= 132:
            try:
                info = DeviceInfo.unpack(data)
                log.info(
                    "Found: %s (%s) at %s  data=%d ctrl=%d",
                    info.name, info.serial, info.device_ip,
                    info.data_port, info.control_port,
                )
                if not self._future.done():
                    self._future.set_result(info)
            except ValueError as e:
                log.debug("Failed to parse device info: %s", e)

    def send_discovery(self, scanner_ip: str, token: bytes) -> None:
        local_ip = _get_local_ip()
        req = DiscoveryRequest(client_ip=local_ip, token=token)
        assert self._transport is not None
        self._transport.sendto(req.pack_vens(), (scanner_ip, DISCOVERY_PORT))
        self._transport.sendto(req.pack_ssnr(), (scanner_ip, DISCOVERY_PORT))
        log.debug("Sent discovery to %s:%d", scanner_ip, DISCOVERY_PORT)


class _NotifyProtocol(asyncio.DatagramProtocol):
    """Receives event notifications from scanner on UDP:55265."""

    def __init__(self, future: asyncio.Future[EventNotification]):
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            evt = EventNotification.unpack(data)
            log.info("Event from %s: type=%d data=0x%08X", addr, evt.event_type, evt.event_data)
            if not self._future.done():
                self._future.set_result(evt)
        except ValueError:
            pass


class ScanSnapDiscovery:
    """Discover ScanSnap devices on the local network."""

    def __init__(self) -> None:
        self.local_ip = _get_local_ip()
        self._heartbeat_task: asyncio.Task | None = None
        self._heartbeat_sock: socket.socket | None = None

    async def wait_for_broadcast(self, timeout: float = 30) -> BroadcastAdvertisement:
        """Wait for a scanner broadcast advertisement on UDP:53220."""
        loop = asyncio.get_event_loop()
        future: asyncio.Future[BroadcastAdvertisement] = loop.create_future()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", BROADCAST_PORT))
        sock.setblocking(False)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _BroadcastProtocol(future),
            sock=sock,
        )
        try:
            return await asyncio.wait_for(future, timeout)
        finally:
            transport.close()

    async def find_scanner(
        self,
        scanner_ip: str | None = None,
        token: bytes | None = None,
        timeout: float = 10,
    ) -> DeviceInfo:
        """Discover a scanner, either by IP or by listening for broadcasts."""
        if token is None:
            token = os.urandom(6) + b"\x00\x00"

        loop = asyncio.get_event_loop()
        future: asyncio.Future[DeviceInfo] = loop.create_future()

        # Bind client discovery port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", CLIENT_DISCOVERY_PORT))
        sock.setblocking(False)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _DiscoveryProtocol(future),
            sock=sock,
        )
        try:
            if scanner_ip:
                # Send directly to known IP
                protocol.send_discovery(scanner_ip, token)
            else:
                # Send discovery to limited broadcast — works across subnets
                log.info("Sending broadcast discovery...")
                protocol.send_discovery("255.255.255.255", token)
                # Also try subnet broadcast based on local IP
                parts = self.local_ip.rsplit(".", 1)
                if len(parts) == 2:
                    subnet_broadcast = parts[0] + ".255"
                    protocol.send_discovery(subnet_broadcast, token)

            return await asyncio.wait_for(future, timeout)
        finally:
            transport.close()

    async def start_heartbeat(
        self, scanner_ip: str, token: bytes, interval: float = 0.5,
    ) -> None:
        """Start sending periodic UDP heartbeat packets."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", CLIENT_DISCOVERY_PORT))
        sock.setblocking(False)
        self._heartbeat_sock = sock
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(scanner_ip, token, sock, interval),
        )
        log.info("Heartbeat started (every %.1fs to %s)", interval, scanner_ip)

    async def _heartbeat_loop(
        self, scanner_ip: str, token: bytes,
        sock: socket.socket, interval: float,
    ) -> None:
        req = DiscoveryRequest(
            client_ip=self.local_ip, token=token, flags=1,
        )
        packet = req.pack_vens()
        try:
            while True:
                sock.sendto(packet, (scanner_ip, DISCOVERY_PORT))
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    async def stop_heartbeat(self) -> None:
        """Stop the heartbeat task."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None
        if self._heartbeat_sock:
            self._heartbeat_sock.close()
            self._heartbeat_sock = None
        log.info("Heartbeat stopped")

    async def wait_for_button(self, timeout: float = 300) -> EventNotification:
        """Wait for a scan button press notification on UDP:55265."""
        loop = asyncio.get_event_loop()
        future: asyncio.Future[EventNotification] = loop.create_future()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", CLIENT_NOTIFY_PORT))
        sock.setblocking(False)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _NotifyProtocol(future),
            sock=sock,
        )
        try:
            return await asyncio.wait_for(future, timeout)
        finally:
            transport.close()
