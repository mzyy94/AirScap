"""High-level Scanner API."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

from scansnap.packets import CLIENT_NOTIFY_PORT, ColorMode, ScanConfig
from scansnap.data import DataChannel
from scansnap.discovery import ScanSnapDiscovery
from scansnap.session import ControlSession

log = logging.getLogger(__name__)


class Scanner:
    """High-level interface for ScanSnap operations.

    Usage::

        scanner = Scanner(host="192.168.0.176", identity="177111643645")
        await scanner.connect()

        # Wait for button press, then scan
        pages = await scanner.scan_to_files("./output")

        await scanner.disconnect()
    """

    def __init__(
        self,
        host: str,
        data_port: int = 53218,
        control_port: int = 53219,
        token: bytes | None = None,
        identity: str = "",
    ) -> None:
        self.host = host
        self.data_port = data_port
        self.control_port = control_port
        self.token = token or os.urandom(6) + b"\x00\x00"
        self.identity = identity
        self._control = ControlSession(host, control_port)
        self._discovery = ScanSnapDiscovery()
        self._local_ip = self._discovery.local_ip
        self._connected = False

    # Identity derivation constants.
    # PasswordManager.getEncryptionBytesFromString():
    #   identity[i] = ord(password[i]) + ord(KEY[i]) + SHIFT
    _IDENTITY_KEY = "pFusCANsNapFiPfu"
    _IDENTITY_SHIFT = 11

    @staticmethod
    def password_from_serial(serial: str) -> str:
        """Derive the default scanner password from a serial number.

        The password is the last 4 characters of the serial after stripping
        trailing spaces and NUL bytes.  e.g. "iX500-AK6ABB0700" -> "0700".
        """
        s = serial.rstrip(" \x00")
        return s[-4:] if len(s) > 4 else s

    @classmethod
    def compute_identity(cls, password: str) -> str:
        """Compute pairing identity from a password."""
        key = cls._IDENTITY_KEY
        if len(password) > len(key):
            raise ValueError(
                f"Password too long (max {len(key)} chars, got {len(password)})"
            )
        return "".join(
            str(ord(c) + ord(key[i]) + cls._IDENTITY_SHIFT)
            for i, c in enumerate(password)
        )

    @classmethod
    async def pair(
        cls,
        password: str | None = None,
        identity: str | None = None,
        scanner_ip: str | None = None,
        timeout: float = 30,
    ) -> tuple[Scanner, str]:
        """Pair with a scanner using password or pre-computed identity.

        If neither *password* nor *identity* is given, the password is
        derived from the scanner serial (last 4 non-space/NUL characters).

        Returns (scanner, identity) on success.
        Raises ValueError if pairing is rejected.
        """
        if password is not None and identity is not None:
            raise ValueError("Provide password or identity, not both")

        if password is not None:
            identity = cls.compute_identity(password)
            log.info("Computed identity from password: %s", identity)

        # Step 1: UDP discovery
        discovery = ScanSnapDiscovery()
        token = os.urandom(6) + b"\x00\x00"
        info = await discovery.find_scanner(
            scanner_ip=scanner_ip, token=token, timeout=timeout,
        )
        log.info("Discovered: %s (%s) at %s", info.name, info.serial, info.device_ip)

        # Auto-derive password from serial if neither password nor identity given
        if identity is None:
            password = cls.password_from_serial(info.serial)
            identity = cls.compute_identity(password)
            log.info("Password derived from serial: %s", password)

        scanner = cls(
            host=info.device_ip,
            data_port=info.data_port,
            control_port=info.control_port,
            token=token,
            identity=identity,
        )
        scanner._discovered = True
        scanner._discovery = discovery

        # Step 2: ReserveRequest with identity — check acceptance
        accepted = await scanner._control.try_configure(
            token, scanner._local_ip, CLIENT_NOTIFY_PORT, identity=identity,
        )
        if not accepted:
            await discovery.stop_heartbeat()
            raise ValueError("Pairing rejected — wrong password")

        # Step 3: Start heartbeats
        await discovery.start_heartbeat(info.device_ip, token)
        await asyncio.sleep(0.3)

        # Step 4: Data channel setup (same as connect)
        data_ch = DataChannel(info.device_ip, info.data_port, token)
        await scanner._data_request_with_retry(data_ch.get_device_info)
        await scanner._data_request_with_retry(data_ch.get_scan_params)

        # Step 5: Control channel — status check + register
        await scanner._control.check_status(token)
        await scanner._control.register(token)

        scanner._connected = True
        log.info("Pairing complete! identity=%s", identity)

        return scanner, identity

    @classmethod
    async def discover(
        cls,
        scanner_ip: str | None = None,
        timeout: float = 30,
        identity: str = "",
    ) -> Scanner:
        """Discover a scanner and create a Scanner instance."""
        discovery = ScanSnapDiscovery()
        token = os.urandom(6) + b"\x00\x00"
        info = await discovery.find_scanner(
            scanner_ip=scanner_ip, token=token, timeout=timeout,
        )
        log.info("Discovered: %s (%s)", info.name, info.serial)
        scanner = cls(
            host=info.device_ip,
            data_port=info.data_port,
            control_port=info.control_port,
            token=token,
            identity=identity,
        )
        scanner._discovered = True
        return scanner

    async def _ensure_discovered(self) -> None:
        """Make sure we've sent UDP discovery so the scanner knows our token."""
        if getattr(self, "_discovered", False):
            return
        log.info("Sending UDP discovery to %s...", self.host)
        info = await self._discovery.find_scanner(
            scanner_ip=self.host, token=self.token, timeout=10,
        )
        log.info("Discovery OK: %s (%s)", info.name, info.serial)
        self._discovered = True

    async def _data_request_with_retry(
        self, coro_factory, retries: int = 3, delay: float = 2.0,
    ):
        """Run a data channel coroutine with retry on connection failure."""
        for attempt in range(retries):
            try:
                return await coro_factory()
            except (ConnectionError, OSError) as e:
                if attempt == retries - 1:
                    raise
                log.warning(
                    "Data channel error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt + 1, retries, e, delay,
                )
                await asyncio.sleep(delay)

    async def connect(self) -> None:
        """Establish session with the scanner."""
        await self._ensure_discovered()

        # Start heartbeats to keep session alive
        await self._discovery.start_heartbeat(self.host, self.token)

        # Give the scanner a moment to register our heartbeats
        await asyncio.sleep(0.3)

        # Configure session on control channel
        await self._control.configure(
            self.token, self._local_ip, CLIENT_NOTIFY_PORT,
            identity=self.identity,
        )
        log.info("Session configured")

        # Setup on data channel (with retry for flaky connections)
        data_ch = DataChannel(self.host, self.data_port, self.token)

        await self._data_request_with_retry(data_ch.get_device_info)
        log.info("Device info OK")

        status = await self._control.check_status(self.token)
        log.info("Status: state=%d", status.state)

        await self._data_request_with_retry(data_ch.get_scan_params)
        log.info("Scan params OK")

        await self._data_request_with_retry(data_ch.set_config)
        log.info("Config OK")

        self._connected = True

    async def scan(
        self,
        config: ScanConfig | None = None,
        wait_for_button: bool = False,
    ) -> list[tuple[int, int, bytes]]:
        """Scan and return pages.

        If ``wait_for_button`` is True, waits for a physical button press
        before starting. Otherwise, triggers the scan directly (paper must
        be in the ADF).

        Returns list of (sheet, side, jpeg_data) tuples.
        Empty pages (0-byte JPEG) are excluded.
        """
        if config is None:
            config = ScanConfig()
        if wait_for_button:
            log.info("Waiting for scan button press...")
            await self._discovery.wait_for_button()
            log.info("Button pressed!")
        log.info("Starting scan...")
        data_ch = DataChannel(self.host, self.data_port, self.token)
        pages = await data_ch.run_scan(config)
        return [(s, sd, d) for s, sd, d in pages if d]

    async def scan_to_files(
        self,
        output_dir: str | Path,
        config: ScanConfig | None = None,
        wait_for_button: bool = False,
    ) -> list[Path]:
        """Scan and save image files (JPEG or TIFF depending on color mode).

        If ``wait_for_button`` is True, waits for a physical button press
        before starting. Otherwise, triggers the scan directly (paper must
        be in the ADF).

        Empty pages (blank back sides) are not saved.
        """
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        saved: list[Path] = []

        if config is None:
            config = ScanConfig()

        is_bw = config.color_mode == ColorMode.BW

        async def on_page(sheet: int, side: int, data: bytes) -> None:
            if not data:
                return
            side_name = "front" if side == 0 else "back"
            ext = "tiff" if is_bw else "jpg"
            filename = output / f"page_{sheet:03d}_{side_name}.{ext}"
            filename.write_bytes(data)
            saved.append(filename)
            log.info("Saved: %s (%d bytes)", filename, len(data))

        if wait_for_button:
            log.info("Waiting for scan button press...")
            await self._discovery.wait_for_button()
            log.info("Button pressed!")
        log.info("Starting scan...")
        data_ch = DataChannel(self.host, self.data_port, self.token)
        await data_ch.run_scan(config, on_page=on_page)
        return saved

    async def disconnect(self) -> None:
        """Deregister from the scanner."""
        try:
            await self._control.deregister(self.token)
        except (ConnectionError, OSError) as e:
            log.warning("Deregister failed: %s", e)
        await self._discovery.stop_heartbeat()
        self._connected = False
        log.info("Disconnected")
