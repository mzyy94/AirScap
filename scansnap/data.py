"""TCP data channel (port 53218) — device queries and scan data transfer."""

from __future__ import annotations

import asyncio
import logging
import struct

from scansnap.packets import (
    ConfigRequest,
    EndScanRequest,
    GetDeviceInfoRequest,
    GetPageMetadataRequest,
    GetScanParamsRequest,
    GetScanSettingsRequest,
    GetStatusRequest,
    PageHeader,
    PageTransferRequest,
    PrepareScanRequest,
    ScanConfig,
    WaitForScanRequest,
    WelcomePacket,
)

log = logging.getLogger(__name__)


class ScanError(Exception):
    """Scanner error (no paper, hardware failure, etc.)."""


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = await reader.read(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf.extend(chunk)
    return bytes(buf)


class DataChannel:
    """A single TCP data channel connection to port 53218.

    Each logical operation (device info, scan settings, page transfer)
    uses a separate TCP connection, matching the observed protocol.
    """

    def __init__(self, host: str, port: int, token: bytes) -> None:
        self.host = host
        self.port = port
        self.token = token

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        welcome = await _read_exact(reader, WelcomePacket.size())
        WelcomePacket.unpack(welcome)
        log.debug("Data channel connected to %s:%d", self.host, self.port)
        return reader, writer

    async def _request(self, data: bytes) -> bytes:
        """Send request, read single VENS response."""
        reader, writer = await self._open()
        try:
            writer.write(data)
            await writer.drain()
            len_data = await _read_exact(reader, 4)
            resp_len = int.from_bytes(len_data, "big")
            rest = await _read_exact(reader, resp_len - 4)
            return len_data + rest
        finally:
            writer.close()
            await writer.wait_closed()

    async def get_device_info(self) -> bytes:
        """Query device identity (cmd=0x06, sub=0x12)."""
        req = GetDeviceInfoRequest(token=self.token)
        resp = await self._request(req.pack())
        log.info("Device info: %d bytes", len(resp))
        return resp

    async def get_scan_params(self) -> bytes:
        """Query scanner capabilities (cmd=0x06, sub=0x90)."""
        req = GetScanParamsRequest(token=self.token)
        return await self._request(req.pack())

    async def get_scan_settings(self) -> bytes:
        """Query current scan settings (cmd=0x06, sub=0xD8)."""
        req = GetScanSettingsRequest(token=self.token)
        return await self._request(req.pack())

    async def read_all_settings(self) -> dict[str, bytes]:
        """Query all settings-related endpoints and return raw responses."""
        queries = [
            ("device_info", self.get_device_info),
            ("scan_params", self.get_scan_params),
            ("scan_settings", self.get_scan_settings),
        ]
        results: dict[str, bytes] = {}
        for name, fn in queries:
            try:
                results[name] = await fn()
            except (ConnectionError, OSError) as e:
                log.warning("Query %s failed: %s", name, e)
                results[name] = b""
        return results

    async def set_config(self) -> bytes:
        """Send scanner config (cmd=0x08)."""
        req = ConfigRequest(token=self.token)
        return await self._request(req.pack())

    # ------------------------------------------------------------------
    # Scan session — uses a long-lived connection for the entire scan
    # ------------------------------------------------------------------

    async def run_scan(
        self,
        config: ScanConfig,
        on_page: asyncio.coroutines = None,
    ) -> list[tuple[int, int, bytes]]:
        """Execute a full scan session.

        Returns list of (sheet, side, jpeg_data) tuples.

        ``on_page`` is an optional async callback: on_page(sheet, side, jpeg_data).
        """
        reader, writer = await self._open()
        pages: list[tuple[int, int, bytes]] = []

        try:
            # Step 1: Get current settings
            writer.write(GetScanSettingsRequest(token=self.token).pack())
            await writer.drain()
            resp = await self._read_response(reader)
            log.debug("Get settings response: %d bytes", len(resp))

            # Step 2: Write scan config
            writer.write(config.pack(self.token))
            await writer.drain()
            resp = await self._read_response(reader)
            log.debug("Set config response: %d bytes, hex=%s", len(resp), resp.hex())

            # Step 3: Prepare scan (sub=0xD5)
            writer.write(PrepareScanRequest(token=self.token).pack())
            await writer.drain()
            resp = await self._read_response(reader)
            log.debug("Prepare scan response: %d bytes", len(resp))

            # Step 4: Get status — check for paper in ADF
            writer.write(GetStatusRequest(token=self.token).pack())
            await writer.drain()
            resp = await self._read_response(reader)
            log.debug("Status response: %d bytes", len(resp))

            if len(resp) >= 44:
                scan_status = struct.unpack_from("!I", resp, 40)[0]
                log.info("Scan status: 0x%08X", scan_status)
                if scan_status & 0x80:
                    raise ScanError("No paper in ADF")

            # Step 5: Wait for scan (blocks until button pressed or app trigger)
            log.info("Waiting for scan to start...")
            writer.write(WaitForScanRequest(token=self.token).pack())
            await writer.drain()
            resp = await self._read_response(reader)
            wait_status = struct.unpack_from("!I", resp, 12)[0] if len(resp) >= 16 else 0
            log.info("Scan started (wait_status=%d)", wait_status)

            # Step 6: Receive pages (chunked transfer, 256KB per chunk)
            # In duplex mode, the scanner sends front and back as separate
            # transfer "sheets": sheet N = front, sheet N+1 = back.
            physical_sheet = 0
            transfer_sheet = 0
            scanning = True
            while scanning:
                # --- Transfer one side (front, or back in duplex) ---
                sides_per_sheet = 2 if config.duplex else 1
                for side_idx in range(sides_per_sheet):
                    log.debug(
                        "Requesting page: transfer_sheet=%d side=%d",
                        transfer_sheet, side_idx,
                    )
                    jpeg_data = await self._transfer_page_chunks(
                        reader, writer, transfer_sheet,
                        back_side=side_idx == 1,
                    )
                    side_name = "front" if side_idx == 0 else "back"
                    log.info(
                        "Page: physical_sheet=%d side=%s size=%d",
                        physical_sheet, side_name, len(jpeg_data),
                    )
                    pages.append((physical_sheet, side_idx, jpeg_data))
                    if on_page:
                        await on_page(physical_sheet, side_idx, jpeg_data)

                    # Page metadata after each transfer sheet
                    writer.write(
                        GetPageMetadataRequest(token=self.token).pack(),
                    )
                    await writer.drain()
                    meta = await self._read_response(reader)
                    log.debug("Page metadata: %d bytes", len(meta))

                    transfer_sheet += 1

                # Check if more physical sheets are available
                writer.write(GetStatusRequest(token=self.token).pack())
                await writer.drain()
                status_resp = await self._read_response(reader)

                if len(status_resp) >= 44:
                    scan_status = struct.unpack_from("!I", status_resp, 40)[0]
                    log.info("Scan status: 0x%08X", scan_status)

                # Wait for next physical sheet — status != 0 means scan complete
                writer.write(WaitForScanRequest(token=self.token).pack())
                await writer.drain()
                resp = await self._read_response(reader)
                wait_status = struct.unpack_from("!I", resp, 12)[0] if len(resp) >= 16 else 0
                if wait_status != 0:
                    log.info("WaitForScan status=%d, scan complete", wait_status)
                    break

                physical_sheet += 1

            non_empty = sum(1 for _, _, d in pages if d)
            log.info("Scan finished: %d page(s) received (%d non-empty)", len(pages), non_empty)

        finally:
            # End scan session (sub=0xD6) — required to reset scanner state
            try:
                writer.write(EndScanRequest(token=self.token).pack())
                await writer.drain()
                await self._read_response(reader)
                log.debug("End scan session OK")
            except (ConnectionError, OSError):
                pass
            writer.close()
            await writer.wait_closed()

        return pages

    async def _transfer_page_chunks(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        sheet: int,
        back_side: bool = False,
    ) -> bytes:
        """Request page chunks until the full JPEG is received.

        The scanner sends data in 256KB chunks.  ``page_type=0`` means
        more chunks follow; ``page_type=2`` marks the final chunk.
        All chunks are concatenated to form one complete JPEG.
        """
        page_base = sheet << 8
        chunk = 0
        jpeg_buf = bytearray()

        while True:
            page_num = page_base | chunk
            req = PageTransferRequest(
                token=self.token, page_num=page_num, sheet=sheet,
                back_side=back_side,
            )
            writer.write(req.pack())
            await writer.drain()

            header_data = await _read_exact(reader, PageHeader.size())
            header = PageHeader.unpack(header_data)
            log.debug(
                "Chunk: page_num=0x%04X page_type=%d size=%d",
                page_num, header.page_type, header.jpeg_size,
            )

            jpeg_chunk = await _read_exact(reader, header.jpeg_size)
            jpeg_buf.extend(jpeg_chunk)

            if header.page_type == 2:
                break  # Final chunk

            chunk += 1

        log.debug("Transfer sheet %d: %d bytes in %d chunk(s)", sheet, len(jpeg_buf), chunk + 1)
        return bytes(jpeg_buf)

    async def _read_response(self, reader: asyncio.StreamReader) -> bytes:
        """Read a standard VENS response (length-prefixed)."""
        len_data = await _read_exact(reader, 4)
        resp_len = int.from_bytes(len_data, "big")
        rest = await _read_exact(reader, resp_len - 4)
        return len_data + rest
