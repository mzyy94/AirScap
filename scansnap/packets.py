"""ScanSnap iX500 protocol packet definitions."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

MAGIC = b"VENS"
MAGIC_SSNR = b"ssNR"

BROADCAST_PORT = 53220
DISCOVERY_PORT = 52217
DEFAULT_DATA_PORT = 53218
DEFAULT_CONTROL_PORT = 53219
CLIENT_DISCOVERY_PORT = 55264
CLIENT_NOTIFY_PORT = 55265


class ControlCommand(IntEnum):
    REGISTER = 0x12
    CONFIGURE = 0x11
    STATUS = 0x30


class DataCommand(IntEnum):
    GET_SET = 0x06
    CONFIG = 0x08
    GET_STATUS = 0x0A
    PAGE_TRANSFER = 0x0C


class ColorMode(IntEnum):
    AUTO = 0
    COLOR = 1
    GRAY = 2
    BW = 3


class Quality(IntEnum):
    AUTO = 0
    NORMAL = 1    # 150 DPI
    FINE = 2      # 200 DPI
    SUPERFINE = 3  # 300 DPI


class PaperSize(IntEnum):
    AUTO = 0
    A4 = 1
    A5 = 2
    BUSINESS_CARD = 3
    POSTCARD = 4


# Paper dimensions in 1/1200 inch units (width, height)
PAPER_DIMENSIONS: dict[int, tuple[int, int]] = {
    PaperSize.AUTO: (0x28D0, 0x45A4),           # max scan area
    PaperSize.A4: (0x26D0, 0x36D0),             # 210mm x 297mm
    PaperSize.A5: (0x1B50, 0x26C0),             # 148mm x 210mm
    PaperSize.BUSINESS_CARD: (0x28D0, 0x1274),  # auto-width x 100mm
    PaperSize.POSTCARD: (0x1280, 0x1B50),        # 100mm x 148mm
}

_QUALITY_DPI = {Quality.AUTO: 0, Quality.NORMAL: 150, Quality.FINE: 200, Quality.SUPERFINE: 300}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip_to_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def _ip_from_bytes(b: bytes) -> str:
    return socket.inet_ntoa(b)


def _mac_to_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _null_terminated(b: bytes) -> str:
    idx = b.find(b"\x00")
    return b[:idx].decode("ascii", errors="replace") if idx >= 0 else b.decode("ascii", errors="replace")


# ---------------------------------------------------------------------------
# UDP packets
# ---------------------------------------------------------------------------

@dataclass
class BroadcastAdvertisement:
    """Scanner → broadcast (UDP:53220), 48 bytes."""
    device_ip: str = ""
    device_id: bytes = b""

    @classmethod
    def unpack(cls, data: bytes) -> BroadcastAdvertisement:
        if len(data) < 48 or data[4:8] != MAGIC:
            raise ValueError("Not a VENS broadcast")
        cmd = struct.unpack_from("!I", data, 8)[0]
        if cmd != 0x21:
            raise ValueError(f"Unexpected broadcast command: 0x{cmd:X}")
        ip = _ip_from_bytes(data[20:24])
        dev_id = data[24:30]
        return cls(device_ip=ip, device_id=dev_id)


@dataclass
class DiscoveryRequest:
    """Client → scanner (UDP:52217), 32 bytes each for VENS and ssNR."""
    client_ip: str = ""
    token: bytes = b"\x00" * 8
    client_port: int = CLIENT_DISCOVERY_PORT
    flags: int = 0x00000000  # 0=discovery, 1=heartbeat

    def pack_vens(self) -> bytes:
        return struct.pack(
            "!4sI4s8sHH8s",
            MAGIC,
            self.flags,
            _ip_to_bytes(self.client_ip),
            self.token,
            0,  # padding
            self.client_port,
            b"\x00\x10\x00\x00\x00\x00\x00\x00",
        )

    def pack_ssnr(self) -> bytes:
        return struct.pack(
            "!4sI4s8sHH8s",
            MAGIC_SSNR,
            0,
            _ip_to_bytes(self.client_ip),
            self.token,
            0,
            self.client_port,
            b"\x01\x00\x00\x00\x00\x00\x00\x00",
        )


@dataclass
class DeviceInfo:
    """Scanner → client (UDP:55264), 132 bytes."""
    paired: bool = False
    protocol_version: int = 4
    device_ip: str = ""
    data_port: int = DEFAULT_DATA_PORT
    control_port: int = DEFAULT_CONTROL_PORT
    mac: str = ""
    state: int = 0
    serial: str = ""
    name: str = ""
    client_ip: str = ""

    @classmethod
    def unpack(cls, data: bytes) -> DeviceInfo:
        if len(data) < 132 or data[0:4] != MAGIC:
            raise ValueError("Not a VENS device info")
        paired = struct.unpack_from("!H", data, 4)[0] != 0
        version = struct.unpack_from("!H", data, 8)[0]
        device_ip = _ip_from_bytes(data[16:20])
        data_port = struct.unpack_from("!H", data, 22)[0]
        control_port = struct.unpack_from("!H", data, 26)[0]
        mac = _mac_to_str(data[28:34])
        state = struct.unpack_from("!I", data, 36)[0]
        serial = _null_terminated(data[40:104])
        name = _null_terminated(data[104:120])
        client_ip_raw = data[120:124]
        client_ip = _ip_from_bytes(client_ip_raw) if client_ip_raw != b"\x00\x00\x00\x00" else ""
        return cls(
            paired=paired,
            protocol_version=version,
            device_ip=device_ip,
            data_port=data_port,
            control_port=control_port,
            mac=mac,
            state=state,
            serial=serial,
            name=name,
            client_ip=client_ip,
        )


@dataclass
class EventNotification:
    """Scanner → client (UDP:55265), 48 bytes."""
    event_type: int = 0
    event_data: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> EventNotification:
        if len(data) < 48 or data[4:8] != MAGIC:
            raise ValueError("Not a VENS notification")
        etype = struct.unpack_from("!I", data, 8)[0]
        edata = struct.unpack_from("!I", data, 16)[0]
        return cls(event_type=etype, event_data=edata)


# ---------------------------------------------------------------------------
# TCP control channel (port 53219) packets
# ---------------------------------------------------------------------------

@dataclass
class WelcomePacket:
    """Server → client, 16 bytes. Sent at start of every TCP connection."""

    @classmethod
    def unpack(cls, data: bytes) -> WelcomePacket:
        if len(data) < 16 or data[4:8] != MAGIC:
            raise ValueError("Not a VENS welcome")
        return cls()

    @staticmethod
    def size() -> int:
        return 16


@dataclass
class RegisterRequest:
    """Client → server on control channel, 32 bytes."""
    token: bytes = b"\x00" * 8
    action: int = 1  # 1 = register

    def pack(self) -> bytes:
        buf = bytearray(32)
        struct.pack_into("!I", buf, 0, 32)
        buf[4:8] = MAGIC
        struct.pack_into("!I", buf, 8, ControlCommand.REGISTER)
        struct.pack_into("!I", buf, 12, 0)
        buf[16:24] = self.token
        struct.pack_into("!I", buf, 24, self.action)
        return bytes(buf)


@dataclass
class ConfigureRequest:
    """Client → server on control channel, 384 bytes."""
    token: bytes = b"\x00" * 8
    client_ip: str = ""
    notify_port: int = CLIENT_NOTIFY_PORT
    identity: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def pack(self) -> bytes:
        buf = bytearray(384)
        struct.pack_into("!I", buf, 0, 384)
        buf[4:8] = MAGIC
        struct.pack_into("!I", buf, 8, ControlCommand.CONFIGURE)
        struct.pack_into("!I", buf, 12, 0)
        buf[16:24] = self.token
        # config fields
        struct.pack_into("!I", buf, 32, 0x00040500)
        struct.pack_into("!I", buf, 36, 0x00000001)
        struct.pack_into("!I", buf, 40, 0x00000001)
        buf[44:48] = _ip_to_bytes(self.client_ip)
        struct.pack_into("!H", buf, 48, 0)
        struct.pack_into("!H", buf, 50, self.notify_port)
        # identity string at offset 52 — pairing secret
        id_str = self.identity.encode("ascii") if self.identity else \
            "".join(self.client_ip.split(".")).encode("ascii")
        buf[52:52 + min(len(id_str), 44)] = id_str[:44]
        # date/time at offset 100
        dt = self.timestamp
        struct.pack_into("!H", buf, 100, dt.year)
        struct.pack_into("!B", buf, 102, dt.month)
        struct.pack_into("!B", buf, 103, dt.day)
        struct.pack_into("!B", buf, 104, dt.hour)
        struct.pack_into("!B", buf, 105, dt.minute)
        struct.pack_into("!B", buf, 106, dt.second)
        struct.pack_into("!I", buf, 116, 0xFFFF8170)
        return bytes(buf)


@dataclass
class StatusRequest:
    """Client → server on control channel, 32 bytes."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        buf = bytearray(32)
        struct.pack_into("!I", buf, 0, 32)
        buf[4:8] = MAGIC
        struct.pack_into("!I", buf, 8, ControlCommand.STATUS)
        buf[16:24] = self.token
        return bytes(buf)


@dataclass
class StatusResponse:
    """Server → client on control channel, 32 bytes."""
    state: int = 0

    @classmethod
    def unpack(cls, data: bytes) -> StatusResponse:
        if len(data) < 32:
            raise ValueError("Status response too short")
        state = struct.unpack_from("!I", data, 16)[0]
        return cls(state=state)


# ---------------------------------------------------------------------------
# TCP data channel (port 53218) packets
# ---------------------------------------------------------------------------

def _build_data_request(token: bytes, command: int, payload: bytes) -> bytes:
    """Build a data channel request packet."""
    length = 32 + len(payload)
    buf = bytearray(length)
    struct.pack_into("!I", buf, 0, length)
    buf[4:8] = MAGIC
    struct.pack_into("!I", buf, 8, 1)  # direction = client
    struct.pack_into("!I", buf, 12, 0)
    buf[16:24] = token
    # bytes 24-31: reserved
    struct.pack_into("!I", buf, 32, command)
    buf[36:36 + len(payload) - 4] = payload[4:] if len(payload) > 4 else b""
    # Actually, let's be more precise: the command is at offset 32,
    # and payload follows from offset 36
    return bytes(buf)


@dataclass
class DataRequest:
    """Generic data channel request builder."""
    token: bytes = b"\x00" * 8
    command: DataCommand = DataCommand.GET_SET

    def pack(self, params: bytes = b"") -> bytes:
        total = 32 + 4 + len(params)  # header(32) + command(4) + params
        buf = bytearray(total)
        struct.pack_into("!I", buf, 0, total)
        buf[4:8] = MAGIC
        struct.pack_into("!I", buf, 8, 1)  # direction = client
        struct.pack_into("!I", buf, 12, 0)
        buf[16:24] = self.token
        struct.pack_into("!I", buf, 32, self.command)
        if params:
            buf[36:36 + len(params)] = params
        return bytes(buf)


@dataclass
class GetDeviceInfoRequest:
    """cmd=0x06, sub=0x12 — get device identity."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000060,  # data size
            0x00000000,
            0x00000000,
            0x12000000,  # sub-command
            0x60000000,  # response buffer size
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class GetScanSettingsRequest:
    """cmd=0x06, sub=0xD8 — get current scan settings."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000000,
            0x00000000,
            0x00000000,
            0xD8000000,
            0x00000000,
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class GetScanParamsRequest:
    """cmd=0x06, sub=0x90 — get scanner capabilities/parameters."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000090,
            0x00000000,
            0x00000000,
            0x1201F000,
            0x90000000,
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class ScanConfig:
    """Scan configuration for SET command.

    Config byte mapping (offset relative to config data start at packet byte 64):
      +1:     duplex (0x03=duplex, 0x01=simplex)
      +2,+5:  auto_all flag (0x01 when color=auto AND quality=auto)
      +4:     multi-feed detection (0xD0=on, 0x80=off)
      +6:     multi-feed detection (0xC1=on, 0xC0=off)
      +7:     0xc1=auto color+quality, 0x80=specific
      +8:     blank page removal (0xE0=on, 0x80=off)
      +10:    0xa0=auto quality, 0x80=specified
      +11:    0xc0=bleed-through ON, 0x80=OFF
      +33:    0x10=color/gray/auto, 0x40=BW
      +34-37: resolution (uint16 x2, DPI; 0=auto)
      +38-40: color encoding (05 82 0b=color, 02 82 0b=gray, 00 03 00=BW)
      +44-45: paper width  (uint16, 1/1200 inch)
      +48-49: paper height (uint16, 1/1200 inch)
      +57:    BW flag (0x01=BW, 0x00=other)
      +60:    BW density (value + 6)
    """
    color_mode: int = ColorMode.AUTO
    quality: int = Quality.AUTO
    duplex: bool = True
    bleed_through: bool = True
    paper_size: int = PaperSize.AUTO
    bw_density: int = 0  # 0-10, only used when color_mode=BW
    multi_feed: bool = True
    blank_page_removal: bool = True

    def describe(self) -> dict[str, str]:
        """Return human-readable key-value settings."""
        dpi = _QUALITY_DPI.get(self.quality, 0)
        w, h = PAPER_DIMENSIONS.get(self.paper_size, PAPER_DIMENSIONS[PaperSize.AUTO])
        w_mm = round(w / 1200 * 25.4, 1)
        h_mm = round(h / 1200 * 25.4, 1)
        return {
            "color_mode": ColorMode(self.color_mode).name.lower(),
            "quality": f"{Quality(self.quality).name.lower()} ({dpi} dpi)" if dpi else "auto",
            "duplex": str(self.duplex).lower(),
            "bleed_through": str(self.bleed_through).lower(),
            "paper_size": f"{PaperSize(self.paper_size).name.lower()} ({w_mm}mm x {h_mm}mm)",
            "bw_density": str(self.bw_density) if self.color_mode == ColorMode.BW else "n/a",
            "multi_feed": str(self.multi_feed).lower(),
            "blank_page_removal": str(self.blank_page_removal).lower(),
        }

    def pack(self, token: bytes) -> bytes:
        """Build the scan config SET packet (cmd=0x06, sub=0xD4)."""
        is_bw = self.color_mode == ColorMode.BW
        is_gray = self.color_mode == ColorMode.GRAY
        is_auto_color = self.color_mode == ColorMode.AUTO
        is_auto_quality = self.quality == Quality.AUTO
        is_full_auto = is_auto_color and is_auto_quality
        dpi = _QUALITY_DPI.get(self.quality, 0)
        w, h = PAPER_DIMENSIONS.get(self.paper_size, PAPER_DIMENSIONS[PaperSize.AUTO])

        # Config data (80 bytes for simplex/shared, 128 for duplex with explicit back)
        config_size = 0x50  # 80 bytes — sufficient for all modes
        if self.duplex and is_full_auto:
            config_size = 0x80  # 128 bytes — includes explicit back side params

        total = 64 + config_size
        buf = bytearray(total)

        # Standard data channel header (32 bytes)
        struct.pack_into("!I", buf, 0, total)
        buf[4:8] = MAGIC
        struct.pack_into("!I", buf, 8, 1)  # direction = client
        buf[16:24] = token
        struct.pack_into("!I", buf, 32, DataCommand.GET_SET)

        # GET_SET param header (offset 36-63)
        struct.pack_into("!I", buf, 40, config_size)
        struct.pack_into("!I", buf, 48, 0xD4000000)  # sub-command 0xD4
        struct.pack_into("!I", buf, 52, config_size << 24)

        # Config data starts at offset 64
        c = 64  # config base offset

        # +1: duplex
        buf[c + 1] = 0x03 if self.duplex else 0x01
        # +2, +5: full auto flags
        buf[c + 2] = 0x01 if is_full_auto else 0x00
        buf[c + 5] = 0x01 if is_full_auto else 0x00
        # +3: BW density flag
        if is_bw and self.bw_density == 0:
            buf[c + 3] = 0x02
        elif is_full_auto:
            buf[c + 3] = 0x01
        # +4: multi-feed detection
        buf[c + 4] = 0xD0 if self.multi_feed else 0x80
        # +6: multi-feed detection
        buf[c + 6] = 0xC1 if self.multi_feed else 0xC0
        # +7: auto color flag
        buf[c + 7] = 0xC1 if is_auto_color and is_auto_quality else 0x80
        # +8: blank page removal
        buf[c + 8] = 0xE0 if self.blank_page_removal else 0x80
        # +9: constant
        buf[c + 9] = 0xC8
        # +10: auto quality
        buf[c + 10] = 0xA0 if is_auto_quality else 0x80
        # +11: bleed-through
        buf[c + 11] = 0xC0 if self.bleed_through else 0x80
        # +12: constant
        buf[c + 12] = 0x80

        # Front side params
        buf[c + 31] = 0x30
        buf[c + 33] = 0x40 if is_bw else 0x10
        struct.pack_into("!HH", buf, c + 34, dpi, dpi)
        # +38-40: color encoding
        # Third byte is 0x09 for small paper (POSTCARD), 0x0B otherwise
        _color_enc_tail = b"\x09" if self.paper_size == PaperSize.POSTCARD else b"\x0B"
        if is_gray:
            buf[c + 38:c + 41] = b"\x02\x82" + _color_enc_tail
        elif is_bw:
            buf[c + 38:c + 41] = b"\x00\x03\x00"
        else:
            buf[c + 38:c + 41] = b"\x05\x82" + _color_enc_tail
        # +44-45, +48-49: paper size
        struct.pack_into("!H", buf, c + 44, w)
        struct.pack_into("!H", buf, c + 48, h)
        # +50: constant
        buf[c + 50] = 0x04
        # +54-56: constants
        buf[c + 54:c + 57] = b"\x01\x01\x01"
        # +57: BW flag
        buf[c + 57] = 0x01 if is_bw else 0x00
        # +60: BW density value
        if is_bw:
            buf[c + 60] = 0x06 + self.bw_density

        # Back side params (only for full-auto duplex, explicit 128B config)
        if config_size == 0x80:
            bc = c + 80  # back config offset
            buf[bc + 0] = 0x01
            buf[bc + 1] = 0x10
            struct.pack_into("!HH", buf, bc + 2, dpi, dpi)
            buf[bc + 6:bc + 9] = b"\x02\x82\x0B"
            struct.pack_into("!H", buf, bc + 12, w)
            struct.pack_into("!H", buf, bc + 16, h)
            buf[bc + 18] = 0x04
            buf[bc + 22:bc + 25] = b"\x01\x01\x01"

        return bytes(buf)

    @classmethod
    def unpack(cls, data: bytes) -> ScanConfig:
        """Decode ScanConfig from raw config bytes (starting at config data, packet offset 64)."""
        duplex = data[1] == 0x03

        # Quality from resolution
        dpi = struct.unpack_from("!H", data, 34)[0]
        quality = Quality.AUTO
        for q, d in _QUALITY_DPI.items():
            if d == dpi:
                quality = q
                break

        # Color mode
        color_enc = data[38:41]
        if color_enc == b"\x02\x82\x0B":
            color_mode = ColorMode.GRAY
        elif color_enc == b"\x00\x03\x00":
            color_mode = ColorMode.BW
        elif data[7] == 0xC1 and data[10] == 0xA0:
            color_mode = ColorMode.AUTO
        else:
            color_mode = ColorMode.COLOR

        bleed_through = data[11] == 0xC0

        # Paper size from dimensions
        w = struct.unpack_from("!H", data, 44)[0]
        h = struct.unpack_from("!H", data, 48)[0]
        paper_size = PaperSize.AUTO
        for ps, (pw, ph) in PAPER_DIMENSIONS.items():
            if pw == w and ph == h:
                paper_size = ps
                break

        bw_density = max(0, data[60] - 6) if color_mode == ColorMode.BW else 0
        multi_feed = data[4] == 0xD0
        blank_page_removal = data[8] == 0xE0

        return cls(
            color_mode=color_mode,
            quality=quality,
            duplex=duplex,
            bleed_through=bleed_through,
            paper_size=paper_size,
            bw_density=bw_density,
            multi_feed=multi_feed,
            blank_page_removal=blank_page_removal,
        )


@dataclass
class ConfigRequest:
    """cmd=0x08 — scanner config."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIIII",
            0x00000000,
            0x00000004,
            0x00000000,
            0xEB000000,
            0x00040000,
            0x00000000,
            0x00000000,
            0x05010000,
        )
        return DataRequest(self.token, DataCommand.CONFIG).pack(params)


@dataclass
class GetStatusRequest:
    """cmd=0x0A — get scan status."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000020,
            0x00000000,
            0x00000000,
            0xC2000000,
            0x00000000,
            0x20000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_STATUS).pack(params)


@dataclass
class PrepareScanRequest:
    """cmd=0x06, sub=0xD5 — prepare scanner for scanning (72 bytes total)."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIIIII",
            0x00000008,
            0x00000008,
            0x00000000,
            0xD5000000,
            0x08080000,
            0x00000000,
            0x00000000,
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class WaitForScanRequest:
    """cmd=0x06, sub=0xE0 — wait for scan to start (blocks until button press)."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000000,
            0x00000000,
            0x00000000,
            0xE0000000,
            0x00000000,
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class PageTransferRequest:
    """cmd=0x0C — request a page of scan data.

    Pages are requested sequentially per sheet.  The scanner returns
    front‑side chunks (page_type=0) followed by back‑side data
    (page_type=2) for duplex scans.  ``page_num`` encodes
    ``(sheet << 8) | chunk_index``.
    """
    token: bytes = b"\x00" * 8
    page_num: int = 0   # (sheet << 8) | chunk_index
    sheet: int = 0

    def pack(self) -> bytes:
        page_flags = 0x00800400 if self.sheet % 2 == 1 else 0x00000400
        params = struct.pack(
            "!IIIIIII",
            0x00040000,  # buffer size: 256KB (must match capture for duplex)
            0x00000000,
            0x00000000,
            0x28000002,
            page_flags,
            self.page_num,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.PAGE_TRANSFER).pack(params)


@dataclass
class GetPageMetadataRequest:
    """cmd=0x06, sub=0x12 — get page metadata after transfer."""
    token: bytes = b"\x00" * 8

    def pack(self) -> bytes:
        params = struct.pack(
            "!IIIIIII",
            0x00000012,
            0x00000000,
            0x00000000,
            0x03000000,
            0x12000000,
            0x00000000,
            0x00000000,
        )
        return DataRequest(self.token, DataCommand.GET_SET).pack(params)


@dataclass
class PageHeader:
    """Response header before JPEG data, 42 bytes.

    First 4 bytes = total response length (header + JPEG data).
    JPEG size = total_length - 42.
    """
    total_length: int = 0
    page_type: int = 0  # 0=front, 2=back
    sheet: int = 0
    side: int = 0  # 0=front, 1=back

    @property
    def jpeg_size(self) -> int:
        return max(0, self.total_length - 42)

    @classmethod
    def unpack(cls, data: bytes) -> PageHeader:
        if len(data) < 42 or data[4:8] != MAGIC:
            raise ValueError("Not a page header")
        total_length = struct.unpack_from("!I", data, 0)[0]
        page_type = struct.unpack_from("!I", data, 12)[0]
        sheet = data[40]
        side = data[41]
        return cls(
            total_length=total_length, page_type=page_type,
            sheet=sheet, side=side,
        )

    @staticmethod
    def size() -> int:
        return 42
