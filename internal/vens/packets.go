package vens

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func ipToBytes(ip string) [4]byte {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return [4]byte{}
	}
	return [4]byte{parsed[0], parsed[1], parsed[2], parsed[3]}
}

func ipFromBytes(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func macToString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// --------------------------------------------------------------------------
// packet is a helper for building binary packets with sparse field layouts.
// --------------------------------------------------------------------------

type packet []byte

func newPacket(size int) packet               { return make(packet, size) }
func (p packet) putU32(off int, v uint32)     { binary.BigEndian.PutUint32(p[off:], v) }
func (p packet) putU16(off int, v uint16)     { binary.BigEndian.PutUint16(p[off:], v) }
func (p packet) putBytes(off int, b []byte)   { copy(p[off:], b) }

// --------------------------------------------------------------------------
// Wire types — struct layout matches the on-wire format byte-for-byte.
// Padding fields (_) are zero-initialized automatically.
// Serialize/deserialize with binary.Write/Read (BigEndian).
// --------------------------------------------------------------------------

// controlHeader is the 24-byte common header for TCP control channel packets.
type controlHeader struct {
	Size    uint32   // [0:4]
	Magic   [4]byte  // [4:8]
	Command uint32   // [8:12]
	_       [4]byte  // [12:16]
	Token   [8]byte  // [16:24]
}

// releaseRequestWire is a 32-byte release packet (register/deregister session).
type releaseRequestWire struct {
	controlHeader        // [0:24]
	Action        uint32 // [24:28]
	_             [4]byte // [28:32]
}

// getWifiStatusRequestWire is a 32-byte WiFi status request packet.
type getWifiStatusRequestWire struct {
	controlHeader        // [0:24]
	_             [8]byte // [24:32]
}

// dataHeader is the 36-byte common header for TCP data channel requests.
type dataHeader struct {
	Size      uint32   // [0:4]
	Magic     [4]byte  // [4:8]
	Direction uint32   // [8:12]  1=client→scanner
	_         [4]byte  // [12:16]
	Token     [8]byte  // [16:24]
	_         [8]byte  // [24:32]
	Command   uint32   // [32:36]
}

// broadcastWire is a 48-byte scanner advertisement (UDP:53220).
type broadcastWire struct {
	_        [4]byte  // [0:4]
	Magic    [4]byte  // [4:8]
	Command  uint32   // [8:12]
	_        [8]byte  // [12:20]
	DeviceIP [4]byte  // [20:24]
	_        [24]byte // [24:48]
}

// deviceInfoWire is a 132-byte device info response (UDP:55264).
type deviceInfoWire struct {
	Magic       [4]byte  // [0:4]
	Paired      uint16   // [4:6]
	_           [10]byte // [6:16]
	DeviceIP    [4]byte  // [16:20]
	_           [2]byte  // [20:22]
	DataPort    uint16   // [22:24]
	_           [2]byte  // [24:26]
	ControlPort uint16   // [26:28]
	MAC         [6]byte  // [28:34]
	_           [2]byte  // [34:36]
	State       uint32   // [36:40]
	Serial      [64]byte // [40:104]
	Name        [16]byte // [104:120]
	ClientIP    [4]byte  // [120:124]
	_           [8]byte  // [124:132]
}

// eventNotificationWire is a 48-byte event notification (UDP:55265).
type eventNotificationWire struct {
	_         [4]byte  // [0:4]
	Magic     [4]byte  // [4:8]
	EventType uint32   // [8:12]
	_         [4]byte  // [12:16]
	EventData uint32   // [16:20]
	_         [28]byte // [20:48]
}

// pageHeaderWire is a 42-byte header preceding each JPEG data chunk.
type pageHeaderWire struct {
	TotalLength uint32   // [0:4]
	Magic       [4]byte  // [4:8]
	_           [4]byte  // [8:12]
	PageType    uint32   // [12:16]
	_           [24]byte // [16:40]
	Sheet       uint8    // [40]
	Side        uint8    // [41]
}

// --------------------------------------------------------------------------
// Serialization helpers
// --------------------------------------------------------------------------

func writeWire(v any) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, v)
	return buf.Bytes()
}

func readWire(data []byte, v any) error {
	return binary.Read(bytes.NewReader(data), binary.BigEndian, v)
}

// --------------------------------------------------------------------------
// UDP packets
// --------------------------------------------------------------------------

// ParseBroadcastAdvertisement parses a 48-byte scanner broadcast (UDP:53220).
func ParseBroadcastAdvertisement(data []byte) (deviceIP string, err error) {
	if len(data) < 48 {
		return "", errors.New("not a VENS broadcast")
	}
	var wire broadcastWire
	readWire(data[:48], &wire)
	if wire.Magic != Magic {
		return "", errors.New("not a VENS broadcast")
	}
	if wire.Command != CmdBroadcast {
		return "", fmt.Errorf("unexpected broadcast command: 0x%X", wire.Command)
	}
	return ipFromBytes(wire.DeviceIP[:]), nil
}

// MarshalDiscoveryVENS builds a 32-byte VENS discovery/heartbeat packet.
func MarshalDiscoveryVENS(clientIP string, token [8]byte, clientPort uint16, heartbeat bool) []byte {
	p := newPacket(32)
	p.putBytes(0, Magic[:])
	if heartbeat {
		p.putU32(4, 1)
	}
	ip := ipToBytes(clientIP)
	p.putBytes(8, ip[:])
	p.putBytes(12, token[:])
	p.putU16(22, clientPort)
	p[24] = 0x00
	p[25] = 0x10
	return p
}

// MarshalDiscoverySSNR builds a 32-byte ssNR companion packet.
func MarshalDiscoverySSNR(clientIP string, token [8]byte, clientPort uint16) []byte {
	p := newPacket(32)
	p.putBytes(0, MagicSSNR[:])
	ip := ipToBytes(clientIP)
	p.putBytes(8, ip[:])
	p.putBytes(12, token[:])
	p.putU16(22, clientPort)
	p[24] = 0x01
	return p
}

// ParseDeviceInfo parses a 132-byte device info response (UDP:55264).
func ParseDeviceInfo(data []byte) (*DeviceInfo, error) {
	if len(data) < 132 {
		return nil, errors.New("not a VENS device info")
	}
	var wire deviceInfoWire
	if err := readWire(data[:132], &wire); err != nil {
		return nil, fmt.Errorf("device info: %w", err)
	}
	if wire.Magic != Magic {
		return nil, errors.New("not a VENS device info")
	}
	info := &DeviceInfo{
		Paired:      wire.Paired != 0,
		DeviceIP:    ipFromBytes(wire.DeviceIP[:]),
		DataPort:    wire.DataPort,
		ControlPort: wire.ControlPort,
		MAC:         macToString(wire.MAC[:]),
		State:       wire.State,
		Serial:      nullTerminated(wire.Serial[:]),
		Name:        nullTerminated(wire.Name[:]),
	}
	if wire.ClientIP != [4]byte{} {
		info.ClientIP = ipFromBytes(wire.ClientIP[:])
	}
	return info, nil
}

// ParseEventNotification parses a 48-byte event notification (UDP:55265).
func ParseEventNotification(data []byte) (eventType uint32, eventData uint32, err error) {
	if len(data) < 48 {
		return 0, 0, errors.New("not a VENS notification")
	}
	var wire eventNotificationWire
	readWire(data[:48], &wire)
	if wire.Magic != Magic {
		return 0, 0, errors.New("not a VENS notification")
	}
	return wire.EventType, wire.EventData, nil
}

// --------------------------------------------------------------------------
// TCP control channel packets (port 53219)
// --------------------------------------------------------------------------

// WelcomeSize is the size of the welcome packet at connection start.
const WelcomeSize = 16

// ValidateWelcome checks a 16-byte welcome packet.
func ValidateWelcome(data []byte) error {
	if len(data) < WelcomeSize {
		return errors.New("welcome packet too short")
	}
	if [4]byte(data[4:8]) != Magic {
		return errors.New("welcome packet: bad magic")
	}
	return nil
}

// MarshalReleaseRequest builds a 32-byte release request (register/deregister session).
func MarshalReleaseRequest(token [8]byte, action uint32) []byte {
	return writeWire(&releaseRequestWire{
		controlHeader: controlHeader{Size: 32, Magic: Magic, Command: CmdRelease, Token: token},
		Action:        action,
	})
}

// MarshalReserveRequest builds a 384-byte reserve request.
func MarshalReserveRequest(token [8]byte, clientIP string, notifyPort uint16, identity string, ts time.Time) []byte {
	p := newPacket(384)
	p.putU32(0, 384)
	p.putBytes(4, Magic[:])
	p.putU32(8, CmdReserve)
	p.putBytes(16, token[:])

	// Config block
	p.putU32(32, 0x00040500)
	p.putU32(36, 0x00000001)
	p.putU32(40, 0x00000001)
	ip := ipToBytes(clientIP)
	p.putBytes(44, ip[:])
	p.putU16(50, notifyPort)

	// Identity string at offset 52 (max 48 bytes = SIZE_OF_PSW_BYTES in APK)
	idStr := identity
	if idStr == "" {
		parsed := net.ParseIP(clientIP).To4()
		if parsed != nil {
			idStr = fmt.Sprintf("%d%d%d%d", parsed[0], parsed[1], parsed[2], parsed[3])
		}
	}
	idBytes := []byte(idStr)
	if len(idBytes) > 48 {
		idBytes = idBytes[:48]
	}
	p.putBytes(52, idBytes)

	// Timestamp at offset 100
	p.putU16(100, uint16(ts.Year()))
	p[102] = byte(ts.Month())
	p[103] = byte(ts.Day())
	p[104] = byte(ts.Hour())
	p[105] = byte(ts.Minute())
	p[106] = byte(ts.Second())

	// Client type constant
	p.putU32(116, 0xFFFF8170)
	return p
}

// MarshalGetWifiStatusRequest builds a 32-byte WiFi status request.
func MarshalGetWifiStatusRequest(token [8]byte) []byte {
	return writeWire(&getWifiStatusRequestWire{
		controlHeader: controlHeader{Size: 32, Magic: Magic, Command: CmdGetWifiStatus, Token: token},
	})
}

// ParseGetWifiStatusResponse extracts the state field from a 32-byte status response.
func ParseGetWifiStatusResponse(data []byte) (state uint32, err error) {
	if len(data) < 32 {
		return 0, errors.New("status response too short")
	}
	return binary.BigEndian.Uint32(data[16:20]), nil
}

// ParseReserveResponse extracts the status code from a 20-byte reserve response.
func ParseReserveResponse(data []byte) (status uint32, err error) {
	if len(data) < 20 {
		return 0, errors.New("reserve response too short")
	}
	return binary.BigEndian.Uint32(data[8:12]), nil
}

// --------------------------------------------------------------------------
// TCP data channel packets (port 53218)
// --------------------------------------------------------------------------

// marshalDataRequest builds a data channel request with the given command and params.
func marshalDataRequest(token [8]byte, command uint32, params []byte) []byte {
	hdr := writeWire(&dataHeader{
		Size:      uint32(36 + len(params)),
		Magic:     Magic,
		Direction: 1,
		Token:     token,
		Command:   command,
	})
	return append(hdr, params...)
}

// ParseDataDeviceInfo parses a 136-byte TCP GET_SET sub=0x12 response.
// Extracts device name (offset 48, 33 bytes) and firmware revision from the name suffix.
func ParseDataDeviceInfo(data []byte) (*DataDeviceInfo, error) {
	if len(data) < 136 {
		return nil, fmt.Errorf("device info response too short: %d bytes", len(data))
	}
	name := nullTerminated(data[48:81])
	// Firmware revision is the last space-separated token in the device name
	// e.g. "FUJITSU ScanSnap iX500  0M00" → revision "0M00"
	var revision string
	trimmed := strings.TrimRight(name, " ")
	if i := strings.LastIndex(trimmed, " "); i >= 0 {
		revision = trimmed[i+1:]
	}
	return &DataDeviceInfo{
		DeviceName:       name,
		FirmwareRevision: revision,
	}, nil
}

// MarshalGetDeviceInfo builds cmd=0x06, sub=0x12.
func MarshalGetDeviceInfo(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(0, 0x00000060)
	p.putU32(12, 0x12000000)
	p.putU32(16, 0x60000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalGetScanSettings builds cmd=0x06, sub=0xD8.
func MarshalGetScanSettings(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(12, 0xD8000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalGetScanParams builds cmd=0x06, sub=0x90.
func MarshalGetScanParams(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(0, 0x00000090)
	p.putU32(12, 0x1201F000)
	p.putU32(16, 0x90000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalConfigCommand builds cmd=0x08.
func MarshalConfigCommand(token [8]byte) []byte {
	p := newPacket(32)
	p.putU32(4, 0x00000004)
	p.putU32(12, 0xEB000000)
	p.putU32(16, 0x00040000)
	p.putU32(28, 0x05010000)
	return marshalDataRequest(token, CmdConfig, p)
}

// MarshalGetStatus builds cmd=0x0A.
func MarshalGetStatus(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(0, 0x00000020)
	p.putU32(12, 0xC2000000)
	p.putU32(20, 0x20000000)
	return marshalDataRequest(token, CmdGetStatus, p)
}

// MarshalPrepareScan builds cmd=0x06, sub=0xD5.
func MarshalPrepareScan(token [8]byte) []byte {
	p := newPacket(36)
	p.putU32(0, 0x00000008)
	p.putU32(4, 0x00000008)
	p.putU32(12, 0xD5000000)
	p.putU32(16, 0x08080000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalWaitForScan builds cmd=0x06, sub=0xE0.
func MarshalWaitForScan(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(12, 0xE0000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalEndScan builds cmd=0x06, sub=0xD6 (end scan session).
func MarshalEndScan(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(12, 0xD6000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// MarshalPageTransfer builds cmd=0x0C for requesting scan page data.
// pageNum = (sheet << 8) | chunkIndex
// backSide indicates whether this is the back side of a duplex scan.
func MarshalPageTransfer(token [8]byte, pageNum int, backSide bool) []byte {
	pageFlags := uint32(0x00000400) // front side
	if backSide {
		pageFlags = 0x00800400 // back side
	}
	p := newPacket(28)
	p.putU32(0, 0x00040000) // 256KB buffer
	p.putU32(12, 0x28000002)
	p.putU32(16, pageFlags)
	p.putU32(20, uint32(pageNum))
	return marshalDataRequest(token, CmdPageTransfer, p)
}

// MarshalGetPageMetadata builds cmd=0x06, sub=0x12 (in-scan variant).
func MarshalGetPageMetadata(token [8]byte) []byte {
	p := newPacket(28)
	p.putU32(0, 0x00000012)
	p.putU32(12, 0x03000000)
	p.putU32(16, 0x12000000)
	return marshalDataRequest(token, CmdGetSet, p)
}

// bleedThroughLUT is the 256-byte tone curve for bleed-through reduction.
// Captured from ScanSnap Home — boosts highlights to reduce bleed-through.
var bleedThroughLUT = [256]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x88, 0x8a, 0x8b, 0x8c, 0x8d, 0x8f, 0x90, 0x91, 0x92,
	0x93, 0x95, 0x96, 0x97, 0x98, 0x9a, 0x9b, 0x9c, 0x9d, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa5, 0xa6,
	0xa7, 0xa8, 0xaa, 0xab, 0xac, 0xad, 0xaf, 0xb0, 0xb1, 0xb2, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xba,
	0xbb, 0xbc, 0xbd, 0xbf, 0xc0, 0xc1, 0xc2, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xca, 0xcb, 0xcc, 0xcd,
	0xcf, 0xd0, 0xd1, 0xd2, 0xd4, 0xd5, 0xd6, 0xd7, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xdf, 0xe0, 0xe1,
	0xe2, 0xe4, 0xe5, 0xe6, 0xe7, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xef, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5,
	0xf6, 0xf7, 0xf9, 0xfa, 0xfb, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// MarshalWriteToneCurve builds cmd=0x08, sub=0xDB (tone curve for bleed-through).
func MarshalWriteToneCurve(token [8]byte) []byte {
	// Params: 28 bytes header + 10 bytes tone curve header + 256 bytes LUT = 294
	p := newPacket(294)
	// Param header
	p.putU32(4, 0x0000010A)  // input param length = 266
	p.putU32(12, 0xDB850000) // sub-command 0xDB
	p.putU32(16, 0x00010A00)
	// Tone curve header (10 bytes at offset 28)
	p.putU32(28, 0x00001000)
	p.putU16(32, 0x0100)
	p.putU16(34, 0x0100)
	p.putU16(36, 0x0000)
	// LUT data (256 bytes at offset 38)
	copy(p[38:], bleedThroughLUT[:])
	return marshalDataRequest(token, CmdConfig, p)
}

// MarshalScanConfig builds the scan config SET packet (cmd=0x06, sub=0xD4).
func MarshalScanConfig(token [8]byte, cfg ScanConfig) []byte {
	isBW := cfg.ColorMode == ColorBW
	isGray := cfg.ColorMode == ColorGray
	isAutoColor := cfg.ColorMode == ColorAuto
	isAutoQuality := cfg.Quality == QualityAuto
	isFullAuto := isAutoColor && isAutoQuality

	dpi := QualityDPI[cfg.Quality]
	dim := PaperDimensions[cfg.PaperSize]
	if dim.Width == 0 && dim.Height == 0 {
		dim = PaperDimensions[PaperAuto]
	}

	configSize := 0x50 // 80 bytes
	if cfg.Duplex && isFullAuto {
		configSize = 0x80 // 128 bytes
	}

	total := 64 + configSize
	p := newPacket(total)

	// Data channel header [0:36]
	p.putU32(0, uint32(total))
	p.putBytes(4, Magic[:])
	p.putU32(8, 1) // direction = client
	p.putBytes(16, token[:])
	p.putU32(32, CmdGetSet)

	// GET_SET param header [36:64]
	p.putU32(40, uint32(configSize))
	p.putU32(48, 0xD4000000)
	p.putU32(52, uint32(configSize)<<24)

	// Config data at offset 64
	c := 64

	// +1: duplex
	if cfg.Duplex {
		p[c+1] = 0x03
	} else {
		p[c+1] = 0x01
	}
	// +2, +3, +5: always 0x01
	p[c+2] = 0x01
	p[c+3] = 0x01
	p[c+5] = 0x01
	// +4: multi-feed detection
	if cfg.MultiFeed {
		p[c+4] = 0xD0
	} else {
		p[c+4] = 0x80
	}
	// +6: multi-feed detection
	if cfg.MultiFeed {
		p[c+6] = 0xC1
	} else {
		p[c+6] = 0xC0
	}
	// +7: auto color+quality
	if isAutoColor && isAutoQuality {
		p[c+7] = 0xC1
	} else {
		p[c+7] = 0x80
	}
	// +8: blank page removal
	if cfg.BlankPageRemoval {
		p[c+8] = 0xE0
	} else {
		p[c+8] = 0x80
	}
	// +9: constant
	p[c+9] = 0xC8
	// +10: auto quality
	if isAutoQuality {
		p[c+10] = 0xA0
	} else {
		p[c+10] = 0x80
	}
	// +11: bleed-through
	if cfg.BleedThrough {
		p[c+11] = 0xC0
	} else {
		p[c+11] = 0x80
	}
	// +12: constant
	p[c+12] = 0x80

	// Front side params
	p[c+31] = 0x30
	if isBW {
		p[c+33] = 0x40
	} else {
		p[c+33] = 0x10
	}
	p.putU16(c+34, uint16(dpi))
	p.putU16(c+36, uint16(dpi))

	// +38-40: color encoding
	colorEncTail := byte(0x0B)
	if cfg.PaperSize == PaperPostcard {
		colorEncTail = 0x09
	}
	if isGray {
		p[c+38] = 0x02
		p[c+39] = 0x82
		p[c+40] = colorEncTail
	} else if isBW {
		p[c+38] = 0x00
		p[c+39] = 0x03
		p[c+40] = 0x00
	} else {
		p[c+38] = 0x05
		p[c+39] = 0x82
		p[c+40] = colorEncTail
	}

	// +44-45, +48-49: paper size
	p.putU16(c+44, dim.Width)
	p.putU16(c+48, dim.Height)
	// +50: constant
	p[c+50] = 0x04
	// +54-56: constants
	p[c+54] = 0x01
	p[c+55] = 0x01
	p[c+56] = 0x01
	// +57: BW flag
	if isBW {
		p[c+57] = 0x01
	}
	// +60: BW density value
	if isBW {
		p[c+60] = byte(6 + cfg.BWDensity)
	}

	// Back side params (only for full-auto duplex)
	if configSize == 0x80 {
		bc := c + 80
		p[bc+0] = 0x01
		p[bc+1] = 0x10
		p.putU16(bc+2, uint16(dpi))
		p.putU16(bc+4, uint16(dpi))
		p[bc+6] = 0x02
		p[bc+7] = 0x82
		p[bc+8] = 0x0B
		p.putU16(bc+12, dim.Width)
		p.putU16(bc+16, dim.Height)
		p[bc+18] = 0x04
		p[bc+22] = 0x01
		p[bc+23] = 0x01
		p[bc+24] = 0x01
	}

	return p
}

// --------------------------------------------------------------------------
// Page header (42 bytes, before JPEG data)
// --------------------------------------------------------------------------

// PageHeader is returned before each JPEG chunk during page transfer.
type PageHeader struct {
	TotalLength uint32 // header(42) + JPEG data size
	PageType    uint32 // 0=more chunks, 2=final chunk
	Sheet       byte
	Side        byte // 0=front, 1=back
}

// PageHeaderSize is the fixed size of the page header.
const PageHeaderSize = 42

// JPEGSize returns the number of JPEG bytes following this header.
func (h *PageHeader) JPEGSize() int {
	if h.TotalLength < PageHeaderSize {
		return 0
	}
	return int(h.TotalLength) - PageHeaderSize
}

// ParsePageHeader parses a 42-byte page header.
func ParsePageHeader(data []byte) (*PageHeader, error) {
	if len(data) < PageHeaderSize {
		return nil, errors.New("page header too short")
	}
	var wire pageHeaderWire
	if err := readWire(data[:PageHeaderSize], &wire); err != nil {
		return nil, fmt.Errorf("page header: %w", err)
	}
	if wire.Magic != Magic {
		return nil, errors.New("page header: bad magic")
	}
	return &PageHeader{
		TotalLength: wire.TotalLength,
		PageType:    wire.PageType,
		Sheet:       wire.Sheet,
		Side:        wire.Side,
	}, nil
}

// HasPaper checks the ADF status response for paper presence.
func HasPaper(adfStatus uint32) bool {
	return adfStatus&ADFPaperMask != 0
}
