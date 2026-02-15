package vens

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
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
// UDP packets
// --------------------------------------------------------------------------

// ParseBroadcastAdvertisement parses a 48-byte scanner broadcast (UDP:53220).
func ParseBroadcastAdvertisement(data []byte) (deviceIP string, err error) {
	if len(data) < 48 || data[4] != Magic[0] || data[5] != Magic[1] || data[6] != Magic[2] || data[7] != Magic[3] {
		return "", errors.New("not a VENS broadcast")
	}
	cmd := binary.BigEndian.Uint32(data[8:12])
	if cmd != CmdBroadcast {
		return "", fmt.Errorf("unexpected broadcast command: 0x%X", cmd)
	}
	return ipFromBytes(data[20:24]), nil
}

// MarshalDiscoveryVENS builds a 32-byte VENS discovery/heartbeat packet.
func MarshalDiscoveryVENS(clientIP string, token [8]byte, clientPort uint16, heartbeat bool) []byte {
	buf := make([]byte, 32)
	copy(buf[0:4], Magic[:])
	if heartbeat {
		binary.BigEndian.PutUint32(buf[4:8], 1) // flags=1 for heartbeat
	}
	ip := ipToBytes(clientIP)
	copy(buf[8:12], ip[:])
	copy(buf[12:20], token[:])
	binary.BigEndian.PutUint16(buf[22:24], clientPort)
	buf[24] = 0x00
	buf[25] = 0x10
	return buf
}

// MarshalDiscoverySSNR builds a 32-byte ssNR companion packet.
func MarshalDiscoverySSNR(clientIP string, token [8]byte, clientPort uint16) []byte {
	buf := make([]byte, 32)
	copy(buf[0:4], MagicSSNR[:])
	ip := ipToBytes(clientIP)
	copy(buf[8:12], ip[:])
	copy(buf[12:20], token[:])
	binary.BigEndian.PutUint16(buf[22:24], clientPort)
	buf[24] = 0x01
	return buf
}

// ParseDeviceInfo parses a 132-byte device info response (UDP:55264).
func ParseDeviceInfo(data []byte) (*DeviceInfo, error) {
	if len(data) < 132 || data[0] != Magic[0] || data[1] != Magic[1] || data[2] != Magic[2] || data[3] != Magic[3] {
		return nil, errors.New("not a VENS device info")
	}
	info := &DeviceInfo{
		Paired:      binary.BigEndian.Uint16(data[4:6]) != 0,
		DeviceIP:    ipFromBytes(data[16:20]),
		DataPort:    binary.BigEndian.Uint16(data[22:24]),
		ControlPort: binary.BigEndian.Uint16(data[26:28]),
		MAC:         macToString(data[28:34]),
		State:       binary.BigEndian.Uint32(data[36:40]),
		Serial:      nullTerminated(data[40:104]),
		Name:        nullTerminated(data[104:120]),
	}
	clientIPRaw := data[120:124]
	if clientIPRaw[0] != 0 || clientIPRaw[1] != 0 || clientIPRaw[2] != 0 || clientIPRaw[3] != 0 {
		info.ClientIP = ipFromBytes(clientIPRaw)
	}
	return info, nil
}

// ParseEventNotification parses a 48-byte event notification (UDP:55265).
func ParseEventNotification(data []byte) (eventType uint32, eventData uint32, err error) {
	if len(data) < 48 || data[4] != Magic[0] || data[5] != Magic[1] || data[6] != Magic[2] || data[7] != Magic[3] {
		return 0, 0, errors.New("not a VENS notification")
	}
	eventType = binary.BigEndian.Uint32(data[8:12])
	eventData = binary.BigEndian.Uint32(data[16:20])
	return eventType, eventData, nil
}

// --------------------------------------------------------------------------
// TCP control channel packets (port 53219)
// --------------------------------------------------------------------------

// WelcomeSize is the size of the welcome packet sent at the start of every TCP connection.
const WelcomeSize = 16

// ValidateWelcome checks a 16-byte welcome packet.
func ValidateWelcome(data []byte) error {
	if len(data) < WelcomeSize {
		return errors.New("welcome packet too short")
	}
	if data[4] != Magic[0] || data[5] != Magic[1] || data[6] != Magic[2] || data[7] != Magic[3] {
		return errors.New("welcome packet: bad magic")
	}
	return nil
}

// MarshalRegisterRequest builds a 32-byte register/deregister request.
func MarshalRegisterRequest(token [8]byte, action uint32) []byte {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:4], 32)
	copy(buf[4:8], Magic[:])
	binary.BigEndian.PutUint32(buf[8:12], CmdRegister)
	copy(buf[16:24], token[:])
	binary.BigEndian.PutUint32(buf[24:28], action)
	return buf
}

// MarshalConfigureRequest builds a 384-byte configure request.
func MarshalConfigureRequest(token [8]byte, clientIP string, notifyPort uint16, identity string, ts time.Time) []byte {
	buf := make([]byte, 384)
	binary.BigEndian.PutUint32(buf[0:4], 384)
	copy(buf[4:8], Magic[:])
	binary.BigEndian.PutUint32(buf[8:12], CmdConfigure)
	copy(buf[16:24], token[:])

	// Config block
	binary.BigEndian.PutUint32(buf[32:36], 0x00040500)
	binary.BigEndian.PutUint32(buf[36:40], 0x00000001)
	binary.BigEndian.PutUint32(buf[40:44], 0x00000001)
	ip := ipToBytes(clientIP)
	copy(buf[44:48], ip[:])
	binary.BigEndian.PutUint16(buf[50:52], notifyPort)

	// Identity string at offset 52 (max 44 bytes)
	idStr := identity
	if idStr == "" {
		// Fallback: concatenate IP digits
		parsed := net.ParseIP(clientIP).To4()
		if parsed != nil {
			idStr = fmt.Sprintf("%d%d%d%d", parsed[0], parsed[1], parsed[2], parsed[3])
		}
	}
	idBytes := []byte(idStr)
	if len(idBytes) > 44 {
		idBytes = idBytes[:44]
	}
	copy(buf[52:], idBytes)

	// Timestamp at offset 100
	binary.BigEndian.PutUint16(buf[100:102], uint16(ts.Year()))
	buf[102] = byte(ts.Month())
	buf[103] = byte(ts.Day())
	buf[104] = byte(ts.Hour())
	buf[105] = byte(ts.Minute())
	buf[106] = byte(ts.Second())

	// Client type constant
	binary.BigEndian.PutUint32(buf[116:120], 0xFFFF8170)
	return buf
}

// MarshalStatusRequest builds a 32-byte status request.
func MarshalStatusRequest(token [8]byte) []byte {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:4], 32)
	copy(buf[4:8], Magic[:])
	binary.BigEndian.PutUint32(buf[8:12], CmdStatus)
	copy(buf[16:24], token[:])
	return buf
}

// ParseStatusResponse extracts the state field from a 32-byte status response.
func ParseStatusResponse(data []byte) (state uint32, err error) {
	if len(data) < 32 {
		return 0, errors.New("status response too short")
	}
	return binary.BigEndian.Uint32(data[16:20]), nil
}

// ParseConfigureResponse extracts the status code from a 20-byte configure response.
func ParseConfigureResponse(data []byte) (status uint32, err error) {
	if len(data) < 20 {
		return 0, errors.New("configure response too short")
	}
	return binary.BigEndian.Uint32(data[8:12]), nil
}

// --------------------------------------------------------------------------
// TCP data channel packets (port 53218)
// --------------------------------------------------------------------------

// marshalDataRequest builds the common data channel request header.
func marshalDataRequest(token [8]byte, command uint32, params []byte) []byte {
	total := 36 + len(params) // header(32) + command(4) + params
	buf := make([]byte, total)
	binary.BigEndian.PutUint32(buf[0:4], uint32(total))
	copy(buf[4:8], Magic[:])
	binary.BigEndian.PutUint32(buf[8:12], 1) // direction = client→server
	copy(buf[16:24], token[:])
	binary.BigEndian.PutUint32(buf[32:36], command)
	copy(buf[36:], params)
	return buf
}

// MarshalGetDeviceInfo builds cmd=0x06, sub=0x12.
func MarshalGetDeviceInfo(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[0:4], 0x00000060)
	binary.BigEndian.PutUint32(params[12:16], 0x12000000)
	binary.BigEndian.PutUint32(params[16:20], 0x60000000)
	return marshalDataRequest(token, CmdGetSet, params)
}

// MarshalGetScanSettings builds cmd=0x06, sub=0xD8.
func MarshalGetScanSettings(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[12:16], 0xD8000000)
	return marshalDataRequest(token, CmdGetSet, params)
}

// MarshalGetScanParams builds cmd=0x06, sub=0x90.
func MarshalGetScanParams(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[0:4], 0x00000090)
	binary.BigEndian.PutUint32(params[12:16], 0x1201F000)
	binary.BigEndian.PutUint32(params[16:20], 0x90000000)
	return marshalDataRequest(token, CmdGetSet, params)
}

// MarshalConfigCommand builds cmd=0x08.
func MarshalConfigCommand(token [8]byte) []byte {
	params := make([]byte, 32)
	binary.BigEndian.PutUint32(params[4:8], 0x00000004)
	binary.BigEndian.PutUint32(params[12:16], 0xEB000000)
	binary.BigEndian.PutUint32(params[16:20], 0x00040000)
	binary.BigEndian.PutUint32(params[28:32], 0x05010000)
	return marshalDataRequest(token, CmdConfig, params)
}

// MarshalGetStatus builds cmd=0x0A.
func MarshalGetStatus(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[0:4], 0x00000020)
	binary.BigEndian.PutUint32(params[12:16], 0xC2000000)
	binary.BigEndian.PutUint32(params[20:24], 0x20000000)
	return marshalDataRequest(token, CmdGetStatus, params)
}

// MarshalPrepareScan builds cmd=0x06, sub=0xD5.
func MarshalPrepareScan(token [8]byte) []byte {
	params := make([]byte, 36)
	binary.BigEndian.PutUint32(params[0:4], 0x00000008)
	binary.BigEndian.PutUint32(params[4:8], 0x00000008)
	binary.BigEndian.PutUint32(params[12:16], 0xD5000000)
	binary.BigEndian.PutUint32(params[16:20], 0x08080000)
	return marshalDataRequest(token, CmdGetSet, params)
}

// MarshalWaitForScan builds cmd=0x06, sub=0xE0.
func MarshalWaitForScan(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[12:16], 0xE0000000)
	return marshalDataRequest(token, CmdGetSet, params)
}

// MarshalPageTransfer builds cmd=0x0C for requesting scan page data.
// pageNum = (sheet << 8) | chunkIndex
func MarshalPageTransfer(token [8]byte, pageNum int, sheet int) []byte {
	pageFlags := uint32(0x00000400) // even sheet
	if sheet%2 == 1 {
		pageFlags = 0x00800400 // odd sheet
	}
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[0:4], 0x00040000) // 256KB buffer
	binary.BigEndian.PutUint32(params[12:16], 0x28000002)
	binary.BigEndian.PutUint32(params[16:20], pageFlags)
	binary.BigEndian.PutUint32(params[20:24], uint32(pageNum))
	return marshalDataRequest(token, CmdPageTransfer, params)
}

// MarshalGetPageMetadata builds cmd=0x06, sub=0x12 (in-scan variant).
func MarshalGetPageMetadata(token [8]byte) []byte {
	params := make([]byte, 28)
	binary.BigEndian.PutUint32(params[0:4], 0x00000012)
	binary.BigEndian.PutUint32(params[12:16], 0x03000000)
	binary.BigEndian.PutUint32(params[16:20], 0x12000000)
	return marshalDataRequest(token, CmdGetSet, params)
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
	buf := make([]byte, total)

	// Data channel header
	binary.BigEndian.PutUint32(buf[0:4], uint32(total))
	copy(buf[4:8], Magic[:])
	binary.BigEndian.PutUint32(buf[8:12], 1) // direction = client
	copy(buf[16:24], token[:])
	binary.BigEndian.PutUint32(buf[32:36], CmdGetSet)

	// GET_SET param header
	binary.BigEndian.PutUint32(buf[40:44], uint32(configSize))
	binary.BigEndian.PutUint32(buf[48:52], 0xD4000000)
	binary.BigEndian.PutUint32(buf[52:56], uint32(configSize)<<24)

	// Config data at offset 64
	c := 64

	// +1: duplex
	if cfg.Duplex {
		buf[c+1] = 0x03
	} else {
		buf[c+1] = 0x01
	}
	// +2, +5: full auto flags
	if isFullAuto {
		buf[c+2] = 0x01
		buf[c+5] = 0x01
	}
	// +3: BW density flag
	if isBW && cfg.BWDensity == 0 {
		buf[c+3] = 0x02
	} else if isFullAuto {
		buf[c+3] = 0x01
	}
	// +4: multi-feed detection
	if cfg.MultiFeed {
		buf[c+4] = 0xD0
	} else {
		buf[c+4] = 0x80
	}
	// +6: multi-feed detection
	if cfg.MultiFeed {
		buf[c+6] = 0xC1
	} else {
		buf[c+6] = 0xC0
	}
	// +7: auto color+quality
	if isAutoColor && isAutoQuality {
		buf[c+7] = 0xC1
	} else {
		buf[c+7] = 0x80
	}
	// +8: blank page removal
	if cfg.BlankPageRemoval {
		buf[c+8] = 0xE0
	} else {
		buf[c+8] = 0x80
	}
	// +9: constant
	buf[c+9] = 0xC8
	// +10: auto quality
	if isAutoQuality {
		buf[c+10] = 0xA0
	} else {
		buf[c+10] = 0x80
	}
	// +11: bleed-through
	if cfg.BleedThrough {
		buf[c+11] = 0xC0
	} else {
		buf[c+11] = 0x80
	}
	// +12: constant
	buf[c+12] = 0x80

	// Front side params
	buf[c+31] = 0x30
	if isBW {
		buf[c+33] = 0x40
	} else {
		buf[c+33] = 0x10
	}
	binary.BigEndian.PutUint16(buf[c+34:c+36], uint16(dpi))
	binary.BigEndian.PutUint16(buf[c+36:c+38], uint16(dpi))

	// +38-40: color encoding
	colorEncTail := byte(0x0B)
	if cfg.PaperSize == PaperPostcard {
		colorEncTail = 0x09
	}
	if isGray {
		buf[c+38] = 0x02
		buf[c+39] = 0x82
		buf[c+40] = colorEncTail
	} else if isBW {
		buf[c+38] = 0x00
		buf[c+39] = 0x03
		buf[c+40] = 0x00
	} else {
		buf[c+38] = 0x05
		buf[c+39] = 0x82
		buf[c+40] = colorEncTail
	}

	// +44-45, +48-49: paper size
	binary.BigEndian.PutUint16(buf[c+44:c+46], dim.Width)
	binary.BigEndian.PutUint16(buf[c+48:c+50], dim.Height)
	// +50: constant
	buf[c+50] = 0x04
	// +54-56: constants
	buf[c+54] = 0x01
	buf[c+55] = 0x01
	buf[c+56] = 0x01
	// +57: BW flag
	if isBW {
		buf[c+57] = 0x01
	}
	// +60: BW density value
	if isBW {
		buf[c+60] = byte(6 + cfg.BWDensity)
	}

	// Back side params (only for full-auto duplex)
	if configSize == 0x80 {
		bc := c + 80
		buf[bc+0] = 0x01
		buf[bc+1] = 0x10
		binary.BigEndian.PutUint16(buf[bc+2:bc+4], uint16(dpi))
		binary.BigEndian.PutUint16(buf[bc+4:bc+6], uint16(dpi))
		buf[bc+6] = 0x02
		buf[bc+7] = 0x82
		buf[bc+8] = 0x0B
		binary.BigEndian.PutUint16(buf[bc+12:bc+14], dim.Width)
		binary.BigEndian.PutUint16(buf[bc+16:bc+18], dim.Height)
		buf[bc+18] = 0x04
		buf[bc+22] = 0x01
		buf[bc+23] = 0x01
		buf[bc+24] = 0x01
	}

	return buf
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
	if data[4] != Magic[0] || data[5] != Magic[1] || data[6] != Magic[2] || data[7] != Magic[3] {
		return nil, errors.New("page header: bad magic")
	}
	return &PageHeader{
		TotalLength: binary.BigEndian.Uint32(data[0:4]),
		PageType:    binary.BigEndian.Uint32(data[12:16]),
		Sheet:       data[40],
		Side:        data[41],
	}, nil
}

// HasPaper checks the ADF status response for paper presence.
// offsetBytes is the ADF status field from the GET_STATUS response.
func HasPaper(adfStatus uint32) bool {
	return adfStatus&ADFPaperMask != 0
}
