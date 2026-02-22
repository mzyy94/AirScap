package vens

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildPcapScanParamsResponse constructs a 184-byte INQUIRY VPD 0xF0 response
// matching pcap captures from ScanSnap iX500. Values were verified identical
// across all 24 pcap files, representing static hardware capabilities.
func buildPcapScanParamsResponse() []byte {
	data := make([]byte, 184)
	// VENS response header [0:40]
	binary.BigEndian.PutUint32(data[0:4], 184)    // Size
	copy(data[4:8], Magic[:])                      // Magic "VENS"
	binary.BigEndian.PutUint32(data[32:36], CmdGetSet) // Command echo

	// SCSI INQUIRY VPD 0xF0 data [40:]
	data[40] = 0x06                                    // Device Type = scanner
	data[41] = 0xF0                                    // Page Code
	binary.BigEndian.PutUint16(data[42:44], 0x0200)    // Page Length
	data[44] = 0x8B                                    // Vendor data length = 139
	binary.BigEndian.PutUint16(data[45:47], 600)       // Max Resolution X (DPI)
	binary.BigEndian.PutUint16(data[47:49], 600)       // Max Resolution Y (DPI)
	data[49] = 0x11                                    // Color Modes bitmask
	binary.BigEndian.PutUint16(data[50:52], 600)       // Default Resolution X
	binary.BigEndian.PutUint16(data[52:54], 600)       // Default Resolution Y
	binary.BigEndian.PutUint16(data[54:56], 50)        // Min Resolution X
	binary.BigEndian.PutUint16(data[56:58], 50)        // Min Resolution Y
	data[58] = 0xFF                                    // unknown
	data[59] = 0xFC                                    // unknown
	binary.BigEndian.PutUint16(data[62:64], 0x1468)    // Max Width = 5224 (1/600 inch)
	binary.BigEndian.PutUint16(data[66:68], 0x50E8)    // Max Height = 20712 (1/600 inch)

	// Additional data after offset 68 (from pcap, partial)
	data[68] = 0x8F
	data[72] = 0x92
	data[73] = 0x0A
	data[74] = 0x18
	data[80] = 0xEF
	data[81] = 0xBF
	data[83] = 0x04

	return data
}

func TestParseScanParams_PcapGroundTruth(t *testing.T) {
	data := buildPcapScanParamsResponse()

	params, err := ParseScanParams(data)
	if err != nil {
		t.Fatalf("ParseScanParams failed: %v", err)
	}

	// All values verified against 24 pcap captures of ScanSnap iX500
	if params.MaxResolutionX != 600 {
		t.Errorf("MaxResolutionX = %d, want 600", params.MaxResolutionX)
	}
	if params.MaxResolutionY != 600 {
		t.Errorf("MaxResolutionY = %d, want 600", params.MaxResolutionY)
	}
	if params.MinResolutionX != 50 {
		t.Errorf("MinResolutionX = %d, want 50", params.MinResolutionX)
	}
	if params.MinResolutionY != 50 {
		t.Errorf("MinResolutionY = %d, want 50", params.MinResolutionY)
	}
	if params.ColorModes != 0x11 {
		t.Errorf("ColorModes = 0x%02X, want 0x11", params.ColorModes)
	}
	// Wire value 0x1468 (5224) in 1/600 inch × 2 = 0x28D0 (10448) in 1/1200 inch
	if params.MaxWidth != 0x28D0 {
		t.Errorf("MaxWidth = 0x%04X, want 0x28D0", params.MaxWidth)
	}
	// Wire value 0x50E8 (20712) in 1/600 inch × 2 = 0xA1D0 (41424) in 1/1200 inch
	if params.MaxHeight != 0xA1D0 {
		t.Errorf("MaxHeight = 0x%04X, want 0xA1D0", params.MaxHeight)
	}
}

// TestParseScanParams_MaxWidthMatchesPaperAuto verifies that the scanner's
// reported MaxWidth matches the PaperAuto width in PaperDimensions.
func TestParseScanParams_MaxWidthMatchesPaperAuto(t *testing.T) {
	data := buildPcapScanParamsResponse()
	params, err := ParseScanParams(data)
	if err != nil {
		t.Fatalf("ParseScanParams failed: %v", err)
	}

	paperAutoWidth := PaperDimensions[PaperAuto].Width
	if params.MaxWidth != paperAutoWidth {
		t.Errorf("MaxWidth 0x%04X does not match PaperAuto width 0x%04X",
			params.MaxWidth, paperAutoWidth)
	}
}

// TestParseScanParams_UnitConversion verifies wire value (1/600 inch) to
// internal value (1/1200 inch) conversion by checking the ×2 factor.
func TestParseScanParams_UnitConversion(t *testing.T) {
	data := make([]byte, 68)
	copy(data[4:8], Magic[:])

	// Set known wire values in 1/600 inch
	wireWidth := uint16(1000)
	wireHeight := uint16(2000)
	binary.BigEndian.PutUint16(data[62:64], wireWidth)
	binary.BigEndian.PutUint16(data[66:68], wireHeight)

	params, err := ParseScanParams(data)
	if err != nil {
		t.Fatalf("ParseScanParams failed: %v", err)
	}

	if params.MaxWidth != wireWidth*2 {
		t.Errorf("MaxWidth = %d, want %d (wire %d × 2)", params.MaxWidth, wireWidth*2, wireWidth)
	}
	if params.MaxHeight != wireHeight*2 {
		t.Errorf("MaxHeight = %d, want %d (wire %d × 2)", params.MaxHeight, wireHeight*2, wireHeight)
	}
}

func TestParseScanParams_TooShort(t *testing.T) {
	// Minimum required length is 68 bytes
	data := make([]byte, 67)
	_, err := ParseScanParams(data)
	if err == nil {
		t.Fatal("expected error for 67-byte input, got nil")
	}
}

func TestParseScanParams_ExactMinLength(t *testing.T) {
	data := make([]byte, 68)
	copy(data[4:8], Magic[:])
	binary.BigEndian.PutUint16(data[45:47], 300) // Max Res X
	binary.BigEndian.PutUint16(data[47:49], 300) // Max Res Y
	data[49] = 0x07                               // Color Modes
	binary.BigEndian.PutUint16(data[54:56], 100) // Min Res X
	binary.BigEndian.PutUint16(data[56:58], 100) // Min Res Y
	binary.BigEndian.PutUint16(data[62:64], 500) // Max Width (1/600)
	binary.BigEndian.PutUint16(data[66:68], 800) // Max Height (1/600)

	params, err := ParseScanParams(data)
	if err != nil {
		t.Fatalf("ParseScanParams failed with exact min length: %v", err)
	}
	if params.MaxResolutionX != 300 {
		t.Errorf("MaxResolutionX = %d, want 300", params.MaxResolutionX)
	}
	if params.ColorModes != 0x07 {
		t.Errorf("ColorModes = 0x%02X, want 0x07", params.ColorModes)
	}
	if params.MinResolutionX != 100 {
		t.Errorf("MinResolutionX = %d, want 100", params.MinResolutionX)
	}
	if params.MaxWidth != 1000 { // 500 × 2
		t.Errorf("MaxWidth = %d, want 1000", params.MaxWidth)
	}
	if params.MaxHeight != 1600 { // 800 × 2
		t.Errorf("MaxHeight = %d, want 1600", params.MaxHeight)
	}
}

// TestParseScanParams_VPDHeader verifies the VPD page header at offsets 40-44.
func TestParseScanParams_VPDHeader(t *testing.T) {
	data := buildPcapScanParamsResponse()

	if data[40] != 0x06 {
		t.Errorf("Device Type = 0x%02X, want 0x06 (scanner)", data[40])
	}
	if data[41] != 0xF0 {
		t.Errorf("Page Code = 0x%02X, want 0xF0", data[41])
	}
	pageLen := binary.BigEndian.Uint16(data[42:44])
	if pageLen != 0x0200 {
		t.Errorf("Page Length = 0x%04X, want 0x0200", pageLen)
	}
	if data[44] != 0x8B {
		t.Errorf("Vendor Data Length = 0x%02X, want 0x8B (139)", data[44])
	}
}

func TestParseDataDeviceInfo(t *testing.T) {
	data := make([]byte, 136)
	// Device name at offset 48 (33 bytes), space-padded
	name := "FUJITSU ScanSnap iX500  0M00"
	copy(data[48:81], name)

	info, err := ParseDataDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDataDeviceInfo failed: %v", err)
	}
	wantName := "FUJITSU ScanSnap iX500"
	if info.DeviceName != wantName {
		t.Errorf("DeviceName = %q, want %q", info.DeviceName, wantName)
	}
	if info.FirmwareRevision != "0M00" {
		t.Errorf("FirmwareRevision = %q, want %q", info.FirmwareRevision, "0M00")
	}
}

func TestParseDataDeviceInfo_SingleWord(t *testing.T) {
	data := make([]byte, 136)
	copy(data[48:81], "FUJITSU\x00")

	info, err := ParseDataDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDataDeviceInfo failed: %v", err)
	}
	if info.DeviceName != "FUJITSU" {
		t.Errorf("DeviceName = %q, want %q", info.DeviceName, "FUJITSU")
	}
	// Single word has no space separator, so no revision extracted
	if info.FirmwareRevision != "" {
		t.Errorf("FirmwareRevision = %q, want empty", info.FirmwareRevision)
	}
}

func TestParseDataDeviceInfo_TooShort(t *testing.T) {
	data := make([]byte, 135)
	_, err := ParseDataDeviceInfo(data)
	if err == nil {
		t.Fatal("expected error for 135-byte input, got nil")
	}
}

func TestParseBroadcastAdvertisement(t *testing.T) {
	data := make([]byte, 48)
	copy(data[4:8], Magic[:])
	binary.BigEndian.PutUint32(data[8:12], CmdBroadcast)
	data[20] = 192
	data[21] = 168
	data[22] = 1
	data[23] = 100

	ip, err := ParseBroadcastAdvertisement(data)
	if err != nil {
		t.Fatalf("ParseBroadcastAdvertisement failed: %v", err)
	}
	if ip != "192.168.1.100" {
		t.Errorf("deviceIP = %q, want %q", ip, "192.168.1.100")
	}
}

func TestParseBroadcastAdvertisement_BadMagic(t *testing.T) {
	data := make([]byte, 48)
	copy(data[4:8], []byte("XXXX"))
	binary.BigEndian.PutUint32(data[8:12], CmdBroadcast)

	_, err := ParseBroadcastAdvertisement(data)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParseBroadcastAdvertisement_WrongCommand(t *testing.T) {
	data := make([]byte, 48)
	copy(data[4:8], Magic[:])
	binary.BigEndian.PutUint32(data[8:12], 0xFF) // wrong command

	_, err := ParseBroadcastAdvertisement(data)
	if err == nil {
		t.Fatal("expected error for wrong command, got nil")
	}
}

func TestParseBroadcastAdvertisement_TooShort(t *testing.T) {
	data := make([]byte, 47)
	_, err := ParseBroadcastAdvertisement(data)
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestParseDeviceInfo(t *testing.T) {
	data := make([]byte, 132)
	copy(data[0:4], Magic[:])
	binary.BigEndian.PutUint16(data[4:6], 1) // Paired
	data[16] = 192                            // DeviceIP
	data[17] = 168
	data[18] = 5
	data[19] = 3
	binary.BigEndian.PutUint16(data[22:24], DefaultDataPort)    // DataPort
	binary.BigEndian.PutUint16(data[26:28], DefaultControlPort) // ControlPort
	// MAC at [28:34]
	data[28] = 0xAA
	data[29] = 0xBB
	data[30] = 0xCC
	data[31] = 0xDD
	data[32] = 0xEE
	data[33] = 0xFF
	binary.BigEndian.PutUint32(data[36:40], 0x00000001) // State
	copy(data[40:104], "iX500-AK7CC00700\x00")          // Serial
	copy(data[104:120], "ScanSnap iX500\x00")           // Name
	data[120] = 192                                      // ClientIP
	data[121] = 168
	data[122] = 5
	data[123] = 10

	info, err := ParseDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDeviceInfo failed: %v", err)
	}
	if !info.Paired {
		t.Error("Paired = false, want true")
	}
	if info.DeviceIP != "192.168.5.3" {
		t.Errorf("DeviceIP = %q, want %q", info.DeviceIP, "192.168.5.3")
	}
	if info.DataPort != DefaultDataPort {
		t.Errorf("DataPort = %d, want %d", info.DataPort, DefaultDataPort)
	}
	if info.ControlPort != DefaultControlPort {
		t.Errorf("ControlPort = %d, want %d", info.ControlPort, DefaultControlPort)
	}
	if info.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, want %q", info.MAC, "aa:bb:cc:dd:ee:ff")
	}
	if info.Serial != "iX500-AK7CC00700" {
		t.Errorf("Serial = %q, want %q", info.Serial, "iX500-AK7CC00700")
	}
	if info.Name != "ScanSnap iX500" {
		t.Errorf("Name = %q, want %q", info.Name, "ScanSnap iX500")
	}
	if info.ClientIP != "192.168.5.10" {
		t.Errorf("ClientIP = %q, want %q", info.ClientIP, "192.168.5.10")
	}
}

func TestParseDeviceInfo_NotPaired(t *testing.T) {
	data := make([]byte, 132)
	copy(data[0:4], Magic[:])
	// Paired = 0 (not paired)

	info, err := ParseDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDeviceInfo failed: %v", err)
	}
	if info.Paired {
		t.Error("Paired = true, want false")
	}
}

func TestParseDeviceInfo_BadMagic(t *testing.T) {
	data := make([]byte, 132)
	copy(data[0:4], []byte("XXXX"))

	_, err := ParseDeviceInfo(data)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParseDeviceInfo_TooShort(t *testing.T) {
	data := make([]byte, 131)
	_, err := ParseDeviceInfo(data)
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestParseEventNotification(t *testing.T) {
	data := make([]byte, 48)
	copy(data[4:8], Magic[:])
	binary.BigEndian.PutUint32(data[8:12], 0x01)  // EventType
	binary.BigEndian.PutUint32(data[16:20], 0x02) // EventData

	evType, evData, err := ParseEventNotification(data)
	if err != nil {
		t.Fatalf("ParseEventNotification failed: %v", err)
	}
	if evType != 1 {
		t.Errorf("EventType = %d, want 1", evType)
	}
	if evData != 2 {
		t.Errorf("EventData = %d, want 2", evData)
	}
}

func TestParseEventNotification_BadMagic(t *testing.T) {
	data := make([]byte, 48)
	copy(data[4:8], []byte("XXXX"))

	_, _, err := ParseEventNotification(data)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParseEventNotification_TooShort(t *testing.T) {
	_, _, err := ParseEventNotification(make([]byte, 47))
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestValidateWelcome(t *testing.T) {
	data := make([]byte, WelcomeSize)
	copy(data[4:8], Magic[:])

	if err := ValidateWelcome(data); err != nil {
		t.Errorf("ValidateWelcome failed: %v", err)
	}
}

func TestValidateWelcome_BadMagic(t *testing.T) {
	data := make([]byte, WelcomeSize)
	copy(data[4:8], []byte("XXXX"))

	if err := ValidateWelcome(data); err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestValidateWelcome_TooShort(t *testing.T) {
	data := make([]byte, WelcomeSize-1)
	if err := ValidateWelcome(data); err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestParseGetWifiStatusResponse(t *testing.T) {
	data := make([]byte, 32)
	binary.BigEndian.PutUint32(data[16:20], 0x00000042)

	state, err := ParseGetWifiStatusResponse(data)
	if err != nil {
		t.Fatalf("ParseGetWifiStatusResponse failed: %v", err)
	}
	if state != 0x42 {
		t.Errorf("state = 0x%X, want 0x42", state)
	}
}

func TestParseGetWifiStatusResponse_TooShort(t *testing.T) {
	_, err := ParseGetWifiStatusResponse(make([]byte, 31))
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestParseReserveResponse(t *testing.T) {
	data := make([]byte, 20)
	binary.BigEndian.PutUint32(data[8:12], 0x00000001)

	status, err := ParseReserveResponse(data)
	if err != nil {
		t.Fatalf("ParseReserveResponse failed: %v", err)
	}
	if status != 1 {
		t.Errorf("status = %d, want 1", status)
	}
}

func TestParseReserveResponse_TooShort(t *testing.T) {
	_, err := ParseReserveResponse(make([]byte, 19))
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestParsePageHeader(t *testing.T) {
	data := make([]byte, PageHeaderSize)
	binary.BigEndian.PutUint32(data[0:4], 1000) // TotalLength
	copy(data[4:8], Magic[:])
	binary.BigEndian.PutUint32(data[12:16], PageTypeFinal) // PageType
	data[40] = 3 // Sheet
	data[41] = 1 // Side (back)

	hdr, err := ParsePageHeader(data)
	if err != nil {
		t.Fatalf("ParsePageHeader failed: %v", err)
	}
	if hdr.TotalLength != 1000 {
		t.Errorf("TotalLength = %d, want 1000", hdr.TotalLength)
	}
	if hdr.PageType != PageTypeFinal {
		t.Errorf("PageType = %d, want %d", hdr.PageType, PageTypeFinal)
	}
	if hdr.Sheet != 3 {
		t.Errorf("Sheet = %d, want 3", hdr.Sheet)
	}
	if hdr.Side != 1 {
		t.Errorf("Side = %d, want 1", hdr.Side)
	}
}

func TestParsePageHeader_BadMagic(t *testing.T) {
	data := make([]byte, PageHeaderSize)
	copy(data[4:8], []byte("XXXX"))

	_, err := ParsePageHeader(data)
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParsePageHeader_TooShort(t *testing.T) {
	_, err := ParsePageHeader(make([]byte, PageHeaderSize-1))
	if err == nil {
		t.Fatal("expected error for too short input, got nil")
	}
}

func TestPageHeader_JPEGSize(t *testing.T) {
	tests := []struct {
		name        string
		totalLength uint32
		want        int
	}{
		{"normal", 1000, 1000 - PageHeaderSize},
		{"header_only", PageHeaderSize, 0},
		{"less_than_header", 10, 0},
		{"zero", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr := &PageHeader{TotalLength: tt.totalLength}
			if got := hdr.JPEGSize(); got != tt.want {
				t.Errorf("JPEGSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHasPaper(t *testing.T) {
	tests := []struct {
		name       string
		scanStatus uint32
		want       bool
	}{
		{"paper_present", 0x00000000, true},
		{"no_paper", ADFPaperMask, false},
		{"paper_with_other_bits", 0x00000001, true},
		{"no_paper_with_other_bits", ADFPaperMask | 0x00000001, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasPaper(tt.scanStatus); got != tt.want {
				t.Errorf("HasPaper(0x%08X) = %v, want %v", tt.scanStatus, got, tt.want)
			}
		})
	}
}

func TestParseSenseError(t *testing.T) {
	tests := []struct {
		name     string
		senseKey byte
		asc      byte
		ascq     byte
		wantNil  bool
		wantKind ScanErrorKind
	}{
		{"no_sense", SenseKeyNoSense, 0, 0, true, 0},
		{"not_ready", SenseKeyNotReady, 0, 0, false, ScanErrGeneric},
		{"paper_jam", SenseKeyMediumError, VendorASC, ASCQPaperJam, false, ScanErrPaperJam},
		{"cover_open", SenseKeyMediumError, VendorASC, ASCQCoverOpen, false, ScanErrCoverOpen},
		{"multi_feed", SenseKeyMediumError, VendorASC, ASCQMultiFeed, false, ScanErrMultiFeed},
		{"scan_complete", SenseKeyMediumError, VendorASC, ASCQScanComplete, true, 0},
		{"unknown_medium_error", SenseKeyMediumError, 0x40, 0x01, false, ScanErrGeneric},
		{"unknown_sense_key", 0x05, 0, 0, false, ScanErrGeneric},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a VENS response with sense data at SenseDataOffset
			resp := make([]byte, SenseDataOffset+14)
			resp[SenseDataOffset+2] = tt.senseKey
			resp[SenseDataOffset+12] = tt.asc
			resp[SenseDataOffset+13] = tt.ascq

			result := parseSenseError(resp)
			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Fatal("expected error, got nil")
				}
				if result.Kind != tt.wantKind {
					t.Errorf("Kind = %d, want %d", result.Kind, tt.wantKind)
				}
			}
		})
	}
}

func TestParseSenseError_TooShort(t *testing.T) {
	resp := make([]byte, SenseDataOffset+13) // one byte too short
	result := parseSenseError(resp)
	if result != nil {
		t.Errorf("expected nil for too-short response, got %v", result)
	}
}

// --------------------------------------------------------------------------
// Marshal function tests — verify wire format matches protocol specification
// --------------------------------------------------------------------------

func TestMarshalGetScanParams(t *testing.T) {
	token := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00}
	pkt := MarshalGetScanParams(token)

	// Total size = 36 (data header) + 28 (params) = 64
	if len(pkt) != 64 {
		t.Fatalf("packet length = %d, want 64", len(pkt))
	}

	// Data header checks
	size := binary.BigEndian.Uint32(pkt[0:4])
	if size != 64 {
		t.Errorf("Size = %d, want 64", size)
	}
	if [4]byte(pkt[4:8]) != Magic {
		t.Error("Magic mismatch")
	}
	direction := binary.BigEndian.Uint32(pkt[8:12])
	if direction != 1 {
		t.Errorf("Direction = %d, want 1 (client→scanner)", direction)
	}
	if [8]byte(pkt[16:24]) != token {
		t.Error("Token mismatch")
	}
	command := binary.BigEndian.Uint32(pkt[32:36])
	if command != CmdGetSet {
		t.Errorf("Command = 0x%02X, want 0x%02X (CmdGetSet)", command, CmdGetSet)
	}

	// SCSI CDB checks (in params starting at offset 36)
	// param[12] = offset 48: CDB[0] should be INQUIRY (0x12)
	cdb0 := pkt[48]
	if cdb0 != SCSIOpcodeInquiry {
		t.Errorf("CDB[0] = 0x%02X, want 0x%02X (INQUIRY)", cdb0, SCSIOpcodeInquiry)
	}
	// EVPD=1, Page=0xF0: encoded as 0x12 << 24 | 0x01F000
	cdbWord := binary.BigEndian.Uint32(pkt[48:52])
	if cdbWord != uint32(SCSIOpcodeInquiry)<<24|0x01F000 {
		t.Errorf("CDB word = 0x%08X, want 0x%08X", cdbWord, uint32(SCSIOpcodeInquiry)<<24|0x01F000)
	}
	// Allocation length = 0x90 (144)
	allocLen := binary.BigEndian.Uint32(pkt[52:56])
	if allocLen != 0x90000000 {
		t.Errorf("Allocation length = 0x%08X, want 0x90000000", allocLen)
	}
}

func TestMarshalGetDeviceInfo(t *testing.T) {
	token := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00}
	pkt := MarshalGetDeviceInfo(token)

	// Total size = 36 + 28 = 64
	if len(pkt) != 64 {
		t.Fatalf("packet length = %d, want 64", len(pkt))
	}

	command := binary.BigEndian.Uint32(pkt[32:36])
	if command != CmdGetSet {
		t.Errorf("Command = 0x%02X, want 0x%02X", command, CmdGetSet)
	}

	// CDB[0] = INQUIRY (0x12)
	cdb0 := pkt[48]
	if cdb0 != SCSIOpcodeInquiry {
		t.Errorf("CDB[0] = 0x%02X, want 0x%02X (INQUIRY)", cdb0, SCSIOpcodeInquiry)
	}
}

func TestMarshalPageTransfer(t *testing.T) {
	token := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00}

	tests := []struct {
		name     string
		sheet    int
		chunk    int
		backSide bool
	}{
		{"front_first", 0, 0, false},
		{"front_second_chunk", 0, 1, false},
		{"back_first", 0, 0, true},
		{"second_sheet", 1, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := MarshalPageTransfer(token, tt.sheet, tt.chunk, tt.backSide)

			// Total size = 36 + 28 = 64
			if len(pkt) != 64 {
				t.Fatalf("packet length = %d, want 64", len(pkt))
			}

			command := binary.BigEndian.Uint32(pkt[32:36])
			if command != CmdPageTransfer {
				t.Errorf("Command = 0x%02X, want 0x%02X", command, CmdPageTransfer)
			}

			// CDB at param[12:24] = pkt[48:60]
			cdb := pkt[48:60]
			if cdb[0] != SCSIOpcodeRead10 {
				t.Errorf("CDB[0] = 0x%02X, want 0x%02X (READ10)", cdb[0], SCSIOpcodeRead10)
			}

			// Back side flag at CDB[5]
			if tt.backSide && cdb[5] != 0x80 {
				t.Errorf("CDB[5] = 0x%02X, want 0x80 for back side", cdb[5])
			}
			if !tt.backSide && cdb[5] != 0x00 {
				t.Errorf("CDB[5] = 0x%02X, want 0x00 for front side", cdb[5])
			}

			// Sheet ID at CDB[10]
			if cdb[10] != byte(tt.sheet) {
				t.Errorf("CDB[10] (Page ID) = %d, want %d", cdb[10], tt.sheet)
			}

			// Chunk ID at CDB[11]
			if cdb[11] != byte(tt.chunk) {
				t.Errorf("CDB[11] (Sequence ID) = %d, want %d", cdb[11], tt.chunk)
			}
		})
	}
}

func TestMarshalDiscoveryVENS(t *testing.T) {
	token := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00}

	tests := []struct {
		name      string
		heartbeat bool
		wantByte4 uint32
	}{
		{"discovery", false, 0},
		{"heartbeat", true, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := MarshalDiscoveryVENS("192.168.1.10", token, ClientNotifyPort, tt.heartbeat)

			if len(pkt) != 32 {
				t.Fatalf("packet length = %d, want 32", len(pkt))
			}

			// Magic at offset 0
			if [4]byte(pkt[0:4]) != Magic {
				t.Error("Magic mismatch at offset 0")
			}

			// Heartbeat flag at offset 4
			hbFlag := binary.BigEndian.Uint32(pkt[4:8])
			if hbFlag != tt.wantByte4 {
				t.Errorf("heartbeat flag = %d, want %d", hbFlag, tt.wantByte4)
			}

			// Client IP at offset 8
			if pkt[8] != 192 || pkt[9] != 168 || pkt[10] != 1 || pkt[11] != 10 {
				t.Errorf("client IP = %d.%d.%d.%d, want 192.168.1.10", pkt[8], pkt[9], pkt[10], pkt[11])
			}

			// Token at offset 12
			if [8]byte(pkt[12:20]) != token {
				t.Error("Token mismatch at offset 12")
			}

			// Notify port at offset 22
			port := binary.BigEndian.Uint16(pkt[22:24])
			if port != ClientNotifyPort {
				t.Errorf("port = %d, want %d", port, ClientNotifyPort)
			}
		})
	}
}

func TestMarshalScanConfig_Duplex(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name     string
		duplex   bool
		wantByte byte
	}{
		{"simplex", false, 0x01},
		{"duplex", true, 0x03},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.Duplex = tt.duplex
			cfg.ColorMode = ColorColor // non-auto to avoid full-auto duplex back-side
			cfg.Quality = QualityNormal

			pkt := MarshalScanConfig(token, cfg)
			// Config data starts at offset 64, duplex byte at +1
			if pkt[65] != tt.wantByte {
				t.Errorf("duplex byte = 0x%02X, want 0x%02X", pkt[65], tt.wantByte)
			}
		})
	}
}

func TestMarshalScanConfig_ColorModes(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name       string
		colorMode  ColorMode
		wantByte38 byte // config[38] — color encoding first byte
		wantByte33 byte // config[33] — BW vs color indicator
	}{
		{"color", ColorColor, 0x05, 0x10},
		{"grayscale", ColorGray, 0x02, 0x10},
		{"bw", ColorBW, 0x00, 0x40},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.ColorMode = tt.colorMode
			cfg.Quality = QualityNormal
			cfg.Duplex = false

			pkt := MarshalScanConfig(token, cfg)
			c := 64 // config data offset
			if pkt[c+38] != tt.wantByte38 {
				t.Errorf("config[38] = 0x%02X, want 0x%02X", pkt[c+38], tt.wantByte38)
			}
			if pkt[c+33] != tt.wantByte33 {
				t.Errorf("config[33] = 0x%02X, want 0x%02X", pkt[c+33], tt.wantByte33)
			}
		})
	}
}

func TestMarshalScanConfig_BWDensity(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name    string
		density int
		want    byte
	}{
		{"min", -5, 1},  // 6 + (-5) = 1
		{"zero", 0, 6},  // 6 + 0 = 6
		{"max", 5, 11},  // 6 + 5 = 11
		{"mid", 3, 9},   // 6 + 3 = 9
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.ColorMode = ColorBW
			cfg.Quality = QualityNormal
			cfg.BWDensity = tt.density
			cfg.Duplex = false

			pkt := MarshalScanConfig(token, cfg)
			c := 64
			if pkt[c+60] != tt.want {
				t.Errorf("BWDensity wire value = %d, want %d", pkt[c+60], tt.want)
			}
		})
	}
}

func TestMarshalScanConfig_MultiFeed(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name      string
		multiFeed bool
		wantByte4 byte
		wantByte6 byte
	}{
		{"enabled", true, 0xD0, 0xC1},
		{"disabled", false, 0x80, 0xC0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.MultiFeed = tt.multiFeed
			cfg.ColorMode = ColorColor
			cfg.Quality = QualityNormal
			cfg.Duplex = false

			pkt := MarshalScanConfig(token, cfg)
			c := 64
			if pkt[c+4] != tt.wantByte4 {
				t.Errorf("config[4] = 0x%02X, want 0x%02X", pkt[c+4], tt.wantByte4)
			}
			if pkt[c+6] != tt.wantByte6 {
				t.Errorf("config[6] = 0x%02X, want 0x%02X", pkt[c+6], tt.wantByte6)
			}
		})
	}
}

func TestMarshalScanConfig_PaperDimensions(t *testing.T) {
	token := [8]byte{}

	for ps, dim := range PaperDimensions {
		cfg := DefaultScanConfig()
		cfg.PaperSize = ps
		cfg.ColorMode = ColorColor
		cfg.Quality = QualityNormal
		cfg.Duplex = false

		pkt := MarshalScanConfig(token, cfg)
		c := 64
		width := binary.BigEndian.Uint16(pkt[c+44 : c+46])
		height := binary.BigEndian.Uint16(pkt[c+48 : c+50])

		if width != dim.Width {
			t.Errorf("PaperSize=%d: width = 0x%04X, want 0x%04X", ps, width, dim.Width)
		}
		if height != dim.Height {
			t.Errorf("PaperSize=%d: height = 0x%04X, want 0x%04X", ps, height, dim.Height)
		}
	}
}

func TestMarshalScanConfig_Resolution(t *testing.T) {
	token := [8]byte{}

	for q, expectedDPI := range QualityDPI {
		cfg := DefaultScanConfig()
		cfg.Quality = q
		cfg.ColorMode = ColorColor
		cfg.Duplex = false

		pkt := MarshalScanConfig(token, cfg)
		c := 64
		dpiX := binary.BigEndian.Uint16(pkt[c+34 : c+36])
		dpiY := binary.BigEndian.Uint16(pkt[c+36 : c+38])

		if int(dpiX) != expectedDPI {
			t.Errorf("Quality=%d: DPI X = %d, want %d", q, dpiX, expectedDPI)
		}
		if int(dpiY) != expectedDPI {
			t.Errorf("Quality=%d: DPI Y = %d, want %d", q, dpiY, expectedDPI)
		}
	}
}

func TestMarshalScanConfig_BlankPageRemoval(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name    string
		enabled bool
		want    byte
	}{
		{"enabled", true, 0xE0},
		{"disabled", false, 0x80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.BlankPageRemoval = tt.enabled
			cfg.ColorMode = ColorColor
			cfg.Quality = QualityNormal
			cfg.Duplex = false

			pkt := MarshalScanConfig(token, cfg)
			c := 64
			if pkt[c+8] != tt.want {
				t.Errorf("config[8] = 0x%02X, want 0x%02X", pkt[c+8], tt.want)
			}
		})
	}
}

func TestMarshalScanConfig_BleedThrough(t *testing.T) {
	token := [8]byte{}

	tests := []struct {
		name    string
		enabled bool
		want    byte
	}{
		{"enabled", true, 0xC0},
		{"disabled", false, 0x80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultScanConfig()
			cfg.BleedThrough = tt.enabled
			cfg.ColorMode = ColorColor
			cfg.Quality = QualityNormal
			cfg.Duplex = false

			pkt := MarshalScanConfig(token, cfg)
			c := 64
			if pkt[c+11] != tt.want {
				t.Errorf("config[11] = 0x%02X, want 0x%02X", pkt[c+11], tt.want)
			}
		})
	}
}

func TestMarshalScanConfig_FullAutoDuplexSize(t *testing.T) {
	token := [8]byte{}

	// Full auto (ColorAuto + QualityAuto) duplex → configSize=0x80 (128)
	cfg := DefaultScanConfig()
	cfg.ColorMode = ColorAuto
	cfg.Quality = QualityAuto
	cfg.Duplex = true

	pkt := MarshalScanConfig(token, cfg)
	expectedLen := 64 + 0x80
	if len(pkt) != expectedLen {
		t.Errorf("full-auto duplex packet length = %d, want %d", len(pkt), expectedLen)
	}

	// Non-auto → configSize=0x50 (80)
	cfg.ColorMode = ColorColor
	pkt = MarshalScanConfig(token, cfg)
	expectedLen = 64 + 0x50
	if len(pkt) != expectedLen {
		t.Errorf("non-auto duplex packet length = %d, want %d", len(pkt), expectedLen)
	}
}

// --------------------------------------------------------------------------
// Helper function tests
// --------------------------------------------------------------------------

func TestNullTerminated(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"null_terminated", []byte("hello\x00world"), "hello"},
		{"no_null", []byte("hello"), "hello"},
		{"empty", []byte{0}, ""},
		{"all_null", []byte{0, 0, 0}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nullTerminated(tt.input); got != tt.want {
				t.Errorf("nullTerminated(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIpToBytes(t *testing.T) {
	got := ipToBytes("192.168.1.100")
	want := [4]byte{192, 168, 1, 100}
	if got != want {
		t.Errorf("ipToBytes(\"192.168.1.100\") = %v, want %v", got, want)
	}
}

func TestIpFromBytes(t *testing.T) {
	got := ipFromBytes([]byte{10, 0, 0, 1})
	if got != "10.0.0.1" {
		t.Errorf("ipFromBytes = %q, want %q", got, "10.0.0.1")
	}
}

func TestMacToString(t *testing.T) {
	got := macToString([]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	want := "aa:bb:cc:dd:ee:ff"
	if got != want {
		t.Errorf("macToString = %q, want %q", got, want)
	}
}

// --------------------------------------------------------------------------
// Pcap-based test helpers — raw packet data from real ScanSnap iX500 captures
// --------------------------------------------------------------------------
//
// All helpers construct byte slices matching actual captured packets.
// Sensitive data (IP, MAC, serial) is replaced with dummy values:
//   Scanner IP: 192.168.5.3       Client IP: 192.168.5.10
//   MAC: aa:bb:cc:dd:ee:ff        Serial: iX500-XX0YY00000
//   Token: {0x01,0x02,0x03,0x04,0x05,0x06,0x00,0x00}

// pcapToken is the dummy token used in pcap-based test fixtures.
var pcapToken = [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00}

// comparePacketRegion compares byte slices in a region, reporting hex diffs.
func comparePacketRegion(t *testing.T, got, want []byte, start, end int, name string) {
	t.Helper()
	mismatches := 0
	for i := start; i < end && i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			if mismatches < 20 {
				t.Errorf("%s: offset %d (0x%02x): got 0x%02x, want 0x%02x", name, i, i, got[i], want[i])
			}
			mismatches++
		}
	}
	if mismatches > 20 {
		t.Errorf("%s: %d more mismatches not shown", name, mismatches-20)
	}
}

// buildPcapBroadcastAdvertisement constructs a 48-byte scanner broadcast
// matching a capture from scansnap-scan.pcapng (UDP:53220).
// Anonymized: scanner IP at [20:24], device ID at [24:30].
func buildPcapBroadcastAdvertisement() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x30, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x05, 0x03, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapDeviceInfoResponse constructs a 132-byte device info response
// matching scansnap-setup.pcapng pkt#4 (UDP 52217→55264).
// Anonymized: DeviceIP [16:20], MAC [28:34], Serial [40:56].
// Original: IP=192.168.0.176, MAC=84:25:3f:0c:a1:7f, Serial=iX500-AK7CC00700.
func buildPcapDeviceInfoResponse() []byte {
	return []byte{
		// [0:16] row 0 — Magic, Paired=0, padding(00 00), version(0x0004), sub-type(0x0030), bcast mask
		0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x30, 0xff, 0xff, 0xff, 0xff,
		// [16:32] row 1 — DeviceIP(anon), pad, DataPort=53218, pad, ControlPort=53219, MAC(anon)
		0xc0, 0xa8, 0x05, 0x03, 0x00, 0x00, 0xcf, 0xe2, 0x00, 0x00, 0xcf, 0xe3, 0xaa, 0xbb, 0xcc, 0xdd,
		// [32:48] row 2 — MAC(anon cont), pad, State=1, Serial(anon) "iX500-XX0YY00000"
		0xee, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x69, 0x58, 0x35, 0x30, 0x30, 0x2d, 0x58, 0x58,
		// [48:64] row 3 — Serial(anon cont) + null padding
		0x30, 0x59, 0x59, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [64:80] row 4
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [80:96] row 5
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [96:112] row 6 — zero padding, then Name "ScanSnap iX500  "
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0x63, 0x61, 0x6e, 0x53, 0x6e, 0x61, 0x70,
		// [112:128] row 7 — Name cont " iX500  ", ClientIP=0.0.0.0(not paired), trailing
		0x20, 0x69, 0x58, 0x35, 0x30, 0x30, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x5f, 0xa6,
		// [128:132] row 8 — trailing
		0xb5, 0x73, 0x00, 0x00,
	}
}

// buildPcapEventNotification constructs a 48-byte event notification
// matching a capture from scansnap-scan.pcapng (UDP:55265).
// EventType=1 (button press), EventData=0x02000000.
func buildPcapEventNotification() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x30, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapWelcomePacket constructs a 16-byte welcome packet
// matching a capture from scansnap-scan.pcapng (TCP:53219).
func buildPcapWelcomePacket() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x10, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapWifiStatusResponse constructs a 32-byte WiFi status response
// matching a capture from scansnap-setting.pcapng (TCP:53219).
// State=3 (strong signal).
func buildPcapWifiStatusResponse() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x20, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapReserveResponseRejected constructs a 20-byte reserve response
// matching a capture from scansnap-pairing.pcapng (TCP:53219).
// Status=0xFFFFFFFD (rejected — scanner already paired to another client).
func buildPcapReserveResponseRejected() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x14, 0x56, 0x45, 0x4e, 0x53, 0xff, 0xff, 0xff, 0xfd, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapDataDeviceInfoResponse constructs a 136-byte SCSI INQUIRY response
// matching a capture from scansnap-scan.pcapng (TCP:53218).
// Contains full VENS response header + device identity.
func buildPcapDataDeviceInfoResponse() []byte {
	return []byte{
		// [0:40] VENS response header
		0x00, 0x00, 0x00, 0x88, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [40:48] SCSI INQUIRY header
		0x06, 0x00, 0x92, 0x02, 0x5b, 0x00, 0x00, 0x10,
		// [48:81] Device name: "FUJITSU ScanSnap iX500  0M00"
		0x46, 0x55, 0x4a, 0x49, 0x54, 0x53, 0x55, 0x20, // "FUJITSU "
		0x53, 0x63, 0x61, 0x6e, 0x53, 0x6e, 0x61, 0x70, // "ScanSnap"
		0x20, 0x69, 0x58, 0x35, 0x30, 0x30, 0x20, 0x20, // " iX500  "
		0x30, 0x4d, 0x30, 0x30, 0x00, // "0M00\0"
		// [81:136] remaining bytes from capture
		0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapPageHeaderFinal constructs a 42-byte final page header
// matching a capture from scan-normal-bw.pcapng (TCP:53218).
// TotalLength=43713, PageType=2 (final), Sheet=0, Side=0.
func buildPcapPageHeaderFinal() []byte {
	return []byte{
		0x00, 0x00, 0xaa, 0xc1, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapSenseNoError constructs a 58-byte REQUEST SENSE response
// matching a capture from scansnap-scan.pcapng (TCP:53218).
// SenseKey=0x00 (NO SENSE) — scan page OK.
func buildPcapSenseNoError() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x3a, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x60, 0x00, 0x03, 0x6a, 0x19, 0x0a,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapSenseScanComplete constructs a 58-byte REQUEST SENSE response
// matching a capture from scansnap-scan.pcapng (TCP:53218).
// SenseKey=0x03 (MEDIUM ERROR), ASC=0x80, ASCQ=0x03 (scan complete — not an error).
func buildPcapSenseScanComplete() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x3a, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x0a,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapSenseIllegalRequest constructs a 58-byte REQUEST SENSE response
// matching a capture from scan-2paper-second-failed.pcapng (TCP:53218).
// SenseKey=0x05 (ILLEGAL REQUEST), ASC=0x24, ASCQ=0x00.
func buildPcapSenseIllegalRequest() []byte {
	return []byte{
		0x00, 0x00, 0x00, 0x3a, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x0a,
		0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapScanConfigBWDuplexAutoQuality constructs a 144-byte D4 SET SCAN CONFIG
// matching scan-normal-bw.pcapng config #1 (TCP:53218).
// Config: BW, Duplex, QualityAuto, MultiFeed=ON, BlankPageRemoval=ON,
// BleedThrough=OFF, PaperAuto, BWDensity=0.
// Token replaced with pcapToken.
func buildPcapScanConfigBWDuplexAutoQuality() []byte {
	return []byte{
		// [0:4] Size=144
		0x00, 0x00, 0x00, 0x90,
		// [4:8] Magic
		0x56, 0x45, 0x4e, 0x53,
		// [8:12] Direction=1
		0x00, 0x00, 0x00, 0x01,
		// [12:16] padding
		0x00, 0x00, 0x00, 0x00,
		// [16:24] Token (anonymized)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
		// [24:32] padding
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [32:36] Command=CmdGetSet(0x06)
		0x00, 0x00, 0x00, 0x06,
		// [36:40] padding
		0x00, 0x00, 0x00, 0x00,
		// [40:44] ConfigSize=0x50 (80)
		0x00, 0x00, 0x00, 0x50,
		// [44:48] padding
		0x00, 0x00, 0x00, 0x00,
		// [48:52] CDB opcode D4
		0xd4, 0x00, 0x00, 0x00,
		// [52:56] ConfigSize in CDB
		0x50, 0x00, 0x00, 0x00,
		// [56:64] padding
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [64:144] Config data (80 bytes)
		// +0    +1(duplex) +2(auto) +3(auto) +4(mfeed) +5(auto) +6(mfeed) +7(autoCQ)
		0x00, 0x03, 0x01, 0x01, 0xd0, 0x01, 0xc1, 0x80,
		// +8(blank) +9(const) +10(autoQ) +11(bleed) +12(const) +13..+15
		0xe0, 0xc8, 0xa0, 0x80, 0x80, 0x00, 0x00, 0x00,
		// +16..+30
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// +31(0x30) +32 +33(BW=0x40)
		0x30, 0x00, 0x40,
		// +34-35(DPI X=0) +36-37(DPI Y=0)
		0x00, 0x00, 0x00, 0x00,
		// +38(colorMode=BW) +39(fixed=0x03) +40(compression=0x00 for BW)
		0x00, 0x03, 0x00,
		// +41..+43
		0x00, 0x00, 0x00,
		// +44-45(width=0x28D0) +46-47
		0x28, 0xd0, 0x00, 0x00,
		// +48-49(height=0x45A4) +50(const=0x04)
		0x45, 0xa4, 0x04,
		// +51..+53
		0x00, 0x00, 0x00,
		// +54(0x01) +55(0x01) +56(0x01) +57(BW flag=0x01)
		0x01, 0x01, 0x01, 0x01,
		// +58-59
		0x00, 0x00,
		// +60(BWDensity=6 → density=0)
		0x06,
		// +61..+79 (zeros)
		0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildPcapScanConfigMultiFeedOff constructs a 144-byte D4 SET SCAN CONFIG
// matching multifeed-on-off.pcapng config #1 (TCP:53218).
// Config: BW, Duplex, QualityAuto, MultiFeed=OFF, BlankPageRemoval=ON,
// BleedThrough=ON, PaperAuto, BWDensity=0.
// Token replaced with pcapToken.
func buildPcapScanConfigMultiFeedOff() []byte {
	return []byte{
		// [0:36] Data header
		0x00, 0x00, 0x00, 0x90, 0x56, 0x45, 0x4e, 0x53, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x06,
		// [36:64] GET_SET param header
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0xd4, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [64:144] Config data (80 bytes) — MultiFeed=OFF
		0x00, 0x03, 0x01, 0x01, 0x80, 0x01, 0xc0, 0x80, 0xe0, 0xc8, 0xa0, 0xc0, 0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30,
		0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x28, 0xd0, 0x00, 0x00,
		0x45, 0xa4, 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// --------------------------------------------------------------------------
// Pcap-based parse tests
// --------------------------------------------------------------------------

func TestParseBroadcastAdvertisement_Pcap(t *testing.T) {
	data := buildPcapBroadcastAdvertisement()
	ip, err := ParseBroadcastAdvertisement(data)
	if err != nil {
		t.Fatalf("ParseBroadcastAdvertisement failed: %v", err)
	}
	if ip != "192.168.5.3" {
		t.Errorf("deviceIP = %q, want %q", ip, "192.168.5.3")
	}
	// Verify full packet structure
	if binary.BigEndian.Uint32(data[0:4]) != 0x30 {
		t.Error("packet length field != 0x30")
	}
	if binary.BigEndian.Uint32(data[8:12]) != CmdBroadcast {
		t.Errorf("command = 0x%X, want 0x%X", binary.BigEndian.Uint32(data[8:12]), CmdBroadcast)
	}
}

func TestParseDeviceInfo_Pcap(t *testing.T) {
	data := buildPcapDeviceInfoResponse()
	info, err := ParseDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDeviceInfo failed: %v", err)
	}
	if info.Paired {
		t.Error("Paired = true, want false")
	}
	if info.DeviceIP != "192.168.5.3" {
		t.Errorf("DeviceIP = %q, want %q", info.DeviceIP, "192.168.5.3")
	}
	if info.DataPort != DefaultDataPort {
		t.Errorf("DataPort = %d, want %d", info.DataPort, DefaultDataPort)
	}
	if info.ControlPort != DefaultControlPort {
		t.Errorf("ControlPort = %d, want %d", info.ControlPort, DefaultControlPort)
	}
	if info.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC = %q, want %q", info.MAC, "aa:bb:cc:dd:ee:ff")
	}
	if info.Serial != "iX500-XX0YY00000" {
		t.Errorf("Serial = %q, want %q", info.Serial, "iX500-XX0YY00000")
	}
	if strings.TrimSpace(info.Name) != "ScanSnap iX500" {
		t.Errorf("Name = %q, want %q (trimmed)", info.Name, "ScanSnap iX500")
	}
	if info.State != 1 {
		t.Errorf("State = %d, want 1", info.State)
	}
	if info.ClientIP != "" {
		t.Errorf("ClientIP = %q, want empty (not paired)", info.ClientIP)
	}
	// Verify protocol version from wire bytes [8:10]
	if data[8] != 0x00 || data[9] != 0x04 {
		t.Errorf("protocol version = 0x%02X%02X, want 0x0004", data[8], data[9])
	}
}

func TestParseEventNotification_Pcap(t *testing.T) {
	data := buildPcapEventNotification()
	evType, evData, err := ParseEventNotification(data)
	if err != nil {
		t.Fatalf("ParseEventNotification failed: %v", err)
	}
	if evType != 1 {
		t.Errorf("EventType = %d, want 1 (button press)", evType)
	}
	if evData != 0x02000000 {
		t.Errorf("EventData = 0x%08X, want 0x02000000", evData)
	}
}

func TestValidateWelcome_Pcap(t *testing.T) {
	data := buildPcapWelcomePacket()
	if err := ValidateWelcome(data); err != nil {
		t.Errorf("ValidateWelcome failed: %v", err)
	}
	// Verify size field
	if binary.BigEndian.Uint32(data[0:4]) != 0x10 {
		t.Errorf("welcome size = 0x%X, want 0x10", binary.BigEndian.Uint32(data[0:4]))
	}
}

func TestParseGetWifiStatusResponse_Pcap(t *testing.T) {
	data := buildPcapWifiStatusResponse()
	state, err := ParseGetWifiStatusResponse(data)
	if err != nil {
		t.Fatalf("ParseGetWifiStatusResponse failed: %v", err)
	}
	if state != 3 {
		t.Errorf("state = %d, want 3 (strong)", state)
	}
	// Verify full packet: size field, magic
	if binary.BigEndian.Uint32(data[0:4]) != 0x20 {
		t.Errorf("size = 0x%X, want 0x20", binary.BigEndian.Uint32(data[0:4]))
	}
	if [4]byte(data[4:8]) != Magic {
		t.Error("magic mismatch")
	}
}

func TestParseReserveResponse_PcapRejected(t *testing.T) {
	data := buildPcapReserveResponseRejected()
	status, err := ParseReserveResponse(data)
	if err != nil {
		t.Fatalf("ParseReserveResponse failed: %v", err)
	}
	if status != 0xFFFFFFFD {
		t.Errorf("status = 0x%08X, want 0xFFFFFFFD", status)
	}
	// Verify protocol version at offset 12
	ver := binary.BigEndian.Uint32(data[12:16])
	if ver != 0x00040000 {
		t.Errorf("protocol version = 0x%08X, want 0x00040000", ver)
	}
}

func TestParseDataDeviceInfo_Pcap(t *testing.T) {
	data := buildPcapDataDeviceInfoResponse()
	info, err := ParseDataDeviceInfo(data)
	if err != nil {
		t.Fatalf("ParseDataDeviceInfo failed: %v", err)
	}
	if info.DeviceName != "FUJITSU ScanSnap iX500" {
		t.Errorf("DeviceName = %q, want %q", info.DeviceName, "FUJITSU ScanSnap iX500")
	}
	if info.FirmwareRevision != "0M00" {
		t.Errorf("FirmwareRevision = %q, want %q", info.FirmwareRevision, "0M00")
	}
	// Verify VENS header
	if binary.BigEndian.Uint32(data[0:4]) != 0x88 {
		t.Errorf("size = 0x%X, want 0x88 (136)", binary.BigEndian.Uint32(data[0:4]))
	}
	if [4]byte(data[4:8]) != Magic {
		t.Error("magic mismatch")
	}
	// Verify SCSI device type
	if data[40] != 0x06 {
		t.Errorf("device type = 0x%02X, want 0x06 (scanner)", data[40])
	}
}

func TestParsePageHeader_PcapFinal(t *testing.T) {
	data := buildPcapPageHeaderFinal()
	hdr, err := ParsePageHeader(data)
	if err != nil {
		t.Fatalf("ParsePageHeader failed: %v", err)
	}
	if hdr.TotalLength != 43713 {
		t.Errorf("TotalLength = %d, want 43713", hdr.TotalLength)
	}
	if hdr.PageType != PageTypeFinal {
		t.Errorf("PageType = %d, want %d (final)", hdr.PageType, PageTypeFinal)
	}
	if hdr.Sheet != 0 {
		t.Errorf("Sheet = %d, want 0", hdr.Sheet)
	}
	if hdr.Side != 0 {
		t.Errorf("Side = %d, want 0", hdr.Side)
	}
	// JPEG size = TotalLength - 42 = 43671
	if hdr.JPEGSize() != 43671 {
		t.Errorf("JPEGSize() = %d, want 43671", hdr.JPEGSize())
	}
}

func TestParseSenseError_PcapNoError(t *testing.T) {
	resp := buildPcapSenseNoError()
	err := parseSenseError(resp)
	if err != nil {
		t.Errorf("expected nil for NO SENSE, got %v", err)
	}
	// Verify sense key is 0 (bit masked)
	senseKey := resp[SenseDataOffset+2] & 0x0F
	if senseKey != SenseKeyNoSense {
		t.Errorf("senseKey = 0x%02X, want 0x00", senseKey)
	}
}

func TestParseSenseError_PcapScanComplete(t *testing.T) {
	resp := buildPcapSenseScanComplete()
	err := parseSenseError(resp)
	if err != nil {
		t.Errorf("expected nil for scan complete, got %v", err)
	}
	// Verify raw sense fields
	senseKey := resp[SenseDataOffset+2] & 0x0F
	asc := resp[SenseDataOffset+12]
	ascq := resp[SenseDataOffset+13]
	if senseKey != SenseKeyMediumError {
		t.Errorf("senseKey = 0x%02X, want 0x03", senseKey)
	}
	if asc != VendorASC {
		t.Errorf("ASC = 0x%02X, want 0x80", asc)
	}
	if ascq != ASCQScanComplete {
		t.Errorf("ASCQ = 0x%02X, want 0x03", ascq)
	}
}

func TestParseSenseError_PcapIllegalRequest(t *testing.T) {
	resp := buildPcapSenseIllegalRequest()
	err := parseSenseError(resp)
	if err == nil {
		t.Fatal("expected error for ILLEGAL REQUEST, got nil")
	}
	if err.Kind != ScanErrGeneric {
		t.Errorf("Kind = %d, want %d (ScanErrGeneric)", err.Kind, ScanErrGeneric)
	}
}

// --------------------------------------------------------------------------
// Pcap-based round-trip (marshal) tests
// --------------------------------------------------------------------------

func TestMarshalScanConfig_PcapRoundTrip_BWSimplex(t *testing.T) {
	// BW + QualityAuto + Duplex + MultiFeed + BlankPageRemoval, no bleed-through
	// Matches scan-normal-bw.pcapng config #1 (144B)
	cfg := ScanConfig{
		ColorMode:        ColorBW,
		Quality:          QualityAuto,
		Duplex:           true,
		MultiFeed:        true,
		BlankPageRemoval: true,
		BleedThrough:     false,
		PaperSize:        PaperAuto,
		BWDensity:        0,
	}
	got := MarshalScanConfig(pcapToken, cfg)
	want := buildPcapScanConfigBWDuplexAutoQuality()

	if len(got) != len(want) {
		t.Fatalf("packet length = %d, want %d", len(got), len(want))
	}

	// Compare entire packet (token is the same since we use pcapToken)
	comparePacketRegion(t, got, want, 0, len(got), "full packet")
}

func TestMarshalScanConfig_PcapRoundTrip_MultiFeedOff(t *testing.T) {
	// BW + QualityAuto + Duplex + MultiFeed=OFF + BlankPageRemoval + BleedThrough=ON
	// Matches multifeed-on-off.pcapng config #1 (144B)
	cfg := ScanConfig{
		ColorMode:        ColorBW,
		Quality:          QualityAuto,
		Duplex:           true,
		MultiFeed:        false,
		BlankPageRemoval: true,
		BleedThrough:     true,
		PaperSize:        PaperAuto,
		BWDensity:        0,
	}
	got := MarshalScanConfig(pcapToken, cfg)
	want := buildPcapScanConfigMultiFeedOff()

	if len(got) != len(want) {
		t.Fatalf("packet length = %d, want %d", len(got), len(want))
	}

	comparePacketRegion(t, got, want, 0, len(got), "full packet")
}

func TestMarshalGetScanParams_PcapCDB(t *testing.T) {
	// Verify the SCSI CDB region matches all captures:
	// CDB = {0x12, 0x01, 0xF0, 0x00, 0x90, 0x00} at offset 48-53
	pkt := MarshalGetScanParams(pcapToken)
	if len(pkt) != 64 {
		t.Fatalf("length = %d, want 64", len(pkt))
	}
	wantCDB := []byte{0x12, 0x01, 0xF0, 0x00}
	gotCDB := pkt[48:52]
	for i := range wantCDB {
		if gotCDB[i] != wantCDB[i] {
			t.Errorf("CDB[%d] = 0x%02X, want 0x%02X", i, gotCDB[i], wantCDB[i])
		}
	}
	// Allocation length = 0x90 at CDB[4]
	if pkt[52] != 0x90 {
		t.Errorf("allocation length = 0x%02X, want 0x90", pkt[52])
	}
}

func TestMarshalPageTransfer_PcapCDB(t *testing.T) {
	// Verify CDB layout matches captures:
	// READ(10), DataType=0x00, TransferMode=0x02, TransferLen=0x040000
	pkt := MarshalPageTransfer(pcapToken, 0, 0, false)
	if len(pkt) != 64 {
		t.Fatalf("length = %d, want 64", len(pkt))
	}
	cdb := pkt[48:60]
	// Opcode
	if cdb[0] != SCSIOpcodeRead10 {
		t.Errorf("CDB[0] = 0x%02X, want 0x%02X (READ10)", cdb[0], SCSIOpcodeRead10)
	}
	// DataType=IMAGE
	if cdb[2] != 0x00 {
		t.Errorf("CDB[2] DataType = 0x%02X, want 0x00 (IMAGE)", cdb[2])
	}
	// TransferMode=BLOCK_UNTIL_AVAIL
	if cdb[3] != 0x02 {
		t.Errorf("CDB[3] TransferMode = 0x%02X, want 0x02", cdb[3])
	}
	// Transfer length = 0x040000 (256KB) in big-endian at CDB[6:9]
	tlen := uint32(cdb[6])<<16 | uint32(cdb[7])<<8 | uint32(cdb[8])
	if tlen != 0x040000 {
		t.Errorf("transfer length = 0x%06X, want 0x040000", tlen)
	}
}
