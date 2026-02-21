package vens

// Protocol magic bytes.
var (
	Magic     = [4]byte{'V', 'E', 'N', 'S'}
	MagicSSNR = [4]byte{'s', 's', 'N', 'R'}
)

// Network ports used by the ScanSnap protocol.
const (
	BroadcastPort      = 53220 // UDP: scanner advertisement broadcast
	DiscoveryPort      = 52217 // UDP: scanner-side discovery
	DefaultDataPort    = 53218 // TCP: data channel
	DefaultControlPort = 53219 // TCP: control channel
	ClientDiscoveryPort = 55264 // UDP: client-side discovery
	ClientNotifyPort   = 55265 // UDP: event notification (button press)
)

// Control channel commands (TCP:53219).
const (
	CmdReserve       uint32 = 0x11 // Reserve scanner (send identity / client config)
	CmdRelease       uint32 = 0x12 // Release scanner (register / deregister session)
	CmdGetDevInfo    uint32 = 0x13 // Get device info
	CmdSetDevInfo    uint32 = 0x14 // Set device info
	CmdUpdatePsw     uint32 = 0x15 // Update scanner password
	CmdGetWifiStatus uint32 = 0x30 // Query scanner WiFi / connection status
	CmdSetWifiMode   uint32 = 0x31 // Set WiFi mode (infrastructure / direct)
	CmdXferData      uint32 = 0x50 // Data transfer
	CmdFirmUpdate    uint32 = 0x51 // Firmware update
	CmdSetStartMode  uint32 = 0x62 // Set scanner start mode
)

// Data channel commands (TCP:53218).
// These values at offset 32 represent the SCSI CDB byte length:
// 0x06=6-byte CDB, 0x08=8-byte CDB, 0x0A=10-byte CDB, 0x0C=12-byte CDB.
const (
	CmdGetSet       uint32 = 0x06
	CmdConfig       uint32 = 0x08
	CmdGetStatus    uint32 = 0x0A
	CmdPageTransfer uint32 = 0x0C
)

// Broadcast advertisement command.
const CmdBroadcast uint32 = 0x21

// Page type values in PageHeader.
const (
	PageTypeMore  uint32 = 0x00 // More chunks follow
	PageTypeFinal uint32 = 0x02 // Last chunk of a page
)

// ADF status bitmasks applied to the scan status uint32 at response offset 40.
const (
	ADFCoverOpenMask uint32 = 0x0020 // Bit 5: ADF cover open
	ADFPaperMask     uint32 = 0x0080 // Bit 7: set = no paper; clear = paper present
	ADFJamMask       uint32 = 0x8000 // Bit 15: paper jam (valid only in idle/ADF status context)
)

// SCSI opcodes (CDB byte 0).
const (
	SCSIOpcodeRequestSense byte = 0x03 // REQUEST SENSE
	SCSIOpcodeInquiry      byte = 0x12 // INQUIRY (EVPD)
	SCSIOpcodeRead10       byte = 0x28 // READ(10) — page transfer
)

// READ(10) Data Type values (CDB byte 2).
const (
	DataTypeImage       byte = 0x00 // Image data (chunked transfer)
	DataTypePixelSize   byte = 0x80 // Pixel size after scan (32 bytes)
	DataTypePaperSize   byte = 0x81 // Paper size after scan (8 bytes)
	DataTypeCarrierSheet byte = 0x83 // Carrier sheet info (4 bytes)
)

// READ(10) response sizes for metadata types.
const (
	PixelSizeResponseLen  uint32 = 0x20 // 32 bytes
	PaperSizeResponseLen  uint32 = 0x08 // 8 bytes
)

// Page transfer constants.
const PageTransferLen uint32 = 0x040000 // 256KB per chunk

// Response field offsets.
const (
	StatusRespScanStatusOffset = 40 // uint32 at resp[40:44]
	StatusRespErrorOffset      = 44 // uint32 at resp[44:48], error code in lower 16 bits
	WaitRespStatusOffset       = 12 // uint32 at resp[12:16]
)

// SCSI Sense Data layout within REQUEST SENSE (opcode 0x03) VENS responses.
// The 18-byte sense data starts at VENS response offset 40.
const SenseDataOffset = 40

// SCSI Sense Keys (sense[2] & 0x0F).
const (
	SenseKeyNoSense     byte = 0x00
	SenseKeyNotReady    byte = 0x02
	SenseKeyMediumError byte = 0x03
)

// Vendor-specific ASC/ASCQ for ScanSnap (ASC=0x80).
// These appear in REQUEST SENSE responses at sense[12] and sense[13].
const (
	VendorASC        byte = 0x80 // Vendor-specific Additional Sense Code
	ASCQPaperJam     byte = 0x01 // Paper Jam Detected
	ASCQCoverOpen    byte = 0x02 // ADF Cover Open
	ASCQScanComplete byte = 0x03 // No more pages (not an error)
	ASCQMultiFeed    byte = 0x07 // Multi Feed Detected
)
