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

// ADF paper detection bitmask (§5.4).
// Applied to the scan status uint32 at response offset 40.
// Bit set = no paper; bit clear = paper present.
const ADFPaperMask uint32 = 0x80

// SCSI opcodes (CDB byte 0).
const (
	SCSIOpcodeRequestSense byte = 0x03 // REQUEST SENSE
	SCSIOpcodeInquiry      byte = 0x12 // INQUIRY (EVPD)
	SCSIOpcodeRead10       byte = 0x28 // READ(10) — page transfer
)

// Page transfer constants.
const PageTransferLen uint32 = 0x040000 // 256KB per chunk

// Response field offsets.
const (
	StatusRespScanStatusOffset = 40 // uint32 at resp[40:44]
	WaitRespStatusOffset       = 12 // uint32 at resp[12:16]
)
