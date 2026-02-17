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

// ADF paper detection bitmask.
const ADFPaperMask uint32 = 0x00010000
