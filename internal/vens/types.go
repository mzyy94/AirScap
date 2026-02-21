package vens

// ColorMode represents scan color modes.
type ColorMode int

const (
	ColorAuto  ColorMode = 0
	ColorColor ColorMode = 1
	ColorGray  ColorMode = 2
	ColorBW    ColorMode = 3
)

// Quality represents scan quality presets.
type Quality int

const (
	QualityAuto      Quality = 0
	QualityNormal    Quality = 1 // 150 DPI
	QualityFine      Quality = 2 // 200 DPI
	QualitySuperFine Quality = 3 // 300 DPI
)

// QualityDPI maps Quality to actual DPI values.
var QualityDPI = map[Quality]int{
	QualityAuto:      0,
	QualityNormal:    150,
	QualityFine:      200,
	QualitySuperFine: 300,
}

// PaperSize represents supported paper sizes.
type PaperSize int

const (
	PaperAuto         PaperSize = 0
	PaperA4           PaperSize = 1
	PaperA5           PaperSize = 2
	PaperBusinessCard PaperSize = 3
	PaperPostcard     PaperSize = 4
)

// PaperDimension holds paper width and height in 1/1200 inch units.
type PaperDimension struct {
	Width  uint16
	Height uint16
}

// PaperDimensions maps PaperSize to dimensions in 1/1200 inch units.
var PaperDimensions = map[PaperSize]PaperDimension{
	PaperAuto:         {0x28D0, 0x45A4}, // max scan area
	PaperA4:           {0x26D0, 0x36D0}, // 210mm x 297mm
	PaperA5:           {0x1B50, 0x26C0}, // 148mm x 210mm
	PaperBusinessCard: {0x28D0, 0x1274}, // auto-width x 100mm
	PaperPostcard:     {0x1280, 0x1B50}, // 100mm x 148mm
}

// ScanConfig holds scan parameters to send to the scanner.
type ScanConfig struct {
	ColorMode          ColorMode
	Quality            Quality
	Duplex             bool
	BleedThrough       bool
	PaperSize          PaperSize
	PaperWidth         uint16 // override width in 1/1200 inch; 0 = use PaperSize
	PaperHeight        uint16 // override height in 1/1200 inch; 0 = use PaperSize
	BWDensity          int    // -5 to +5, only for BW mode (wire value = 6 + density)
	CompressionArg     byte   // JPEG compression: 0x09 (most compressed) to 0x0D (best quality); 0 = auto
	MultiFeed          bool
	BlankPageRemoval   bool
}

// DefaultScanConfig returns a ScanConfig with default values.
func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		ColorMode:        ColorAuto,
		Quality:          QualityAuto,
		Duplex:           true,
		BleedThrough:     false,
		PaperSize:        PaperAuto,
		MultiFeed:        true,
		BlankPageRemoval: true,
	}
}

// ScanParams holds scanner capabilities from INQUIRY VPD 0xF0 response.
type ScanParams struct {
	MaxResolutionX int    // DPI
	MaxResolutionY int    // DPI
	MinResolutionX int    // DPI
	MinResolutionY int    // DPI
	ColorModes     uint8  // raw bitmask
	MaxWidth       uint16 // 1/1200 inch (converted from 1/600 on the wire)
	MaxHeight      uint16 // 1/1200 inch (converted from 1/600 on the wire)
}

// PixelSizeInfo holds the actual pixel dimensions of a scanned page,
// returned by READ(10) with DataType=0x80.
type PixelSizeInfo struct {
	XPixels        int // Actual width in pixels
	YPixels        int // Actual height in pixels
	DetectedLength int // Detected paper length (1/1200 inch)
	XRes           int // Actual X resolution (DPI)
	YRes           int // Actual Y resolution (DPI)
}

// DataDeviceInfo holds device identity from TCP GET_SET sub=0x12 response.
type DataDeviceInfo struct {
	DeviceName       string
	FirmwareRevision string // extracted from device name suffix (e.g. "0M00")
}

// DeviceInfo holds information about a discovered scanner.
type DeviceInfo struct {
	DeviceIP    string
	DataPort    uint16
	ControlPort uint16
	MAC         string
	Serial      string
	Name        string
	State       uint32
	Paired      bool
	ClientIP    string
}
