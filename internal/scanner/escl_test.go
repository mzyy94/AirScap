package scanner

import (
	"testing"

	"github.com/OpenPrinting/go-mfp/abstract"
	"github.com/OpenPrinting/go-mfp/util/optional"

	"github.com/mzyy94/airscap/internal/vens"
)

// --------------------------------------------------------------------------
// Dimension conversion helpers
// --------------------------------------------------------------------------

func TestDimToInch1200(t *testing.T) {
	tests := []struct {
		name string
		dim  abstract.Dimension
		want uint16
	}{
		// 210mm = 21000 (1/100mm) → 21000 * 1200 / 2540 ≈ 9921
		{"210mm_A4_width", 210 * abstract.Millimeter, 9921},
		// 297mm = 29700 → 29700 * 1200 / 2540 = 14031
		{"297mm_A4_height", 297 * abstract.Millimeter, 14031},
		// 216mm = 21600 → 21600 * 1200 / 2540 ≈ 10204
		{"216mm_default_maxWidth", 216 * abstract.Millimeter, 10204},
		// 360mm = 36000 → 36000 * 1200 / 2540 ≈ 17007
		{"360mm_default_maxHeight", 360 * abstract.Millimeter, 17007},
		{"zero", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dimToInch1200(tt.dim)
			if got != tt.want {
				t.Errorf("dimToInch1200(%d) = %d, want %d", tt.dim, got, tt.want)
			}
		})
	}
}

func TestInch1200ToDim(t *testing.T) {
	tests := []struct {
		name string
		v    uint16
		want abstract.Dimension
	}{
		// 0x28D0 = 10448 (1/1200 inch) → 10448 * 2540 / 1200 ≈ 22114 (1/100mm) ≈ 221.1mm
		{"PaperAuto_width", 0x28D0, abstract.Dimension(22114)},
		// 0xA1D0 = 41424 (1/1200 inch) → 41424 * 2540 / 1200 ≈ 87680 (1/100mm) ≈ 876.8mm
		{"MaxHeight_from_scanner", 0xA1D0, abstract.Dimension(87680)},
		{"zero", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inch1200ToDim(tt.v)
			if got != tt.want {
				t.Errorf("inch1200ToDim(0x%04X) = %d, want %d", tt.v, got, tt.want)
			}
		})
	}
}

// TestDimConversion_RoundTrip verifies that converting Dimension→1/1200inch→Dimension
// preserves values within 1mm tolerance (rounding from integer division).
func TestDimConversion_RoundTrip(t *testing.T) {
	tests := []abstract.Dimension{
		210 * abstract.Millimeter, // A4 width
		297 * abstract.Millimeter, // A4 height
		148 * abstract.Millimeter, // A5 width
		100 * abstract.Millimeter, // postcard width
	}
	for _, dim := range tests {
		inch := dimToInch1200(dim)
		back := inch1200ToDim(inch)
		diff := int(dim) - int(back)
		if diff < 0 {
			diff = -diff
		}
		// Allow up to 1mm (100 units) tolerance due to integer rounding
		if diff > 100 {
			t.Errorf("round-trip %d → %d → %d, diff=%d exceeds 1mm", dim, inch, back, diff)
		}
	}
}

// --------------------------------------------------------------------------
// mapScanConfig tests
// --------------------------------------------------------------------------

func TestMapScanConfig_ColorModes(t *testing.T) {
	tests := []struct {
		name     string
		mode     abstract.ColorMode
		wantVens vens.ColorMode
	}{
		{"color", abstract.ColorModeColor, vens.ColorColor},
		{"mono", abstract.ColorModeMono, vens.ColorGray},
		{"binary", abstract.ColorModeBinary, vens.ColorBW},
		{"unset", abstract.ColorModeUnset, vens.ColorAuto},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := abstract.ScannerRequest{ColorMode: tt.mode}
			cfg := mapScanConfig(req, false)
			if cfg.ColorMode != tt.wantVens {
				t.Errorf("ColorMode = %d, want %d", cfg.ColorMode, tt.wantVens)
			}
		})
	}
}

func TestMapScanConfig_Resolution(t *testing.T) {
	tests := []struct {
		name    string
		dpi     int
		wantQ   vens.Quality
	}{
		{"zero_auto", 0, vens.QualityAuto},
		{"150_normal", 150, vens.QualityNormal},
		{"200_fine", 200, vens.QualityFine},
		{"300_superfine", 300, vens.QualitySuperFine},
		{"100_normal", 100, vens.QualityNormal},    // <= 150 → Normal
		{"175_fine", 175, vens.QualityFine},         // <= 200 → Fine
		{"250_superfine", 250, vens.QualitySuperFine}, // > 200 → SuperFine
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := abstract.ScannerRequest{
				Resolution: abstract.Resolution{XResolution: tt.dpi, YResolution: tt.dpi},
			}
			cfg := mapScanConfig(req, false)
			if cfg.Quality != tt.wantQ {
				t.Errorf("Quality = %d, want %d", cfg.Quality, tt.wantQ)
			}
		})
	}
}

func TestMapScanConfig_Duplex(t *testing.T) {
	// Duplex
	req := abstract.ScannerRequest{ADFMode: abstract.ADFModeDuplex}
	cfg := mapScanConfig(req, false)
	if !cfg.Duplex {
		t.Error("Duplex = false, want true for ADFModeDuplex")
	}

	// Simplex
	req = abstract.ScannerRequest{ADFMode: abstract.ADFModeSimplex}
	cfg = mapScanConfig(req, false)
	if cfg.Duplex {
		t.Error("Duplex = true, want false for ADFModeSimplex")
	}

	// Unset
	req = abstract.ScannerRequest{}
	cfg = mapScanConfig(req, false)
	if cfg.Duplex {
		t.Error("Duplex = true, want false for ADFModeUnset")
	}
}

func TestMapScanConfig_Threshold(t *testing.T) {
	tests := []struct {
		name    string
		val     int
		wantBWD int
	}{
		{"min", -5, -5},
		{"zero", 0, 0},
		{"max", 5, 5},
		{"mid", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := abstract.ScannerRequest{
				ColorMode: abstract.ColorModeBinary,
				Threshold: optional.New(tt.val),
			}
			cfg := mapScanConfig(req, false)
			if cfg.BWDensity != tt.wantBWD {
				t.Errorf("BWDensity = %d, want %d", cfg.BWDensity, tt.wantBWD)
			}
		})
	}
}

func TestMapScanConfig_NoThreshold(t *testing.T) {
	req := abstract.ScannerRequest{ColorMode: abstract.ColorModeBinary}
	cfg := mapScanConfig(req, false)
	if cfg.BWDensity != 0 {
		t.Errorf("BWDensity = %d, want 0 when no threshold set", cfg.BWDensity)
	}
}

func TestMapScanConfig_RegionToPaper(t *testing.T) {
	// Specific region → paper override
	req := abstract.ScannerRequest{
		Region: abstract.Region{
			Width:  210 * abstract.Millimeter,
			Height: 297 * abstract.Millimeter,
		},
	}
	cfg := mapScanConfig(req, false)
	if cfg.PaperWidth == 0 || cfg.PaperHeight == 0 {
		t.Error("expected paper override for specific region, got 0")
	}
	// Verify conversion: 210mm → 1/1200 inch
	expectedW := dimToInch1200(210 * abstract.Millimeter)
	expectedH := dimToInch1200(297 * abstract.Millimeter)
	if cfg.PaperWidth != expectedW {
		t.Errorf("PaperWidth = %d, want %d", cfg.PaperWidth, expectedW)
	}
	if cfg.PaperHeight != expectedH {
		t.Errorf("PaperHeight = %d, want %d", cfg.PaperHeight, expectedH)
	}
}

func TestMapScanConfig_MaxRegionIsAuto(t *testing.T) {
	// Region >= max scan area (216mm × 360mm) → treated as auto, no override
	req := abstract.ScannerRequest{
		Region: abstract.Region{
			Width:  216 * abstract.Millimeter,
			Height: 360 * abstract.Millimeter,
		},
	}
	cfg := mapScanConfig(req, false)
	if cfg.PaperWidth != 0 || cfg.PaperHeight != 0 {
		t.Errorf("max region should not set paper override: width=%d, height=%d",
			cfg.PaperWidth, cfg.PaperHeight)
	}
}

func TestMapScanConfig_ZeroRegionIsAuto(t *testing.T) {
	req := abstract.ScannerRequest{} // zero region
	cfg := mapScanConfig(req, false)
	if cfg.PaperWidth != 0 || cfg.PaperHeight != 0 {
		t.Errorf("zero region should not set paper override: width=%d, height=%d",
			cfg.PaperWidth, cfg.PaperHeight)
	}
}

func TestMapScanConfig_ForcePaperAuto(t *testing.T) {
	// Even with a specific region, forcePaperAuto skips paper override
	req := abstract.ScannerRequest{
		Region: abstract.Region{
			Width:  210 * abstract.Millimeter,
			Height: 297 * abstract.Millimeter,
		},
	}
	cfg := mapScanConfig(req, true)
	if cfg.PaperWidth != 0 || cfg.PaperHeight != 0 {
		t.Errorf("forcePaperAuto should skip paper override: width=%d, height=%d",
			cfg.PaperWidth, cfg.PaperHeight)
	}
}

func TestMapScanConfig_Defaults(t *testing.T) {
	req := abstract.ScannerRequest{}
	cfg := mapScanConfig(req, false)

	// mapScanConfig starts from DefaultScanConfig()
	if !cfg.MultiFeed {
		t.Error("MultiFeed should default to true")
	}
	if !cfg.BlankPageRemoval {
		t.Error("BlankPageRemoval should default to true")
	}
	if cfg.BleedThrough {
		t.Error("BleedThrough should default to false")
	}
}

// --------------------------------------------------------------------------
// buildCapabilities tests
// --------------------------------------------------------------------------

// newTestScanner creates a minimal Scanner with the given ScanParams for testing.
func newTestScanner(params *vens.ScanParams) *Scanner {
	s := &Scanner{
		host:             "192.168.5.3",
		name:             "ScanSnap iX500",
		serial:           "iX500-TEST",
		deviceName:       "FUJITSU ScanSnap iX500",
		firmwareRevision: "0M00",
		scanParams:       params,
	}
	return s
}

func TestBuildCapabilities_WithScanParams(t *testing.T) {
	params := &vens.ScanParams{
		MaxResolutionX: 600,
		MaxResolutionY: 600,
		MinResolutionX: 50,
		MinResolutionY: 50,
		ColorModes:     0x11,
		MaxWidth:       0x28D0, // 10448 in 1/1200 inch ≈ 221mm
		MaxHeight:      0xA1D0, // 41424 in 1/1200 inch ≈ 877mm
	}
	s := newTestScanner(params)
	a := &ESCLAdapter{scanner: s, listenPort: 8080}
	caps := a.buildCapabilities()

	// Resolutions: 150, 200, 300 all within [50, 600]
	if caps.ADFSimplex == nil {
		t.Fatal("ADFSimplex is nil")
	}
	if len(caps.ADFSimplex.Profiles) == 0 {
		t.Fatal("no profiles in ADFSimplex")
	}
	resolutions := caps.ADFSimplex.Profiles[0].Resolutions
	if len(resolutions) != 3 {
		t.Errorf("resolutions count = %d, want 3", len(resolutions))
	}
	expectedDPIs := []int{150, 200, 300}
	for i, r := range resolutions {
		if i < len(expectedDPIs) && r.XResolution != expectedDPIs[i] {
			t.Errorf("resolution[%d] = %d, want %d", i, r.XResolution, expectedDPIs[i])
		}
	}

	// MaxOpticalResolution from scanner (600)
	if caps.ADFSimplex.MaxOpticalXResolution != 600 {
		t.Errorf("MaxOpticalXResolution = %d, want 600", caps.ADFSimplex.MaxOpticalXResolution)
	}

	// MaxWidth/Height from scanner params
	expectedMaxWidth := inch1200ToDim(0x28D0)
	if caps.ADFSimplex.MaxWidth != expectedMaxWidth {
		t.Errorf("MaxWidth = %d, want %d", caps.ADFSimplex.MaxWidth, expectedMaxWidth)
	}
	expectedMaxHeight := inch1200ToDim(0xA1D0)
	if caps.ADFSimplex.MaxHeight != expectedMaxHeight {
		t.Errorf("MaxHeight = %d, want %d", caps.ADFSimplex.MaxHeight, expectedMaxHeight)
	}

	// MinWidth/MinHeight default (non-ForcePaperAuto)
	if caps.ADFSimplex.MinWidth != 50*abstract.Millimeter {
		t.Errorf("MinWidth = %d, want %d", caps.ADFSimplex.MinWidth, 50*abstract.Millimeter)
	}

	// Device info: MakeAndModel from DeviceName minus firmware revision
	if caps.MakeAndModel != "FUJITSU ScanSnap iX500" {
		t.Errorf("MakeAndModel = %q, want %q", caps.MakeAndModel, "FUJITSU ScanSnap iX500")
	}
	if caps.SerialNumber != "iX500-TEST" {
		t.Errorf("SerialNumber = %q, want %q", caps.SerialNumber, "iX500-TEST")
	}

	// Threshold range
	if caps.ThresholdRange.Min != -5 || caps.ThresholdRange.Max != 5 {
		t.Errorf("ThresholdRange = [%d, %d], want [-5, 5]", caps.ThresholdRange.Min, caps.ThresholdRange.Max)
	}

	// ADF capacity
	if caps.ADFCapacity != 50 {
		t.Errorf("ADFCapacity = %d, want 50", caps.ADFCapacity)
	}

	// Document formats
	expectedFormats := []string{"image/jpeg", "image/tiff", "application/pdf"}
	if len(caps.DocumentFormats) != len(expectedFormats) {
		t.Errorf("DocumentFormats count = %d, want %d", len(caps.DocumentFormats), len(expectedFormats))
	}
	for i, f := range caps.DocumentFormats {
		if i < len(expectedFormats) && f != expectedFormats[i] {
			t.Errorf("DocumentFormats[%d] = %q, want %q", i, f, expectedFormats[i])
		}
	}
}

func TestBuildCapabilities_NilScanParams(t *testing.T) {
	s := newTestScanner(nil)
	a := &ESCLAdapter{scanner: s, listenPort: 8080}
	caps := a.buildCapabilities()

	// Fallback values when ScanParams is nil
	if caps.ADFSimplex.MaxWidth != 216*abstract.Millimeter {
		t.Errorf("MaxWidth = %d, want %d (216mm fallback)", caps.ADFSimplex.MaxWidth, 216*abstract.Millimeter)
	}
	if caps.ADFSimplex.MaxHeight != 360*abstract.Millimeter {
		t.Errorf("MaxHeight = %d, want %d (360mm fallback)", caps.ADFSimplex.MaxHeight, 360*abstract.Millimeter)
	}
	if caps.ADFSimplex.MaxOpticalXResolution != 300 {
		t.Errorf("MaxOpticalXResolution = %d, want 300 (fallback)", caps.ADFSimplex.MaxOpticalXResolution)
	}

	// Resolutions: default range 150-300
	resolutions := caps.ADFSimplex.Profiles[0].Resolutions
	if len(resolutions) != 3 {
		t.Errorf("resolutions count = %d, want 3", len(resolutions))
	}
}

func TestBuildCapabilities_ForcePaperAuto(t *testing.T) {
	params := &vens.ScanParams{
		MaxResolutionX: 600,
		MaxWidth:       0x28D0,
		MaxHeight:      0xA1D0,
	}
	s := newTestScanner(params)
	a := &ESCLAdapter{scanner: s, listenPort: 8080, forcePaperAuto: true}
	caps := a.buildCapabilities()

	// ForcePaperAuto constrains to A4
	if caps.ADFSimplex.MaxWidth != 210*abstract.Millimeter {
		t.Errorf("MaxWidth = %d, want %d (A4 210mm)", caps.ADFSimplex.MaxWidth, 210*abstract.Millimeter)
	}
	if caps.ADFSimplex.MaxHeight != 297*abstract.Millimeter {
		t.Errorf("MaxHeight = %d, want %d (A4 297mm)", caps.ADFSimplex.MaxHeight, 297*abstract.Millimeter)
	}
	if caps.ADFSimplex.MinWidth != 209*abstract.Millimeter {
		t.Errorf("MinWidth = %d, want %d (209mm)", caps.ADFSimplex.MinWidth, 209*abstract.Millimeter)
	}
	if caps.ADFSimplex.MinHeight != 296*abstract.Millimeter {
		t.Errorf("MinHeight = %d, want %d (296mm)", caps.ADFSimplex.MinHeight, 296*abstract.Millimeter)
	}
}

func TestBuildCapabilities_EmptyName(t *testing.T) {
	s := newTestScanner(nil)
	s.name = ""
	s.serial = ""
	s.deviceName = ""

	a := &ESCLAdapter{scanner: s, listenPort: 8080}
	caps := a.buildCapabilities()

	if caps.MakeAndModel != "Unknown" {
		t.Errorf("MakeAndModel = %q, want %q (fallback)", caps.MakeAndModel, "Unknown")
	}
	if caps.SerialNumber != "192.168.5.3" {
		t.Errorf("SerialNumber = %q, want %q (fallback to host)", caps.SerialNumber, "192.168.5.3")
	}
}

func TestBuildCapabilities_SimplexDuplexSame(t *testing.T) {
	s := newTestScanner(nil)
	a := &ESCLAdapter{scanner: s, listenPort: 8080}
	caps := a.buildCapabilities()

	// ADFSimplex and ADFDuplex should reference the same capabilities
	if caps.ADFSimplex != caps.ADFDuplex {
		t.Error("ADFSimplex and ADFDuplex should share same capabilities")
	}
}
