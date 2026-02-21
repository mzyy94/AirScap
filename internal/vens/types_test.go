package vens

import "testing"

func TestDefaultScanConfig(t *testing.T) {
	cfg := DefaultScanConfig()

	if cfg.ColorMode != ColorAuto {
		t.Errorf("ColorMode = %d, want %d (ColorAuto)", cfg.ColorMode, ColorAuto)
	}
	if cfg.Quality != QualityAuto {
		t.Errorf("Quality = %d, want %d (QualityAuto)", cfg.Quality, QualityAuto)
	}
	if !cfg.Duplex {
		t.Error("Duplex = false, want true")
	}
	if cfg.BleedThrough {
		t.Error("BleedThrough = true, want false")
	}
	if cfg.PaperSize != PaperAuto {
		t.Errorf("PaperSize = %d, want %d (PaperAuto)", cfg.PaperSize, PaperAuto)
	}
	if cfg.PaperWidth != 0 {
		t.Errorf("PaperWidth = %d, want 0", cfg.PaperWidth)
	}
	if cfg.PaperHeight != 0 {
		t.Errorf("PaperHeight = %d, want 0", cfg.PaperHeight)
	}
	if cfg.BWDensity != 0 {
		t.Errorf("BWDensity = %d, want 0", cfg.BWDensity)
	}
	if !cfg.MultiFeed {
		t.Error("MultiFeed = false, want true")
	}
	if !cfg.BlankPageRemoval {
		t.Error("BlankPageRemoval = false, want true")
	}
}

func TestColorModeConstants(t *testing.T) {
	// Verify constants match expected values (protocol-defined)
	tests := []struct {
		name string
		got  ColorMode
		want ColorMode
	}{
		{"ColorAuto", ColorAuto, 0},
		{"ColorColor", ColorColor, 1},
		{"ColorGray", ColorGray, 2},
		{"ColorBW", ColorBW, 3},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestQualityConstants(t *testing.T) {
	tests := []struct {
		name string
		got  Quality
		want Quality
	}{
		{"QualityAuto", QualityAuto, 0},
		{"QualityNormal", QualityNormal, 1},
		{"QualityFine", QualityFine, 2},
		{"QualitySuperFine", QualitySuperFine, 3},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestQualityDPI(t *testing.T) {
	expected := map[Quality]int{
		QualityAuto:      0,
		QualityNormal:    150,
		QualityFine:      200,
		QualitySuperFine: 300,
	}
	for q, wantDPI := range expected {
		if gotDPI, ok := QualityDPI[q]; !ok {
			t.Errorf("QualityDPI[%d] missing", q)
		} else if gotDPI != wantDPI {
			t.Errorf("QualityDPI[%d] = %d, want %d", q, gotDPI, wantDPI)
		}
	}
	// Verify no extra entries
	if len(QualityDPI) != len(expected) {
		t.Errorf("QualityDPI has %d entries, want %d", len(QualityDPI), len(expected))
	}
}

func TestPaperSizeConstants(t *testing.T) {
	tests := []struct {
		name string
		got  PaperSize
		want PaperSize
	}{
		{"PaperAuto", PaperAuto, 0},
		{"PaperA4", PaperA4, 1},
		{"PaperA5", PaperA5, 2},
		{"PaperBusinessCard", PaperBusinessCard, 3},
		{"PaperPostcard", PaperPostcard, 4},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestPaperDimensions(t *testing.T) {
	// Verify all declared paper sizes have dimensions
	expected := []PaperSize{PaperAuto, PaperA4, PaperA5, PaperBusinessCard, PaperPostcard}
	for _, ps := range expected {
		dim, ok := PaperDimensions[ps]
		if !ok {
			t.Errorf("PaperDimensions[%d] missing", ps)
			continue
		}
		if dim.Width == 0 && dim.Height == 0 {
			t.Errorf("PaperDimensions[%d] has zero dimensions", ps)
		}
	}
	if len(PaperDimensions) != len(expected) {
		t.Errorf("PaperDimensions has %d entries, want %d", len(PaperDimensions), len(expected))
	}
}

func TestPaperDimensions_SpecificValues(t *testing.T) {
	tests := []struct {
		name   string
		ps     PaperSize
		width  uint16
		height uint16
	}{
		{"PaperAuto", PaperAuto, 0x28D0, 0x45A4},
		{"PaperA4", PaperA4, 0x26D0, 0x36D0},
		{"PaperA5", PaperA5, 0x1B50, 0x26C0},
		{"PaperBusinessCard", PaperBusinessCard, 0x28D0, 0x1274},
		{"PaperPostcard", PaperPostcard, 0x1280, 0x1B50},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dim := PaperDimensions[tt.ps]
			if dim.Width != tt.width {
				t.Errorf("Width = 0x%04X, want 0x%04X", dim.Width, tt.width)
			}
			if dim.Height != tt.height {
				t.Errorf("Height = 0x%04X, want 0x%04X", dim.Height, tt.height)
			}
		})
	}
}

// TestPaperDimensions_A4Millimeters verifies A4 dimensions match physical size.
// PaperA4: 210mm × 297mm in 1/1200 inch units.
func TestPaperDimensions_A4Millimeters(t *testing.T) {
	dim := PaperDimensions[PaperA4]

	// Convert 1/1200 inch to mm: value * 25.4 / 1200
	widthMM := float64(dim.Width) * 25.4 / 1200.0
	heightMM := float64(dim.Height) * 25.4 / 1200.0

	// A4 is 210mm × 297mm, allow 1mm tolerance
	if widthMM < 209 || widthMM > 211 {
		t.Errorf("A4 width = %.1fmm, want ~210mm", widthMM)
	}
	if heightMM < 296 || heightMM > 298 {
		t.Errorf("A4 height = %.1fmm, want ~297mm", heightMM)
	}
}

func TestScanErrorKindConstants(t *testing.T) {
	// Verify ScanErrorKind iota values
	if ScanErrGeneric != 0 {
		t.Errorf("ScanErrGeneric = %d, want 0", ScanErrGeneric)
	}
	if ScanErrNoPaper != 1 {
		t.Errorf("ScanErrNoPaper = %d, want 1", ScanErrNoPaper)
	}
	if ScanErrPaperJam != 2 {
		t.Errorf("ScanErrPaperJam = %d, want 2", ScanErrPaperJam)
	}
	if ScanErrMultiFeed != 3 {
		t.Errorf("ScanErrMultiFeed = %d, want 3", ScanErrMultiFeed)
	}
	if ScanErrCoverOpen != 4 {
		t.Errorf("ScanErrCoverOpen = %d, want 4", ScanErrCoverOpen)
	}
}

func TestScanError_Error(t *testing.T) {
	err := &ScanError{Kind: ScanErrPaperJam, Msg: "paper jam"}
	if err.Error() != "paper jam" {
		t.Errorf("Error() = %q, want %q", err.Error(), "paper jam")
	}
}
