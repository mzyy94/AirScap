package scanner

import (
	"bytes"
	"context"
	"io"
	"log/slog"

	"github.com/OpenPrinting/go-mfp/abstract"
	"github.com/OpenPrinting/go-mfp/util/generic"
	"github.com/OpenPrinting/go-mfp/util/uuid"

	"github.com/mzyy94/airscap/internal/vens"
)

// ESCLAdapter implements abstract.Scanner for ScanSnap hardware.
type ESCLAdapter struct {
	scanner  *Scanner
	caps     *abstract.ScannerCapabilities
	adfEmpty bool // true after a scan session completes (ADF likely exhausted)
}

// NewESCLAdapter creates an eSCL adapter wrapping the given Scanner.
func NewESCLAdapter(s *Scanner) *ESCLAdapter {
	a := &ESCLAdapter{scanner: s}
	a.caps = a.buildCapabilities()
	return a
}

func (a *ESCLAdapter) buildCapabilities() *abstract.ScannerCapabilities {
	profile := abstract.SettingsProfile{
		ColorModes: generic.MakeBitset(
			abstract.ColorModeColor,
			abstract.ColorModeMono,
			abstract.ColorModeBinary,
		),
		Depths: generic.MakeBitset(abstract.ColorDepth8),
		BinaryRenderings: generic.MakeBitset(
			abstract.BinaryRenderingThreshold,
		),
		Resolutions: []abstract.Resolution{
			{XResolution: 150, YResolution: 150},
			{XResolution: 200, YResolution: 200},
			{XResolution: 300, YResolution: 300},
		},
	}

	adfCaps := &abstract.InputCapabilities{
		MinWidth:              50 * abstract.Millimeter,
		MaxWidth:              216 * abstract.Millimeter,
		MinHeight:             50 * abstract.Millimeter,
		MaxHeight:             360 * abstract.Millimeter,
		MaxOpticalXResolution: 300,
		MaxOpticalYResolution: 300,
		Intents: generic.MakeBitset(
			abstract.IntentDocument,
			abstract.IntentPhoto,
			abstract.IntentTextAndGraphic,
		),
		Profiles: []abstract.SettingsProfile{profile},
	}

	// Generate deterministic UUID from scanner host
	deviceUUID := uuid.SHA1(uuid.NameSpaceDNS, "airscap."+a.scanner.Host())

	name := a.scanner.Name()
	if name == "" {
		name = "ScanSnap"
	}

	serial := a.scanner.Serial()
	if serial == "" {
		serial = a.scanner.Host()
	}

	return &abstract.ScannerCapabilities{
		UUID:            deviceUUID,
		MakeAndModel:    name,
		Manufacturer:    "Fujitsu",
		SerialNumber:    serial,
		DocumentFormats: []string{"image/jpeg", "application/pdf"},
		ADFCapacity:     50,
		ADFSimplex:      adfCaps,
		ADFDuplex:       adfCaps,
	}
}

// Capabilities returns the scanner capabilities.
func (a *ESCLAdapter) Capabilities() *abstract.ScannerCapabilities {
	return a.caps
}

// Scan converts an eSCL request to VENS parameters and executes the scan.
func (a *ESCLAdapter) Scan(ctx context.Context, req abstract.ScannerRequest) (abstract.Document, error) {
	if err := req.Validate(a.caps); err != nil {
		return nil, err
	}

	cfg := mapScanConfig(req)
	slog.Info("scan requested",
		"colorMode", req.ColorMode,
		"resolution", req.Resolution,
		"adfMode", req.ADFMode,
		"duplex", cfg.Duplex,
	)

	pages, err := a.scanner.Scan(cfg, nil)
	if err != nil {
		// Mark ADF as empty on scan error (likely no paper)
		a.adfEmpty = true
		return nil, err
	}
	// Scan session completed — ADF is likely exhausted
	a.adfEmpty = true

	// Collect JPEG data from pages
	jpegs := make([][]byte, len(pages))
	for i, p := range pages {
		jpegs[i] = p.JPEG
	}

	res := req.Resolution
	if res.IsZero() {
		dpi := vens.QualityDPI[cfg.Quality]
		if dpi == 0 {
			dpi = 300
		}
		res = abstract.Resolution{XResolution: dpi, YResolution: dpi}
	}

	doc := &jpegDocument{res: res, pages: jpegs}

	// Apply filter for format conversion if needed
	if req.DocumentFormat != "" && req.DocumentFormat != "image/jpeg" {
		return abstract.NewFilter(doc, abstract.FilterOptions{
			OutputFormat: req.DocumentFormat,
		}), nil
	}

	return doc, nil
}

// CheckADFStatus queries the scanner for paper presence.
// On error, falls back to cached state from the last scan session.
func (a *ESCLAdapter) CheckADFStatus() (bool, error) {
	hasPaper, err := a.scanner.CheckADFStatus()
	if err != nil {
		if a.adfEmpty {
			slog.Warn("ADF status check failed, using cached state (empty)", "err", err)
			return false, nil
		}
		return false, err
	}
	a.adfEmpty = !hasPaper
	return hasPaper, nil
}

// Close closes the scanner connection.
func (a *ESCLAdapter) Close() error {
	a.scanner.Disconnect()
	return nil
}

// mapScanConfig converts an eSCL ScannerRequest to VENS ScanConfig.
func mapScanConfig(req abstract.ScannerRequest) vens.ScanConfig {
	cfg := vens.DefaultScanConfig()

	// Color mode
	switch req.ColorMode {
	case abstract.ColorModeColor:
		cfg.ColorMode = vens.ColorColor
	case abstract.ColorModeMono:
		cfg.ColorMode = vens.ColorGray
	case abstract.ColorModeBinary:
		cfg.ColorMode = vens.ColorBW
	default:
		cfg.ColorMode = vens.ColorAuto
	}

	// Resolution → Quality
	dpi := req.Resolution.XResolution
	switch {
	case dpi <= 0:
		cfg.Quality = vens.QualityAuto
	case dpi <= 150:
		cfg.Quality = vens.QualityNormal
	case dpi <= 200:
		cfg.Quality = vens.QualityFine
	default:
		cfg.Quality = vens.QualitySuperFine
	}

	// ADF mode → Duplex
	cfg.Duplex = req.ADFMode == abstract.ADFModeDuplex

	return cfg
}

// --------------------------------------------------------------------------
// Document / DocumentFile implementation for JPEG pages
// --------------------------------------------------------------------------

// jpegDocument wraps scanned JPEG pages as an abstract.Document.
type jpegDocument struct {
	res   abstract.Resolution
	pages [][]byte
	idx   int
}

func (d *jpegDocument) Resolution() abstract.Resolution { return d.res }

func (d *jpegDocument) Next() (abstract.DocumentFile, error) {
	if d.idx >= len(d.pages) {
		return nil, io.EOF
	}
	f := &jpegFile{Reader: bytes.NewReader(d.pages[d.idx])}
	d.idx++
	return f, nil
}

func (d *jpegDocument) Close() error { return nil }

// jpegFile wraps a single JPEG page as an abstract.DocumentFile.
type jpegFile struct {
	*bytes.Reader
}

func (f *jpegFile) Format() string { return "image/jpeg" }
