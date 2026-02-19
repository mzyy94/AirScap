package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/OpenPrinting/go-mfp/abstract"
	"github.com/OpenPrinting/go-mfp/proto/escl"
	"github.com/OpenPrinting/go-mfp/util/generic"
	"github.com/OpenPrinting/go-mfp/util/uuid"

	"github.com/mzyy94/airscap/internal/vens"
)

// ESCLAdapter implements abstract.Scanner for ScanSnap hardware.
type ESCLAdapter struct {
	scanner          *Scanner
	listenPort       int
	caps             *abstract.ScannerCapabilities
	adfEmpty         bool // true after a scan session completes (ADF likely exhausted)
	blankPageRemoval bool // controlled by eSCL BlankPageDetectionAndRemoval
}

// NewESCLAdapter creates an eSCL adapter wrapping the given Scanner.
func NewESCLAdapter(s *Scanner, listenPort int) *ESCLAdapter {
	a := &ESCLAdapter{scanner: s, listenPort: listenPort, blankPageRemoval: true}
	a.caps = a.buildCapabilities()
	return a
}

// SetBlankPageRemoval sets whether blank page removal is active for the next scan.
func (a *ESCLAdapter) SetBlankPageRemoval(enabled bool) {
	a.blankPageRemoval = enabled
}

func (a *ESCLAdapter) buildCapabilities() *abstract.ScannerCapabilities {
	resolutions := []abstract.Resolution{
		{XResolution: 150, YResolution: 150},
		{XResolution: 200, YResolution: 200},
		{XResolution: 300, YResolution: 300},
	}

	profile := abstract.SettingsProfile{
		ColorModes: generic.MakeBitset(
			abstract.ColorModeBinary,
			abstract.ColorModeMono,
			abstract.ColorModeColor,
		),
		Depths:           generic.MakeBitset(abstract.ColorDepth8),
		BinaryRenderings: generic.MakeBitset(abstract.BinaryRenderingThreshold),
		Resolutions:      resolutions,
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

	manufacturer := a.scanner.Manufacturer()
	if manufacturer == "" {
		manufacturer = "Unknown"
	}

	return &abstract.ScannerCapabilities{
		UUID:            deviceUUID,
		MakeAndModel:    name,
		Manufacturer:    manufacturer,
		SerialNumber:    serial,
		AdminURI:        fmt.Sprintf("http://%s:%d/ui/", vens.GetLocalIP(a.scanner.Host()), a.listenPort),
		DocumentFormats: []string{"image/jpeg", "image/tiff", "application/pdf"},
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
	cfg.BlankPageRemoval = a.blankPageRemoval
	slog.Info("scan requested",
		"colorMode", req.ColorMode,
		"resolution", req.Resolution,
		"adfMode", req.ADFMode,
		"duplex", cfg.Duplex,
		"blankPageRemoval", cfg.BlankPageRemoval,
	)

	pages, err := a.scanner.Scan(cfg, nil)
	a.adfEmpty = true

	// Collect non-empty image data from pages (some may exist even after errors)
	var images [][]byte
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			images = append(images, p.JPEG)
		}
	}

	if len(images) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("no pages scanned")
	}
	if err != nil {
		slog.Warn("scan completed with error, returning partial results",
			"err", err, "pages", len(images))
	}

	res := req.Resolution
	if res.IsZero() {
		dpi := vens.QualityDPI[cfg.Quality]
		if dpi == 0 {
			dpi = 300
		}
		res = abstract.Resolution{XResolution: dpi, YResolution: dpi}
	}

	// BW mode returns TIFF G4 data from the scanner
	isBW := cfg.ColorMode == vens.ColorBW
	format := "image/jpeg"
	if isBW {
		format = "image/tiff"
	}
	doc := &scanDocument{res: res, pages: images, format: format}

	// Apply filter for format conversion if needed
	if req.DocumentFormat != "" && req.DocumentFormat != format {
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

// ScannerState returns the current eSCL scanner state based on connection status.
func (a *ESCLAdapter) ScannerState() escl.ScannerState {
	if !a.scanner.Online() {
		return escl.ScannerDown
	}
	return escl.ScannerIdle
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
// Document / DocumentFile implementation for scanned pages
// --------------------------------------------------------------------------

// scanDocument wraps scanned pages as an abstract.Document.
type scanDocument struct {
	res    abstract.Resolution
	pages  [][]byte
	format string // "image/jpeg" or "image/tiff"
	idx    int
}

func (d *scanDocument) Resolution() abstract.Resolution { return d.res }

func (d *scanDocument) Next() (abstract.DocumentFile, error) {
	if d.idx >= len(d.pages) {
		return nil, io.EOF
	}
	f := &scanFile{Reader: bytes.NewReader(d.pages[d.idx]), format: d.format}
	d.idx++
	return f, nil
}

func (d *scanDocument) Close() error { return nil }

// scanFile wraps a single scanned page as an abstract.DocumentFile.
type scanFile struct {
	*bytes.Reader
	format string
}

func (f *scanFile) Format() string { return f.format }
