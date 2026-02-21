package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/OpenPrinting/go-mfp/abstract"
	"github.com/OpenPrinting/go-mfp/proto/escl"
	"github.com/OpenPrinting/go-mfp/util/generic"
	"github.com/OpenPrinting/go-mfp/util/uuid"

	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/vens"
)

// ESCLAdapter implements abstract.Scanner for ScanSnap hardware.
type ESCLAdapter struct {
	mu               sync.Mutex
	scanner          *Scanner
	listenPort       int
	settings         *config.Store
	caps             *abstract.ScannerCapabilities
	adfEmpty         bool              // true after a scan session completes (ADF likely exhausted)
	blankPageRemoval bool              // controlled by eSCL BlankPageDetectionAndRemoval
	lastScanErr      *vens.ScanError   // last scan error (for ADF state reporting)
	scanning         bool              // true while a scan session is active
}

// NewESCLAdapter creates an eSCL adapter wrapping the given Scanner.
func NewESCLAdapter(s *Scanner, listenPort int, settings *config.Store) *ESCLAdapter {
	a := &ESCLAdapter{scanner: s, listenPort: listenPort, settings: settings, blankPageRemoval: true}
	a.caps = a.buildCapabilities()
	return a
}

// SetBlankPageRemoval sets whether blank page removal is active for the next scan.
func (a *ESCLAdapter) SetBlankPageRemoval(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blankPageRemoval = enabled
}

func (a *ESCLAdapter) buildCapabilities() *abstract.ScannerCapabilities {
	params := a.scanner.ScanParams()

	// Resolutions: filter known DPI values by scanner-reported range
	maxRes := 300
	minRes := 150
	if params != nil && params.MaxResolutionX > 0 {
		maxRes = params.MaxResolutionX
	}
	if params != nil && params.MinResolutionX > 0 {
		minRes = params.MinResolutionX
	}
	var resolutions []abstract.Resolution
	for _, dpi := range []int{150, 200, 300} {
		if dpi >= minRes && dpi <= maxRes {
			resolutions = append(resolutions, abstract.Resolution{XResolution: dpi, YResolution: dpi})
		}
	}
	if len(resolutions) == 0 {
		resolutions = []abstract.Resolution{{XResolution: 300, YResolution: 300}}
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

	// Max dimensions from scanner params, with fallbacks
	maxWidth := 216 * abstract.Millimeter
	maxHeight := 360 * abstract.Millimeter
	if params != nil && params.MaxWidth > 0 {
		maxWidth = inch1200ToDim(params.MaxWidth)
	}
	if params != nil && params.MaxHeight > 0 {
		maxHeight = inch1200ToDim(params.MaxHeight)
	}

	minWidth := 50 * abstract.Millimeter
	minHeight := 50 * abstract.Millimeter

	maxOptRes := 300
	if params != nil && params.MaxResolutionX > 0 {
		maxOptRes = params.MaxResolutionX
	}

	adfCaps := &abstract.InputCapabilities{
		MinWidth:              minWidth,
		MaxWidth:              maxWidth,
		MinHeight:             minHeight,
		MaxHeight:             maxHeight,
		MaxOpticalXResolution: maxOptRes,
		MaxOpticalYResolution: maxOptRes,
		Intents: generic.MakeBitset(
			abstract.IntentDocument,
			abstract.IntentPhoto,
			abstract.IntentTextAndGraphic,
		),
		Profiles: []abstract.SettingsProfile{profile},
	}

	// Generate deterministic UUID from scanner host
	deviceUUID := uuid.SHA1(uuid.NameSpaceDNS, "airscap."+a.scanner.Host())

	name := a.scanner.MakeAndModel()
	if name == "" {
		name = "Unknown"
	}

	serial := a.scanner.Serial()
	if serial == "" {
		serial = a.scanner.Host()
	}

	return &abstract.ScannerCapabilities{
		UUID:            deviceUUID,
		MakeAndModel:    name,
		SerialNumber:    serial,
		AdminURI:        fmt.Sprintf("http://%s:%d/ui/", vens.GetLocalIP(a.scanner.Host()), a.listenPort),
		DocumentFormats: []string{"image/jpeg", "image/tiff", "application/pdf"},
		ThresholdRange:  abstract.Range{Min: -5, Max: 5, Normal: 0, Step: 1},
		ADFCapacity:     50,
		ADFSimplex:      adfCaps,
		ADFDuplex:       adfCaps,
	}
}

// Capabilities returns the scanner capabilities.
func (a *ESCLAdapter) Capabilities() *abstract.ScannerCapabilities {
	return a.caps
}

// Scan converts an eSCL request to VENS parameters and starts a lazy scan session.
// Pages are pulled one at a time, enabling SelectSinglePage support.
func (a *ESCLAdapter) Scan(ctx context.Context, req abstract.ScannerRequest) (abstract.Document, error) {
	if err := req.Validate(a.caps); err != nil {
		return nil, err
	}

	forcePaperAuto := a.settings != nil && a.settings.Get().ForcePaperAuto
	cfg := mapScanConfig(req, forcePaperAuto)
	a.mu.Lock()
	cfg.BlankPageRemoval = a.blankPageRemoval
	a.mu.Unlock()

	slog.Info("scan requested",
		"colorMode", req.ColorMode,
		"resolution", req.Resolution,
		"adfMode", req.ADFMode,
		"duplex", cfg.Duplex,
		"blankPageRemoval", cfg.BlankPageRemoval,
		"bwDensity", cfg.BWDensity,
		"paperWidth", cfg.PaperWidth,
		"paperHeight", cfg.PaperHeight,
	)

	a.mu.Lock()
	a.lastScanErr = nil // Clear previous error on new scan attempt
	a.scanning = true
	a.mu.Unlock()

	session, err := a.scanner.StartScan(cfg)
	if err != nil {
		a.mu.Lock()
		a.scanning = false
		a.adfEmpty = true
		// Remember scan error for ADF state reporting
		var scanErr *vens.ScanError
		if errors.As(err, &scanErr) {
			a.lastScanErr = scanErr
		}
		a.mu.Unlock()
		return nil, err
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
	doc := &scanDocument{res: res, session: session, format: format, adapter: a}

	// Apply filter for format conversion if needed
	if req.DocumentFormat != "" && req.DocumentFormat != format {
		return abstract.NewFilter(doc, abstract.FilterOptions{
			OutputFormat: req.DocumentFormat,
		}), nil
	}

	return doc, nil
}

// CheckADFStatus queries the scanner for paper presence and error conditions.
// On error, falls back to cached state from the last scan session.
// Detects paper jam from scan_status bit 15 (valid in idle context only —
// scanning flag prevents this method from being called during active scans).
// Uses GET_STATUS error code at offset 44 for other scan-time errors.
// During an active scan session, returns cached state to avoid blocking.
func (a *ESCLAdapter) CheckADFStatus() (bool, error) {
	a.mu.Lock()
	if a.scanning {
		// Scanner only handles one TCP connection at a time; skip live query during scan
		empty := a.adfEmpty
		a.mu.Unlock()
		return !empty, nil
	}
	a.mu.Unlock()

	// Network call without lock — CheckADFStatus now probes REQUEST SENSE
	// on the same connection when scan_status has abnormal bits
	status, err := a.scanner.CheckADFStatus()
	if err != nil {
		a.mu.Lock()
		empty := a.adfEmpty
		a.mu.Unlock()
		if empty {
			slog.Warn("ADF status check failed, using cached state (empty)", "err", err)
			return false, nil
		}
		return false, err
	}

	// Update all state under lock
	a.mu.Lock()
	defer a.mu.Unlock()

	if status.HasCoverOpen {
		// Cover open from scan_status bit 5 (reliable in idle context)
		if a.lastScanErr == nil || a.lastScanErr.Kind != vens.ScanErrCoverOpen {
			slog.Warn("ADF cover open detected from ADF status")
		}
		a.lastScanErr = &vens.ScanError{Kind: vens.ScanErrCoverOpen, Msg: "ADF cover open"}
	} else if status.HasJam {
		// Paper jam from scan_status bit 15 (reliable in idle context)
		if a.lastScanErr == nil || a.lastScanErr.Kind != vens.ScanErrPaperJam {
			slog.Warn("paper jam detected from ADF status")
		}
		a.lastScanErr = &vens.ScanError{Kind: vens.ScanErrPaperJam, Msg: "paper jam"}
	} else if status.ErrorCode != 0 {
		// Error from GET_STATUS offset 44 (scan-time errors)
		kind := errorCodeToKind(status.ErrorCode)
		if a.lastScanErr == nil || a.lastScanErr.Kind != kind {
			slog.Warn("scanner error detected", "errorCode", fmt.Sprintf("0x%04X", status.ErrorCode), "kind", kind)
		}
		a.lastScanErr = &vens.ScanError{Kind: kind, Msg: fmt.Sprintf("scanner error 0x%04X", status.ErrorCode)}
	} else if a.lastScanErr != nil {
		slog.Info("scanner error cleared", "previousErr", a.lastScanErr.Msg)
		a.lastScanErr = nil
	}
	a.adfEmpty = !status.HasPaper
	return status.HasPaper, nil
}

// ScannerState returns the current eSCL scanner state based on connection status.
func (a *ESCLAdapter) ScannerState() escl.ScannerState {
	if !a.scanner.Online() {
		return escl.ScannerDown
	}
	a.mu.Lock()
	scanning := a.scanning
	hasErr := a.lastScanErr != nil
	a.mu.Unlock()
	if scanning {
		return escl.ScannerProcessing
	}
	if hasErr {
		return escl.ScannerStopped
	}
	return escl.ScannerIdle
}

// ADFState returns the current eSCL ADF state, reflecting any scan errors.
func (a *ESCLAdapter) ADFState() escl.ADFState {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.scanning {
		return escl.ScannerAdfProcessing
	}
	if a.lastScanErr != nil {
		switch a.lastScanErr.Kind {
		case vens.ScanErrPaperJam:
			return escl.ScannerAdfJam
		case vens.ScanErrCoverOpen:
			return escl.ScannerAdfHatchOpen
		case vens.ScanErrMultiFeed:
			return escl.ScannerAdfMultipickDetected
		default:
			return escl.ScannerAdfInputTrayFailed
		}
	}
	if a.adfEmpty {
		return escl.ScannerAdfEmpty
	}
	return escl.ScannerAdfLoaded
}

// LastErrorKind returns the current scanner error kind, or -1 if no error.
func (a *ESCLAdapter) LastErrorKind() vens.ScanErrorKind {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastScanErr == nil {
		return -1
	}
	return a.lastScanErr.Kind
}

// Close closes the scanner connection.
func (a *ESCLAdapter) Close() error {
	a.scanner.Disconnect()
	return nil
}

// errorCodeToKind maps GET_STATUS error codes (offset 44) to ScanErrorKind.
func errorCodeToKind(code uint16) vens.ScanErrorKind {
	switch code {
	case 0x0155:
		return vens.ScanErrMultiFeed
	default:
		// Unknown error code — log it so we can add mappings later
		return vens.ScanErrGeneric
	}
}

// mapScanConfig converts an eSCL ScannerRequest to VENS ScanConfig.
// When forcePaperAuto is true, paper size override is skipped (always auto-detect).
func mapScanConfig(req abstract.ScannerRequest, forcePaperAuto bool) vens.ScanConfig {
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

	// Threshold → BW Density (B&W mode only, -5 to +5)
	if req.Threshold != nil {
		cfg.BWDensity = *req.Threshold
	}

	// Region → Paper size (1/100 mm → 1/1200 inch)
	// When Region matches max scan area, treat as auto (don't override).
	// When forcePaperAuto is enabled, always skip paper override (auto-detect).
	if !forcePaperAuto {
		maxRegion := req.Region.Width >= 216*abstract.Millimeter && req.Region.Height >= 360*abstract.Millimeter
		if !req.Region.IsZero() && !maxRegion {
			cfg.PaperWidth = dimToInch1200(req.Region.Width)
			cfg.PaperHeight = dimToInch1200(req.Region.Height)
		}
	}

	return cfg
}

// dimToInch1200 converts abstract.Dimension (1/100 mm) to 1/1200 inch.
func dimToInch1200(d abstract.Dimension) uint16 {
	// 1 inch = 25.4 mm = 2540 (1/100 mm)
	return uint16(int(d) * 1200 / 2540)
}

// inch1200ToDim converts 1/1200 inch to abstract.Dimension (1/100 mm).
func inch1200ToDim(v uint16) abstract.Dimension {
	return abstract.Dimension(int(v) * 2540 / 1200)
}

// --------------------------------------------------------------------------
// Document / DocumentFile implementation for scanned pages
// --------------------------------------------------------------------------

// scanDocument wraps a ScanSession as an abstract.Document.
// Pages are pulled lazily from the scanner one at a time.
type scanDocument struct {
	res     abstract.Resolution
	session *vens.ScanSession
	format  string // "image/jpeg" or "image/tiff"
	adapter *ESCLAdapter
}

func (d *scanDocument) Resolution() abstract.Resolution { return d.res }

func (d *scanDocument) Next() (abstract.DocumentFile, error) {
	page, err := d.session.NextPage()
	if err != nil {
		d.adapter.mu.Lock()
		d.adapter.scanning = false
		d.adapter.adfEmpty = true
		// Remember scan error for ADF state reporting
		var scanErr *vens.ScanError
		if errors.As(err, &scanErr) {
			d.adapter.lastScanErr = scanErr
		}
		d.adapter.mu.Unlock()
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	if len(page.JPEG) == 0 {
		// Skip empty pages (blank page removal filtered them out)
		return d.Next()
	}
	return &scanFile{Reader: bytes.NewReader(page.JPEG), format: d.format}, nil
}

func (d *scanDocument) Close() error {
	d.adapter.mu.Lock()
	d.adapter.scanning = false
	d.adapter.adfEmpty = true
	d.adapter.mu.Unlock()
	return d.session.Close()
}

// scanFile wraps a single scanned page as an abstract.DocumentFile.
type scanFile struct {
	*bytes.Reader
	format string
}

func (f *scanFile) Format() string { return f.format }
