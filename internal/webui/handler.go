package webui

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/vens"
	_ "golang.org/x/image/tiff"
)

//go:embed static
var staticFS embed.FS

type handler struct {
	adapter    *scanner.ESCLAdapter
	sc         *scanner.Scanner
	listenPort int
	settings   *config.Store
	scanStatus *scanner.ScanJobStatus // nil when button listener is disabled
	version    string
	scanMu     *sync.Mutex // shared with button listener for scan exclusion
}

// NewHandler creates an HTTP handler for the Web UI.
func NewHandler(sc *scanner.Scanner, adapter *scanner.ESCLAdapter, listenPort int, settings *config.Store, scanStatus *scanner.ScanJobStatus, version string, scanMu *sync.Mutex) http.Handler {
	h := &handler{adapter: adapter, sc: sc, listenPort: listenPort, settings: settings, scanStatus: scanStatus, version: version, scanMu: scanMu}
	mux := http.NewServeMux()
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("GET /api/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", h.handlePutSettings)
	mux.HandleFunc("GET /api/scan/status", h.handleScanStatus)
	mux.HandleFunc("POST /api/scan/preview", h.handleScanPreview)
	mux.Handle("GET /", http.FileServer(http.FS(staticContent)))
	return mux
}

type statusResponse struct {
	Online    bool       `json:"online"`
	State     string     `json:"state"`
	ADF       *adfStatus `json:"adf,omitempty"`
	Device    deviceInfo `json:"device"`
	Caps      capsInfo   `json:"capabilities"`
	ESCLUrl   string     `json:"esclUrl"`
	UpdatedAt string     `json:"updatedAt"`
	Version   string     `json:"version"`
}

type adfStatus struct {
	Loaded bool   `json:"loaded"`
	Error  string `json:"error,omitempty"` // "jam", "hatchOpen", "multiFeed", "error", or ""
}

type deviceInfo struct {
	Name             string `json:"name"`
	Serial           string `json:"serial"`
	Host             string `json:"host"`
	FirmwareRevision string `json:"firmwareRevision,omitempty"`
	WifiState        string `json:"wifiState"` // "strong", "normal", "weak", "disconnected", or "unknown"
}

type capsInfo struct {
	Resolutions []int    `json:"resolutions"`
	ColorModes  []string `json:"colorModes"`
	Duplex      bool     `json:"duplex"`
	Formats     []string `json:"formats"`
}

func (h *handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	online := h.sc.Online()
	state := "idle"
	if !online {
		state = "offline"
	}

	resp := statusResponse{
		Online: online,
		State:  state,
		Device: deviceInfo{
			Name:             h.sc.MakeAndModel(),
			Serial:           h.sc.Serial(),
			Host:             h.sc.Host(),
			FirmwareRevision: h.sc.FirmwareRevision(),
			WifiState:        wifiStateString(h.sc.WifiState()),
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Version:   h.version,
	}

	if online {
		hasPaper, err := h.adapter.CheckADFStatus()
		if err == nil {
			adf := &adfStatus{Loaded: hasPaper}
			switch h.adapter.LastErrorKind() {
			case vens.ScanErrPaperJam:
				adf.Error = "jam"
			case vens.ScanErrCoverOpen:
				adf.Error = "hatchOpen"
			case vens.ScanErrMultiFeed:
				adf.Error = "multiFeed"
			case vens.ScanErrGeneric:
				adf.Error = "error"
			}
			if adf.Error != "" {
				resp.State = "error"
			}
			resp.ADF = adf
		} else {
			// CheckADFStatus failed; still report cached error state
			adf := &adfStatus{}
			switch h.adapter.LastErrorKind() {
			case vens.ScanErrPaperJam:
				adf.Error = "jam"
			case vens.ScanErrCoverOpen:
				adf.Error = "hatchOpen"
			case vens.ScanErrMultiFeed:
				adf.Error = "multiFeed"
			case vens.ScanErrGeneric:
				adf.Error = "error"
			}
			if adf.Error != "" {
				resp.State = "error"
				resp.ADF = adf
			}
		}
	}

	caps := h.adapter.Capabilities()
	resp.Caps = capsInfo{
		Resolutions: []int{0, 150, 200, 300},
		ColorModes:  []string{"auto", "color", "grayscale", "bw"},
		Duplex:      caps.ADFDuplex != nil,
		Formats:     caps.DocumentFormats,
	}

	localIP := vens.GetLocalIP(h.sc.Host())
	resp.ESCLUrl = fmt.Sprintf("http://%s:%d/eSCL", localIP, h.listenPort)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// --- Settings API ---

func (h *handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.settings.Get())
}

func (h *handler) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var s config.Settings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.settings.Update(s); err != nil {
		slog.Warn("settings save failed", "err", err)
		http.Error(w, "failed to save settings", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

// --- Scan Status API ---

func (h *handler) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.scanStatus == nil {
		json.NewEncoder(w).Encode(scanner.ScanJobStatus{})
		return
	}
	json.NewEncoder(w).Encode(h.scanStatus.Snapshot())
}

// --- Scan Preview API ---

func (h *handler) handleScanPreview(w http.ResponseWriter, r *http.Request) {
	if !h.scanMu.TryLock() {
		writeJSONError(w, http.StatusConflict, "scan_in_progress")
		return
	}
	defer h.scanMu.Unlock()

	if !h.sc.Online() {
		writeJSONError(w, http.StatusServiceUnavailable, "scanner_offline")
		return
	}

	s := h.settings.Get()
	cfg := scanner.SettingsToScanConfig(s)

	slog.Info("scan preview starting", "colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex)
	pages, err := h.sc.Scan(cfg, nil)
	if err != nil {
		slog.Error("scan preview failed", "err", err)
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(pages) == 0 {
		writeJSONError(w, http.StatusInternalServerError, "no pages scanned")
		return
	}

	isBW := cfg.ColorMode == vens.ColorBW
	mime := "image/jpeg"
	if isBW {
		mime = "image/tiff"
	}

	type previewPage struct {
		DataURL string `json:"dataUrl"`
		Width   int    `json:"width,omitempty"`
		Height  int    `json:"height,omitempty"`
		DPI     int    `json:"dpi,omitempty"`
		Size    int    `json:"size"`
	}

	result := make([]previewPage, len(pages))
	for i, p := range pages {
		pp := previewPage{
			DataURL: fmt.Sprintf("data:%s;base64,%s", mime, base64.StdEncoding.EncodeToString(p.JPEG)),
			Size:    len(p.JPEG),
		}
		if cfg, _, err := image.DecodeConfig(bytes.NewReader(p.JPEG)); err == nil {
			pp.Width = cfg.Width
			pp.Height = cfg.Height
		}
		if p.PixelSize != nil {
			pp.DPI = p.PixelSize.XRes
		}
		result[i] = pp
	}

	slog.Info("scan preview complete", "pages", len(pages), "format", mime)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"pages": result,
	})
}

func wifiStateString(state uint32) string {
	switch state {
	case 0:
		return "disconnected"
	case 1:
		return "weak"
	case 2:
		return "normal"
	case 3:
		return "strong"
	default:
		return "unknown"
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
