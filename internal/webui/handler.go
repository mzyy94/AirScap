package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/vens"
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
}

// NewHandler creates an HTTP handler for the Web UI.
func NewHandler(sc *scanner.Scanner, adapter *scanner.ESCLAdapter, listenPort int, settings *config.Store, scanStatus *scanner.ScanJobStatus, version string) http.Handler {
	h := &handler{adapter: adapter, sc: sc, listenPort: listenPort, settings: settings, scanStatus: scanStatus, version: version}
	mux := http.NewServeMux()
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("GET /api/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", h.handlePutSettings)
	mux.HandleFunc("GET /api/scan/status", h.handleScanStatus)
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
	Loaded bool `json:"loaded"`
}

type deviceInfo struct {
	Name             string `json:"name"`
	Serial           string `json:"serial"`
	Host             string `json:"host"`
	Manufacturer     string `json:"manufacturer"`
	FirmwareRevision string `json:"firmwareRevision,omitempty"`
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
			Name:             h.sc.Name(),
			Serial:           h.sc.Serial(),
			Host:             h.sc.Host(),
			Manufacturer:     h.sc.Manufacturer(),
			FirmwareRevision: h.sc.FirmwareRevision(),
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Version:   h.version,
	}

	if online {
		hasPaper, err := h.adapter.CheckADFStatus()
		if err == nil {
			resp.ADF = &adfStatus{Loaded: hasPaper}
		}
	}

	caps := h.adapter.Capabilities()
	resp.Caps = capsInfo{
		Resolutions: []int{0, 150, 200, 300},
		ColorModes:  []string{"auto", "color", "grayscale", "bw"},
		Duplex:      caps.ADFDuplex != nil,
		Formats:     caps.DocumentFormats,
	}

	localIP := vens.GetLocalIP()
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

