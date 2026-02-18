package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
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
	settings   *config.Store // nil when persistence is disabled

	mu          sync.RWMutex
	memSettings config.Settings // in-memory fallback when settings is nil
}

// NewHandler creates an HTTP handler for the Web UI.
func NewHandler(sc *scanner.Scanner, adapter *scanner.ESCLAdapter, listenPort int, settings *config.Store) http.Handler {
	h := &handler{adapter: adapter, sc: sc, listenPort: listenPort, settings: settings, memSettings: config.DefaultSettings()}
	mux := http.NewServeMux()
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("GET /api/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /api/settings", h.handlePutSettings)
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
}

type adfStatus struct {
	Loaded bool `json:"loaded"`
}

type deviceInfo struct {
	Name         string `json:"name"`
	Serial       string `json:"serial"`
	Host         string `json:"host"`
	Manufacturer string `json:"manufacturer"`
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
			Name:         h.sc.Name(),
			Serial:       h.sc.Serial(),
			Host:         h.sc.Host(),
			Manufacturer: "Fujitsu",
		},
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if online {
		hasPaper, err := h.adapter.CheckADFStatus()
		if err == nil {
			resp.ADF = &adfStatus{Loaded: hasPaper}
		}
	}

	caps := h.adapter.Capabilities()
	resp.Caps = capsInfo{
		Resolutions: []int{150, 200, 300},
		ColorModes:  []string{"color", "grayscale", "bw"},
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
	var s config.Settings
	if h.settings != nil {
		s = h.settings.Get()
	} else {
		h.mu.RLock()
		s = h.memSettings
		h.mu.RUnlock()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func (h *handler) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var s config.Settings
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if h.settings != nil {
		if err := h.settings.Update(s); err != nil {
			slog.Warn("settings save failed", "err", err)
			http.Error(w, "failed to save settings", http.StatusInternalServerError)
			return
		}
	} else {
		h.mu.Lock()
		h.memSettings = s
		h.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

