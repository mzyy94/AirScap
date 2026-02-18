package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/vens"
)

//go:embed static
var staticFS embed.FS

type handler struct {
	adapter    *scanner.ESCLAdapter
	sc         *scanner.Scanner
	listenPort int
}

// NewHandler creates an HTTP handler for the Web UI.
func NewHandler(sc *scanner.Scanner, adapter *scanner.ESCLAdapter, listenPort int) http.Handler {
	h := &handler{adapter: adapter, sc: sc, listenPort: listenPort}
	mux := http.NewServeMux()
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.HandleFunc("GET /api/status", h.handleStatus)
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
