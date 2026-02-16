package scanner

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// Scanner is a high-level interface for ScanSnap operations.
type Scanner struct {
	host        string
	dataPort    uint16
	controlPort uint16
	token       [8]byte
	identity    string
	control     *vens.ControlSession
	heartbeat   *vens.Heartbeat
	connected   bool
	name        string
	serial      string
}

// New creates a Scanner targeting the given host with a pre-computed identity.
func New(host string, dataPort, controlPort uint16, identity string) *Scanner {
	var token [8]byte
	rand.Read(token[:6])
	slog.Debug("scanner created", "host", host, "dataPort", dataPort, "controlPort", controlPort, "token", fmt.Sprintf("%x", token))
	return &Scanner{
		host:        host,
		dataPort:    dataPort,
		controlPort: controlPort,
		token:       token,
		identity:    identity,
		control:     vens.NewControlSession(host, controlPort),
	}
}

// Connect establishes a session with the scanner: discovery, heartbeat, configure, data setup.
// Matches the Python connect() flow — Register is NOT called here (only needed for initial pairing).
func (s *Scanner) Connect(ctx context.Context) error {
	// Step 1: UDP discovery to let the scanner know our token
	slog.Debug("discovery...", "host", s.host)
	info, err := vens.FindScanner(ctx, vens.DiscoveryOptions{
		ScannerIP: s.host,
		Token:     s.token,
	})
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	slog.Debug("discovery OK", "name", info.Name, "serial", info.Serial, "ip", info.DeviceIP, "dataPort", info.DataPort, "controlPort", info.ControlPort)

	// Update ports from discovery response
	if info.DataPort != 0 {
		s.dataPort = info.DataPort
	}
	if info.ControlPort != 0 {
		s.controlPort = info.ControlPort
		s.control = vens.NewControlSession(s.host, s.controlPort)
	}

	// Step 2: Start heartbeats
	slog.Debug("starting heartbeat...")
	hb, err := vens.StartHeartbeat(ctx, s.host, s.token, 0)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	s.heartbeat = hb
	time.Sleep(300 * time.Millisecond)

	// Step 3: Configure session
	slog.Debug("configuring session...")
	localIP := vens.GetLocalIP()
	accepted, err := s.control.Configure(s.token, localIP, vens.ClientNotifyPort, s.identity)
	if err != nil {
		s.heartbeat.Stop()
		return fmt.Errorf("configure: %w", err)
	}
	if !accepted {
		s.heartbeat.Stop()
		return fmt.Errorf("pairing rejected — wrong password/identity")
	}

	// Step 4: Data channel setup (with status check interleaved, matching Python flow)
	slog.Debug("data channel setup...", "host", s.host, "port", s.dataPort)
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	if _, err := dataCh.GetDeviceInfo(); err != nil {
		slog.Warn("get device info failed, retrying in 2s", "err", err)
		time.Sleep(2 * time.Second)
		if _, err := dataCh.GetDeviceInfo(); err != nil {
			s.heartbeat.Stop()
			return fmt.Errorf("device info: %w", err)
		}
	}

	// Step 5: Status check (between data channel operations, matching Python flow)
	slog.Debug("status check...")
	if _, err := s.control.CheckStatus(s.token); err != nil {
		slog.Warn("status check failed", "err", err)
	}

	if _, err := dataCh.GetScanParams(); err != nil {
		slog.Warn("get scan params failed", "err", err)
	}

	if _, err := dataCh.SetConfig(); err != nil {
		slog.Warn("set config failed", "err", err)
	}

	s.connected = true
	s.name = info.Name
	s.serial = info.Serial
	slog.Info("connected to scanner", "host", s.host, "name", info.Name, "serial", info.Serial)
	return nil
}

// Scan executes a scan with the given config and returns pages.
func (s *Scanner) Scan(cfg vens.ScanConfig, onPage func(vens.Page)) ([]vens.Page, error) {
	if !s.connected {
		return nil, fmt.Errorf("scanner not connected")
	}
	slog.Info("starting scan", "colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex, "paperSize", cfg.PaperSize)
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	pages, err := dataCh.RunScan(cfg, onPage)
	if err != nil {
		slog.Warn("scan error", "err", err, "pages_so_far", len(pages))
		return pages, err
	}
	// Filter out empty pages
	var result []vens.Page
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			result = append(result, p)
		}
	}
	slog.Info("scan complete", "total_pages", len(pages), "non_empty", len(result))
	return result, nil
}

// Disconnect deregisters from the scanner and stops heartbeat.
func (s *Scanner) Disconnect() {
	slog.Debug("disconnecting from scanner...")
	if s.control != nil {
		if err := s.control.Deregister(s.token); err != nil {
			slog.Warn("deregister failed", "err", err)
		}
	}
	if s.heartbeat != nil {
		s.heartbeat.Stop()
	}
	s.connected = false
	slog.Info("disconnected from scanner")
}

// CheckADFStatus queries the scanner's ADF and returns whether paper is present.
func (s *Scanner) CheckADFStatus() (bool, error) {
	if !s.connected {
		return false, fmt.Errorf("scanner not connected")
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.CheckADFStatus()
}

// Host returns the scanner's IP address.
func (s *Scanner) Host() string { return s.host }

// Name returns the scanner's device name from discovery.
func (s *Scanner) Name() string { return strings.TrimSpace(s.name) }

// Serial returns the scanner's serial number from discovery.
func (s *Scanner) Serial() string { return s.serial }

// Connected returns whether the scanner session is active.
func (s *Scanner) Connected() bool { return s.connected }
