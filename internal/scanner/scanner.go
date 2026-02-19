package scanner

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// Scanner is a high-level interface for ScanSnap operations.
type Scanner struct {
	mu          sync.Mutex
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
	deviceName        string // full device name with manufacturer from TCP GET_SET sub=0x12
	firmwareRevision  string // firmware revision from device name suffix (e.g. "0M00")

	reconnCancel context.CancelFunc
	reconnDone   chan struct{}
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

// Online returns whether the scanner session is active (thread-safe).
func (s *Scanner) Online() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

// Connect establishes a session with the scanner: discovery, heartbeat, configure, data setup.
func (s *Scanner) Connect(ctx context.Context) error {
	// Clean up any previous connection state (idempotent for reconnection)
	s.mu.Lock()
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
	s.mu.Unlock()

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
	s.mu.Lock()
	s.heartbeat = hb
	s.mu.Unlock()
	time.Sleep(300 * time.Millisecond)

	// Step 3: Configure session
	slog.Debug("configuring session...")
	localIP := vens.GetLocalIP(s.host)
	accepted, err := s.control.Configure(s.token, localIP, vens.ClientNotifyPort, s.identity)
	if err != nil {
		hb.Stop()
		s.mu.Lock()
		s.heartbeat = nil
		s.mu.Unlock()
		return fmt.Errorf("configure: %w", err)
	}
	if !accepted {
		hb.Stop()
		s.mu.Lock()
		s.heartbeat = nil
		s.mu.Unlock()
		return fmt.Errorf("pairing rejected — wrong password/identity")
	}

	// Step 4: Data channel setup (with status check interleaved, matching Python flow)
	slog.Debug("data channel setup...", "host", s.host, "port", s.dataPort)
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	devInfo, err := dataCh.GetDeviceInfo()
	if err != nil {
		slog.Warn("get device info failed, retrying in 2s", "err", err)
		time.Sleep(2 * time.Second)
		devInfo, err = dataCh.GetDeviceInfo()
		if err != nil {
			hb.Stop()
			s.mu.Lock()
			s.heartbeat = nil
			s.mu.Unlock()
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

	s.mu.Lock()
	s.connected = true
	s.name = info.Name
	s.serial = info.Serial
	if devInfo != nil {
		s.deviceName = devInfo.DeviceName
		s.firmwareRevision = devInfo.FirmwareRevision
	}
	s.mu.Unlock()
	slog.Info("connected to scanner", "host", s.host, "name", info.Name, "serial", info.Serial, "deviceName", s.deviceName)
	return nil
}

// StartScan begins a lazy scan session. Pages are pulled one at a time via
// ScanSession.NextPage, allowing the client to stop after any page.
func (s *Scanner) StartScan(cfg vens.ScanConfig) (*vens.ScanSession, error) {
	if !s.Online() {
		return nil, fmt.Errorf("scanner not connected")
	}
	slog.Info("starting scan session", "colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex, "paperSize", cfg.PaperSize)
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.StartScan(cfg)
}

// Scan executes a scan with the given config and returns pages.
func (s *Scanner) Scan(cfg vens.ScanConfig, onPage func(vens.Page)) ([]vens.Page, error) {
	if !s.Online() {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
	slog.Info("disconnected from scanner")
}

// markOffline stops the heartbeat and marks the scanner as disconnected.
func (s *Scanner) markOffline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return
	}
	slog.Warn("scanner went offline", "host", s.host)
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
}

// StartReconnectLoop starts a background goroutine that monitors scanner
// health and reconnects automatically when the connection is lost.
func (s *Scanner) StartReconnectLoop(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.reconnCancel = cancel
	s.reconnDone = make(chan struct{})
	go s.reconnectLoop(ctx)
}

// StopReconnectLoop stops the reconnection goroutine and waits for it to exit.
func (s *Scanner) StopReconnectLoop() {
	if s.reconnCancel != nil {
		s.reconnCancel()
		<-s.reconnDone
	}
}

func (s *Scanner) reconnectLoop(ctx context.Context) {
	defer close(s.reconnDone)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Online() {
				s.healthCheck()
			} else {
				s.tryReconnect(ctx)
			}
		}
	}
}

func (s *Scanner) healthCheck() {
	s.mu.Lock()
	ctrl := s.control
	token := s.token
	s.mu.Unlock()

	if ctrl == nil {
		s.markOffline()
		return
	}
	if _, err := ctrl.CheckStatus(token); err != nil {
		slog.Warn("health check failed", "err", err)
		s.markOffline()
	}
}

func (s *Scanner) tryReconnect(ctx context.Context) {
	slog.Info("attempting reconnection...", "host", s.host)
	if err := s.Connect(ctx); err != nil {
		slog.Debug("reconnect failed", "host", s.host, "err", err)
	}
}

// CheckSenseStatus probes the scanner for error conditions via REQUEST SENSE.
func (s *Scanner) CheckSenseStatus() *vens.ScanError {
	if !s.Online() {
		return nil
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.CheckSenseStatus()
}

// CheckADFStatus queries the scanner's ADF and returns paper/error status.
func (s *Scanner) CheckADFStatus() (*vens.ADFStatus, error) {
	if !s.Online() {
		return nil, fmt.Errorf("scanner not connected")
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.CheckADFStatus()
}

// Host returns the scanner's IP address.
func (s *Scanner) Host() string { return s.host }

// Name returns the scanner's device name from discovery.
func (s *Scanner) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.name)
}

// Serial returns the scanner's serial number from discovery.
func (s *Scanner) Serial() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// DeviceName returns the full device name from TCP GET_SET sub=0x12
func (s *Scanner) DeviceName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceName
}

// FirmwareRevision returns the firmware revision from the device name suffix.
func (s *Scanner) FirmwareRevision() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firmwareRevision
}

// Manufacturer extracts the manufacturer from the device name
func (s *Scanner) Manufacturer() string {
	s.mu.Lock()
	dn := s.deviceName
	s.mu.Unlock()
	if dn == "" {
		return ""
	}
	name, _, _ := strings.Cut(dn, " ")
	return name
}
