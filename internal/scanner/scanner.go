package scanner

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
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
}

// New creates a Scanner targeting the given host with a pre-computed identity.
func New(host string, dataPort, controlPort uint16, identity string) *Scanner {
	var token [8]byte
	rand.Read(token[:6])
	return &Scanner{
		host:        host,
		dataPort:    dataPort,
		controlPort: controlPort,
		token:       token,
		identity:    identity,
		control:     vens.NewControlSession(host, controlPort),
	}
}

// Connect establishes a session with the scanner: discovery, heartbeat, configure, register.
func (s *Scanner) Connect(ctx context.Context) error {
	// Step 1: UDP discovery to let the scanner know our token
	slog.Info("discovering scanner", "host", s.host)
	info, err := vens.FindScanner(ctx, vens.DiscoveryOptions{
		ScannerIP: s.host,
		Token:     s.token,
	})
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	slog.Info("discovered", "name", info.Name, "serial", info.Serial, "ip", info.DeviceIP)

	// Update ports from discovery response
	if info.DataPort != 0 {
		s.dataPort = info.DataPort
	}
	if info.ControlPort != 0 {
		s.controlPort = info.ControlPort
		s.control = vens.NewControlSession(s.host, s.controlPort)
	}

	// Step 2: Start heartbeats
	hb, err := vens.StartHeartbeat(ctx, s.host, s.token, 0)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	s.heartbeat = hb
	time.Sleep(300 * time.Millisecond)

	// Step 3: Configure session
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

	// Step 4: Data channel setup
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	if _, err := dataCh.GetDeviceInfo(); err != nil {
		slog.Warn("get device info failed, retrying", "err", err)
		time.Sleep(2 * time.Second)
		if _, err := dataCh.GetDeviceInfo(); err != nil {
			s.heartbeat.Stop()
			return fmt.Errorf("device info: %w", err)
		}
	}

	if _, err := dataCh.GetScanParams(); err != nil {
		slog.Warn("get scan params failed", "err", err)
	}

	if _, err := dataCh.SetConfig(); err != nil {
		slog.Warn("set config failed", "err", err)
	}

	// Step 5: Status check + register
	if _, err := s.control.CheckStatus(s.token); err != nil {
		slog.Warn("status check failed", "err", err)
	}

	if err := s.control.Register(s.token); err != nil {
		slog.Warn("register failed", "err", err)
	}

	s.connected = true
	slog.Info("connected to scanner")
	return nil
}

// Scan executes a scan with the given config and returns pages.
func (s *Scanner) Scan(cfg vens.ScanConfig, onPage func(vens.Page)) ([]vens.Page, error) {
	if !s.connected {
		return nil, fmt.Errorf("scanner not connected")
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	pages, err := dataCh.RunScan(cfg, onPage)
	if err != nil {
		return pages, err
	}
	// Filter out empty pages
	var result []vens.Page
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			result = append(result, p)
		}
	}
	return result, nil
}

// Disconnect deregisters from the scanner and stops heartbeat.
func (s *Scanner) Disconnect() {
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

// Host returns the scanner's IP address.
func (s *Scanner) Host() string { return s.host }

// Connected returns whether the scanner session is active.
func (s *Scanner) Connected() bool { return s.connected }
