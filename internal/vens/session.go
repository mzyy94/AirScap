package vens

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// ControlSession manages TCP control channel connections (port 53219).
// Each operation opens a new TCP connection, following the scanner protocol.
type ControlSession struct {
	host string
	port uint16
}

// NewControlSession creates a ControlSession for the given scanner address.
func NewControlSession(host string, port uint16) *ControlSession {
	return &ControlSession{host: host, port: port}
}

// connect opens a TCP connection and reads the welcome packet.
func (s *ControlSession) connect() (net.Conn, error) {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("control connect: %w", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	welcome := make([]byte, WelcomeSize)
	if _, err := io.ReadFull(conn, welcome); err != nil {
		conn.Close()
		return nil, fmt.Errorf("control welcome: %w", err)
	}
	if err := ValidateWelcome(welcome); err != nil {
		conn.Close()
		return nil, err
	}
	slog.Debug("control welcome received", "addr", addr)
	return conn, nil
}

// sendRecv opens a connection, sends data, reads a length-prefixed response, and closes.
func (s *ControlSession) sendRecv(data []byte) ([]byte, error) {
	conn, err := s.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("control send: %w", err)
	}

	// Read response length (first 4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("control recv length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)

	resp := make([]byte, respLen)
	copy(resp[:4], lenBuf)
	if _, err := io.ReadFull(conn, resp[4:]); err != nil {
		return nil, fmt.Errorf("control recv body: %w", err)
	}
	return resp, nil
}

// Register registers this client with the scanner.
func (s *ControlSession) Register(token [8]byte) error {
	conn, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	req := MarshalRegisterRequest(token, 1)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("register send: %w", err)
	}

	// Register response is a fixed 16-byte ack
	ack := make([]byte, 16)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return fmt.Errorf("register recv: %w", err)
	}
	slog.Info("registered with scanner")
	return nil
}

// Configure sends client configuration (identity, notify port, etc.) to the scanner.
// Returns true if the scanner accepted the pairing.
func (s *ControlSession) Configure(token [8]byte, clientIP string, notifyPort uint16, identity string) (bool, error) {
	req := MarshalConfigureRequest(token, clientIP, notifyPort, identity, time.Now())
	slog.Info("configuring session", "ip", clientIP, "port", notifyPort)

	resp, err := s.sendRecv(req)
	if err != nil {
		return false, err
	}

	status, err := ParseConfigureResponse(resp)
	if err != nil {
		return false, err
	}
	if status == 0 {
		slog.Info("pairing accepted")
		return true, nil
	}
	slog.Info("pairing rejected", "status", status)
	return false, nil
}

// CheckStatus queries the scanner's connection status.
func (s *ControlSession) CheckStatus(token [8]byte) (uint32, error) {
	req := MarshalStatusRequest(token)
	resp, err := s.sendRecv(req)
	if err != nil {
		return 0, err
	}
	state, err := ParseStatusResponse(resp)
	if err != nil {
		return 0, err
	}
	slog.Debug("status check", "state", state)
	return state, nil
}

// Deregister removes this client from the scanner.
func (s *ControlSession) Deregister(token [8]byte) error {
	conn, err := s.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	req := MarshalRegisterRequest(token, 1)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("deregister send: %w", err)
	}

	ack := make([]byte, 16)
	if _, err := io.ReadFull(conn, ack); err != nil {
		return fmt.Errorf("deregister recv: %w", err)
	}
	slog.Info("deregistered from scanner")
	return nil
}
