package vens

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// NewToken generates an 8-byte session token (6 random + 2 null).
func NewToken() [8]byte {
	var token [8]byte
	rand.Read(token[:6])
	slog.Debug("generated session token", "token", fmt.Sprintf("%x", token))
	return token
}

// GetLocalIP returns the local IP used to reach the given target.
// It dials a UDP socket to the target to let the OS routing table
// pick the correct outbound interface. If targetIP is empty,
// the link-local all-hosts multicast address (224.0.0.1) is used
// to determine the default LAN interface without any external dependency.
func GetLocalIP(targetIP string) string {
	if targetIP == "" {
		targetIP = "224.0.0.1"
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(targetIP, "80"))
	if err != nil {
		return "0.0.0.0"
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}

// DiscoveryOptions configures scanner discovery.
type DiscoveryOptions struct {
	ScannerIP string   // Empty for broadcast discovery
	Token     [8]byte
	Timeout   time.Duration
}

// FindScanner discovers a scanner on the local network.
func FindScanner(ctx context.Context, opts DiscoveryOptions) (*DeviceInfo, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	localIP := GetLocalIP(opts.ScannerIP)

	// Bind to client discovery port
	listenAddr := &net.UDPAddr{Port: ClientDiscoveryPort}
	conn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("bind discovery port %d: %w", ClientDiscoveryPort, err)
	}
	defer conn.Close()

	// Send discovery packets
	targetIP := opts.ScannerIP
	if targetIP == "" {
		targetIP = "255.255.255.255"
	}

	scannerAddr := &net.UDPAddr{IP: net.ParseIP(targetIP), Port: DiscoveryPort}
	vensPacket := MarshalDiscoveryVENS(localIP, opts.Token, ClientDiscoveryPort, false)
	ssnrPacket := MarshalDiscoverySSNR(localIP, opts.Token, ClientDiscoveryPort)

	if _, err := conn.WriteToUDP(vensPacket, scannerAddr); err != nil {
		return nil, fmt.Errorf("send VENS discovery: %w", err)
	}
	if _, err := conn.WriteToUDP(ssnrPacket, scannerAddr); err != nil {
		return nil, fmt.Errorf("send ssNR discovery: %w", err)
	}
	slog.Debug("sent discovery", "target", targetIP, "port", DiscoveryPort, "localIP", localIP, "vens_size", len(vensPacket), "ssnr_size", len(ssnrPacket))

	// Also send to subnet broadcast if doing broadcast discovery
	if opts.ScannerIP == "" {
		ip := net.ParseIP(localIP).To4()
		if ip != nil {
			subnetBroadcast := fmt.Sprintf("%d.%d.%d.255", ip[0], ip[1], ip[2])
			subnetAddr := &net.UDPAddr{IP: net.ParseIP(subnetBroadcast), Port: DiscoveryPort}
			conn.WriteToUDP(vensPacket, subnetAddr)
			conn.WriteToUDP(ssnrPacket, subnetAddr)
			slog.Debug("sent subnet broadcast discovery", "broadcast", subnetBroadcast)
		}
	}

	// Read responses
	buf := make([]byte, 256)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Resend discovery on timeout
				slog.Debug("discovery timeout, resending...")
				conn.WriteToUDP(vensPacket, scannerAddr)
				conn.WriteToUDP(ssnrPacket, scannerAddr)
				continue
			}
			return nil, fmt.Errorf("read discovery: %w", err)
		}

		slog.Debug("received UDP packet", "from", remoteAddr, "bytes", n)

		// Skip short heartbeat ACKs
		if n < 132 {
			slog.Debug("skipping short packet (heartbeat ACK?)", "bytes", n)
			continue
		}

		info, err := ParseDeviceInfo(buf[:n])
		if err != nil {
			slog.Debug("ignored non-device-info packet", "error", err, "bytes", n)
			continue
		}

		slog.Info("found scanner",
			"name", info.Name,
			"serial", info.Serial,
			"ip", info.DeviceIP,
			"data_port", info.DataPort,
			"control_port", info.ControlPort,
		)
		return info, nil
	}
}
