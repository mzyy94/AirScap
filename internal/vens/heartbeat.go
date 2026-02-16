package vens

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// Heartbeat sends periodic UDP heartbeat packets to keep the session alive.
type Heartbeat struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// StartHeartbeat begins sending heartbeat packets every interval to the scanner.
// Cancel the returned Heartbeat to stop.
func StartHeartbeat(ctx context.Context, scannerIP string, token [8]byte, interval time.Duration) (*Heartbeat, error) {
	if interval == 0 {
		interval = 500 * time.Millisecond
	}

	localIP := GetLocalIP()
	packet := MarshalDiscoveryVENS(localIP, token, ClientDiscoveryPort, true)
	addr := &net.UDPAddr{IP: net.ParseIP(scannerIP), Port: DiscoveryPort}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)
		defer conn.Close()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		slog.Info("heartbeat started", "scanner", scannerIP, "interval", interval)
		for {
			conn.WriteToUDP(packet, addr)
			select {
			case <-ctx.Done():
				slog.Info("heartbeat stopped")
				return
			case <-ticker.C:
			}
		}
	}()

	return &Heartbeat{cancel: cancel, done: done}, nil
}

// Stop stops the heartbeat.
func (h *Heartbeat) Stop() {
	h.cancel()
	<-h.done
}
