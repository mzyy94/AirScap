package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/mzyy94/airscap/internal/vens"
)

// ButtonListener listens for scanner button press events on UDP:55265.
type ButtonListener struct {
	conn     *net.UDPConn
	callback func()
	done     chan struct{}
}

// NewButtonListener creates a ButtonListener that calls callback on button press.
func NewButtonListener(callback func()) *ButtonListener {
	return &ButtonListener{callback: callback}
}

// Start begins listening for button press events. Blocks until ctx is cancelled.
func (b *ButtonListener) Start(ctx context.Context) error {
	addr := &net.UDPAddr{Port: int(vens.ClientNotifyPort)}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP:%d: %w", vens.ClientNotifyPort, err)
	}
	b.conn = conn
	b.done = make(chan struct{})
	slog.Info("button listener started", "port", vens.ClientNotifyPort)

	go b.loop(ctx)
	return nil
}

// Stop closes the listener and waits for the goroutine to exit.
func (b *ButtonListener) Stop() {
	if b.conn != nil {
		b.conn.Close()
	}
	if b.done != nil {
		<-b.done
	}
}

func (b *ButtonListener) loop(ctx context.Context) {
	defer close(b.done)
	buf := make([]byte, 256)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, remote, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Debug("button listener read error", "err", err)
			continue
		}

		eventType, eventData, err := vens.ParseEventNotification(buf[:n])
		if err != nil {
			slog.Debug("ignoring non-VENS packet", "remote", remote, "err", err)
			continue
		}

		slog.Info("scanner event received", "type", eventType, "data", eventData, "remote", remote)
		if b.callback != nil {
			b.callback()
		}
	}
}
