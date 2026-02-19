package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/OpenPrinting/go-mfp/proto/escl"
	"github.com/OpenPrinting/go-mfp/transport"
	"github.com/OpenPrinting/go-mfp/util/optional"
	"github.com/grandcat/zeroconf"

	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/vens"
	"github.com/mzyy94/airscap/internal/webui"
)

// Version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	logLevel := parseLogLevel(envStr("AIRSCAP_LOG_LEVEL", "info"))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// Parse configuration from environment variables
	scannerIP := os.Getenv("AIRSCAP_SCANNER_IP")
	password := os.Getenv("AIRSCAP_PASSWORD")
	passwordFile := os.Getenv("AIRSCAP_PASSWORD_FILE")
	listenPort := envInt("AIRSCAP_LISTEN_PORT", 8080)
	deviceName := os.Getenv("AIRSCAP_DEVICE_NAME")
	dataDir := envStr("AIRSCAP_DATA_DIR", os.Getenv("STATE_DIRECTORY"))

	// Resolve password
	if password == "" && passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			slog.Error("failed to read password file", "path", passwordFile, "err", err)
			os.Exit(1)
		}
		password = strings.TrimSpace(string(data))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Discover scanner if IP not specified, or if password is empty (need serial)
	if scannerIP == "" || password == "" {
		slog.Info("discovering scanner...")
		opts := vens.DiscoveryOptions{Timeout: 30 * time.Second, ScannerIP: scannerIP}
		info, err := vens.FindScanner(ctx, opts)
		if err != nil {
			slog.Error("scanner discovery failed", "err", err)
			os.Exit(1)
		}
		if scannerIP == "" {
			scannerIP = info.DeviceIP
		}
		slog.Info("scanner found", "ip", scannerIP, "name", info.Name, "serial", info.Serial)

		// Derive password from serial if not explicitly set
		if password == "" {
			password = vens.PasswordFromSerial(info.Serial)
			slog.Info("password derived from serial", "password", password)
		}
	}

	// Compute identity from password
	identity, err := vens.ComputeIdentity(password)
	if err != nil {
		slog.Error("failed to compute identity", "err", err)
		os.Exit(1)
	}
	slog.Info("identity computed", "identity", identity)

	// Create and connect scanner
	sc := scanner.New(scannerIP, vens.DefaultDataPort, vens.DefaultControlPort, identity)
	if err := sc.Connect(ctx); err != nil {
		slog.Warn("initial scanner connection failed, will retry in background", "err", err)
	}
	defer sc.Disconnect()

	// Start reconnection loop (health check + auto-reconnect)
	sc.StartReconnectLoop(ctx)
	defer sc.StopReconnectLoop()

	// Use discovered device name if not explicitly set
	if deviceName == "" {
		deviceName = sc.Name()
	}
	if deviceName == "" {
		deviceName = "ScanSnap"
	}

	// Create eSCL adapter
	adapter := scanner.NewESCLAdapter(sc)

	// Initialize settings store
	var settingsStore *config.Store
	if dataDir != "" {
		var err error
		settingsStore, err = config.NewStore(dataDir)
		if err != nil {
			slog.Error("failed to create settings store", "dataDir", dataDir, "err", err)
			os.Exit(1)
		}
		slog.Info("settings store initialized", "path", dataDir)
	} else {
		settingsStore = config.NewMemoryStore()
		slog.Info("settings store initialized (memory-only, set AIRSCAP_DATA_DIR to persist)")
	}

	// Scan job status (shared with WebUI)
	scanStatus := &scanner.ScanJobStatus{}

	// Button listener: trigger scan on physical button press
	var scanMu sync.Mutex
	onButtonPress := func() {
		if !scanMu.TryLock() {
			slog.Warn("scan already in progress, ignoring button press")
			return
		}
		go func() {
			defer scanMu.Unlock()
			s := settingsStore.Get()
			if s.SaveType == "none" || s.SaveType == "" {
				slog.Info("save type is 'none', ignoring button press")
				return
			}
			if s.SaveType == "local" && s.SavePath == "" {
				slog.Warn("save path not configured, ignoring button press")
				return
			}
			if s.SaveType == "ftp" && s.FTPHost == "" {
				slog.Warn("FTP host not configured, ignoring button press")
				return
			}
			if s.SaveType == "paperless" && s.PaperlessURL == "" {
				slog.Warn("Paperless-ngx URL not configured, ignoring button press")
				return
			}
			cfg := scanner.SettingsToScanConfig(s)
			scanStatus.SetScanning(true)
			var pages int
			var err error
			switch s.SaveType {
			case "local":
				pages, err = scanner.RunSaveJob(sc, cfg, s.Format, s.SavePath)
				scanStatus.SetResult(err, pages, s.SavePath)
			case "ftp":
				pages, err = scanner.RunFTPJob(sc, cfg, s.Format, s)
				scanStatus.SetResult(err, pages, s.FTPHost)
			case "paperless":
				pages, err = scanner.RunPaperlessJob(sc, cfg, s.Format, s)
				scanStatus.SetResult(err, pages, s.PaperlessURL)
			}
			if err != nil {
				slog.Error("button scan failed", "err", err)
			}
		}()
	}

	btnListener := scanner.NewButtonListener(onButtonPress)
	if err := btnListener.Start(ctx); err != nil {
		slog.Warn("button listener failed to start", "err", err)
	}
	defer btnListener.Stop()

	// Create eSCL HTTP server (BasePath="" so it handles paths directly)
	esclServer := escl.NewAbstractServer(escl.AbstractServerOptions{
		Scanner:  adapter,
		BasePath: "",
		Hooks: escl.ServerHooks{
			OnScannerStatusResponse: func(_ *transport.ServerQuery, status *escl.ScannerStatus) *escl.ScannerStatus {
				state := adapter.ScannerState()
				status.State = state
				if state == escl.ScannerDown {
					return status
				}
				hasPaper, err := adapter.CheckADFStatus()
				if err != nil {
					slog.Warn("ADF status check failed", "err", err)
					return status
				}
				if hasPaper {
					status.ADFState = optional.New(escl.ScannerAdfLoaded)
				} else {
					status.ADFState = optional.New(escl.ScannerAdfEmpty)
				}
				return status
			},
		},
	})

	mux := http.NewServeMux()
	// Serve at /eSCL/ for clients using the rs TXT record (sane-airscan, macOS)
	mux.Handle("/eSCL/", http.StripPrefix("/eSCL", esclServer))
	// Web UI for status and settings
	mux.Handle("/ui/", http.StripPrefix("/ui", webui.NewHandler(sc, adapter, listenPort, settingsStore, scanStatus, version)))
	// Also serve at root for clients that ignore rs (sane-escl)
	mux.Handle("/", esclServer)

	addr := fmt.Sprintf(":%d", listenPort)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: logMiddleware(mux),
	}

	// Start mDNS advertisement
	mdnsServer, err := zeroconf.Register(
		deviceName,
		"_uscan._tcp",
		"local.",
		listenPort,
		[]string{
			"txtvers=1",
			"ty=" + deviceName,
			"pdl=application/pdf,image/jpeg",
			"cs=color,grayscale,binary",
			"is=adf",
			"duplex=T",
			"rs=eSCL",
		},
		nil,
	)
	if err != nil {
		slog.Error("mDNS registration failed", "err", err)
		os.Exit(1)
	}
	defer mdnsServer.Shutdown()
	slog.Info("mDNS registered", "name", deviceName, "service", "_uscan._tcp")

	// Start HTTP server
	go func() {
		localIP := vens.GetLocalIP()
		hostPort := net.JoinHostPort(localIP, strconv.Itoa(listenPort))
		slog.Info("eSCL server starting", "addr", addr, "escl", fmt.Sprintf("http://%s/eSCL", hostPort), "ui", fmt.Sprintf("http://%s/ui/", hostPort))
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("HTTP server error", "err", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("HTTP shutdown error", "err", err)
	}

	slog.Info("shutdown complete")
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// responseRecorder captures the status code for logging.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(rec, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"remote", r.RemoteAddr,
			"duration", time.Since(start).Round(time.Millisecond),
		)
	})
}
