package scanner

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jlaffaye/ftp"

	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/vens"
)

// ScanJobStatus tracks the state of a button-triggered scan job.
type ScanJobStatus struct {
	mu        sync.RWMutex
	Scanning  bool   `json:"scanning"`
	LastError string `json:"lastError,omitempty"`
	LastScan  string `json:"lastScan,omitempty"` // RFC3339
	Pages     int    `json:"pages"`
	FilePath  string `json:"filePath,omitempty"`
}

// Snapshot returns a copy of the current status.
func (s *ScanJobStatus) Snapshot() ScanJobStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ScanJobStatus{
		Scanning:  s.Scanning,
		LastError: s.LastError,
		LastScan:  s.LastScan,
		Pages:     s.Pages,
		FilePath:  s.FilePath,
	}
}

// SetScanning marks the scan as in-progress.
func (s *ScanJobStatus) SetScanning(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Scanning = v
	if v {
		s.LastError = ""
	}
}

// SetResult records the outcome of a completed scan.
func (s *ScanJobStatus) SetResult(err error, pages int, filePath string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Scanning = false
	s.LastScan = time.Now().UTC().Format(time.RFC3339)
	s.Pages = pages
	s.FilePath = filePath
	if err != nil {
		s.LastError = err.Error()
	} else {
		s.LastError = ""
	}
}

// SettingsToScanConfig converts config.Settings to vens.ScanConfig.
func SettingsToScanConfig(s config.Settings) vens.ScanConfig {
	cfg := vens.DefaultScanConfig()

	switch s.ColorMode {
	case "auto":
		cfg.ColorMode = vens.ColorAuto
	case "color":
		cfg.ColorMode = vens.ColorColor
	case "grayscale":
		cfg.ColorMode = vens.ColorGray
	case "bw":
		cfg.ColorMode = vens.ColorBW
	default:
		cfg.ColorMode = vens.ColorAuto
	}

	switch s.Resolution {
	case 0:
		cfg.Quality = vens.QualityAuto
	case 150:
		cfg.Quality = vens.QualityNormal
	case 200:
		cfg.Quality = vens.QualityFine
	case 300:
		cfg.Quality = vens.QualitySuperFine
	default:
		cfg.Quality = vens.QualityAuto
	}

	cfg.Duplex = s.Duplex
	if s.BlankPageRemoval != nil {
		cfg.BlankPageRemoval = *s.BlankPageRemoval
	}
	cfg.BleedThrough = s.BleedThrough
	return cfg
}

// RunSaveJob executes a scan and saves the result to the filesystem.
func RunSaveJob(sc *Scanner, cfg vens.ScanConfig, format string, savePath string) (int, error) {
	if err := os.MkdirAll(savePath, 0755); err != nil {
		return 0, fmt.Errorf("create save directory: %w", err)
	}

	slog.Info("button scan starting", "format", format, "savePath", savePath)
	pages, err := sc.Scan(cfg, nil)
	if err != nil {
		return len(pages), fmt.Errorf("scan: %w", err)
	}
	if len(pages) == 0 {
		return 0, fmt.Errorf("scan returned no pages")
	}

	timestamp := time.Now().Format("20060102_150405")
	dpi := vens.QualityDPI[cfg.Quality]
	if dpi == 0 {
		dpi = 300
	}

	isBW := cfg.ColorMode == vens.ColorBW

	if format == "application/pdf" {
		outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s.pdf", timestamp))
		if err := WritePDF(pages, dpi, isBW, outPath); err != nil {
			return len(pages), fmt.Errorf("write PDF: %w", err)
		}
		slog.Info("scan saved as PDF", "path", outPath, "pages", len(pages))
	} else {
		// Individual image files: extension matches actual data format
		ext := "jpg"
		if isBW {
			ext = "tiff"
		}
		for i, p := range pages {
			outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s_%03d.%s", timestamp, i+1, ext))
			if err := os.WriteFile(outPath, p.JPEG, 0644); err != nil {
				return len(pages), fmt.Errorf("write page %d: %w", i+1, err)
			}
		}
		slog.Info("scan saved as individual files", "path", savePath, "pages", len(pages), "ext", ext)
	}

	return len(pages), nil
}

// RunFTPJob executes a scan and uploads the result to an FTP server.
func RunFTPJob(sc *Scanner, cfg vens.ScanConfig, format string, s config.Settings) (int, error) {
	host := s.FTPHost
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "21")
	}

	slog.Info("button scan starting (FTP)", "format", format, "host", host)
	pages, err := sc.Scan(cfg, nil)
	if err != nil {
		return len(pages), fmt.Errorf("scan: %w", err)
	}
	if len(pages) == 0 {
		return 0, fmt.Errorf("scan returned no pages")
	}

	conn, err := ftp.Dial(host, ftp.DialWithTimeout(10*time.Second))
	if err != nil {
		return len(pages), fmt.Errorf("FTP connect: %w", err)
	}
	defer conn.Quit()

	user := s.FTPUser
	if user == "" {
		user = "anonymous"
	}
	if err := conn.Login(user, s.FTPPassword); err != nil {
		return len(pages), fmt.Errorf("FTP login: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	dpi := vens.QualityDPI[cfg.Quality]
	if dpi == 0 {
		dpi = 300
	}

	isBW := cfg.ColorMode == vens.ColorBW

	if format == "application/pdf" {
		tmpFile, err := os.CreateTemp("", "scan_*.pdf")
		if err != nil {
			return len(pages), fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		if err := WritePDF(pages, dpi, isBW, tmpPath); err != nil {
			return len(pages), fmt.Errorf("write PDF: %w", err)
		}
		data, err := os.ReadFile(tmpPath)
		if err != nil {
			return len(pages), fmt.Errorf("read temp PDF: %w", err)
		}
		remoteName := fmt.Sprintf("scan_%s.pdf", timestamp)
		if err := conn.Stor(remoteName, bytes.NewReader(data)); err != nil {
			return len(pages), fmt.Errorf("FTP upload %s: %w", remoteName, err)
		}
		slog.Info("scan uploaded via FTP", "file", remoteName, "pages", len(pages))
	} else {
		ext := "jpg"
		if isBW {
			ext = "tiff"
		}
		for i, p := range pages {
			remoteName := fmt.Sprintf("scan_%s_%03d.%s", timestamp, i+1, ext)
			if err := conn.Stor(remoteName, bytes.NewReader(p.JPEG)); err != nil {
				return len(pages), fmt.Errorf("FTP upload page %d: %w", i+1, err)
			}
		}
		slog.Info("scan uploaded via FTP", "pages", len(pages), "ext", ext)
	}

	return len(pages), nil
}

// RunPaperlessJob executes a scan and uploads the result to Paperless-ngx.
func RunPaperlessJob(sc *Scanner, cfg vens.ScanConfig, format string, s config.Settings) (int, error) {
	baseURL := strings.TrimRight(s.PaperlessURL, "/")

	slog.Info("button scan starting (Paperless-ngx)", "format", format, "url", baseURL)
	pages, err := sc.Scan(cfg, nil)
	if err != nil {
		return len(pages), fmt.Errorf("scan: %w", err)
	}
	if len(pages) == 0 {
		return 0, fmt.Errorf("scan returned no pages")
	}

	timestamp := time.Now().Format("20060102_150405")
	dpi := vens.QualityDPI[cfg.Quality]
	if dpi == 0 {
		dpi = 300
	}

	isBW := cfg.ColorMode == vens.ColorBW

	// PDF: upload as single document
	if format == "application/pdf" {
		tmpFile, err := os.CreateTemp("", "scan_*.pdf")
		if err != nil {
			return len(pages), fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(tmpPath)

		if err := WritePDF(pages, dpi, isBW, tmpPath); err != nil {
			return len(pages), fmt.Errorf("write PDF: %w", err)
		}
		docData, err := os.ReadFile(tmpPath)
		if err != nil {
			return len(pages), fmt.Errorf("read temp PDF: %w", err)
		}
		filename := fmt.Sprintf("scan_%s.pdf", timestamp)
		if err := uploadToPaperless(baseURL, s.PaperlessToken, filename, docData); err != nil {
			return len(pages), fmt.Errorf("paperless upload: %w", err)
		}
		slog.Info("scan uploaded to Paperless-ngx", "file", filename, "pages", len(pages))
		return len(pages), nil
	}

	// Individual pages
	for i, p := range pages {
		ext := "jpg"
		if isBW {
			ext = "tiff"
		}
		fn := fmt.Sprintf("scan_%s_%03d.%s", timestamp, i+1, ext)
		if err := uploadToPaperless(baseURL, s.PaperlessToken, fn, p.JPEG); err != nil {
			return len(pages), fmt.Errorf("paperless upload page %d: %w", i+1, err)
		}
	}
	slog.Info("scan uploaded to Paperless-ngx", "pages", len(pages))
	return len(pages), nil
}

func uploadToPaperless(baseURL, token, filename string, data []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write form data: %w", err)
	}
	writer.Close()

	url := baseURL + "/api/documents/post_document/"
	req, err := http.NewRequest("POST", url, &body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Token "+token)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
