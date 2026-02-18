package scanner

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

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
	case "color":
		cfg.ColorMode = vens.ColorColor
	case "grayscale":
		cfg.ColorMode = vens.ColorGray
	case "bw":
		cfg.ColorMode = vens.ColorBW
	default:
		cfg.ColorMode = vens.ColorColor
	}

	switch s.Resolution {
	case 150:
		cfg.Quality = vens.QualityNormal
	case 200:
		cfg.Quality = vens.QualityFine
	case 300:
		cfg.Quality = vens.QualitySuperFine
	default:
		cfg.Quality = vens.QualitySuperFine
	}

	cfg.Duplex = s.Duplex
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

	switch {
	case format == "application/pdf" && !isBW:
		outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s.pdf", timestamp))
		if err := WritePDF(pages, dpi, outPath); err != nil {
			return len(pages), fmt.Errorf("write PDF: %w", err)
		}
		slog.Info("scan saved as PDF", "path", outPath, "pages", len(pages))

	case format == "application/pdf" && isBW:
		// BW mode produces TIFF G4; fpdf doesn't support TIFF, save as individual TIFF files
		slog.Warn("BW mode with PDF format not supported, saving as TIFF files")
		for i, p := range pages {
			outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s_%03d.tiff", timestamp, i+1))
			if err := os.WriteFile(outPath, p.JPEG, 0644); err != nil {
				return len(pages), fmt.Errorf("write TIFF page %d: %w", i+1, err)
			}
		}
		slog.Info("scan saved as TIFF files", "path", savePath, "pages", len(pages))

	case format == "image/jpeg":
		for i, p := range pages {
			ext := "jpg"
			if isBW {
				ext = "tiff"
			}
			outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s_%03d.%s", timestamp, i+1, ext))
			if err := os.WriteFile(outPath, p.JPEG, 0644); err != nil {
				return len(pages), fmt.Errorf("write page %d: %w", i+1, err)
			}
		}
		slog.Info("scan saved as individual files", "path", savePath, "pages", len(pages))

	default:
		// image/tiff or unknown: save raw data
		for i, p := range pages {
			outPath := filepath.Join(savePath, fmt.Sprintf("scan_%s_%03d.tiff", timestamp, i+1))
			if err := os.WriteFile(outPath, p.JPEG, 0644); err != nil {
				return len(pages), fmt.Errorf("write page %d: %w", i+1, err)
			}
		}
		slog.Info("scan saved as TIFF files", "path", savePath, "pages", len(pages))
	}

	return len(pages), nil
}
