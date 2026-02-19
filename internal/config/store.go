package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Settings holds user-configurable scan defaults.
type Settings struct {
	ColorMode        string `json:"colorMode"`
	Resolution       int    `json:"resolution"`
	Duplex           bool   `json:"duplex"`
	Format           string `json:"format"`
	BlankPageRemoval *bool  `json:"blankPageRemoval"` // nil = default (true)
	BleedThrough     bool   `json:"bleedThrough"`
	SaveType         string `json:"saveType"` // "none", "local", "ftp", "paperless"
	SavePath         string `json:"savePath"` // directory path when SaveType="local"
	FTPHost          string `json:"ftpHost"`
	FTPUser          string `json:"ftpUser"`
	FTPPassword      string `json:"ftpPassword"`
	PaperlessURL     string `json:"paperlessUrl"`
	PaperlessToken   string `json:"paperlessToken"`
}

// DefaultSettings returns the default scan settings.
func DefaultSettings() Settings {
	return Settings{
		ColorMode:  "auto",
		Resolution: 0,
		Duplex:     false,
		Format:     "application/pdf",
		SaveType:   "none",
		SavePath:   "",
	}
}

// Store provides thread-safe settings persistence backed by a JSON file.
type Store struct {
	mu       sync.RWMutex
	settings Settings
	path     string
}

// NewStore creates a Store that persists settings to dataDir/settings.json.
// If the file does not exist or is invalid, default settings are used.
func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	s := &Store{
		path:     filepath.Join(dataDir, "settings.json"),
		settings: DefaultSettings(),
	}
	s.load()
	return s, nil
}

// NewMemoryStore creates a Store that keeps settings in memory only (no file persistence).
func NewMemoryStore() *Store {
	return &Store{settings: DefaultSettings()}
}

// Get returns a copy of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// Update replaces the settings and persists to disk.
func (s *Store) Update(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = settings
	return s.save()
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // file missing is OK, use defaults
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		slog.Warn("invalid settings file, using defaults", "path", s.path, "err", err)
		return
	}
	s.settings = settings
}

func (s *Store) save() error {
	if s.path == "" {
		return nil // memory-only mode
	}
	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
