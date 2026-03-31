package ndlocr

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unicode/utf8"
)

// CER test data: image filename -> expected max average CER per line
var cerTestCases = []struct {
	Image  string
	MaxCER float64
}{
	{"digidepo_2531162_0024.jpg", 0.08},
	{"digidepo_3048008_0025.jpg", 0.08},
	{"digidepo_11048278_po_geppo1803_00021.jpg", 0.01},
}

const modelDir = "../ndlocr-lite/src"
const resourceDir = "../ndlocr-lite/resource"

func findRuntimePath() string {
	if p := os.Getenv("ONNXRUNTIME_LIB"); p != "" {
		return p
	}
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		candidates = []string{
			"/opt/homebrew/lib/libonnxruntime.dylib",
			"/usr/local/lib/libonnxruntime.dylib",
		}
	case "linux":
		candidates = []string{
			"/usr/local/lib/libonnxruntime.so",
			"/usr/lib/libonnxruntime.so",
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func TestRecognizeCER(t *testing.T) {
	rtPath := findRuntimePath()
	if !RuntimeAvailable(rtPath) {
		t.Skip("ONNX Runtime not available")
	}
	if err := CheckModels(modelDir); err != nil {
		t.Skipf("models not available: %v", err)
	}

	engine, err := NewEngine(Config{
		ModelDir:    modelDir,
		Device:      "cpu",
		RuntimePath: rtPath,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	for _, tc := range cerTestCases {
		t.Run(tc.Image, func(t *testing.T) {
			imgPath := filepath.Join(resourceDir, tc.Image)
			xmlPath := imgPath[:len(imgPath)-len(filepath.Ext(imgPath))] + ".xml"

			gtLines, err := loadGroundTruthLines(xmlPath)
			if err != nil {
				t.Fatalf("failed to load ground truth: %v", err)
			}

			img, err := LoadImage(imgPath)
			if err != nil {
				t.Fatalf("failed to load image: %v", err)
			}

			blocks, err := engine.Recognize(ctx, img)
			if err != nil {
				t.Fatalf("recognition failed: %v", err)
			}

			// Collect predicted texts
			var predTexts []string
			for _, b := range blocks {
				if b.Text != "" {
					predTexts = append(predTexts, b.Text)
				}
			}

			// Per-line matching: for each GT line, find the best matching prediction
			var totalCER float64
			var totalChars int
			var matched, unmatched int
			for _, gt := range gtLines {
				gtLen := utf8.RuneCountInString(gt)
				if gtLen == 0 {
					continue
				}
				bestCER := 1.0
				for _, pred := range predTexts {
					cer := computeCER(gt, pred)
					if cer < bestCER {
						bestCER = cer
					}
				}
				totalCER += bestCER * float64(gtLen)
				totalChars += gtLen
				if bestCER < 0.5 {
					matched++
				} else {
					unmatched++
					t.Logf("  unmatched GT line (CER=%.3f): %q", bestCER, gt)
				}
			}

			avgCER := 0.0
			if totalChars > 0 {
				avgCER = totalCER / float64(totalChars)
			}
			t.Logf("weighted avg CER: %.4f (%d GT lines, %d matched, %d unmatched, %d predicted blocks)",
				avgCER, len(gtLines), matched, unmatched, len(predTexts))

			if avgCER > tc.MaxCER {
				t.Errorf("weighted avg CER %.4f exceeds threshold %.4f", avgCER, tc.MaxCER)
			}
		})
	}
}

// XML structures for ground truth
type ocrDataset struct {
	XMLName xml.Name `xml:"OCRDATASET"`
	Page    page     `xml:"PAGE"`
}

type page struct {
	TextBlocks []textBlock `xml:"TEXTBLOCK"`
}

type textBlock struct {
	Lines []line `xml:"LINE"`
}

type line struct {
	String string `xml:"STRING,attr"`
}

func loadGroundTruthLines(xmlPath string) ([]string, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML: %w", err)
	}

	var ds ocrDataset
	if err := xml.Unmarshal(data, &ds); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	seen := make(map[string]bool)
	var lines []string
	for _, tb := range ds.Page.TextBlocks {
		for _, l := range tb.Lines {
			if l.String != "" && !seen[l.String] {
				seen[l.String] = true
				lines = append(lines, l.String)
			}
		}
	}
	return lines, nil
}

// computeCER computes Character Error Rate using Levenshtein distance.
func computeCER(reference, hypothesis string) float64 {
	ref := []rune(reference)
	hyp := []rune(hypothesis)

	if len(ref) == 0 {
		if len(hyp) == 0 {
			return 0
		}
		return 1
	}

	// Levenshtein distance (two-row optimization)
	prev := make([]int, len(hyp)+1)
	curr := make([]int, len(hyp)+1)

	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(ref); i++ {
		curr[0] = i
		for j := 1; j <= len(hyp); j++ {
			cost := 1
			if ref[i-1] == hyp[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		prev, curr = curr, prev
	}

	return float64(prev[len(hyp)]) / float64(len(ref))
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
