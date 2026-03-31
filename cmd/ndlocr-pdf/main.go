package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"codeberg.org/go-pdf/fpdf"
	"github.com/mzyy94/airscap/ndlocr"
)

func main() {
	sourceImg := flag.String("sourceimg", "", "Input image file path")
	sourceDir := flag.String("sourcedir", "", "Input image directory path")
	output := flag.String("output", "", "Output PDF file path (required)")
	device := flag.String("device", "cpu", "Inference device: cpu or cuda")
	modelDir := flag.String("modeldir", "ndlocr-lite/src", "Model and config directory")
	jsonOut := flag.Bool("json", false, "Output JSON per image")
	txtOut := flag.Bool("txt", false, "Output TXT per image")
	flag.Parse()

	if *output == "" {
		log.Fatal("--output is required")
	}
	if *sourceImg == "" && *sourceDir == "" {
		log.Fatal("either --sourceimg or --sourcedir is required")
	}

	// Collect input images
	var imagePaths []string
	if *sourceImg != "" {
		imagePaths = append(imagePaths, *sourceImg)
	}
	if *sourceDir != "" {
		entries, err := os.ReadDir(*sourceDir)
		if err != nil {
			log.Fatalf("failed to read directory %s: %v", *sourceDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			switch ext {
			case ".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".jp2":
				imagePaths = append(imagePaths, filepath.Join(*sourceDir, e.Name()))
			}
		}
		sort.Strings(imagePaths)
	}

	if len(imagePaths) == 0 {
		log.Fatal("no input images found")
	}

	// Check models
	if err := ndlocr.CheckModels(*modelDir); err != nil {
		log.Fatalf("model check failed: %v", err)
	}

	// Initialize engine
	engine, err := ndlocr.NewEngine(ndlocr.Config{
		ModelDir:    *modelDir,
		Device:      *device,
		RuntimePath: findRuntimeLib(),
	})
	if err != nil {
		log.Fatalf("failed to initialize engine: %v", err)
	}
	defer engine.Close()

	pdf := fpdf.New("P", "pt", "A4", "")
	pdf.AddUTF8FontFromBytes("ja", "", ndlocr.EmbeddedFont)

	ctx := context.Background()
	outputDir := filepath.Dir(*output)

	for i, imgPath := range imagePaths {
		fmt.Printf("[%d/%d] %s\n", i+1, len(imagePaths), filepath.Base(imgPath))

		img, err := ndlocr.LoadImage(imgPath)
		if err != nil {
			log.Printf("  skip: %v", err)
			continue
		}

		blocks, err := engine.Recognize(ctx, img)
		if err != nil {
			log.Printf("  error: %v", err)
			continue
		}

		addPage(pdf, img, blocks)

		baseName := strings.TrimSuffix(filepath.Base(imgPath), filepath.Ext(imgPath))

		if *txtOut {
			writeTXT(filepath.Join(outputDir, baseName+".txt"), blocks)
		}
		if *jsonOut {
			writeJSON(filepath.Join(outputDir, baseName+".json"), blocks)
		}

		fmt.Printf("  %d text blocks\n", len(blocks))
	}

	if err := pdf.OutputFileAndClose(*output); err != nil {
		log.Fatalf("failed to write PDF: %v", err)
	}
	fmt.Printf("Output: %s\n", *output)
}

func addPage(pdf *fpdf.Fpdf, img image.Image, blocks []ndlocr.TextBlock) {
	bounds := img.Bounds()
	imgW := float64(bounds.Dx())
	imgH := float64(bounds.Dy())

	// Page size matches image size in points (1px = 1pt at 72dpi)
	pdf.AddPageFormat("P", fpdf.SizeType{Wd: imgW, Ht: imgH})

	// Encode image to JPEG in memory for embedding
	var buf bytes.Buffer
	jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	reader := bytes.NewReader(buf.Bytes())
	pdf.RegisterImageOptionsReader(fmt.Sprintf("page_%d", pdf.PageNo()), fpdf.ImageOptions{ImageType: "JPG"}, reader)
	pdf.ImageOptions(fmt.Sprintf("page_%d", pdf.PageNo()), 0, 0, imgW, imgH, false, fpdf.ImageOptions{ImageType: "JPG"}, 0, "")

	// Overlay transparent text
	pdf.SetAlpha(0.0, "Normal")
	pdf.SetTextColor(0, 0, 0)

	for _, b := range blocks {
		x1 := float64(b.BoundingBox[0][0])
		y1 := float64(b.BoundingBox[0][1])
		x2 := float64(b.BoundingBox[2][0])
		y2 := float64(b.BoundingBox[2][1])
		boxW := x2 - x1
		boxH := y2 - y1

		if boxW <= 0 || boxH <= 0 || b.Text == "" {
			continue
		}

		isVertical := strings.HasSuffix(b.Category, "vertical")
		runes := []rune(b.Text)
		nChars := len(runes)
		if nChars == 0 {
			continue
		}

		if isVertical {
			// Vertical: font size = box width, spaced evenly over box height
			fontSize := boxW
			charH := boxH / float64(nChars)
			if charH < fontSize {
				fontSize = charH
			}
			if fontSize <= 0 {
				fontSize = 1
			}
			pdf.SetFont("ja", "", fontSize)
			cx := x1 + (boxW-fontSize)/2
			for j, r := range runes {
				cy := y1 + float64(j)*charH + fontSize
				pdf.Text(cx, cy, string(r))
			}
		} else {
			// Horizontal: font size = box height, scale to fill box width
			fontSize := boxH
			if fontSize <= 0 {
				fontSize = 1
			}
			pdf.SetFont("ja", "", fontSize)
			sw := pdf.GetStringWidth(b.Text)
			if sw > 0 {
				fontSize *= boxW / sw
				pdf.SetFont("ja", "", fontSize)
			}
			pdf.Text(x1, y1+fontSize, b.Text)
		}
	}

	pdf.SetAlpha(1.0, "Normal")
}

func writeTXT(path string, blocks []ndlocr.TextBlock) {
	var sb strings.Builder
	for _, b := range blocks {
		sb.WriteString(b.Text)
		sb.WriteByte('\n')
	}
	os.WriteFile(path, []byte(sb.String()), 0644)
}

type jsonBlock struct {
	Text        string    `json:"text"`
	BoundingBox [4][2]int `json:"bounding_box"`
	Category    string    `json:"category"`
	Confidence  float32   `json:"confidence"`
}

func writeJSON(path string, blocks []ndlocr.TextBlock) {
	var jb []jsonBlock
	for _, b := range blocks {
		jb = append(jb, jsonBlock{
			Text:        b.Text,
			BoundingBox: b.BoundingBox,
			Category:    b.Category,
			Confidence:  b.Confidence,
		})
	}
	data, _ := json.MarshalIndent(jb, "", "  ")
	os.WriteFile(path, data, 0644)
}

func findRuntimeLib() string {
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
