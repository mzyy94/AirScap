package scanner

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg"

	"github.com/go-pdf/fpdf"

	"github.com/mzyy94/airscap/internal/vens"
)

// WritePDF combines scanned JPEG pages into a single PDF file.
func WritePDF(pages []vens.Page, dpi int, outputPath string) error {
	if len(pages) == 0 {
		return fmt.Errorf("no pages to write")
	}
	if dpi <= 0 {
		dpi = 300
	}

	pdf := fpdf.New("P", "mm", "", "")
	pdf.SetAutoPageBreak(false, 0)

	for i, p := range pages {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(p.JPEG))
		if err != nil {
			return fmt.Errorf("decode page %d image config: %w", i+1, err)
		}

		// Convert pixels to mm: mm = pixels / dpi * 25.4
		widthMM := float64(cfg.Width) / float64(dpi) * 25.4
		heightMM := float64(cfg.Height) / float64(dpi) * 25.4

		pdf.AddPageFormat("P", fpdf.SizeType{Wd: widthMM, Ht: heightMM})

		name := fmt.Sprintf("page%d", i)
		pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: "JPEG"}, bytes.NewReader(p.JPEG))
		pdf.ImageOptions(name, 0, 0, widthMM, heightMM, false, fpdf.ImageOptions{ImageType: "JPEG"}, 0, "")
	}

	return pdf.OutputFileAndClose(outputPath)
}
