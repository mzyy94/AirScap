package scanner

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg"

	"codeberg.org/go-pdf/fpdf"
	fpdftiff "codeberg.org/go-pdf/fpdf/contrib/tiff"
	_ "golang.org/x/image/tiff"

	"github.com/mzyy94/airscap/internal/vens"
)

// WritePDF combines scanned pages (JPEG or TIFF) into a single PDF file.
// When isBW is true, TIFF pages are registered via fpdf's contrib/tiff package.
func WritePDF(pages []vens.Page, dpi int, isBW bool, outputPath string) error {
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

		widthMM := float64(cfg.Width) / float64(dpi) * 25.4
		heightMM := float64(cfg.Height) / float64(dpi) * 25.4

		pdf.AddPageFormat("P", fpdf.SizeType{Wd: widthMM, Ht: heightMM})

		name := fmt.Sprintf("page%d", i)
		if isBW {
			opt := fpdf.ImageOptions{ImageType: "tiff"}
			fpdftiff.RegisterReader(pdf, name, opt, bytes.NewReader(p.JPEG))
		} else {
			opt := fpdf.ImageOptions{ImageType: "JPEG"}
			pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(p.JPEG))
		}
		pdf.ImageOptions(name, 0, 0, widthMM, heightMM, false, fpdf.ImageOptions{}, 0, "")
	}

	return pdf.OutputFileAndClose(outputPath)
}
